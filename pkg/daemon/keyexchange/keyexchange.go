// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keyexchange is L5 — establishes the per-peer AEAD session
// key (with optional Ed25519 authentication of identity).
//
// The Manager owns:
//   - pendingRekey map[uint32]*PendingRekeyState — tracks key
//     exchanges we sent and are awaiting a reply on. Drives the
//     retransmit loop.
//   - peerPubKeys map[uint32]ed25519.PublicKey — cached peer Ed25519
//     pubkeys (filled from the verifyFunc callback).
//   - lastInboundDecrypt map[uint32]time.Time — used by the
//     handleAuthKeyExchange "stale reply" gate.
//   - the rekey retransmit goroutine (Loop).
//
// It owns the L5 Store — the per-peer Crypto registry. L6 (envelope)
// imports Store to look up keys when wrapping/unwrapping AEAD frames.
//
// Per docs/architecture/01-LAYERS.md L5:
//
//	Role: establish the per-peer AEAD session key (with optional
//	  Ed25519 authentication of identity).
//	Owns: pendingRekey, peerPubKeys cache, the rekeyRetransmitLoop
//	  goroutine, AND (post T5.x-followup) the per-peer Crypto Store +
//	  replay window + salvage ring + decryptFailCount.
//	Consumes: L1, L2 (sends bootstrap frames; first auth-key-exchange
//	  is the only frame that bypasses L6 envelope), L3 (signs/verifies),
//	  L4 (routes the frame).
//	Exposes: Establish(peer) → SessionKey, RekeyTrigger(peer),
//	  key-install events.
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): rkPendingMu
// is a LEAF lock — never held while taking any TunnelManager mutex.
// All callers obey this by reading state under rkPendingMu, releasing,
// then mutating tm-side state in a separate critical section.
//
// Per docs/architecture/03-INVARIANTS.md §9 (horizontal-incest): L6 →
// L5 is the canonical downward import. keyexchange/ MUST NOT import
// envelope/ — that would be upward and contradict 01-LAYERS.md §"Layer
// dependencies".
package keyexchange

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// Tunable timing constants. Frozen wire-adjacent behavior — changing
// these affects observable retransmit cadence + stale-reply gating.
const (
	// RekeyRetransmitInterval is how long we wait for an inbound encrypted
	// packet to confirm the peer received our key_exchange. After this we
	// retransmit on the assumption either our key_exchange or the peer's
	// reply was dropped.
	RekeyRetransmitInterval = 4 * time.Second

	// MaxRekeyAttempts caps the retransmit loop. The first send + this
	// many retries = 1 + MaxRekeyAttempts total attempts. After that we
	// give up — peer is presumed gone.
	MaxRekeyAttempts = 5

	// RekeyRelayFallbackAfter is the attempt count at which the rekey
	// loop's PreRetransmitHook is invited to flip the peer's routing
	// path to relay. The first attempt goes direct on the optimistic
	// assumption the cached endpoint still resolves; once that has
	// silently failed RekeyRelayFallbackAfter times, the routing layer's
	// blackhole heuristic typically hasn't yet accumulated enough silent
	// observations to flip on its own (BlackholeMissesRequired=3
	// observations × 4s = 12s, and rekey gives up at 24s), so we'd
	// burn the remaining budget on the dead direct path. Forcing the
	// flip here guarantees ≥3 attempts go via relay before give-up.
	//
	// Reproduces the recovery for the 2026-05-11 Mac-restart NAT-
	// remapping wedge: peer endpoint caches pointed at the Mac's old
	// external port (NAT recycled after daemon restart), every direct
	// rekey landed in a black hole, and the loop exhausted all 6
	// attempts before the blackhole heuristic could engage.
	RekeyRelayFallbackAfter = 2

	// KeyExchangeReplyStaleThreshold: when an auth_key_exchange arrives
	// and we already have crypto for the peer with no inbound traffic in
	// this window, reply with our key_exchange too (in case our previous
	// reply was dropped). Loosens handleAuthKeyExchange's "send back" gate.
	KeyExchangeReplyStaleThreshold = 6 * time.Second

	// KeyExchangeReplyMinInterval: minimum gap between two reply-PILAs to
	// the same peer in the asymmetric-recovery branch of HandleAuthFrame.
	// Without this gate the staleness reply path forms a symmetric ping-
	// pong: both sides see InboundDecryptStale (no AEAD traffic yet) on
	// every incoming PILA and reply with another PILA. The next PILA
	// arrives in <100 ms, the staleness test still passes, and the loop
	// runs forever — 466 "encrypted tunnel established" events for one
	// peer in 90 s, observed against nasa-apod on 2026-05-26.
	//
	// 1 s is long enough that the ping-pong cannot sustain itself (the
	// peer's retransmit cadence is RekeyRetransmitInterval=4s), short
	// enough that a genuinely lost reply on a slow path still recovers
	// inside the user-visible dial budget (DialMaxRetries gives ~24 s).
	KeyExchangeReplyMinInterval = 1 * time.Second

	// rekeyGaveUpCooldown is how long after giving up on a rekey cycle
	// before MarkPendingRekey starts a new one for the same peer.
	// Prevents the "bounce" where a transient outbound packet immediately
	// restarts a cycle that just exhausted MaxRekeyAttempts.
	//
	// Was 60s; shortened to 5s after the 2026-05-26 worktree diagnostic
	// showed that under moderate packet loss (15-30%) the L5 rekey loop
	// can exhaust its 24s attempt budget from bad luck, then freeze ALL
	// traffic to the peer for the full minute because every SendTo
	// queues into the per-peer pending buffer (which fills at 64 frames
	// and starts dropping). 5s is still long enough to prevent the
	// original "bounce" pattern (a doomed cycle followed by an immediate
	// retry) but short enough that genuine packet-loss transients
	// self-heal rather than wedge for a minute.
	rekeyGaveUpCooldown = 5 * time.Second

	// DuplicateHandshakeDebounce is the window during which a repeated
	// key_exchange frame from the same peer carrying the SAME X25519
	// ephemeral key is treated as a duplicate of an already-handled
	// handshake. Inside the window the frame is logged at Debug and the
	// observable side effects are skipped: no "encrypted tunnel
	// established" log line, no tunnel.established bus event, no
	// PostInstallHook invocation, and no reply key_exchange.
	//
	// Why this matters: peers retransmit their PILA via the
	// keyexchange.loop's RekeyRetransmitInterval (4 s) PLUS direct +
	// relay copies of the same frame can both land within ms when the
	// beacon relay is hot. Both legs of every duplicate used to fire
	// the postInstall hook (peer-endpoint update, salvage replay,
	// flushPending) and produce a noisy log burst that operators
	// mistook for a real handshake storm. Real rekey (peer's ephemeral
	// key actually changed) is NOT debounced — keyChanged forces the
	// full path so salvage + flushPending run.
	//
	// 250 ms is short enough that an actual second handshake (caused
	// by a real key rotation, not a duplicate frame) still progresses
	// promptly, and long enough to coalesce the direct+relay arrival
	// window plus most peer-side retransmits caused by an early ACK
	// being dropped.
	DuplicateHandshakeDebounce = 250 * time.Millisecond

	NegativePubKeyCacheTTL = 3 * time.Second
	MaxNegPubKeyEntries    = 4096

	// KeyRequestAfterSends is how many of our key-exchange frames to a peer
	// may go unanswered, while we hold no session key for it, before each
	// further send also carries a key request: an unauthenticated PILK
	// frame next to the PILA. See SendKeyExchangeToNode.
	//
	// Why: a node answers a new peer's PILA exactly once and clears its
	// own retransmit state (HandleAuthFrame, the !hadCrypto branch). If
	// that one reply is lost, every retransmit of ours carries the same
	// X25519 key, so the peer treats it as a same-session keepalive and
	// stays silent: the peer holds a session for us, we hold none, and
	// nothing on either side recovers it until the peer's path watchdog
	// drops its half (which our own PILAs keep postponing). Every
	// released daemon answers a PILK from a peer whose identity it knows
	// by rejecting it and sending its authenticated PILA instead
	// (HandleUnauthFrame), and that reply is marked pending, so the peer
	// retransmits it until our PILA arrives. The PILK installs nothing on
	// such a peer and costs one 40-byte frame per retransmit.
	KeyRequestAfterSends = 1
)

// PendingRekeyState tracks a key-exchange we sent and are waiting on.
// Cleared when handleEncrypted records a successful decrypt from peer
// (proof their crypto matches ours). The retransmit loop bumps
// LastSentAt and Attempts on each retry; gives up after MaxRekeyAttempts
// to avoid hammering a peer that's just gone.
type PendingRekeyState struct {
	FirstSentAt time.Time
	LastSentAt  time.Time
	Attempts    int
}

// FrameSender is L2's contribution to L5: ship a raw UDP frame to a
// peer (relay-aware). tunnel.go satisfies this with writeFrame.
//
// When sub-pass 4 extracts L2, this becomes an L2 interface; for now
// the daemon supplies a closure capturing tm.writeFrame.
type FrameSender func(peerNodeID uint32, addr *net.UDPAddr, frame []byte) error

// PeerAddrLookup returns the currently-known UDP address for peerNodeID.
// Used by sendKeyExchangeToNode to find the destination. tunnel.go
// satisfies this with a closure reading tm.peers under tm.mu.
type PeerAddrLookup func(peerNodeID uint32) *net.UDPAddr

// VerifyFunc fetches the canonical Ed25519 public key for nodeID
// (typically from the registry).
type VerifyFunc func(nodeID uint32) (ed25519.PublicKey, error)

// EventPublisher is the daemon's event-bus surface; nil-safe.
// Provided by tunnel.go via a closure over tm.publishEvent.
type EventPublisher func(topic string, payload map[string]any)

// PostInstallHook is invoked AFTER a successful HandleAuthFrame /
// HandleUnauthFrame installs (or refreshes) a Crypto. Carries enough
// context for the daemon to do peer-endpoint bookkeeping, salvage
// replay, flushPending, etc. Implemented in tunnel.go.
type PostInstallHook func(ev PostInstallEvent)

// PreRetransmitHook is invoked by RekeyRetransmitTick once per peer that
// is about to be retransmitted, BEFORE SendKeyExchangeToNode runs. The
// hook receives the peer ID and the upcoming attempt count (1 for the
// first retransmit, 2 for the second, ...). Used by tunnel.go to flip
// the peer's routing path to relay once direct attempts have failed
// often enough that the next direct attempt is unlikely to succeed.
// Implemented in tunnel.go.
type PreRetransmitHook func(peerNodeID uint32, attempt int)

// PostInstallEvent describes a freshly-installed Crypto.
type PostInstallEvent struct {
	PeerNodeID    uint32
	From          *net.UDPAddr
	FromRelay     bool
	Authenticated bool
	HadCrypto     bool // true if an entry existed before
	KeyChanged    bool // true if the peer's X25519 ephemeral key actually changed
	OldCrypto     *Crypto
	NewCrypto     *Crypto
	PeerEd25519   ed25519.PublicKey // non-nil for auth path
}

// Manager owns the L5 state.
type Manager struct {
	env *Store

	// Local identity material — populated by SetIdentity/SetPeerVerifyFunc.
	idMu       sync.RWMutex
	identity   *crypto.Identity
	verifyFunc VerifyFunc

	// X25519 keypair for ECDH. Set via SetX25519Keys.
	keyMu   sync.RWMutex
	privKey *ecdh.PrivateKey
	pubKey  []byte

	// localNodeID is our own node ID; written into outbound key-exchange
	// frames and the auth challenge.
	localNodeIDFn func() uint32

	// peerPubKeys caches Ed25519 keys fetched via verifyFunc.
	pubKeysMu   sync.RWMutex
	peerPubKeys map[uint32]ed25519.PublicKey
	negPubKeys  map[uint32]time.Time

	// rkPendingMu is the LEAF lock guarding pendingRekey +
	// lastInboundDecrypt + rekeyGaveUp. NEVER held while taking any
	// TunnelManager mutex (per 03-INVARIANTS.md §3).
	rkPendingMu        sync.Mutex
	pendingRekey       map[uint32]*PendingRekeyState
	lastInboundDecrypt map[uint32]time.Time
	// rekeyGaveUp records when we gave up retransmitting to a peer.
	// MarkPendingRekey skips peers within the cooldown window so that
	// transient outbound traffic doesn't immediately restart a doomed
	// rekey cycle (the "bounce" pattern).
	rekeyGaveUp map[uint32]time.Time
	// lastKeyExchangeReply records when we last sent a PILA in the
	// asymmetric-recovery branch (HandleAuthFrame "no recent decrypt"
	// path). MarkReplyKeyExchangeSent returns false within
	// KeyExchangeReplyMinInterval to break the symmetric ping-pong
	// described on that constant.
	lastKeyExchangeReply map[uint32]time.Time
	// keyRequestDue marks peers whose next SendKeyExchangeToNode must
	// carry a key request (PILK) regardless of the attempt count: set by
	// MarkKeyRequestDue when the peer is known to hold a session we lack
	// (it sent us an encrypted frame we have no key for).
	keyRequestDue map[uint32]struct{}
	// keyRequestsSent counts key requests (PILK nudges) sent. Metric only.
	keyRequestsSent atomic.Uint64

	// PILOT-344: per-peer whitelist for the reply-interval gate.
	// Whitelisted peers always pass MarkReplyKeyExchangeSent so trusted
	// nodes never get gated by the 1s asymmetric-recovery throttle.
	// Read on the hot path under atomic.Pointer; populated at startup
	// via SetReplyWhitelist.
	replyWhitelist atomic.Pointer[map[uint32]struct{}]
	// PILOT-344 wildcard: when true, every peer bypasses the reply
	// interval gate regardless of replyWhitelist contents. Used on
	// service-agent boxes that respond to many distinct callers.
	replyWhitelistAll atomic.Bool

	// Side-effect hooks plumbed in from the daemon.
	sender      FrameSender
	addrLookup  PeerAddrLookup
	publisher   EventPublisher
	postInstall PostInstallHook
	preRetx     PreRetransmitHook
	onGaveUp    func(nodeID uint32)
	trustFn     func(nodeID uint32) bool
}

// New returns a fresh Manager. The Manager installs into store; pass
// store=nil to have New construct one. The same Store pointer is
// imported by L6 (envelope) for AEAD encrypt/decrypt operations.
func New(store *Store) *Manager {
	if store == nil {
		store = NewStore()
	}
	return &Manager{
		env:                  store,
		peerPubKeys:          make(map[uint32]ed25519.PublicKey),
		negPubKeys:           make(map[uint32]time.Time),
		pendingRekey:         make(map[uint32]*PendingRekeyState),
		lastInboundDecrypt:   make(map[uint32]time.Time),
		rekeyGaveUp:          make(map[uint32]time.Time),
		lastKeyExchangeReply: make(map[uint32]time.Time),
		keyRequestDue:        make(map[uint32]struct{}),
	}
}

// Store returns the per-peer Crypto registry owned by this Manager.
// L6 (envelope) imports it to wrap/unwrap AEAD frames; L7 (tunnel)
// imports it for membership probes (Has/IsReady) and bookkeeping
// (Install/Drop) on rekey paths.
func (m *Manager) Store() *Store { return m.env }

// SetSender wires L2's frame-send hook.
func (m *Manager) SetSender(s FrameSender) { m.sender = s }

// SetAddrLookup wires the peer-address resolver.
func (m *Manager) SetAddrLookup(f PeerAddrLookup) { m.addrLookup = f }

// SetPublisher wires the daemon's event bus (nil-safe).
func (m *Manager) SetPublisher(p EventPublisher) { m.publisher = p }

// SetPostInstallHook wires the post-install daemon callback (peer
// endpoint bookkeeping, salvage replay, etc.).
func (m *Manager) SetPostInstallHook(h PostInstallHook) { m.postInstall = h }

// SetPreRetransmitHook wires a callback invoked once per peer immediately
// before each rekey retransmit. The daemon uses this to apply cross-layer
// policy (e.g. force the peer onto the relay path) without leaking
// routing concerns into the keyexchange package.
func (m *Manager) SetPreRetransmitHook(h PreRetransmitHook) { m.preRetx = h }

// SetOnGaveUpHook wires a callback fired once per peer at the moment the
// rekey machinery gives up (MaxRekeyAttempts retransmits to a stale
// cached endpoint, all unanswered). The daemon uses this to trigger a
// full path reset (fresh resolve + hole-punch) — the ONLY thing that
// recovers a desynced peer, since it is no longer Ready and so is invisible
// to the inbound-silence path watchdog. Invoked outside rkPendingMu.
func (m *Manager) SetOnGaveUpHook(h func(nodeID uint32)) { m.onGaveUp = h }

func (m *Manager) SetTrustFn(f func(nodeID uint32) bool) { m.trustFn = f }

// SetLocalNodeIDFn supplies the closure used to read our own node ID
// (atomic read living in the daemon).
func (m *Manager) SetLocalNodeIDFn(f func() uint32) { m.localNodeIDFn = f }

// SetIdentity sets our Ed25519 identity for signing authenticated key
// exchanges. May be called concurrently with HandleAuthFrame / Send.
func (m *Manager) SetIdentity(id *crypto.Identity) {
	m.idMu.Lock()
	m.identity = id
	m.idMu.Unlock()
}

// Identity returns the currently-set identity (or nil).
func (m *Manager) Identity() *crypto.Identity {
	m.idMu.RLock()
	defer m.idMu.RUnlock()
	return m.identity
}

// HasIdentity is a fast path used to gate auth/unauth frame selection.
func (m *Manager) HasIdentity() bool {
	m.idMu.RLock()
	defer m.idMu.RUnlock()
	return m.identity != nil
}

// SetPeerVerifyFunc sets the callback used to fetch a peer's Ed25519
// public key from the registry on cache miss.
func (m *Manager) SetPeerVerifyFunc(f VerifyFunc) {
	m.idMu.Lock()
	m.verifyFunc = f
	m.idMu.Unlock()
}

// SetX25519Keys installs our X25519 keypair (used for ECDH on inbound
// key-exchange frames and for the pubkey slot in outbound frames).
func (m *Manager) SetX25519Keys(priv *ecdh.PrivateKey, pub []byte) {
	m.keyMu.Lock()
	m.privKey = priv
	m.pubKey = pub
	m.keyMu.Unlock()
}

// PubKey returns the local X25519 public key (32 bytes). May be nil
// if SetX25519Keys was never called.
func (m *Manager) PubKey() []byte {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.pubKey
}

// PrivKey returns the local X25519 private key.
func (m *Manager) PrivKey() *ecdh.PrivateKey {
	m.keyMu.RLock()
	defer m.keyMu.RUnlock()
	return m.privKey
}

// localNodeID is a nil-safe wrapper.
func (m *Manager) localNodeID() uint32 {
	if m.localNodeIDFn == nil {
		return 0
	}
	return m.localNodeIDFn()
}

// publish is a nil-safe event publish.
func (m *Manager) publish(topic string, payload map[string]any) {
	if m.publisher != nil {
		m.publisher(topic, payload)
	}
}

// GetPeerPubKey returns the cached Ed25519 public key for a peer,
// fetching from the registry (via verifyFunc) on cache miss. A recent
// failed lookup is negatively cached (NegativePubKeyCacheTTL) so a flood
// of frames for an unresolved node ID does not re-hit the registry — and
// re-run the Ed25519 path — on every frame.
func (m *Manager) GetPeerPubKey(nodeID uint32) (ed25519.PublicKey, error) {
	m.pubKeysMu.RLock()
	if pk, ok := m.peerPubKeys[nodeID]; ok {
		m.pubKeysMu.RUnlock()
		return pk, nil
	}
	negAt, negOK := m.negPubKeys[nodeID]
	m.pubKeysMu.RUnlock()

	if negOK && time.Since(negAt) < NegativePubKeyCacheTTL {
		return nil, errPubKeyUnresolved
	}

	m.idMu.RLock()
	fn := m.verifyFunc
	m.idMu.RUnlock()
	if fn == nil {
		return nil, errNoVerify
	}

	pk, err := fn(nodeID)
	if err != nil {
		m.recordNegPubKey(nodeID)
		return nil, err
	}
	m.pubKeysMu.Lock()
	m.peerPubKeys[nodeID] = pk
	delete(m.negPubKeys, nodeID)
	m.pubKeysMu.Unlock()
	return pk, nil
}

func (m *Manager) recordNegPubKey(nodeID uint32) {
	now := time.Now()
	m.pubKeysMu.Lock()
	if _, ok := m.negPubKeys[nodeID]; !ok && len(m.negPubKeys) >= MaxNegPubKeyEntries {
		for id, at := range m.negPubKeys {
			if now.Sub(at) >= NegativePubKeyCacheTTL {
				delete(m.negPubKeys, id)
			}
		}
		if len(m.negPubKeys) >= MaxNegPubKeyEntries {
			m.pubKeysMu.Unlock()
			return
		}
	}
	m.negPubKeys[nodeID] = now
	m.pubKeysMu.Unlock()
}

// PeerPubKeyCached returns the cached Ed25519 public key for a peer and
// whether one is present. Unlike GetPeerPubKey it never falls back to
// verifyFunc, so packet-path callers cannot block on a registry RPC.
func (m *Manager) PeerPubKeyCached(nodeID uint32) (ed25519.PublicKey, bool) {
	m.pubKeysMu.RLock()
	defer m.pubKeysMu.RUnlock()
	pk, ok := m.peerPubKeys[nodeID]
	return pk, ok
}

// SetPeerPubKey installs a cache entry directly. Used by handle paths
// after verifying a packet-carried Ed25519 pubkey against the registry.
func (m *Manager) SetPeerPubKey(nodeID uint32, pk ed25519.PublicKey) {
	m.pubKeysMu.Lock()
	m.peerPubKeys[nodeID] = pk
	m.pubKeysMu.Unlock()
}

// InvalidatePeerPubKey deletes a cache entry.
func (m *Manager) InvalidatePeerPubKey(nodeID uint32) {
	m.pubKeysMu.Lock()
	delete(m.peerPubKeys, nodeID)
	m.pubKeysMu.Unlock()
}

// HasPeerPubKey reports whether the cache currently holds an entry for nodeID.
func (m *Manager) HasPeerPubKey(nodeID uint32) bool {
	m.pubKeysMu.RLock()
	defer m.pubKeysMu.RUnlock()
	_, ok := m.peerPubKeys[nodeID]
	return ok
}

// MarkPendingRekey records that we sent a key_exchange to peerNodeID
// and are awaiting confirmation. Idempotent — re-calls bump LastSentAt
// and Attempts but preserve FirstSentAt.
//
// Returns false and is a no-op if the peer is within the rekeyGaveUpCooldown
// window, preventing an immediate restart of a just-failed rekey cycle.
func (m *Manager) MarkPendingRekey(peerNodeID uint32) bool {
	now := time.Now()
	m.rkPendingMu.Lock()
	if gaveUpAt, ok := m.rekeyGaveUp[peerNodeID]; ok {
		if now.Sub(gaveUpAt) < rekeyGaveUpCooldown {
			m.rkPendingMu.Unlock()
			return false
		}
		delete(m.rekeyGaveUp, peerNodeID)
	}
	st, ok := m.pendingRekey[peerNodeID]
	if !ok {
		st = &PendingRekeyState{FirstSentAt: now}
		m.pendingRekey[peerNodeID] = st
	}
	st.LastSentAt = now
	st.Attempts++
	m.rkPendingMu.Unlock()
	return true
}

// ClearPendingRekey cancels any in-flight retransmit tracking for peerNodeID.
// Called from Handle*Frame paths (we received their key exchange, so we no
// longer need to keep hammering them with ours). Does NOT clear rekeyGaveUp —
// receiving a key exchange is not proof of bidirectional reachability; only a
// successful decrypt is. Clearing rekeyGaveUp here caused the bounce to
// re-arm whenever a peer with no cooldown fix kept sending us key exchanges.
func (m *Manager) ClearPendingRekey(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	delete(m.pendingRekey, peerNodeID)
	m.rkPendingMu.Unlock()
}

// ResetPendingRekeyAttempts zeroes the Attempts counter for peerNodeID
// without cancelling the pending-rekey entry. Called when the routing
// path changes (e.g. direct→relay flip) so the peer gets a fresh set
// of retransmit slots on the new path rather than immediately hitting
// the MaxRekeyAttempts give-up threshold from prior direct attempts.
func (m *Manager) ResetPendingRekeyAttempts(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	if st, ok := m.pendingRekey[peerNodeID]; ok {
		st.Attempts = 0
		st.LastSentAt = time.Time{} // force immediate retransmit on next tick
	}
	m.rkPendingMu.Unlock()
}

// ClearRekeyGaveUp lifts the post-give-up cooldown for peerNodeID. Must only
// be called after a successful decrypt — proof that bidirectional crypto works.
func (m *Manager) ClearRekeyGaveUp(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	delete(m.rekeyGaveUp, peerNodeID)
	m.rkPendingMu.Unlock()
}

// PeerInRekeyGaveUp reports whether peerNodeID is within the give-up cooldown.
// Used by the tunnel to skip queuing outbound packets for unreachable peers.
func (m *Manager) PeerInRekeyGaveUp(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	t, ok := m.rekeyGaveUp[peerNodeID]
	in := ok && time.Since(t) < rekeyGaveUpCooldown
	m.rkPendingMu.Unlock()
	return in
}

// PendingRekeyAttempts returns the current attempts count (0 if not pending).
func (m *Manager) PendingRekeyAttempts(peerNodeID uint32) int {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	if st, ok := m.pendingRekey[peerNodeID]; ok {
		return st.Attempts
	}
	return 0
}

// PendingRekeyHas reports whether an entry exists.
func (m *Manager) PendingRekeyHas(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	_, ok := m.pendingRekey[peerNodeID]
	return ok
}

// PendingRekeyForTest returns the live PendingRekeyState pointer (or nil)
// for a peer. Exposed so package-internal tests can inspect the
// FirstSentAt / LastSentAt timestamps without re-deriving them via the
// public counters. Acquires rkPendingMu briefly; safe for concurrent use.
func (m *Manager) PendingRekeyForTest(peerNodeID uint32) *PendingRekeyState {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	return m.pendingRekey[peerNodeID]
}

// InjectPendingRekeyForTest sets a state directly. Test-only; production
// code never bypasses MarkPendingRekey.
func (m *Manager) InjectPendingRekeyForTest(peerNodeID uint32, st *PendingRekeyState) {
	m.rkPendingMu.Lock()
	if st == nil {
		delete(m.pendingRekey, peerNodeID)
	} else {
		m.pendingRekey[peerNodeID] = st
	}
	m.rkPendingMu.Unlock()
}

// RecordInboundDecrypt updates the per-peer last-decrypt timestamp.
func (m *Manager) RecordInboundDecrypt(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	m.lastInboundDecrypt[peerNodeID] = time.Now()
	m.rkPendingMu.Unlock()
}

// SetLastInboundDecryptForTest writes a timestamp directly.
func (m *Manager) SetLastInboundDecryptForTest(peerNodeID uint32, t time.Time) {
	m.rkPendingMu.Lock()
	m.lastInboundDecrypt[peerNodeID] = t
	m.rkPendingMu.Unlock()
}

// MarkRekeyGaveUpForTest stamps the give-up map so PeerInRekeyGaveUp
// returns true. Test-only.
func (m *Manager) MarkRekeyGaveUpForTest(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	m.rekeyGaveUp[peerNodeID] = time.Now()
	m.rkPendingMu.Unlock()
}

// LastInboundDecryptHas reports whether we've recorded any successful
// decrypt timestamp for the peer.
func (m *Manager) LastInboundDecryptHas(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	_, ok := m.lastInboundDecrypt[peerNodeID]
	return ok
}

// LastInboundDecrypt returns the timestamp of the last successful
// decrypt from peerNodeID. ok=false means no decrypt has ever been
// recorded this process. Used by the per-peer path watchdog to measure
// how long a peer's inbound path has been silent.
func (m *Manager) LastInboundDecrypt(peerNodeID uint32) (time.Time, bool) {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	t, ok := m.lastInboundDecrypt[peerNodeID]
	return t, ok
}

// InboundDecryptStale returns true if we haven't successfully
// decrypted any packet from peerNodeID within the staleness window.
func (m *Manager) InboundDecryptStale(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	t, ok := m.lastInboundDecrypt[peerNodeID]
	m.rkPendingMu.Unlock()
	if !ok {
		return true
	}
	return time.Since(t) > KeyExchangeReplyStaleThreshold
}

// MarkReplyKeyExchangeSent is the per-peer rate-limit for the
// asymmetric-recovery reply in HandleAuthFrame. Returns true and
// records the timestamp when the caller IS permitted to send;
// returns false when another reply went out within
// KeyExchangeReplyMinInterval and the caller MUST stay silent.
//
// The check-and-record is atomic under rkPendingMu so two
// concurrent HandleAuthFrame goroutines (direct + relay copy past
// DuplicateHandshakeDebounce) cannot both pass.
func (m *Manager) MarkReplyKeyExchangeSent(peerNodeID uint32) bool {
	// PILOT-344: trusted-peer whitelist bypasses the interval gate.
	// The check is outside rkPendingMu so an atomic.Pointer load is all
	// we need; we still record the timestamp below for consistency with
	// the cleanup loop. The wildcard (replyWhitelistAll) lets
	// service-agent boxes pass every caller.
	whitelisted := false
	if m.replyWhitelistAll.Load() {
		whitelisted = true
	} else if wl := m.replyWhitelist.Load(); wl != nil {
		if _, ok := (*wl)[peerNodeID]; ok {
			whitelisted = true
		}
	}
	now := time.Now()
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	if !whitelisted {
		if last, ok := m.lastKeyExchangeReply[peerNodeID]; ok {
			if now.Sub(last) < KeyExchangeReplyMinInterval {
				return false
			}
		}
	}
	m.lastKeyExchangeReply[peerNodeID] = now
	return true
}

// SetReplyWhitelist replaces the trusted-peer whitelist for the
// asymmetric-recovery reply interval gate (PILOT-344). Whitelisted
// peers always pass MarkReplyKeyExchangeSent. Safe to call concurrently
// with the hot path — backed by an atomic.Pointer.
func (m *Manager) SetReplyWhitelist(nodeIDs []uint32) {
	wm := make(map[uint32]struct{}, len(nodeIDs))
	for _, id := range nodeIDs {
		if id == 0 {
			continue
		}
		wm[id] = struct{}{}
	}
	m.replyWhitelist.Store(&wm)
}

// SetReplyWhitelistMatchAll toggles wildcard mode (PILOT-344). When
// true, every peer bypasses MarkReplyKeyExchangeSent's interval gate.
func (m *Manager) SetReplyWhitelistMatchAll(on bool) {
	m.replyWhitelistAll.Store(on)
}

// RemovePeer wipes per-peer L5 state (called from TunnelManager.RemovePeer).
func (m *Manager) RemovePeer(nodeID uint32) {
	m.pubKeysMu.Lock()
	delete(m.peerPubKeys, nodeID)
	delete(m.negPubKeys, nodeID)
	m.pubKeysMu.Unlock()

	m.rkPendingMu.Lock()
	delete(m.pendingRekey, nodeID)
	delete(m.lastInboundDecrypt, nodeID)
	delete(m.lastKeyExchangeReply, nodeID)
	delete(m.keyRequestDue, nodeID)
	m.rkPendingMu.Unlock()
}

// MarkKeyRequestDue makes the next SendKeyExchangeToNode to peerNodeID
// also send a key request (PILK), provided we still hold no session key
// for it then. The tunnel calls it when the peer sends us an encrypted
// frame we cannot decrypt: proof that the peer holds a session for us
// that we lack, which a same-key PILA alone cannot repair (see
// KeyRequestAfterSends).
func (m *Manager) MarkKeyRequestDue(peerNodeID uint32) {
	m.rkPendingMu.Lock()
	if len(m.keyRequestDue) < MaxNegPubKeyEntries {
		m.keyRequestDue[peerNodeID] = struct{}{}
	}
	m.rkPendingMu.Unlock()
}

// takeKeyRequest reports whether the send about to go out to peerNodeID
// should carry a key request, and consumes a MarkKeyRequestDue mark.
// Caller has already checked that no session key is installed.
func (m *Manager) takeKeyRequest(peerNodeID uint32) bool {
	m.rkPendingMu.Lock()
	defer m.rkPendingMu.Unlock()
	if _, due := m.keyRequestDue[peerNodeID]; due {
		delete(m.keyRequestDue, peerNodeID)
		return true
	}
	st, ok := m.pendingRekey[peerNodeID]
	return ok && st.Attempts >= KeyRequestAfterSends
}

// KeyRequestsSent returns how many key requests (PILK nudges) this
// manager has sent.
func (m *Manager) KeyRequestsSent() uint64 { return m.keyRequestsSent.Load() }
