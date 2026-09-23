// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"crypto/cipher"
	"sync"
	"time"
)

// ReplayWindowSize is the number of nonces tracked in the sliding window
// bitmap for replay detection (H8 fix). Nonces within
// [maxNonce-ReplayWindowSize, maxNonce] are tracked; nonces below the
// window are rejected.
//
// Per-peer state — owned with the key, hence on L5 (keyexchange) rather
// than L6 (envelope).
const ReplayWindowSize = 256

// SalvageMaxEntries bounds memory + replay-storm size on rekey. Originally
// 32, but a 32-frame burst replayed on rekey caused receiver-side nonce
// confusion (concurrent dataexchange retransmits filling salvage +
// out-of-order delivery on the wire). 4 covers the typical "send-message +
// a couple of retries" without overwhelming the receiver.
// Memory at max: 4 × ~1500 B = 6 KiB / peer, ~6 MiB across maxCryptoPeers
// (1024).
const SalvageMaxEntries = 4

// SalvageMaxAge is how far back we replay sends after a rekey. The rekey
// round-trip itself is ~1 RTT plus the rate-limit window (3 s); 5 s gives
// margin for slow handshakes under loss.
const SalvageMaxAge = 5 * time.Second

// DecryptFailDropThreshold is how many consecutive AEAD-authentication
// failures from a single peer trigger a full Crypto drop + re-handshake.
// Sized to swallow a small burst of legitimate packet corruption (kernel
// buffer overruns, mid-flight key rotation crossing the wire) while still
// recovering from peer-side AEAD-key divergence within a few seconds — a
// daemon restart on either side cycles the peer through a fresh
// handshake; this is the "equivalent recovery without restarting" path.
//
// Lives on L5 with the per-peer state it gates rather than on L6 framing,
// because the drop decision uses Crypto.CreatedAt (key-install time, an
// L5 concept) and Crypto.DecryptFailCount (per-peer state).
const DecryptFailDropThreshold = 5

// OutsideWindowDropThreshold is how many consecutive outside-replay-window
// rejections cause us to drop the peer's Crypto and trigger a fresh key
// exchange. Originally 30 — that was rate-gated on the peer continuing
// to send 30 packets, which wedges quiet control-plane peers
// indefinitely (a peer that handshakes once a day and otherwise stays
// silent never generates enough traffic to trip the gate). 5 still
// distinguishes a normal late-relay flurry (typically 1–3 frames) from
// a real divergence, and recovers in seconds for quiet peers too. The
// salvage ring (SalvageMaxEntries=4) further bounds the legitimate
// outside-window burst on rekey. Reset to 0 on success.
const OutsideWindowDropThreshold = 5

// OutsideWindowDropGrace mirrors DecryptFailDropGrace but for the
// outside-window path. Tightened from 3s to 1s alongside the
// OutsideWindowDropThreshold drop (30→5): the grace exists to absorb
// in-flight stale frames after a rekey, which take ≤1 RTT (≤200 ms on
// relay) to drain; 1 s leaves comfortable margin without holding a
// diverged session for the full original 3 s.
const OutsideWindowDropGrace = 1 * time.Second

// ReplayDropThreshold is how many consecutive in-window replay
// rejections trigger a Crypto drop + fresh key exchange. Symmetric
// counterpart to OutsideWindowDropThreshold for the *other* side of
// the window: the peer's send counter is INSIDE our ReplayWindowSize
// range but at positions we've already seen.
//
// Reproduces the rc5 list-agents wedge (2026-05-11): peer daemon
// restarts but keeps its persisted X25519 identity, so no PILA is
// negotiated; the peer's send counter resets to 1 while our
// MaxRecvNonce sits at ~50. Every subsequent frame from the peer
// authenticates with the same key, lands at counter=1..50, and is
// dropped as a replay before AEAD-Open ever runs — neither
// DecryptFailCount nor OutsideWindowCount increment, so the existing
// recovery paths never engage. Sustained replays are the only signal
// that the peer's counter and our window are mis-aligned.
//
// 5 matches OutsideWindowDropThreshold (was 30, dropped to 5): a
// legitimate duplicate-delivery burst (direct + relay both delivering
// the same frame) typically tops out at 1–3 collisions per frame
// pair; 5 consecutive same-peer replays without any successful decrypt
// still cleanly distinguishes the wedge from legitimate duplication,
// while letting quiet control-plane peers recover within seconds
// rather than waiting hours for 30 packets they may never send.
// Reset to 0 on successful decrypt.
const ReplayDropThreshold = 5

// ReplayDropGrace mirrors OutsideWindowDropGrace. Tightened from 3s
// to 1s alongside the ReplayDropThreshold drop (30→5): the grace
// exists to absorb a small relay-vs-direct duplicate-delivery flurry
// after a rekey (~1 RTT), which 1 s comfortably covers.
const ReplayDropGrace = 1 * time.Second

// AgedCryptoFastDropAge is the age past which a Crypto is treated as
// "settled": no rekey, no in-flight drain, no duplicate-delivery
// storm. Once a session has lived this long, *any* ErrReplay or
// ErrOutsideWindow from it is real divergence (peer counter-reset
// after a restart), not transient noise — so the count thresholds
// are bypassed and the drop fires on the first event.
//
// This is the recovery path for "very quiet" peers (control-plane
// agents that handshake once a day and otherwise rarely talk): they
// would never send enough frames to trip ReplayDropThreshold within
// a useful window. With this fast-path, even a single frame after
// the peer's restart triggers re-handshake in ~1 RTT.
//
// 1 minute is well past:
//   - relay RTT (≤200 ms)
//   - SalvageMaxAge (5 s)
//   - any legitimate in-flight drain after a rekey
//
// so it can never fire on a freshly-installed Crypto.
const AgedCryptoFastDropAge = 1 * time.Minute

// DecryptFailDropGrace is the minimum age a Crypto must reach before
// repeated decrypt failures can drop it. Set above the typical relay RTT
// (≤200 ms) plus a comfortable margin: stale ciphertext from before the
// peer's last rekey takes ~1 RTT to drain, but if salvage replay is in
// play it can stretch slightly. 3 s covers worst-case drain without
// holding a genuinely diverged session for long.
const DecryptFailDropGrace = 3 * time.Second

// SalvageEntry is a single plaintext frame retained for post-rekey replay.
type SalvageEntry struct {
	Plaintext []byte
	When      time.Time
}

// Crypto holds per-peer encryption state. Created by L5 (DeriveSecret)
// after key derivation; mutated by L6 on every encrypt/decrypt; cleared
// on rekey or peer drop.
//
// Per docs/architecture/03-INVARIANTS.md §3 (lock graph): Crypto's
// ReplayMu and SalvageMu are LEAF locks. They are never nested with
// any TunnelManager-side mutex (tm.mu, tm.rkPendingMu, etc.). Methods
// on Crypto must not acquire any external lock while holding them.
//
// Ownership lives on L5 (keyexchange) per docs/architecture/01-LAYERS.md:
// L6 'Consumes: ... L5 (key state)' — the envelope is a downward
// consumer of L5's per-peer state, not its owner.
type Crypto struct {
	AEAD        cipher.AEAD
	Nonce       uint64  // monotonic send counter (atomic)
	NoncePrefix [4]byte // random prefix for nonce domain separation

	// Replay detection (H8 fix): sliding window bitmap instead of simple
	// high-water mark. This is the window of the peer's newest send epoch;
	// see CheckAndRecordEpochNonce.
	ReplayMu     sync.Mutex
	MaxRecvNonce uint64                        // highest nonce received
	ReplayBitmap [ReplayWindowSize / 64]uint64 // bitmap for nonces in [max-windowSize, max]

	Ready         bool     // true once key exchange is complete
	Authenticated bool     // true if peer proved Ed25519 identity
	PeerX25519Key [32]byte // peer's X25519 public key (for detecting rekeying)

	// DecryptFailCount tracks consecutive AEAD authentication failures
	// since the last successful decrypt. Older-version peer daemons drift
	// into a state where their derived AEAD key no longer matches ours
	// (likely a session-id or info-string mismatch in HKDF), at which
	// point every encrypted packet from the peer fails with "cipher:
	// message authentication failed". Once this counter exceeds
	// DecryptFailDropThreshold the daemon drops this Crypto entirely
	// and triggers a fresh key exchange — equivalent to a daemon-restart
	// recovery without actually restarting. Reset to 0 on any successful
	// decrypt.
	DecryptFailCount int

	// OutsideWindowCount tracks consecutive frames rejected because their
	// counter was more than ReplayWindowSize behind MaxRecvNonce. A few
	// of these are normal (late relay-buffered frames). A sustained burst
	// means the peer's send counter and our receive window have diverged
	// far enough that no in-band recovery is possible — the only signal
	// the peer has to know there's a problem is silence, and the only
	// fix is a fresh key exchange. Once this counter exceeds
	// OutsideWindowDropThreshold AND the Crypto is older than
	// OutsideWindowDropGrace, the daemon drops this Crypto and requests
	// a rekey. Reset to 0 on any successful decrypt.
	OutsideWindowCount int

	// ReplayCount tracks consecutive in-window replay rejections (counter
	// within ReplayWindowSize of MaxRecvNonce but already marked in the
	// bitmap). Distinct from OutsideWindowCount, which handles the
	// counter-far-behind case. A few replays are normal (duplicate
	// delivery across direct + relay paths); a sustained burst means
	// peer's send counter reset (peer restart with persistent identity)
	// and our window's high-water-mark sits ahead of every frame the
	// peer can now produce — the wedge resolves only when peer's counter
	// climbs past our max, but with no traffic in flight it never will.
	// Once this counter exceeds ReplayDropThreshold AND the Crypto is
	// older than ReplayDropGrace, drop the Crypto and request rekey.
	// Reset to 0 on any successful decrypt.
	ReplayCount int

	// CreatedAt is when this Crypto was installed. Used by L5's
	// handleAuthKeyExchange to decide between preserving existing state
	// (fresh handshake retransmit/reply within seconds) and resetting it
	// (long-lived peer's own state desynced — e.g. older-version daemon
	// rotated its send counter without rotating X25519 keys, which
	// otherwise leaves us with a high MaxRecvNonce that rejects the
	// peer's resumed packets as replays). Also gates the rc5 grace
	// period (see DecryptFailDropGrace).
	CreatedAt time.Time

	// P1-010 desync salvage: ring buffer of recent plaintext sent with
	// this key. On a peer-initiated rekey, these are re-encrypted with
	// the new key and re-sent — recovering the data that was vaporized
	// when the peer dropped our stale-keyed frames.
	SalvageMu sync.Mutex
	Salvage   []SalvageEntry

	// Receive epochs, guarded by ReplayMu. Every sender picks a fresh
	// random NoncePrefix each time it derives a Crypto (every version
	// since v1.9 does this in DeriveSecret), and its counter only ever
	// grows within one Crypto. So the prefix on an authenticated frame
	// names the sender's session epoch: a prefix we have not seen before
	// means the peer re-derived its half of the session (same X25519
	// keys, so the same AEAD key, but a counter restarted at 1). Each
	// epoch gets its own replay window. MaxRecvNonce/ReplayBitmap are the
	// window of the NEWEST epoch (recvPrefix); older epochs keep theirs in
	// olderEpochs. See CheckAndRecordEpochNonce.
	recvPrefix    [4]byte
	recvPrefixSet bool
	olderEpochs   [RetainedRecvEpochs]recvEpochWindow
	olderCount    int
	epochClock    uint64
}

// RetainedRecvEpochs bounds how many earlier peer epochs a Crypto keeps a
// replay window for, besides the newest. A peer re-derives rarely, so a
// handful covers any real churn (late stragglers of the previous epoch,
// replays of it); the least recently used one is forgotten first.
const RetainedRecvEpochs = 4

// recvEpochWindow is the replay window of one earlier peer epoch.
type recvEpochWindow struct {
	prefix  [4]byte
	max     uint64
	bitmap  [ReplayWindowSize / 64]uint64
	lastUse uint64
}

// RecvEpoch says which of the peer's send epochs an authenticated frame
// was judged in by CheckAndRecordEpochNonce.
type RecvEpoch int

const (
	// RecvEpochNewest: the peer's newest epoch — the window MaxRecvNonce
	// and ReplayBitmap track. Also the first frame on a fresh Crypto.
	RecvEpochNewest RecvEpoch = iota
	// RecvEpochNew: a prefix never seen on this Crypto, replacing an
	// earlier newest epoch — the peer re-derived its half of the session.
	// The frame starts a fresh newest window; the previous one is kept.
	RecvEpochNew
	// RecvEpochOlder: an earlier epoch still retained, judged against its
	// own window. Nothing about it says anything about the newest epoch.
	RecvEpochOlder
)

// CheckAndRecordEpochNonce is CheckAndRecordNonce for a frame whose nonce
// carried prefix: it judges (and records) counter in the replay window of
// the frame's own epoch. A never-seen prefix becomes the newest epoch with
// a fresh window, keeping the previous newest window for its stragglers.
// A frame of a retained older epoch is judged against that epoch's window
// and never touches the newest one, so no frame can lock the peer's live
// epoch out: its own frames always meet its own window. An epoch that is
// no longer retained comes back as a new one (like any frame on a fresh
// window after a re-handshake), which again leaves every other epoch's
// window intact.
//
// Must be called with c.ReplayMu held, and only for frames that passed
// AEAD authentication.
func (c *Crypto) CheckAndRecordEpochNonce(prefix [4]byte, counter uint64) (bool, RecvEpoch) {
	c.epochClock++
	if !c.recvPrefixSet {
		c.recvPrefix = prefix
		c.recvPrefixSet = true
	}
	if prefix == c.recvPrefix {
		return c.CheckAndRecordNonce(counter), RecvEpochNewest
	}
	for i := 0; i < c.olderCount; i++ {
		w := &c.olderEpochs[i]
		if w.prefix != prefix {
			continue
		}
		w.lastUse = c.epochClock
		// Judge the frame in its own window: swap it in, check, swap back.
		c.MaxRecvNonce, w.max = w.max, c.MaxRecvNonce
		c.ReplayBitmap, w.bitmap = w.bitmap, c.ReplayBitmap
		ok := c.CheckAndRecordNonce(counter)
		c.MaxRecvNonce, w.max = w.max, c.MaxRecvNonce
		c.ReplayBitmap, w.bitmap = w.bitmap, c.ReplayBitmap
		return ok, RecvEpochOlder
	}

	// A new epoch: keep the current newest window among the older ones
	// (forgetting the least recently used if full) and start fresh.
	slot := c.olderCount
	if slot < RetainedRecvEpochs {
		c.olderCount++
	} else {
		slot = 0
		for i := 1; i < RetainedRecvEpochs; i++ {
			if c.olderEpochs[i].lastUse < c.olderEpochs[slot].lastUse {
				slot = i
			}
		}
	}
	c.olderEpochs[slot] = recvEpochWindow{
		prefix:  c.recvPrefix,
		max:     c.MaxRecvNonce,
		bitmap:  c.ReplayBitmap,
		lastUse: c.epochClock,
	}
	c.recvPrefix = prefix
	c.MaxRecvNonce = 0
	c.ReplayBitmap = [ReplayWindowSize / 64]uint64{}
	return c.CheckAndRecordNonce(counter), RecvEpochNew
}

// CheckAndRecordNonce returns true if the nonce is valid (not replayed,
// not too old). Must be called with c.ReplayMu held.
//
// Note on nonce wraparound: the counter is uint64, so it wraps after
// 2^64 packets. At 1 billion packets/sec this takes ~585 years — purely
// theoretical. If a connection ever approaches this limit, rekeying
// (new secure handshake) resets the counter naturally.
func (c *Crypto) CheckAndRecordNonce(counter uint64) bool {
	if c.MaxRecvNonce == 0 {
		// First packet ever
		c.MaxRecvNonce = counter
		c.SetReplayBit(counter)
		return true
	}

	if counter > c.MaxRecvNonce {
		// New maximum — shift window forward
		shift := counter - c.MaxRecvNonce
		if shift >= ReplayWindowSize {
			// Clear entire bitmap
			c.ReplayBitmap = [ReplayWindowSize / 64]uint64{}
		} else {
			// Clear the new positions that the shifted window will occupy
			for s := uint64(0); s < shift; s++ {
				newBit := (counter - s) % ReplayWindowSize
				c.ReplayBitmap[newBit/64] &^= 1 << (newBit % 64)
			}
		}
		c.MaxRecvNonce = counter
		c.SetReplayBit(counter)
		return true
	}

	// counter <= MaxRecvNonce
	diff := c.MaxRecvNonce - counter
	if diff >= ReplayWindowSize {
		return false // too old
	}

	// Check if already seen
	bit := counter % ReplayWindowSize
	if c.ReplayBitmap[bit/64]&(1<<(bit%64)) != 0 {
		return false // replay
	}
	c.SetReplayBit(counter)
	return true
}

// WouldAcceptNonce reports whether counter would be accepted by
// CheckAndRecordNonce WITHOUT mutating any replay state — a read-only
// verdict. (L6's DecryptFrame no longer pre-checks with it: the window a
// frame is judged in depends on its receive epoch, which only an
// authenticated frame may decide, so it runs AEAD.Open first and then
// CheckAndRecordEpochNonce in one critical section.) The replay window is
// only advanced by CheckAndRecordNonce, and L6 calls that ONLY after
// AEAD.Open authenticates the frame. This ordering is what stops a forged
// high-counter frame (which fails AEAD) from pinning MaxRecvNonce and
// wedging every subsequent genuine frame out of the window.
//
// Must be called with c.ReplayMu held. The logic mirrors the accept/reject
// verdicts of CheckAndRecordNonce exactly, minus the writes.
func (c *Crypto) WouldAcceptNonce(counter uint64) bool {
	if c.MaxRecvNonce == 0 {
		return true // first packet ever
	}
	if counter > c.MaxRecvNonce {
		return true // new maximum
	}
	// counter <= MaxRecvNonce
	if c.MaxRecvNonce-counter >= ReplayWindowSize {
		return false // too old (outside window)
	}
	bit := counter % ReplayWindowSize
	if c.ReplayBitmap[bit/64]&(1<<(bit%64)) != 0 {
		return false // already seen (replay)
	}
	return true
}

// SetReplayBit sets the replay-window bit corresponding to counter.
// Must be called with c.ReplayMu held.
func (c *Crypto) SetReplayBit(counter uint64) {
	bit := counter % ReplayWindowSize
	c.ReplayBitmap[bit/64] |= 1 << (bit % 64)
}

// UndoReplayBit clears the bit set by a prior SetReplayBit. Used by L6
// when AEAD-Open fails to roll back the speculative bookkeeping —
// without this, a flood of failed-decrypt frames would wedge legitimate
// later packets out of the replay window. Must be called with
// c.ReplayMu held.
func (c *Crypto) UndoReplayBit(counter uint64) {
	bit := counter % ReplayWindowSize
	c.ReplayBitmap[bit/64] &^= 1 << (bit % 64)
}
