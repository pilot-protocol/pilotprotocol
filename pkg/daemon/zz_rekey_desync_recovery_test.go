// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Regression tests for the 2026-09-23 rekey-desync loop (v1.13.9 laptop,
// node 230204; peers 16392, 242944 and 179172, all via relay).
//
// Every fresh process handshook with those peers within ~1s and then, ~90s
// later, fell into a loop that nothing short of a restart could leave:
//
//	path watchdog: peer inbound-silent past probe budget — resetting path
//	encrypted packet from node but no key            (every ~30s per peer)
//	rekey retransmit gave up after maxRekeyAttempts
//	rekey gave up (session desync) — reset peer path  (every ~30s per peer)
//	transport wedged while transmitting — attempting soft recovery
//
// Across 54 processes in the rotated log, 16392 and 242944 established
// exactly once per process (right after start) and never again after the
// first reset in that process (~4550 resets each).
//
// The chain:
//
//  1. The path-watchdog probe had no Dst. Every deployed version answers a
//     ping with Src = ping.Dst, so the pong came back claiming node 0 and the
//     identity binding in handleEncrypted dropped it as "spoofed" BEFORE it
//     could refresh lastInboundDecrypt. Probes could never prove liveness.
//  2. Peers older than v1.12.1 send their NAT keepalive with a zero Src, so
//     those were dropped the same way. A quiet peer therefore looked
//     inbound-silent 55s after every handshake, and the watchdog reset it.
//  3. resetPeerPath went through RemovePeer, which also DROPPED THE SESSION
//     KEYS. The peer still held its half of the session, keyed to our X25519
//     key, which is fixed for the lifetime of the process. So our recovery
//     PILA looked to the peer like a same-session keepalive: nothing to
//     install, and no reply either (its reply gate is already re-armed by the
//     liveness stamp in onKeyInstalled). The peer kept sending under the old
//     session, we had no key for it, and every rekey we sent went unanswered.
//     A fresh process generates a NEW X25519 keypair, so the peer sees
//     keyChanged, reinstalls and replies, which is why only a restart
//     recovered.
//
// Keeping the session across a path reset fixes the case above (the peer
// still holds its half — "case A"), but a session can also be one-sided
// the other way round ("case B"): the peer threw ITS half away (a
// v1.13.x path reset or drop gate does exactly that) while we kept ours.
// Two more links make case B, and the drop gates, recover in-process:
//
//  4. A peer that lost its half re-derives the same AEAD key from our PILA
//     with its send counter restarted at 1 — under a NEW random nonce
//     prefix. Our kept replay window used to reject that restarted counter
//     as a replay, and the aged fast-drop then threw OUR half away too,
//     leaving us keyless against a peer that now holds a fresh session.
//     envelope.DecryptFrame now treats a never-seen prefix as the peer's
//     new epoch and gives it a fresh replay window (each epoch keeps its
//     own, so stragglers and replays of the old one are still judged).
//  5. The liveness stamp in onKeyInstalled (link 3) is now only taken for a
//     real install, so a peer that lost its half — and sends us same-key
//     PILAs — gets our PILA back once we have heard nothing authenticated
//     from it for KeyExchangeReplyStaleThreshold.
//
// Link 4 has two consequences of its own. The epoch a peer starts on a
// session we kept is new even though our Crypto is aged, so the replay and
// outside-window gates judge the newest epoch's age (else one early
// duplicate dropped our half again). And every epoch shares the AEAD key,
// so every recorded frame of every earlier epoch still authenticates: an
// epoch whose window is evicted is retired, never re-opened, and only a
// frame of the peer's live epoch moves our path to it.
//
// All pairs below are two real TunnelManagers talking over loopback, each
// inside a Daemon with a fake registry, so resetPeerPath, ensureTunnel,
// the key-exchange loop, the gave-up hook and the real ping handler all run
// their production code.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
)

const desyncTestWait = 2 * time.Second

// desyncRecoverWait bounds recoveries that wait on the stale-recovery reply
// gate: a side holding the session answers a same-key PILA only once it has
// had no authenticated traffic from the peer for
// KeyExchangeReplyStaleThreshold (6s), and the peer's PILAs come every
// RekeyRetransmitInterval (4s) or rekeyRequestInterval (3s) — ~8-10s worst
// case on a clean path.
const desyncRecoverWait = 3 * keyexchange.KeyExchangeReplyStaleThreshold

// desyncNode is one daemon in a desync test pair.
type desyncNode struct {
	d    *Daemon
	tm   *TunnelManager
	id   uint32
	idn  *crypto.Identity
	addr *net.UDPAddr
	data chan string

	answerPings atomic.Bool
	// peerAddr is what this node's fake registry resolves its peer to;
	// empty means "node not found" (peer deregistered).
	peerAddr atomic.Value // string
}

// startDesyncNode brings a daemon's tunnel up the way the daemon does at
// startup (X25519 encryption, a loopback UDP socket, node ID, Ed25519
// identity) and runs the daemon's route loop reduced to what these tests
// need: pings go to the real control handler (it answers the path probe),
// data payloads go to n.data. id may be nil for a fresh identity.
func startDesyncNode(t *testing.T, nodeID uint32, id *crypto.Identity) *desyncNode {
	t.Helper()
	d := New(Config{})
	tm := d.tunnels
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { tm.Close() })
	tm.SetNodeID(nodeID)
	if id == nil {
		var err error
		if id, err = crypto.GenerateIdentity(); err != nil {
			t.Fatalf("GenerateIdentity: %v", err)
		}
	}
	tm.SetIdentity(id)
	n := &desyncNode{d: d, tm: tm, id: nodeID, idn: id, addr: tunnelUDPAddr(t, tm), data: make(chan string, 1024)}
	n.answerPings.Store(true)
	n.peerAddr.Store("")
	go func() {
		for in := range tm.RecvCh() {
			if in.Packet.Protocol == protocol.ProtoControl {
				if n.answerPings.Load() {
					d.handleControlPacket(in.Packet)
				}
				continue
			}
			select {
			case n.data <- string(in.Packet.Payload):
			default:
			}
		}
	}()
	return n
}

// useRegistry points n at a fake registry that resolves peerID to
// n.peerAddr (or "node not found" while it is empty) and knows the given
// Ed25519 keys, so resetPeerPath/ensureTunnel run their full sequence.
func (n *desyncNode) useRegistry(t *testing.T, peerID uint32, keys map[uint32]ed25519.PublicKey) {
	t.Helper()
	n.tm.SetPeerVerifyFunc(registryKeys(keys))
	rc, stop := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] != "resolve" {
			return map[string]interface{}{}
		}
		addr, _ := n.peerAddr.Load().(string)
		if addr == "" {
			return map[string]interface{}{"type": "error", "error": "node not found"}
		}
		return map[string]interface{}{"node_id": float64(peerID), "real_addr": addr}
	})
	t.Cleanup(stop)
	n.d.regConn.Store(rc)
}

// newDesyncNodes starts two daemons that can resolve and verify each other.
// No session exists yet — see handshake / establishAgedSession.
func newDesyncNodes(t *testing.T, aID, bID uint32) (a, b *desyncNode) {
	t.Helper()
	a, b = startDesyncNode(t, aID, nil), startDesyncNode(t, bID, nil)
	keys := map[uint32]ed25519.PublicKey{aID: a.idn.PublicKey, bID: b.idn.PublicKey}
	a.peerAddr.Store(b.addr.String())
	b.peerAddr.Store(a.addr.String())
	a.useRegistry(t, bID, keys)
	b.useRegistry(t, aID, keys)
	return a, b
}

// handshake runs the real key exchange a→b, like the first second of a
// fresh process in the incident.
func handshake(t *testing.T, a, b *desyncNode) {
	t.Helper()
	a.tm.AddPeer(b.id, b.addr)
	waitUntil(t, "initial handshake", func() bool { return a.tm.HasCrypto(b.id) && b.tm.HasCrypto(a.id) })
	// Past the duplicate debounce, so a later PILA is handled as a
	// same-session keepalive (as in production, >=85s later) rather than
	// coalesced; also lets the handshake's trailing PILAs settle.
	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 50*time.Millisecond)
}

// establishAgedSession installs, on both sides, the session a completed
// handshake leaves — but aged past AgedCryptoFastDropAge, like every
// session a path reset or drop gate meets in production (the watchdog
// alone needs >=85s of silence). Each Crypto is built and backdated before
// it is installed, so no other goroutine ever sees it change.
func establishAgedSession(t *testing.T, a, b *desyncNode) {
	t.Helper()
	aged := time.Now().Add(-3 * keyexchange.AgedCryptoFastDropAge)
	for _, side := range []struct{ self, peer *desyncNode }{{a, b}, {b, a}} {
		pc, err := side.self.tm.deriveSecret(side.peer.tm.pubKey)
		if err != nil {
			t.Fatalf("deriveSecret: %v", err)
		}
		pc.Authenticated = true
		pc.CreatedAt = aged
		side.self.tm.envelope.Install(side.peer.id, pc)
		side.self.tm.mu.Lock()
		side.self.tm.peers[side.peer.id] = side.peer.addr
		side.self.tm.mu.Unlock()
		side.self.tm.kx.RecordInboundDecrypt(side.peer.id)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(desyncTestWait)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// deliver sends one data packet from→to over the tunnel and reports
// whether the receiver decrypted and delivered it within `within`. With no
// key the send queues and requests a key exchange, as in production.
func deliver(from, to *desyncNode, payload string, within time.Duration) bool {
	pkt := newPacket(payload)
	pkt.Src.Node = from.id
	pkt.Dst.Node = to.id
	_ = from.tm.Send(to.id, pkt)
	deadline := time.After(within)
	for {
		select {
		case got := <-to.data:
			if got == payload {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

var desyncSeq atomic.Uint64

// bothWays reports whether a fresh packet gets through in each direction.
func bothWays(a, b *desyncNode, within time.Duration) bool {
	n := desyncSeq.Add(1)
	ab := deliver(a, b, fmt.Sprintf("a-to-b-%d", n), within)
	ba := deliver(b, a, fmt.Sprintf("b-to-a-%d", n), within)
	return ab && ba
}

// recovers keeps offering traffic both ways until it flows in both
// directions again, and fails the test if that takes longer than limit.
func recovers(t *testing.T, a, b *desyncNode, limit time.Duration, why string) {
	t.Helper()
	start := time.Now()
	for time.Since(start) < limit {
		if bothWays(a, b, 500*time.Millisecond) {
			t.Logf("%s: traffic flows both ways again after %v", why, time.Since(start).Truncate(10*time.Millisecond))
			return
		}
	}
	t.Fatalf("%s: no two-way traffic within %v without a restart (A has key: %v, B has key: %v)",
		why, limit, a.tm.HasCrypto(b.id), b.tm.HasCrypto(a.id))
}

func baseline(t *testing.T, a, b *desyncNode) {
	t.Helper()
	for i := 0; i < 3; i++ {
		if !bothWays(a, b, desyncTestWait) {
			t.Fatal("baseline: session does not carry data in both directions")
		}
	}
}

// sealFromPeer encrypts pkt exactly as peerNodeID's daemon would for us
// under pc, returning the handleEncrypted input (frame minus PILS magic).
func sealFromPeer(t *testing.T, pc *peerCrypto, peerNodeID uint32, counter uint64, pkt *protocol.Packet) []byte {
	t.Helper()
	return sealWithPrefix(t, pc, pc.NoncePrefix, peerNodeID, counter, pkt)
}

// sealWithPrefix is sealFromPeer with an explicit nonce prefix — the
// prefix a peer's Crypto picks at derivation names its send epoch.
func sealWithPrefix(t *testing.T, pc *peerCrypto, prefix [4]byte, peerNodeID uint32, counter uint64, pkt *protocol.Packet) []byte {
	t.Helper()
	plaintext, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	nonce := make([]byte, pc.AEAD.NonceSize())
	copy(nonce[0:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:12], counter)
	aad := make([]byte, 4)
	binary.BigEndian.PutUint32(aad, peerNodeID)
	ct := pc.AEAD.Seal(nil, nonce, plaintext, aad)
	data := make([]byte, 4+12+len(ct))
	binary.BigEndian.PutUint32(data[0:4], peerNodeID)
	copy(data[4:16], nonce)
	copy(data[16:], ct)
	return data
}

// registryKeys is a verify func that knows exactly the given node pubkeys,
// standing in for the registry lookup HandleAuthFrame performs.
func registryKeys(keys map[uint32]ed25519.PublicKey) func(uint32) (ed25519.PublicKey, error) {
	return func(nodeID uint32) (ed25519.PublicKey, error) {
		if pk, ok := keys[nodeID]; ok {
			return pk, nil
		}
		return nil, fmt.Errorf("unknown node %d", nodeID)
	}
}

func tunnelUDPAddr(t *testing.T, tm *TunnelManager) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", tm.LocalAddr().String())
	if err != nil {
		t.Fatalf("resolve local addr: %v", err)
	}
	return addr
}

// --- case A: the peer still holds its half -------------------------------

// TestPathResetKeepsSessionWithPeerThatStillHoldsIt is link 3, the reason
// the loop never converged: after resetPeerPath the peer, which never lost
// anything, must still be able to talk to us over its existing session —
// on a busy session and on one that went quiet (both sides past the
// stale-recovery threshold, so the reset's PILA is answered).
func TestPathResetKeepsSessionWithPeerThatStillHoldsIt(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		name := "busy"
		if quiet {
			name = "quiet"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a, b := newDesyncNodes(t, 230204, 16392)
			establishAgedSession(t, a, b)
			baseline(t, a, b)
			if quiet {
				old := time.Now().Add(-2 * pathSilenceThreshold)
				a.tm.kx.SetLastInboundDecryptForTest(b.id, old)
				b.tm.kx.SetLastInboundDecryptForTest(a.id, old)
			}
			aPC, bPC := a.tm.envelope.Get(b.id), b.tm.envelope.Get(a.id)

			res := a.d.resetPeerPath(b.id)
			if res.ResolveErr != "" || !res.PilaPushed || !res.SessionKept {
				t.Fatalf("reset did not run its full sequence with the session kept: %+v", res)
			}
			if !bothWays(a, b, desyncTestWait) {
				t.Fatalf("BUG: after resetPeerPath the session no longer carries traffic "+
					"(we have key: %v, peer has key: %v). Dropping our half leaves the peer "+
					"treating our recovery PILA as a same-session keepalive: the \"no key\" -> "+
					"\"rekey gave up\" -> \"reset peer path\" loop that only a restart escapes",
					a.tm.HasCrypto(b.id), b.tm.HasCrypto(a.id))
			}
			if a.tm.envelope.Get(b.id) != aPC || b.tm.envelope.Get(a.id) != bPC {
				t.Fatal("a path reset against a peer that holds the session must not reinstall either half")
			}
		})
	}
}

// TestPathResetOnKeptSessionIsFireAndForget covers the kept-session reset's
// PILA: it must not arm the rekey retransmit machinery. A peer holding the
// session answers that PILA with nothing, so if the single path probe (or
// its pong) is lost, the retransmits would flip a healthy direct peer to
// relay after ~4s (RekeyRelayFallbackAfter) and give up after ~20s,
// firing another full reset. Liveness is proven by the probe instead.
func TestPathResetOnKeptSessionIsFireAndForget(t *testing.T) {
	t.Run("live path", func(t *testing.T) {
		t.Parallel()
		a, b := newDesyncNodes(t, 230204, 242944)
		establishAgedSession(t, a, b)
		stale := time.Now().Add(-2 * pathSilenceThreshold)
		a.tm.kx.SetLastInboundDecryptForTest(b.id, stale)

		res := a.d.resetPeerPath(b.id)
		if res.ResolveErr != "" || !res.PilaPushed || !res.SessionKept {
			t.Fatalf("reset did not run its full sequence with the session kept: %+v", res)
		}
		if a.tm.kx.PendingRekeyHas(b.id) {
			t.Fatal("a kept session's reset PILA must not arm a pending rekey")
		}
		waitUntil(t, "the probe's pong to refresh inbound liveness", func() bool {
			last, ok := a.tm.LastInboundDecrypt(b.id)
			return ok && last.After(stale.Add(time.Minute))
		})
	})
	t.Run("probe lost", func(t *testing.T) {
		t.Parallel()
		a, b := newDesyncNodes(t, 230204, 242944)
		establishAgedSession(t, a, b)
		b.answerPings.Store(false) // the probe or its pong is lost

		res := a.d.resetPeerPath(b.id)
		if !res.SessionKept || !res.PilaPushed {
			t.Fatalf("reset did not keep the session: %+v", res)
		}
		if a.tm.kx.PendingRekeyHas(b.id) {
			t.Fatalf("BUG: a kept session's reset PILA armed a pending rekey (attempts=%d): "+
				"with the probe lost, its retransmits flip a healthy direct peer to relay "+
				"and give up into another full reset", a.tm.kx.PendingRekeyAttempts(b.id))
		}
		a.tm.rekeyRetransmitTick()
		if a.tm.IsRelayPeer(b.id) {
			t.Fatal("a healthy direct peer was flipped to relay")
		}
		if !bothWays(a, b, desyncTestWait) {
			t.Fatal("the kept session must keep carrying traffic")
		}
	})
}

// TestPathProbePongRefreshesLiveness is link 1: the pong a peer sends back
// for our path probe must pass the identity binding and count as inbound
// liveness, or the watchdog resets every quiet peer it probes.
func TestPathProbePongRefreshesLiveness(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 179172)
	handshake(t, a, b)

	// The peer has been quiet past the silence threshold: the watchdog
	// probes it, and the peer's real control handler answers, as every
	// deployed version does: pong.Src = probe.Dst.
	stale := time.Now().Add(-2 * pathSilenceThreshold)
	a.tm.kx.SetLastInboundDecryptForTest(b.id, stale)
	if err := a.tm.SendPathProbe(b.id); err != nil {
		t.Fatalf("SendPathProbe: %v", err)
	}
	deadline := time.Now().Add(desyncTestWait)
	for time.Now().Before(deadline) {
		if last, ok := a.tm.LastInboundDecrypt(b.id); ok && last.After(stale.Add(time.Minute)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("BUG: the peer's pong did not refresh inbound liveness: without Dst on the probe " +
		"the pong claims Src=0, the identity binding drops it as spoofed and the watchdog " +
		"resets a healthy path")
}

// TestLegacyUnstampedKeepaliveCountsAsLiveness is link 2: the zero-Src NAT
// keepalive every pre-v1.12.1 peer sends is authenticated inbound traffic
// and must refresh liveness (and feed PktsRecv for the rx watchdog), while
// never reaching the application.
func TestLegacyUnstampedKeepaliveCountsAsLiveness(t *testing.T) {
	t.Parallel()
	const peerID uint32 = 242944

	newTM := func() (*TunnelManager, *peerCrypto) {
		tm := NewTunnelManager()
		if err := tm.EnableEncryption(); err != nil {
			t.Fatalf("EnableEncryption: %v", err)
		}
		peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("peer keygen: %v", err)
		}
		pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
		if err != nil {
			t.Fatalf("deriveSecret: %v", err)
		}
		tm.envelope.Install(peerID, pc)
		return tm, pc
	}
	from := mustUDPAddr(t, "127.0.0.1:5555")

	// What keepaliveSweep sent before v1.12.1: no Src at all.
	tm, pc := newTM()
	now := time.Now()
	tm.kx.InjectPendingRekeyForTest(peerID, &pendingRekeyState{FirstSentAt: now, LastSentAt: now, Attempts: 1})
	legacy := &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing}
	tm.handleEncrypted(sealFromPeer(t, pc, peerID, 1, legacy), from)

	if _, ok := tm.LastInboundDecrypt(peerID); !ok {
		t.Fatal("BUG: legacy zero-Src keepalive dropped as spoofed before recording liveness; " +
			"every quiet pre-v1.12.1 peer looks inbound-silent to the path watchdog")
	}
	if tm.kx.PendingRekeyHas(peerID) {
		t.Fatal("authenticated legacy keepalive must clear the pending rekey like any other decrypt")
	}
	if got := atomic.LoadUint64(&tm.PktsRecv); got != 1 {
		t.Fatalf("PktsRecv = %d, want 1 (the rx watchdog counts keepalives as inbound progress)", got)
	}
	select {
	case in := <-tm.RecvCh():
		t.Fatalf("keepalive must never reach the application, got %+v", in.Packet)
	case <-time.After(50 * time.Millisecond):
	}

	// The exemption is narrow: a zero-Src frame that is not a bare
	// keepalive is still an identity-binding violation with no side effects.
	tm2, pc2 := newTM()
	withPayload := newPacket("not-a-keepalive") // Src left zero
	tm2.handleEncrypted(sealFromPeer(t, pc2, peerID, 1, withPayload), from)
	if _, ok := tm2.LastInboundDecrypt(peerID); ok {
		t.Fatal("zero-Src frame with a payload must still be dropped without refreshing liveness")
	}
	if got := atomic.LoadUint64(&tm2.PktsRecv); got != 0 {
		t.Fatalf("zero-Src frame with a payload must not count as received; PktsRecv = %d", got)
	}
	select {
	case in := <-tm2.RecvCh():
		t.Fatalf("zero-Src frame with a payload must not be delivered, got %q", in.Packet.Payload)
	case <-time.After(50 * time.Millisecond):
	}
}

// --- case B: the peer lost its half ---------------------------------------

// dropHalfLikeOldReset is what every v1.10–v1.13 peer's resetPeerPath
// (watchdog, rekey gave up, prefer-direct) does to its half of the
// session: RemovePeer drops the keys with the path, then ensureTunnel's
// AddPeer pushes a fresh PILA — under the same X25519 key, since the
// process did not restart.
func dropHalfLikeOldReset(n, peer *desyncNode, pushPILA bool) {
	n.tm.RemovePeer(peer.id)
	if pushPILA {
		n.tm.AddPeer(peer.id, peer.addr)
	}
}

// TestPathResetRecoversPeerThatLostItsHalf: the peer already threw its half
// away, then our side resets the path (watchdog, rekey gave up or
// prefer-direct). The session we keep must converge with the one the peer
// re-derives from our PILA — whose send counter restarts at 1 — without
// either side restarting, and without our half being dropped on the way.
func TestPathResetRecoversPeerThatLostItsHalf(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 16392)
	establishAgedSession(t, a, b)
	baseline(t, a, b)
	ours := a.tm.envelope.Get(b.id)

	dropHalfLikeOldReset(b, a, false)
	res := a.d.resetPeerPath(b.id)
	if !res.SessionKept || !res.PilaPushed {
		t.Fatalf("reset did not keep our session: %+v", res)
	}
	if !bothWays(a, b, desyncTestWait) {
		t.Fatalf("BUG: the peer re-derived the session from our PILA but traffic does not flow "+
			"(we have key: %v, peer has key: %v). Its restarted send counter hit our kept replay "+
			"window, the aged fast-drop threw our half away, and the peer — now holding a fresh "+
			"session — ignores our re-handshake as a same-session keepalive",
			a.tm.HasCrypto(b.id), b.tm.HasCrypto(a.id))
	}
	if a.tm.envelope.Get(b.id) != ours {
		t.Fatal("our half must survive: the peer's new epoch gets a fresh window, it does not drop the session")
	}
}

// TestSimultaneousPathResetsWithPeerThatDropsItsHalf: one dead path makes
// both watchdogs fire. The peer runs v1.10–v1.13 (its reset drops its half
// and pushes a PILA), we run this build. Both orders must converge.
func TestSimultaneousPathResetsWithPeerThatDropsItsHalf(t *testing.T) {
	for _, order := range []string{"peer-first", "we-first"} {
		t.Run(order, func(t *testing.T) {
			t.Parallel()
			a, b := newDesyncNodes(t, 230204, 16392)
			establishAgedSession(t, a, b)
			baseline(t, a, b)
			ours := a.tm.envelope.Get(b.id)

			if order == "peer-first" {
				dropHalfLikeOldReset(b, a, true)
				a.d.resetPeerPath(b.id)
			} else {
				// Our reset completes first — its PILA reached the peer as
				// a same-session keepalive and the probe was answered —
				// and only then does the peer drop its half. We now hold
				// fresh liveness, so our answer to its PILAs waits out the
				// stale-recovery threshold.
				before := time.Now()
				a.d.resetPeerPath(b.id)
				waitUntil(t, "our reset's probe to be answered", func() bool {
					last, ok := a.tm.LastInboundDecrypt(b.id)
					return ok && last.After(before)
				})
				dropHalfLikeOldReset(b, a, true)
			}
			recovers(t, a, b, desyncRecoverWait, order)
			if a.tm.envelope.Get(b.id) != ours {
				t.Fatal("our half must survive both resets")
			}
		})
	}
}

// TestPeerThatLostItsHalfIsAnsweredWithoutAReset: the peer threw its half
// away and asks for ours with same-key PILAs; nothing on our side resets.
// Link 5: we must answer once the peer has been silent past the
// stale-recovery threshold. Before, onKeyInstalled stamped liveness on
// every such PILA before the reply gate ran, so the reply never fired —
// and those PILAs also kept our path watchdog from ever noticing.
func TestPeerThatLostItsHalfIsAnsweredWithoutAReset(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 242944)
	establishAgedSession(t, a, b)
	baseline(t, a, b)
	ours := a.tm.envelope.Get(b.id)

	dropHalfLikeOldReset(b, a, true)
	recovers(t, a, b, desyncRecoverWait, "peer lost its half")
	if a.tm.envelope.Get(b.id) != ours {
		t.Fatal("answering the peer must not reinstall our half")
	}
}

// TestPeerRestartMidSessionRecovers: the peer's process restarts (new
// X25519 key and port, same node ID and identity) and dials us again. We
// must pick the new session up in place.
func TestPeerRestartMidSessionRecovers(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 179172)
	establishAgedSession(t, a, b)
	baseline(t, a, b)
	old := a.tm.envelope.Get(b.id)

	b.tm.Close() // the old process is gone
	b2 := startDesyncNode(t, b.id, b.idn)
	keys := map[uint32]ed25519.PublicKey{a.id: a.idn.PublicKey, b.id: b.idn.PublicKey}
	b2.peerAddr.Store(a.addr.String())
	b2.useRegistry(t, a.id, keys)
	a.peerAddr.Store(b2.addr.String())

	b2.tm.AddPeer(a.id, a.addr)
	recovers(t, a, b2, desyncRecoverWait, "peer restarted")
	if a.tm.envelope.Get(b.id) == old {
		t.Fatal("the restarted peer's new X25519 key must replace the old session")
	}
}

// --- the drop gates --------------------------------------------------------

// TestDropGateOnOurHalfRecoversWithoutRestart: one of handleEncrypted's
// drop gates throws OUR half away while the peer keeps its own — here the
// aged fast path on an authenticated in-window replay (a duplicate
// delivery, or a late relay-buffered frame for the outside-window gate).
// The peer runs this build: it must answer our re-handshake once we have
// been silent past the stale-recovery threshold, and the session we then
// re-derive — send counter restarted under a new prefix — must be accepted
// by its kept window as our new epoch.
func TestDropGateOnOurHalfRecoversWithoutRestart(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 16392)
	establishAgedSession(t, a, b)
	baseline(t, a, b)

	// Re-deliver B's first frame to A: authenticated, current epoch,
	// already seen. On an aged session the replay gate drops A's half.
	replay := sealFromPeer(t, b.tm.envelope.Get(a.id), b.id, 1, newPacket("duplicate"))
	conn, err := net.DialUDP("udp", nil, a.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(append(append([]byte{}, protocol.TunnelMagicSecure[:]...), replay...)); err != nil {
		t.Fatalf("write replay: %v", err)
	}
	waitUntil(t, "the replay drop gate to drop our half", func() bool { return !a.tm.HasCrypto(b.id) })
	if !b.tm.HasCrypto(a.id) {
		t.Fatal("setup: the peer must still hold its half")
	}

	recovers(t, a, b, desyncRecoverWait, "drop gate")
}

// TestPeerNewEpochDoesNotTripAgedDropGates is link 4 at the tunnel layer:
// a peer that re-derived our session (same AEAD key, counter restarted at
// 1 under a new nonce prefix) is delivered from its first frame, with no
// drop and no rekey; frames of its previous epoch are judged in that
// epoch's own window without touching the session either.
func TestPeerNewEpochDoesNotTripAgedDropGates(t *testing.T) {
	t.Parallel()
	const peerID uint32 = 0x44444444
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0x33333333)
	peerAddr := mustUDPAddr(t, "127.0.0.1:56789")
	peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	pc.CreatedAt = time.Now().Add(-time.Hour)
	tm.mu.Lock()
	tm.peers[peerID] = peerAddr
	tm.mu.Unlock()
	tm.envelope.Install(peerID, pc)

	pkt := func(s string) *protocol.Packet {
		p := newPacket(s)
		p.Src.Node = peerID
		return p
	}
	recv := func(want string) {
		t.Helper()
		select {
		case in := <-tm.RecvCh():
			if string(in.Packet.Payload) != want {
				t.Fatalf("delivered %q, want %q", in.Packet.Payload, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("%q was not delivered", want)
		}
	}
	rekeyRequested := func() bool {
		tm.rekeyMu.Lock()
		defer tm.rekeyMu.Unlock()
		_, ok := tm.lastRekeyReq[peerID]
		return ok
	}

	oldEpoch := [4]byte{1, 1, 1, 1}
	newEpoch := [4]byte{2, 2, 2, 2}
	for i := uint64(1); i <= 300; i++ { // past the 256-frame window
		tm.handleEncrypted(sealWithPrefix(t, pc, oldEpoch, peerID, i, pkt("old")), peerAddr)
		recv("old")
	}

	// The peer re-derives: its first frame is counter 1, outside our
	// window — on the aged session the old code dropped it on sight.
	tm.handleEncrypted(sealWithPrefix(t, pc, newEpoch, peerID, 1, pkt("new-1")), peerAddr)
	recv("new-1")
	tm.handleEncrypted(sealWithPrefix(t, pc, newEpoch, peerID, 2, pkt("new-2")), peerAddr)
	recv("new-2")
	if tm.envelope.Get(peerID) != pc || rekeyRequested() {
		t.Fatal("the peer's new epoch must not drop the session or request a rekey")
	}

	// Frames of the previous epoch are judged in that epoch's own window:
	// a late one it never saw is delivered, a duplicate is dropped — and
	// neither drops the session or requests a rekey.
	tm.handleEncrypted(sealWithPrefix(t, pc, oldEpoch, peerID, 301, pkt("straggler")), peerAddr)
	recv("straggler")
	tm.handleEncrypted(sealWithPrefix(t, pc, oldEpoch, peerID, 300, pkt("duplicate")), peerAddr)
	select {
	case in := <-tm.RecvCh():
		t.Fatalf("a duplicate from the peer's previous epoch was delivered: %q", in.Packet.Payload)
	case <-time.After(50 * time.Millisecond):
	}
	if tm.envelope.Get(peerID) != pc || rekeyRequested() {
		t.Fatal("a previous-epoch frame must not drop the session or request a rekey")
	}

	// The new epoch's window is untouched by all of that.
	tm.handleEncrypted(sealWithPrefix(t, pc, newEpoch, peerID, 3, pkt("new-3")), peerAddr)
	recv("new-3")
}

// --- a reset whose re-resolve fails ---------------------------------------

// TestResetWithFailedResolveKeepsDetachedSessionBounded: the reset keeps
// the session but cannot re-resolve the peer, so the session has no path
// entry. A live peer re-attaches it with its next frame; a departed peer's
// session is reaped once it has been silent as long as a stale peer —
// instead of leaking for the life of the process.
func TestResetWithFailedResolveKeepsDetachedSessionBounded(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 16392)
	establishAgedSession(t, a, b)
	baseline(t, a, b)

	a.peerAddr.Store("") // registry: "node not found"
	res := a.d.resetPeerPath(b.id)
	if !res.SessionKept || res.ResolveErr == "" {
		t.Fatalf("want a kept session with a failed re-resolve, got %+v", res)
	}
	if a.tm.HasPeer(b.id) || !a.tm.HasCrypto(b.id) {
		t.Fatalf("want a detached session (no path, keys kept): hasPeer=%v hasCrypto=%v",
			a.tm.HasPeer(b.id), a.tm.HasCrypto(b.id))
	}

	// Registry blip, peer alive: the sweep keeps it, and the peer's next
	// (direct) frame re-attaches the path.
	a.d.reapStalePeers()
	if !a.tm.HasCrypto(b.id) {
		t.Fatal("a detached session with a live peer must not be reaped")
	}
	if !deliver(b, a, "reattach", desyncTestWait) || !a.tm.HasPeer(b.id) {
		t.Fatal("the peer's next frame must decrypt and re-attach the path")
	}
	if !bothWays(a, b, desyncTestWait) {
		t.Fatal("the re-attached session must carry traffic both ways")
	}

	// Peer gone for good: another failed reset detaches it again, and
	// once it has been silent past peerReapIdleTimeout the sweep drops it.
	b.tm.Close()
	a.d.resetPeerPath(b.id)
	a.tm.kx.SetLastInboundDecryptForTest(b.id, time.Now().Add(-2*peerReapIdleTimeout))
	a.d.reapStalePeers()
	if a.tm.HasCrypto(b.id) || a.tm.envelope.Len() != 0 {
		t.Fatalf("BUG: a departed peer's detached session leaked (hasCrypto=%v, sessions=%d): "+
			"nothing that walks tm.peers can ever reclaim it", a.tm.HasCrypto(b.id), a.tm.envelope.Len())
	}
	if _, ok := a.tm.LastInboundDecrypt(b.id); ok {
		t.Fatal("reaping a detached session must also clear its per-peer liveness state")
	}
}

// --- a peer epoch on a kept session: drain grace and replays ---------------

// agedTunnelWithPeer is one TunnelManager holding an aged session with a
// peer that exists only as the frames the test seals for it, and the
// peer's path.
func agedTunnelWithPeer(t *testing.T) (tm *TunnelManager, pc *peerCrypto, peerID uint32, peerAddr *net.UDPAddr) {
	t.Helper()
	peerID = 0x44444444
	tm = NewTunnelManager()
	t.Cleanup(func() { tm.Close() })
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0x33333333)
	peerAddr = mustUDPAddr(t, "127.0.0.1:56789")
	peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer keygen: %v", err)
	}
	if pc, err = tm.deriveSecret(peerPriv.PublicKey().Bytes()); err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	pc.CreatedAt = time.Now().Add(-time.Hour)
	tm.mu.Lock()
	tm.peers[peerID] = peerAddr
	tm.mu.Unlock()
	tm.envelope.Install(peerID, pc)
	return tm, pc, peerID, peerAddr
}

// recvOnly reports what tm delivers to its application within d, if
// anything.
func recvOnly(tm *TunnelManager, d time.Duration) (string, bool) {
	select {
	case in := <-tm.RecvCh():
		return string(in.Packet.Payload), true
	case <-time.After(d):
		return "", false
	}
}

func peerPath(tm *TunnelManager, peerID uint32) string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	if a := tm.peers[peerID]; a != nil {
		return a.String()
	}
	return ""
}

// TestPeersNewEpochOnKeptSessionGetsDrainGrace: the replay and
// outside-window gates judge the age of the peer's newest epoch, not of
// our Crypto. A session we keep across a reset is always aged (the
// watchdog alone needs ~85s of silence), but the epoch the peer starts on
// it by re-deriving is brand new, and drains the same early duplicates and
// late frames as a fresh session. Judged by the Crypto's age, the first
// such frame dropped our half — and a v1.10.9–v1.13 peer, which then holds
// the fresh half, never answers a same-key exchange: the pair wedged.
func TestPeersNewEpochOnKeptSessionGetsDrainGrace(t *testing.T) {
	for _, tc := range []string{"duplicate", "late frame"} {
		t.Run(tc, func(t *testing.T) {
			t.Parallel()
			a, b := newDesyncNodes(t, 230204, 16392)
			establishAgedSession(t, a, b)
			baseline(t, a, b)
			ours := a.tm.envelope.Get(b.id)

			// Case B: the peer threw its half away, then our reset keeps
			// ours; the peer re-derives from our PILA and traffic flows.
			dropHalfLikeOldReset(b, a, false)
			a.d.resetPeerPath(b.id)
			if !bothWays(a, b, desyncTestWait) || a.tm.envelope.Get(b.id) != ours {
				t.Fatal("setup: case B must converge on our kept half")
			}
			theirs := b.tm.envelope.Get(a.id)

			p := newPacket("drain")
			p.Src.Node = b.id
			switch tc {
			case "duplicate":
				// An early frame of the peer's new epoch arrives twice
				// (relay re-delivery / UDP duplicate).
				redeliverTo(t, a, sealFromPeer(t, theirs, b.id, 1, p))
			case "late frame":
				// A burst past the window, then an early frame held up on
				// the relay lands.
				for i := 0; i < keyexchange.ReplayWindowSize+44; i++ {
					if !deliver(b, a, fmt.Sprintf("burst-%d", i), desyncTestWait) {
						t.Fatalf("burst frame %d not delivered", i)
					}
				}
				redeliverTo(t, a, sealFromPeer(t, theirs, b.id, 2, p))
			}
			time.Sleep(200 * time.Millisecond)

			if a.tm.envelope.Get(b.id) != ours {
				t.Fatalf("BUG: one %s of the peer's brand-new epoch dropped our kept half (we have key: %v); "+
					"a v1.10.9–v1.13 peer holding the fresh half never answers our re-handshake", tc, a.tm.HasCrypto(b.id))
			}
			if !bothWays(a, b, desyncTestWait) {
				t.Fatal("the session must keep carrying traffic both ways")
			}
		})
	}
}

// redeliverTo sends frame to n's tunnel socket from a different UDP
// source, as a relay re-delivery or a network duplicate would.
func redeliverTo(t *testing.T, n *desyncNode, frame []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp", nil, n.addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(append(append([]byte{}, protocol.TunnelMagicSecure[:]...), frame...)); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestRecordedFramesOfEarlierEpochsAreNeverReaccepted: every epoch of a
// session shares one AEAD key, so every recorded frame of every earlier
// peer epoch still authenticates. Once more epochs had passed than
// RetainedRecvEpochs keeps windows for, an evicted epoch used to come back
// as a "new" one with a fresh window: replaying recorded frames of 6+
// epochs round-robin re-opened the replayed epoch every time, and every
// replay was delivered — and moved our path to the peer to the replayer's
// address. Evicted epochs are now retired: rejected for good.
func TestRecordedFramesOfEarlierEpochsAreNeverReaccepted(t *testing.T) {
	t.Parallel()
	tm, pc, peerID, peerAddr := agedTunnelWithPeer(t)
	attacker := mustUDPAddr(t, "127.0.0.1:56790")

	const epochs = 3 * (keyexchange.RetainedRecvEpochs + 2)
	var recorded [][]byte
	for k := 0; k < epochs; k++ {
		prefix := [4]byte{0xE0, 0, 0, byte(k)}
		p := newPacket(fmt.Sprintf("cmd-%d", k))
		p.Src.Node = peerID
		f := sealWithPrefix(t, pc, prefix, peerID, 1, p)
		tm.handleEncrypted(f, peerAddr)
		if got, ok := recvOnly(tm, time.Second); !ok || got != fmt.Sprintf("cmd-%d", k) {
			t.Fatalf("genuine frame of epoch %d: delivered %q (%v)", k, got, ok)
		}
		recorded = append(recorded, f)
	}

	// The attacker re-sends every earlier epoch's recorded frame, byte for
	// byte, round-robin, from its own address.
	for round := 0; round < 20; round++ {
		for _, f := range recorded[:epochs-1] {
			tm.handleEncrypted(f, attacker)
		}
	}
	if got, ok := recvOnly(tm, 100*time.Millisecond); ok {
		t.Fatalf("BUG: a recorded frame of an earlier epoch was delivered again: %q", got)
	}
	if got := peerPath(tm, peerID); got != peerAddr.String() {
		t.Fatalf("BUG: replayed frames moved our path to the peer to %s (peer is at %s)", got, peerAddr)
	}
	if tm.envelope.Get(peerID) != pc {
		t.Fatal("replays of earlier epochs must not touch the session")
	}

	// The peer's live epoch is unaffected.
	p := newPacket("live")
	p.Src.Node = peerID
	tm.handleEncrypted(sealWithPrefix(t, pc, [4]byte{0xE0, 0, 0, byte(epochs - 1)}, peerID, 2, p), peerAddr)
	if got, ok := recvOnly(tm, time.Second); !ok || got != "live" {
		t.Fatalf("the live epoch's next frame: delivered %q (%v)", got, ok)
	}
}

// TestOnlyTheLiveEpochMovesThePath: a frame of an earlier epoch (a
// straggler its window still accepts) or the first frame of an epoch this
// Crypto never saw is delivered, but it is not proof of where the peer is
// now — with one AEAD key for every epoch, it may be a recorded frame
// re-sent from anywhere — so it does not move the path or clear relay
// mode. The peer's next frame of its live epoch does.
func TestOnlyTheLiveEpochMovesThePath(t *testing.T) {
	t.Parallel()
	tm, pc, peerID, peerAddr := agedTunnelWithPeer(t)
	elsewhere := mustUDPAddr(t, "127.0.0.1:56791")
	oldEpoch, newEpoch := [4]byte{1, 1, 1, 1}, [4]byte{2, 2, 2, 2}
	frame := func(prefix [4]byte, counter uint64, payload string) []byte {
		p := newPacket(payload)
		p.Src.Node = peerID
		return sealWithPrefix(t, pc, prefix, peerID, counter, p)
	}
	expect := func(want string) {
		t.Helper()
		if got, ok := recvOnly(tm, time.Second); !ok || got != want {
			t.Fatalf("delivered %q (%v), want %q", got, ok, want)
		}
	}

	tm.handleEncrypted(frame(oldEpoch, 1, "old-1"), peerAddr)
	expect("old-1")
	tm.SetRelayPeer(peerID, true)

	tm.handleEncrypted(frame(newEpoch, 1, "new-1"), elsewhere)
	expect("new-1")
	if got := peerPath(tm, peerID); got != peerAddr.String() {
		t.Fatalf("the first frame of a new epoch moved the path to %s", got)
	}
	// Enough direct frames to clear relay mode, were they of the live epoch.
	for i := 0; i < routing.DirectClearsRequired; i++ {
		payload := fmt.Sprintf("straggler-%d", i)
		tm.handleEncrypted(frame(oldEpoch, uint64(2+i), payload), elsewhere)
		expect(payload)
	}
	if got := peerPath(tm, peerID); got != peerAddr.String() {
		t.Fatalf("a straggler of an earlier epoch moved the path to %s", got)
	}
	if !tm.routing.IsRelayPeer(peerID) {
		t.Fatal("frames outside the live epoch cleared relay mode")
	}

	for i := 0; i < routing.DirectClearsRequired; i++ {
		payload := fmt.Sprintf("new-%d", 2+i)
		tm.handleEncrypted(frame(newEpoch, uint64(2+i), payload), elsewhere)
		expect(payload)
	}
	if got := peerPath(tm, peerID); got != elsewhere.String() {
		t.Fatalf("the live epoch's frames must still learn the peer's new address: path %s, want %s", got, elsewhere)
	}
	if tm.routing.IsRelayPeer(peerID) {
		t.Fatal("direct frames of the live epoch must still clear relay mode")
	}
}

// forcePeerEpoch makes b throw its half of the session away and re-derive
// it from a's answer: a new b send epoch on a's kept Crypto. a's liveness
// for b is backdated past KeyExchangeReplyStaleThreshold first, so a
// answers b's first same-key PILA instead of after 6s of real silence.
func forcePeerEpoch(t *testing.T, a, b *desyncNode, why string) {
	t.Helper()
	time.Sleep(keyexchange.KeyExchangeReplyMinInterval) // a's reply rate limit
	a.tm.kx.SetLastInboundDecryptForTest(b.id, time.Now().Add(-2*keyexchange.KeyExchangeReplyStaleThreshold))
	dropHalfLikeOldReset(b, a, true)
	recovers(t, a, b, desyncRecoverWait, why)
}

// TestReplaysAcrossManyPeerEpochsEndToEnd is the same attack on two real
// daemons: the peer re-derives our kept session RetainedRecvEpochs+2
// times (each a real drop and key exchange), an observer records one
// genuine frame per epoch, and re-sends those of every earlier epoch —
// more than the windows a Crypto retains — from the peer's socket and
// from its own. None may reach our application or move our path.
func TestReplaysAcrossManyPeerEpochsEndToEnd(t *testing.T) {
	t.Parallel()
	a, b := newDesyncNodes(t, 230204, 16392)
	establishAgedSession(t, a, b)
	baseline(t, a, b)
	ours := a.tm.envelope.Get(b.id)

	const epochs = keyexchange.RetainedRecvEpochs + 3
	var recorded [][]byte
	for k := 0; k < epochs; k++ {
		if k > 0 {
			forcePeerEpoch(t, a, b, fmt.Sprintf("epoch %d", k))
		}
		if a.tm.envelope.Get(b.id) != ours {
			t.Fatalf("setup: our half was replaced at epoch %d", k)
		}
		payload := fmt.Sprintf("cmd-%d", k)
		p := newPacket(payload)
		p.Src.Node, p.Dst.Node = b.id, a.id
		pt, err := p.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		f := b.tm.encryptFrame(b.tm.envelope.Get(a.id), pt)
		if err := b.tm.writeFrame(a.id, a.addr, f); err != nil {
			t.Fatal(err)
		}
		deadline := time.After(desyncTestWait)
	wait:
		for {
			select {
			case got := <-a.data:
				if got == payload {
					break wait
				}
			case <-deadline:
				t.Fatalf("genuine %s not delivered", payload)
			}
		}
		recorded = append(recorded, f)
	}
	time.Sleep(100 * time.Millisecond)
	for len(a.data) > 0 {
		<-a.data
	}

	atk, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer atk.Close()
	for round := 0; round < 10; round++ {
		for _, f := range recorded[:epochs-1] {
			_ = b.tm.writeFrame(a.id, a.addr, f)
			_, _ = atk.WriteToUDP(f, a.addr)
			time.Sleep(2 * time.Millisecond)
		}
	}
	time.Sleep(200 * time.Millisecond)
	replayed := map[string]int{}
	for len(a.data) > 0 {
		replayed[<-a.data]++
	}
	if len(replayed) > 0 {
		t.Fatalf("BUG: recorded frames of earlier epochs were delivered again: %v", replayed)
	}
	if got := peerPath(a.tm, b.id); got != b.addr.String() {
		t.Fatalf("BUG: replays moved our path to the peer to %s (peer is at %s, replayer at %s)", got, b.addr, atk.LocalAddr())
	}
	if a.tm.envelope.Get(b.id) != ours || !bothWays(a, b, desyncTestWait) {
		t.Fatal("the session must be untouched and keep carrying traffic both ways")
	}
}
