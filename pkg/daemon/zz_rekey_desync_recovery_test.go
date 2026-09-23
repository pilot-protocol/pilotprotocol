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
// The chain, one test per link:
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
)

const desyncTestWait = 2 * time.Second

// startAuthLoopbackTunnel brings tm up the way a daemon does at startup:
// X25519 encryption, a UDP socket on loopback, a node ID and an Ed25519
// identity. Frames between two such tunnels go through the real readLoop
// dispatch. Returns the identity's public key for the peer's verify func.
func startAuthLoopbackTunnel(t *testing.T, tm *TunnelManager, nodeID uint32) ed25519.PublicKey {
	t.Helper()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { tm.Close() })
	tm.SetNodeID(nodeID)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	tm.SetIdentity(id)
	return id.PublicKey
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

// newDesyncPair builds two daemons talking over loopback: laptop (the
// side whose path gets reset, with a fake registry that resolves the peer
// to its endpoint so resetPeerPath runs its full production sequence) and
// peer. Both have authenticated identities and have completed the initial
// handshake, like the first second of a fresh process in the incident.
func newDesyncPair(t *testing.T, laptopID, peerID uint32) (laptop, peer *Daemon) {
	t.Helper()
	laptop, peer = New(Config{}), New(Config{})
	a, b := laptop.tunnels, peer.tunnels
	keys := map[uint32]ed25519.PublicKey{
		laptopID: startAuthLoopbackTunnel(t, a, laptopID),
		peerID:   startAuthLoopbackTunnel(t, b, peerID),
	}
	a.SetPeerVerifyFunc(registryKeys(keys))
	b.SetPeerVerifyFunc(registryKeys(keys))
	bAddr := tunnelUDPAddr(t, b)

	rc, stopRegistry := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "resolve" {
			return map[string]interface{}{"node_id": float64(peerID), "real_addr": bAddr.String()}
		}
		return map[string]interface{}{}
	})
	t.Cleanup(stopRegistry)
	laptop.regConn.Store(rc)

	a.AddPeer(peerID, bAddr)
	waitUntil(t, "initial handshake", func() bool { return a.HasCrypto(peerID) && b.HasCrypto(laptopID) })
	// In production the watchdog fires >=85s after the handshake, so the
	// peer treats a later PILA as a same-session keepalive rather than
	// coalescing it as a duplicate of the handshake; the wait also lets the
	// handshake's trailing PILAs settle.
	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 50*time.Millisecond)
	return laptop, peer
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

// deliveredWithin sends one data packet from→to over the tunnel and
// reports whether the receiver decrypted and delivered it in time.
func deliveredWithin(from *TunnelManager, fromID uint32, to *TunnelManager, toID uint32, payload string) bool {
	pkt := newPacket(payload)
	pkt.Src.Node = fromID
	pkt.Dst.Node = toID
	_ = from.Send(toID, pkt) // with no key it queues + rekeys; delivery is what we assert
	deadline := time.After(desyncTestWait)
	for {
		select {
		case in, ok := <-to.RecvCh():
			if !ok {
				return false
			}
			if string(in.Packet.Payload) == payload {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

// sealFromPeer encrypts pkt exactly as peerNodeID's daemon would for us
// under pc, returning the handleEncrypted input (frame minus PILS magic).
func sealFromPeer(t *testing.T, pc *peerCrypto, peerNodeID uint32, counter uint64, pkt *protocol.Packet) []byte {
	t.Helper()
	plaintext, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	nonce := make([]byte, pc.AEAD.NonceSize())
	copy(nonce[0:4], pc.NoncePrefix[:])
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

// TestPathResetKeepsSessionWithPeerThatStillHoldsIt is link 3, the reason
// the loop never converged: after resetPeerPath the peer, which never lost
// anything, must still be able to talk to us over its existing session.
func TestPathResetKeepsSessionWithPeerThatStillHoldsIt(t *testing.T) {
	const laptopID, peerID uint32 = 230204, 16392
	dA, dB := newDesyncPair(t, laptopID, peerID)
	a, b := dA.tunnels, dB.tunnels

	if !deliveredWithin(b, peerID, a, laptopID, "baseline-b-to-a") ||
		!deliveredWithin(a, laptopID, b, peerID, "baseline-a-to-b") {
		t.Fatal("baseline: session does not carry data in both directions")
	}

	res := dA.resetPeerPath(peerID)
	if res.ResolveErr != "" || !res.PilaPushed {
		t.Fatalf("reset did not run its full sequence: %+v", res)
	}
	if !res.SessionKept {
		t.Errorf("reset must report the established session as kept: %+v", res)
	}

	// The peer noticed nothing and keeps using its session.
	if !deliveredWithin(b, peerID, a, laptopID, "after-reset-b-to-a") {
		t.Fatalf("BUG: after resetPeerPath we can no longer decrypt the peer's traffic "+
			"(we have key: %v, peer has key: %v). The reset dropped our session keys; the peer "+
			"still holds its half, keyed to our unchanged X25519 key, so it treats our recovery "+
			"PILA as a same-session keepalive and never replies: the \"no key\" -> \"rekey gave up\" "+
			"-> \"reset peer path\" loop that only a restart (new X25519 key) escapes",
			a.HasCrypto(peerID), b.HasCrypto(laptopID))
	}
	if !deliveredWithin(a, laptopID, b, peerID, "after-reset-a-to-b") {
		t.Fatalf("BUG: after resetPeerPath the peer can no longer decrypt our traffic (we have key: %v)",
			a.HasCrypto(peerID))
	}
}

// TestPathResetOnLivePathSettlesWithoutGivingUp: once the session survives
// the reset, the peer answers the recovery PILA with nothing (same session),
// so the rekey it armed can only be cleared by an inbound decrypt. A quiet
// peer's next keepalive is up to ~30s away, past the ~24s rekey give-up,
// which would fire a spurious "rekey gave up" and another reset. The reset
// must solicit that decrypt itself (path probe → pong) within one RTT.
func TestPathResetOnLivePathSettlesWithoutGivingUp(t *testing.T) {
	const laptopID, peerID uint32 = 230204, 242944
	dA, dB := newDesyncPair(t, laptopID, peerID)
	a, b := dA.tunnels, dB.tunnels

	// The peer's route loop, reduced to what matters here: answer pings.
	go func() {
		for in := range b.RecvCh() {
			if in.Packet.Protocol == protocol.ProtoControl {
				dB.handleControlPacket(in.Packet)
			}
		}
	}()

	res := dA.resetPeerPath(peerID)
	if res.ResolveErr != "" || !res.PilaPushed || !res.SessionKept {
		t.Fatalf("reset did not run its full sequence with the session kept: %+v", res)
	}
	waitUntil(t, "pending rekey cleared by an inbound decrypt from the live path", func() bool {
		return !a.kx.PendingRekeyHas(peerID)
	})
	if _, ok := a.LastInboundDecrypt(peerID); !ok {
		t.Fatal("live path must re-record inbound liveness after the reset")
	}
}

// TestPathProbePongRefreshesLiveness is link 1: the pong a peer sends back
// for our path probe must pass the identity binding and count as inbound
// liveness, or the watchdog resets every quiet peer it probes.
func TestPathProbePongRefreshesLiveness(t *testing.T) {
	const laptopID, peerID uint32 = 230204, 179172
	dA, dB := newDesyncPair(t, laptopID, peerID)
	a, b := dA.tunnels, dB.tunnels

	// The peer has been quiet past the silence threshold: the watchdog
	// probes it.
	stale := time.Now().Add(-2 * pathSilenceThreshold)
	a.kx.SetLastInboundDecryptForTest(peerID, stale)
	if err := a.SendPathProbe(peerID); err != nil {
		t.Fatalf("SendPathProbe: %v", err)
	}

	// The peer's real control handler answers, as every deployed version
	// does: pong.Src = probe.Dst.
	var probe *protocol.Packet
	deadline := time.After(desyncTestWait)
	for probe == nil {
		select {
		case in := <-b.RecvCh():
			if in.Packet.Protocol == protocol.ProtoControl && in.Packet.DstPort == protocol.PortPing {
				probe = in.Packet
			}
		case <-deadline:
			t.Fatal("peer never received the path probe")
		}
	}
	dB.handleControlPacket(probe)

	deadlineT := time.Now().Add(desyncTestWait)
	for time.Now().Before(deadlineT) {
		if last, ok := a.LastInboundDecrypt(peerID); ok && last.After(stale.Add(time.Minute)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("BUG: the peer's pong did not refresh inbound liveness (probe Dst=%d, so pong Src=%d): "+
		"the identity binding drops it as spoofed and the watchdog resets a healthy path",
		probe.Dst.Node, probe.Dst.Node)
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
