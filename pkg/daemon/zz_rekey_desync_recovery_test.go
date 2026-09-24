// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// Regression tests for the trigger of the 2026-09-23 rekey-desync loop
// (v1.13.9 laptop, node 230204; peers 16392, 242944 and 179172, all via
// relay).
//
// Every fresh process handshook with those peers within ~1s and then, ~90s
// later, the path watchdog reset them:
//
//	path watchdog: peer inbound-silent past probe budget — resetting path
//
// The peers were healthy. The watchdog reset them because nothing they sent
// was allowed to count as inbound liveness:
//
//  1. The path-watchdog probe had no Dst. Every deployed version answers a
//     ping with Src = ping.Dst, so the pong came back claiming node 0 and the
//     identity binding in handleEncrypted dropped it as "spoofed" BEFORE it
//     could refresh lastInboundDecrypt. Probes could never prove liveness.
//  2. Peers older than v1.12.1 send their NAT keepalive with a zero Src, so
//     those were dropped the same way. A quiet peer therefore looked
//     inbound-silent 55s after every handshake, and the watchdog reset it.
//
// These tests cover only those two triggers. What a reset does to the
// session afterwards is a separate change.

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
// side whose watchdog runs, with a fake registry that resolves the peer
// to its endpoint so resetPeerPath could run its full production sequence)
// and peer. Both have authenticated identities and have completed the
// initial handshake, like the first second of a fresh process in the
// incident.
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
	// Every deployed responder (v1.10.0–v1.13.9) answers with
	// pong.Src = probe.Dst, so the probe itself must name the peer.
	if probe.Dst.Node != peerID {
		t.Fatalf("BUG: probe Dst.Node = %d, want %d: a deployed peer's pong would claim node %d "+
			"and be dropped as spoofed", probe.Dst.Node, peerID, probe.Dst.Node)
	}
	// The peer's real control handler answers.
	dB.handleControlPacket(probe)

	deadlineT := time.Now().Add(desyncTestWait)
	for time.Now().Before(deadlineT) {
		if last, ok := a.LastInboundDecrypt(peerID); ok && last.After(stale.Add(time.Minute)) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("BUG: the peer's pong did not refresh inbound liveness: " +
		"the identity binding drops it as spoofed and the watchdog resets a healthy path")
}

// TestPongToLegacyPathProbeRefreshesProberLiveness is link 1 in a mixed
// fleet. A prober on v1.13.0–v1.13.9 still sends its path probe with no
// Dst, and its identity binding treats a pong (a frame with a payload)
// exactly as this build does. Our pong must name us anyway, or the prober
// drops it as spoofed and its watchdog resets our healthy path. A ping that
// does name a destination keeps getting that destination back unchanged.
func TestPongToLegacyPathProbeRefreshesProberLiveness(t *testing.T) {
	const laptopID, peerID uint32 = 230204, 179172
	dA, dB := newDesyncPair(t, laptopID, peerID)
	a, b := dA.tunnels, dB.tunnels
	answerPings(t, dB)
	// Keep the peer's own keepalive out of it, so only the pong can prove
	// the path.
	b.routing.RecordOutboundSend(laptopID, time.Now())

	// The prober's route loop is not running, so every pong that passes its
	// identity binding waits in its recvCh.
	nextPong := func() *protocol.Packet {
		t.Helper()
		deadline := time.After(desyncTestWait)
		for {
			select {
			case in := <-a.RecvCh():
				if in.Packet.Protocol == protocol.ProtoControl && in.Packet.HasFlag(protocol.FlagACK) {
					return in.Packet
				}
			case <-deadline:
				t.Fatal("BUG: no pong got past the prober's identity binding: a pong claiming " +
					"node 0 is dropped as spoofed, so a v1.13.0–v1.13.9 watchdog resets this healthy path")
			}
		}
	}

	stale := time.Now().Add(-2 * pathSilenceThreshold)
	a.kx.SetLastInboundDecryptForTest(peerID, stale)
	sendV1139PathProbe(t, a, peerID)
	pong := nextPong()
	if pong.Src.Node != peerID {
		t.Fatalf("pong Src.Node = %d, want %d (the responder)", pong.Src.Node, peerID)
	}
	if last, ok := a.LastInboundDecrypt(peerID); !ok || !last.After(stale.Add(time.Minute)) {
		t.Fatal("BUG: the pong to a v1.13.9 path probe did not refresh the prober's inbound liveness")
	}

	named := protocol.Addr{Network: 7, Node: peerID}
	dB.handleControlPacket(&protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: laptopID},
		Dst:      named,
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Payload:  []byte("named"),
	})
	if got := nextPong().Src; got != named {
		t.Fatalf("pong Src = %+v, want the ping's Dst %+v unchanged", got, named)
	}
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

// TestSpoofedSourceStillDroppedNextToLegacyKeepaliveExemption pins how
// narrow the legacy-keepalive exemption is. Only an authenticated, empty
// ProtoControl frame to PortPing with a zero Src gets past the identity
// binding. Every other frame whose Src disagrees with the authenticated
// peer, including one shaped exactly like a keepalive but naming another
// node, is still dropped as spoofed: no liveness, no PktsRecv, no
// delivery, and a security.src_spoofed event.
func TestSpoofedSourceStillDroppedNextToLegacyKeepaliveExemption(t *testing.T) {
	t.Parallel()
	const peerID uint32 = 16392
	from := mustUDPAddr(t, "127.0.0.1:5556")

	cases := []struct {
		name   string
		pkt    *protocol.Packet
		exempt bool
	}{
		{
			name:   "legacy zero-Src keepalive (control)",
			pkt:    &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing},
			exempt: true,
		},
		{
			name: "keepalive shape claiming another node",
			pkt: &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing,
				Src: protocol.Addr{Node: 0x99999999}},
		},
		{
			name: "zero Src ping with a payload",
			pkt: &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing,
				Payload: []byte("x")},
		},
		{
			name: "zero Src control frame to another port",
			pkt:  &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing + 1},
		},
		{
			name: "zero Src empty stream frame to the ping port",
			pkt: &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoStream, DstPort: protocol.PortPing,
				Flags: protocol.FlagSYN},
		},
		{
			name: "zero Src empty datagram to the ping port",
			pkt:  &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoDatagram, DstPort: protocol.PortPing},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tm := NewTunnelManager()
			if err := tm.EnableEncryption(); err != nil {
				t.Fatalf("EnableEncryption: %v", err)
			}
			bus := newInProcessBus(nil)
			tm.SetEventBus(bus)
			spoofEvents, unsub := bus.Subscribe("security.src_spoofed")
			defer unsub()
			peerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("peer keygen: %v", err)
			}
			pc, err := tm.deriveSecret(peerPriv.PublicKey().Bytes())
			if err != nil {
				t.Fatalf("deriveSecret: %v", err)
			}
			tm.envelope.Install(peerID, pc)

			tm.handleEncrypted(sealFromPeer(t, pc, peerID, 1, tc.pkt), from)

			_, live := tm.LastInboundDecrypt(peerID)
			recv := atomic.LoadUint64(&tm.PktsRecv)
			var spoofed bool
			select {
			case <-spoofEvents:
				spoofed = true
			default:
			}
			if tc.exempt {
				if !live || recv != 1 || spoofed {
					t.Fatalf("legacy keepalive: liveness=%v PktsRecv=%d src_spoofed=%v, want true/1/false",
						live, recv, spoofed)
				}
			} else if live || recv != 0 || !spoofed {
				t.Fatalf("BUG: exemption too wide, a spoofed frame got through: liveness=%v PktsRecv=%d "+
					"src_spoofed=%v, want false/0/true", live, recv, spoofed)
			}
			select {
			case in := <-tm.RecvCh():
				t.Fatalf("frame must never reach the application, got %+v", in.Packet)
			default:
			}
		})
	}
}

// answerPingsLikeV1139 answers pings the way every deployed handleControlPacket
// (v1.10.0–v1.13.9) does, with pong.Src = ping.Dst even when Dst is zero.
func answerPingsLikeV1139(t *testing.T, d *Daemon) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case in, ok := <-d.tunnels.RecvCh():
				if !ok {
					return
				}
				ping := in.Packet
				if ping.Protocol != protocol.ProtoControl || ping.DstPort != protocol.PortPing ||
					ping.HasFlag(protocol.FlagACK) {
					continue
				}
				d.tunnels.Send(ping.Src.Node, &protocol.Packet{
					Version:  protocol.Version,
					Flags:    protocol.FlagACK,
					Protocol: protocol.ProtoControl,
					Src:      ping.Dst,
					Dst:      ping.Src,
					SrcPort:  protocol.PortPing,
					DstPort:  ping.SrcPort,
					Seq:      ping.Seq,
					Ack:      ping.Seq + 1,
					Payload:  ping.Payload,
				})
			case <-done:
				return
			}
		}
	}()
}

// answerPings runs the peer's route loop, reduced to what matters here:
// this build's real control handler answers pings.
func answerPings(t *testing.T, d *Daemon) {
	t.Helper()
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case in, ok := <-d.tunnels.RecvCh():
				if !ok {
					return
				}
				if in.Packet.Protocol == protocol.ProtoControl {
					d.handleControlPacket(in.Packet)
				}
			case <-done:
				return
			}
		}
	}()
}

// sendV1120Keepalive sends one NAT keepalive from peer to toID exactly as
// a v1.12.0 daemon's keepaliveSweep does: over the established session,
// with no inner Src.
func sendV1120Keepalive(t *testing.T, peer *TunnelManager, toID uint32) {
	t.Helper()
	ka := &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoControl, DstPort: protocol.PortPing}
	sendOverSession(t, peer, toID, ka)
}

// sendV1139PathProbe sends a path probe from prober to toID exactly as
// SendPathProbe did in v1.13.0–v1.13.9: over the established session, with
// no Dst.
func sendV1139PathProbe(t *testing.T, prober *TunnelManager, toID uint32) {
	t.Helper()
	probe := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Src:      protocol.Addr{Node: prober.loadNodeID()},
		Payload:  pathProbePayload,
	}
	sendOverSession(t, prober, toID, probe)
}

// sendOverSession seals pkt under from's established session with toID and
// writes it to toID's endpoint, as the sending daemon's tunnel does.
func sendOverSession(t *testing.T, from *TunnelManager, toID uint32, pkt *protocol.Packet) {
	t.Helper()
	plaintext, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	pc := from.envelope.Get(toID)
	from.mu.RLock()
	addr := from.peers[toID]
	from.mu.RUnlock()
	if pc == nil || addr == nil {
		t.Fatalf("no session/endpoint for %d", toID)
	}
	if err := from.writeFrame(toID, addr, from.encryptFrame(pc, plaintext)); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
}

// waitForInboundAfter reports whether tm records an authenticated inbound
// frame from peerID newer than since, within desyncTestWait. It does not
// fail the test: callers assert on what the watchdog does next.
func waitForInboundAfter(tm *TunnelManager, peerID uint32, since time.Time) bool {
	deadline := time.Now().Add(desyncTestWait)
	for time.Now().Before(deadline) {
		if last, ok := tm.LastInboundDecrypt(peerID); ok && last.After(since) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// TestPathWatchdogDoesNotResetHealthyQuietPeer ties both fixes to the
// outcome that mattered in the incident: the path watchdog must never reach
// resetPeerPath for a healthy peer that is only quiet. Two real daemons
// over loopback; the peer answers pings either with this build's real
// handler or exactly as every deployed version does.
//
// Not parallel: swaps the package-level pathWatchResetPeer hook.
func TestPathWatchdogDoesNotResetHealthyQuietPeer(t *testing.T) {
	// A peer with nothing to send. It looks inbound-silent past the
	// threshold, so the watchdog probes it; its pong must clear the
	// suspicion before the probe budget runs out. The deployed responder
	// echoes the probe's Dst as the pong's Src, so it pins the probe fix on
	// its own; this build's responder would name itself anyway.
	for _, peer := range []struct {
		name   string
		answer func(*testing.T, *Daemon)
	}{
		{"current peer answers the probe", answerPings},
		{"v1.13.9 peer answers the probe", answerPingsLikeV1139},
	} {
		t.Run(peer.name, func(t *testing.T) {
			const laptopID, peerID uint32 = 230204, 179172
			dA, dB := newDesyncPair(t, laptopID, peerID)
			a, b := dA.tunnels, dB.tunnels
			resets := swapPathResetForTest(t)
			peer.answer(t, dB)
			// Keep the peer's own keepalive from firing during the test, so
			// only the pong can prove the path.
			b.routing.RecordOutboundSend(laptopID, time.Now())

			stale := time.Now().Add(-2 * pathSilenceThreshold)
			a.kx.SetLastInboundDecryptForTest(peerID, stale)

			st := &pathPeerState{}
			var actions []pathWatchAction
			for tick := 0; tick <= pathProbeMax; tick++ {
				act := dA.pathWatchPeer(peerID, st, time.Now())
				actions = append(actions, act)
				if act == pathActionProbe {
					waitForInboundAfter(a, peerID, stale)
				}
			}
			if len(*resets) != 0 {
				t.Fatalf("BUG: the watchdog reset a healthy peer that answered every probe (actions %v): "+
					"its pongs never counted as inbound liveness", actions)
			}
			if actions[0] != pathActionProbe || actions[len(actions)-1] != pathActionHealthy {
				t.Fatalf("actions = %v, want one probe and then healthy", actions)
			}
		})
	}

	// A v1.12.0 peer with nothing to send. Its only inbound is the zero-Src
	// keepalive every ~25s, which must keep it from ever looking silent: no
	// probe and no reset for the full probe budget.
	t.Run("v1.12.0 peer sending zero-Src keepalives", func(t *testing.T) {
		const laptopID, peerID uint32 = 230204, 242944
		dA, dB := newDesyncPair(t, laptopID, peerID)
		a, b := dA.tunnels, dB.tunnels
		resets := swapPathResetForTest(t)
		answerPingsLikeV1139(t, dB) // v1.12.0 answers pings the same way

		st := &pathPeerState{}
		var actions []pathWatchAction
		for tick := 0; tick <= pathProbeMax; tick++ {
			// Nothing counted since long ago, as main saw it once the peer's
			// keepalives were dropped; then the peer's next keepalive lands.
			stale := time.Now().Add(-2 * pathSilenceThreshold)
			a.kx.SetLastInboundDecryptForTest(peerID, stale)
			sendV1120Keepalive(t, b, laptopID)
			waitForInboundAfter(a, peerID, stale)
			actions = append(actions, dA.pathWatchPeer(peerID, st, time.Now()))
		}
		if len(*resets) != 0 {
			t.Fatalf("BUG: the watchdog reset a healthy v1.12.0 peer (actions %v): "+
				"its zero-Src keepalives and pongs never counted as inbound liveness", actions)
		}
		for i, act := range actions {
			if act != pathActionHealthy {
				t.Fatalf("tick %d action = %q (all %v), want healthy on every tick: "+
					"the peer's zero-Src keepalive did not count as inbound liveness", i, act, actions)
			}
		}
	})
}
