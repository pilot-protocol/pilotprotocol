// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// readyPeer installs a peer with a ready session whose last outbound send
// was long ago, so keepaliveSweep would normally refresh it.
func readyPeer(t *testing.T, tm *TunnelManager, nodeID uint32) {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peer listen: %v", err)
	}
	t.Cleanup(func() { sock.Close() })
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pc, err := tm.deriveSecret(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("deriveSecret: %v", err)
	}
	pc.Ready = true
	tm.mu.Lock()
	tm.peers[nodeID] = sock.LocalAddr().(*net.UDPAddr)
	tm.envelope.Install(nodeID, pc)
	tm.routing.RecordOutboundSend(nodeID, time.Now().Add(-time.Minute))
	tm.mu.Unlock()
}

func newEncryptedTunnel(t *testing.T) *TunnelManager {
	t.Helper()
	tm := NewTunnelManager()
	t.Cleanup(func() { tm.Close() })
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	tm.SetNodeID(0xAA000002)
	return tm
}

// Keepalives go to peers in use and to peers with an open connection, and
// not to peers nobody has used for longer than PeerIdleAfter.
func TestKeepaliveSweepSkipsIdlePeers(t *testing.T) {
	t.Parallel()
	tm := newEncryptedTunnel(t)

	const active, idle, idleOpenConn, untracked = 0xB1, 0xB2, 0xB3, 0xB4
	for _, id := range []uint32{active, idle, idleOpenConn, untracked} {
		readyPeer(t, tm, id)
	}
	now := time.Now()
	tm.activity.note(active, now.Add(-10*time.Second))
	tm.activity.note(idle, now.Add(-PeerIdleAfter-time.Minute))
	tm.activity.note(idleOpenConn, now.Add(-PeerIdleAfter-time.Minute))
	tm.SetOpenConnPeers(func() map[uint32]bool { return map[uint32]bool{idleOpenConn: true} })

	if sent := tm.keepaliveSweep(now); sent != 3 {
		t.Fatalf("keepalives sent = %d, want 3 (active, open connection, untracked; not the idle peer)", sent)
	}
	if last, _ := tm.routing.LastOutboundSend(idle); now.Sub(last) < 30*time.Second {
		t.Fatal("the idle peer was sent a keepalive")
	}
}

// Application traffic in either direction makes a peer active; path
// upkeep does not.
func TestOnlyApplicationTrafficCountsAsActivity(t *testing.T) {
	t.Parallel()
	tm := newEncryptedTunnel(t)
	const peer = 0xC1
	readyPeer(t, tm, peer)
	old := time.Now().Add(-PeerIdleAfter - time.Minute)
	tm.activity.note(peer, old)

	// Upkeep: a keepalive and a path probe must not refresh activity.
	tm.keepaliveSweep(time.Now())
	if err := tm.SendPathProbe(peer); err != nil {
		t.Fatalf("SendPathProbe: %v", err)
	}
	if last, _ := tm.activity.last(peer); !last.Equal(time.Unix(0, old.UnixNano())) {
		t.Fatal("keepalive or path probe counted as application activity")
	}
	if !tm.PeerIdle(peer) {
		t.Fatal("peer should be idle")
	}

	// Our pong to the peer's path probe is upkeep too: counting it made
	// every peer with a path watchdog active again 55 s after it went quiet.
	_ = tm.Send(peer, &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: 0xAA000002},
		Dst:      protocol.Addr{Node: peer},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Payload:  []byte("probe"),
	})
	if !tm.PeerIdle(peer) {
		t.Fatal("answering the peer's path probe counted as application activity")
	}

	// Application traffic: any packet sent through Send.
	_ = tm.Send(peer, &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 0xAA000002},
		Dst:      protocol.Addr{Node: peer},
		DstPort:  protocol.PortDataExchange,
	})
	if tm.PeerIdle(peer) {
		t.Fatal("sending application data did not make the peer active")
	}
}

// The path watchdog leaves idle peers alone: no probes, no resets.
func TestPathWatchSkipsIdlePeers(t *testing.T) {
	resets := swapPathResetForTest(t)
	const peer = 61
	d := newPathWatchTestDaemon(t, peer)
	// Long silent, and long unused.
	d.tunnels.kx.RecordInboundDecrypt(peer)
	states := map[uint32]*pathPeerState{}
	silentNow := time.Now().Add(2 * pathSilenceThreshold)
	d.tunnels.activity.note(peer, silentNow.Add(-PeerIdleAfter-time.Minute))

	for i := 0; i < pathProbeMax+3; i++ {
		d.pathWatchTick(states, silentNow.Add(time.Duration(i)*pathWatchTickInterval))
	}
	if len(*resets) != 0 {
		t.Fatalf("idle peer was reset %d times", len(*resets))
	}
	if st := states[peer]; st != nil && st.probesSent != 0 {
		t.Fatalf("idle peer was probed %d times", st.probesSent)
	}

	// The same peer in use is still watched.
	d.tunnels.activity.note(peer, silentNow)
	for i := 0; i < pathProbeMax+2; i++ {
		d.pathWatchTick(states, silentNow.Add(time.Duration(i)*pathWatchTickInterval))
	}
	if len(*resets) == 0 {
		t.Fatal("an active silent peer was not reset; the watchdog no longer works")
	}
}

// Once an idle peer gets no keepalives, the stale-peer reaper can drop it
// (keepalives used to count as contact and kept every peer forever). A
// peer still sending to us is kept, even when its frames come through the
// relay, which LastDirectRecv does not count.
func TestReaperDropsIdlePeersButKeepsTalkingOnes(t *testing.T) {
	const silent, talking = 71, 72
	d := newPathWatchTestDaemon(t, silent)
	d.ports = NewPortManager()
	d.tunnels.AddPeer(talking, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 8), Port: 4000})
	long := time.Now().Add(-10 * time.Minute)
	for _, id := range []uint32{silent, talking} {
		d.tunnels.routing.RecordOutboundSend(id, long)
		d.tunnels.routing.RecordDirectRecv(id, long)
	}
	d.tunnels.kx.RecordInboundDecrypt(talking) // a relayed frame just now

	d.reapStalePeers()
	if d.tunnels.HasPeer(silent) {
		t.Fatal("a peer silent for 10 minutes was not reaped")
	}
	if !d.tunnels.HasPeer(talking) {
		t.Fatal("a peer that just sent us a frame was reaped")
	}
}
