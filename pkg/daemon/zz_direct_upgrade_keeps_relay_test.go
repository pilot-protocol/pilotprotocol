// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"
)

// A peer whose direct path went silent is flipped to the relay and
// pinned there. relayProbeLoop then calls tryDirectUpgrade every
// RelayProbeInterval to give direct another chance. It has to unpin the
// peer for that, and it used SetRelayPeerPinned(id, false), which clears
// the relay flag as well. The peer was back on its dead direct path within
// 15 s of every flip and stayed there until three more silent sends
// tripped the blackhole heuristic again.
//
// Seen live on 2026-10-01 against a peer whose registry endpoint was
// stale: "direct path silent, flipping to relay" every ~90 s for over
// half an hour, with no "relay→direct auto-cleared" between the flips.
func TestDirectUpgradeUnpinsWithoutLeavingTheRelay(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peer uint32 = 0x0002BBE4
	peerConn := addPeerOnDaemon(t, d, peer)
	t.Cleanup(func() { peerConn.Close() })

	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	t.Cleanup(func() { beacon.Close() })
	if err := d.tunnels.SetBeaconAddr(beacon.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}

	// The registry says the peer is directly reachable (not relay-only),
	// so tryDirectUpgrade goes ahead without a registry round trip.
	d.cacheResolve(peer, map[string]interface{}{
		"real_addr": peerConn.LocalAddr().String(),
	})

	// State after a blackhole flip: on the relay, pinned.
	d.tunnels.SetRelayPeerPinned(peer, true)

	d.tryDirectUpgrade(peer)

	if d.tunnels.IsRelayPinned(peer) {
		t.Fatal("pin must be cleared so a working direct path can win")
	}
	if !d.tunnels.IsRelayPeer(peer) {
		t.Fatal("peer left the relay before any direct packet arrived from it")
	}

	// The upgrade itself still works: direct packets from the peer move it
	// back, and only they do.
	from := peerConn.LocalAddr().(*net.UDPAddr)
	for i := 1; i < directClearsRequired; i++ {
		if d.tunnels.routing.ClearRelayOnDirect(peer, from) {
			t.Fatalf("relay cleared after %d direct packets, want %d", i, directClearsRequired)
		}
	}
	if !d.tunnels.routing.ClearRelayOnDirect(peer, from) {
		t.Fatalf("relay not cleared after %d direct packets", directClearsRequired)
	}
	if d.tunnels.IsRelayPeer(peer) {
		t.Fatal("peer still on the relay after the direct path was confirmed")
	}
}

// The blackhole heuristic and the probe loop must not fight. With the
// direct path dead, one flip keeps the peer on the relay across any
// number of probe ticks; writes do not flip it again.
func TestBlackholedPeerStaysOnRelayAcrossProbeTicks(t *testing.T) {
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peer uint32 = 0x0002BBE5
	peerConn := addPeerOnDaemon(t, d, peer)
	t.Cleanup(func() { peerConn.Close() })

	beacon, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("beacon listen: %v", err)
	}
	t.Cleanup(func() { beacon.Close() })
	if err := d.tunnels.SetBeaconAddr(beacon.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}
	d.cacheResolve(peer, map[string]interface{}{
		"real_addr": peerConn.LocalAddr().String(),
	})

	// Nothing has come from the peer directly for a long time.
	d.tunnels.routing.RecordDirectRecv(peer, time.Now().Add(-10*time.Minute))
	addr := peerConn.LocalAddr().(*net.UDPAddr)
	frame := []byte("PILS-not-a-real-frame")

	flips := 0
	write := func() {
		was := d.tunnels.IsRelayPeer(peer)
		_ = d.tunnels.writeFrame(peer, addr, frame)
		if !was && d.tunnels.IsRelayPeer(peer) {
			flips++
		}
	}

	for i := 0; i < blackholeMissesRequired; i++ {
		write()
	}
	if flips != 1 || !d.tunnels.IsRelayPeer(peer) {
		t.Fatalf("setup: want one flip to the relay after %d silent sends, got %d (relay=%v)",
			blackholeMissesRequired, flips, d.tunnels.IsRelayPeer(peer))
	}

	for tick := 0; tick < 3; tick++ {
		d.tryDirectUpgrade(peer)
		for i := 0; i < blackholeMissesRequired+1; i++ {
			write()
		}
	}
	if flips != 1 {
		t.Fatalf("peer flipped to the relay %d times; the probe loop keeps putting it back on the dead direct path", flips)
	}
	if !d.tunnels.IsRelayPeer(peer) {
		t.Fatal("peer is not on the relay although its direct path never answered")
	}
}
