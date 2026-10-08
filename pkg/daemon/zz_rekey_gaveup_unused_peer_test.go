// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// A peer nobody uses is not reset when its rekey gives up: the reset's own
// key exchange, never answered by a peer that went away, ended in another
// give-up, and its frames kept the reaper from ever dropping the peer.
// A peer in use still is (TestOnRekeyGaveUpResetsWithCooldown).
func TestRekeyGaveUpLeavesUnusedPeerToReaper(t *testing.T) {
	var resets atomic.Int32
	prev := gaveUpResetPeer
	gaveUpResetPeer = func(_ *Daemon, _ uint32) peerPathReset {
		resets.Add(1)
		return peerPathReset{}
	}
	t.Cleanup(func() { gaveUpResetPeer = prev })

	d := churnDaemon(t)
	d.lastGaveUpReset = make(map[uint32]time.Time)
	const unknown, idle = 0x00400001, 0x00400002
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4000}
	d.tunnels.AddPeer(unknown, addr) // only ever sent a key request
	d.tunnels.AddPeer(idle, addr)
	d.tunnels.activity.note(idle, time.Now().Add(-PeerIdleAfter-time.Minute))

	d.onRekeyGaveUp(unknown)
	d.onRekeyGaveUp(idle)
	time.Sleep(100 * time.Millisecond) // a reset would run in a goroutine
	if n := resets.Load(); n != 0 {
		t.Fatalf("%d path resets for peers nobody uses; want none", n)
	}

	// With nothing sent to them any more, the reaper drops both.
	long := time.Now().Add(-10 * time.Minute)
	for _, id := range []uint32{unknown, idle} {
		d.tunnels.routing.RecordOutboundSend(id, long)
	}
	d.reapStalePeers()
	if d.tunnels.HasPeer(unknown) || d.tunnels.HasPeer(idle) {
		t.Fatal("unused peers were not reaped once nothing was sent to them")
	}
}

// A path reset re-keys a peer; it keeps the record of when the peer was
// last used. Losing it made every reset peer look unused (or, to the
// keepalive and upgrade loops, untracked and therefore active).
func TestResetPeerPathKeepsActivity(t *testing.T) {
	const peer = 48
	d := newPathWatchTestDaemon(t, peer)
	used := time.Now().Add(-30 * time.Second)
	d.tunnels.activity.note(peer, used)

	d.resetPeerPath(peer)

	last, ok := d.tunnels.activity.last(peer)
	if !ok || !last.Equal(time.Unix(0, used.UnixNano())) {
		t.Fatalf("activity after reset = %v, %v; want %v", last, ok, used)
	}
}
