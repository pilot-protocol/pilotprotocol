// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/ecdh"
	"crypto/rand"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// churnDaemon is the part of a daemon that holds per-peer state: an
// encrypted tunnel on a real socket, and a port table for the reaper's
// open-connection check.
func churnDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{
		tunnels:   newEncryptedTunnel(t),
		ports:     NewPortManager(),
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
	d.tunnels.SetOpenConnPeers(d.ports.ActiveNodeIDs)
	return d
}

// addChurnPeer gives the daemon a peer the way a client's first request
// does: a key exchange (a real AES-GCM session) and some application
// traffic. Its frames go to sink, which nobody reads.
func addChurnPeer(t *testing.T, d *Daemon, nodeID uint32, sink *net.UDPAddr) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := d.tunnels.deriveSecret(priv.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	pc.Ready = true
	pc.Authenticated = true
	d.tunnels.AddPeer(nodeID, sink)
	d.tunnels.envelope.Install(nodeID, pc)
	d.tunnels.noteAppActivity(nodeID) // as onKeyInstalled does for a new session
	d.tunnels.kx.RecordInboundDecrypt(nodeID)
	_ = d.tunnels.Send(nodeID, &protocol.Packet{ // the reply
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: 0xAA000002},
		Dst:      protocol.Addr{Node: nodeID},
		DstPort:  protocol.PortDataExchange,
		Payload:  []byte("reply"),
	})
}

// ageChurnPeer moves a peer's clocks back as if it had used the daemon long
// ago and nothing had been sent either way since: the daemon's own
// periodic jobs decide what happens next.
func ageChurnPeer(d *Daemon, nodeID uint32, ago time.Time) {
	d.tunnels.activity.note(nodeID, ago)
	d.tunnels.routing.RecordOutboundSend(nodeID, ago)
	d.tunnels.routing.RecordDirectRecv(nodeID, ago)
	d.tunnels.kx.SetLastInboundDecryptForTest(nodeID, ago)
}

func totalEntries(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// churnRounds runs the service-agent workload that grew the fleet's
// daemons from ~26 MB to ~330 MB: every round perRound new clients make one
// request each and go quiet. Between rounds, time passes — every earlier
// client has been quiet for longer than PeerIdleAfter plus the reaper's
// five minutes — and the daemon runs its periodic jobs as idleSweepLoop
// and keepaliveLoop do: the NAT keepalive sweep, then the stale-peer
// reaper, then the pending-queue sweep. It returns the per-peer table
// sizes and the live heap after each round.
func churnRounds(t *testing.T, rounds, perRound int) (peers []int, entries []int, heap []uint64) {
	t.Helper()
	d := churnDaemon(t)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	sinkAddr := sink.LocalAddr().(*net.UDPAddr)

	var ids []uint32
	next := uint32(0x00100000)
	for r := 0; r < rounds; r++ {
		longAgo := time.Now().Add(-(PeerIdleAfter + 6*time.Minute))
		for _, id := range ids {
			if d.tunnels.HasPeer(id) {
				ageChurnPeer(d, id, longAgo)
			}
		}
		for i := 0; i < perRound; i++ {
			next++
			addChurnPeer(t, d, next, sinkAddr)
			ids = append(ids, next)
		}
		now := time.Now()
		d.tunnels.keepaliveSweep(now)
		d.reapStalePeers()
		d.tunnels.reapStalePending(now)

		sizes := d.tunnels.peerStateEntries()
		peers = append(peers, sizes["peers"])
		entries = append(entries, totalEntries(sizes))
		heap = append(heap, liveHeap())
	}
	return peers, entries, heap
}

// Per-peer state stays at about one round of clients however many rounds
// run. Before the idle-peer change the NAT keepalive refreshed every
// peer's last contact, the stale-peer reaper never fired, and the tables
// (and the heap) grew by a round's worth every round; the control below
// runs that behaviour and must show the growth, so this test fails if
// the reaper stops firing again.
func TestPeerChurnStateStaysBounded(t *testing.T) {
	// Not parallel: PeerIdleAfter is package state.
	const rounds, perRound = 12, 400

	t.Run("idle peers are reaped", func(t *testing.T) {
		peers, entries, heap := churnRounds(t, rounds, perRound)
		t.Logf("peers per round: %v", peers)
		t.Logf("per-peer table entries per round: %v", entries)
		t.Logf("live heap per round (KB): %v", heapKB(heap))
		for r, n := range peers {
			if n > perRound {
				t.Fatalf("round %d: %d peers held, want at most the %d of the latest round", r, n, perRound)
			}
		}
		// Every table drops back with its peers: the last round holds no
		// more entries than the first did.
		if last, first := entries[len(entries)-1], entries[0]; last > first+first/10 {
			t.Fatalf("per-peer tables grew from %d to %d entries across %d rounds of churn", first, last, rounds)
		}
		// The heap stays flat too: well under what the peers reaped since
		// round 2 would cost if they were still held (a few KB each).
		if grew := int64(heap[len(heap)-1]) - int64(heap[1]); grew > int64(perRound)*1024 {
			t.Fatalf("live heap grew by %d KB over %d rounds; the peers are reaped, so it should be flat", grew/1024, rounds-2)
		}
	})

	t.Run("control: upkeep forever keeps every peer", func(t *testing.T) {
		prev := PeerIdleAfter
		PeerIdleAfter = 0 // no peer is ever idle: the keepalive behaviour before the change
		t.Cleanup(func() { PeerIdleAfter = prev })
		peers, _, heap := churnRounds(t, rounds, perRound)
		t.Logf("peers per round: %v", peers)
		t.Logf("live heap per round (KB): %v", heapKB(heap))
		if got, want := peers[len(peers)-1], rounds*perRound; got != want {
			t.Fatalf("with keepalives to every peer, %d peers held after %d rounds; want all %d (the reaper must not fire)", got, rounds, want)
		}
	})
}

func heapKB(h []uint64) []uint64 {
	out := make([]uint64, len(h))
	for i, v := range h {
		out[i] = v / 1024
	}
	return out
}

// A queue of frames waiting for a key exchange the peer never answers is
// dropped after pendingMaxAge, and when the reaper forgets the peer.
// Before, it stayed until the daemon exited: dead peers filled all
// maxPendingPeers slots and every first send to a new peer then failed
// with "too many pending key exchanges".
func TestPendingQueueForSilentPeerDoesNotOutliveIt(t *testing.T) {
	t.Parallel()
	tm := newEncryptedTunnel(t)
	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sink.Close() })
	addr := sink.LocalAddr().(*net.UDPAddr)

	syn := func(nodeID uint32) error {
		return tm.Send(nodeID, &protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagSYN,
			Protocol: protocol.ProtoStream,
			Src:      protocol.Addr{Node: 0xAA000002},
			Dst:      protocol.Addr{Node: nodeID},
			DstPort:  protocol.PortDataExchange,
		})
	}
	// Fill every pending slot with peers that will never answer.
	for i := uint32(0); i < maxPendingPeers; i++ {
		tm.AddPeer(0x00200000+i, addr)
		if err := syn(0x00200000 + i); err != nil {
			t.Fatalf("queueing for dead peer %d: %v", i, err)
		}
	}
	const fresh = 0x00300000
	tm.AddPeer(fresh, addr)
	if err := syn(fresh); err == nil {
		t.Fatal("expected the pending table to be full")
	}

	// Within pendingMaxAge nothing is dropped.
	if n := tm.reapStalePending(time.Now()); n != 0 {
		t.Fatalf("dropped %d queues before they were stale", n)
	}
	// Past it, the dead peers' queues go and a new peer can be reached.
	if n := tm.reapStalePending(time.Now().Add(pendingMaxAge + time.Second)); n != maxPendingPeers {
		t.Fatalf("dropped %d stale queues, want %d", n, maxPendingPeers)
	}
	if err := syn(fresh); err != nil {
		t.Fatalf("send to a new peer after the sweep: %v", err)
	}
	if got := tm.peerStateEntries()["pending"]; got != 2 { // one queue: pending + pendingSince
		t.Fatalf("pending entries = %d, want only the new peer's", got)
	}

	// Forgetting a peer drops its queue at once.
	d := &Daemon{tunnels: tm}
	d.forgetPeer(fresh)
	if got := tm.peerStateEntries()["pending"]; got != 0 {
		t.Fatalf("pending entries after forgetPeer = %d, want 0", got)
	}
	if tm.HasPeer(fresh) {
		t.Fatal("forgetPeer left the tunnel entry")
	}
}

// Per-peer state for a node with no tunnel entry is reaped too: a path
// reset that cannot re-resolve its peer leaves the relay flag it restored
// (and whatever else the peer had), which the loop over tunnel peers never
// visits. State with recent contact stays; state with none recorded gets
// peerReapIdleTimeout from when the sweep first finds it.
func TestReaperForgetsOrphanedPeerState(t *testing.T) {
	d := churnDaemon(t)
	now := time.Now()
	const flagOnly, longQuiet, recent = 0x00500001, 0x00500002, 0x00500003
	d.tunnels.SetRelayPeer(flagOnly, true) // what a failed path reset leaves
	d.tunnels.SetRelayPeer(longQuiet, true)
	d.tunnels.routing.RecordOutboundSend(longQuiet, now.Add(-10*time.Minute))
	d.tunnels.kx.SetLastInboundDecryptForTest(longQuiet, now.Add(-10*time.Minute))
	d.tunnels.routing.RecordOutboundSend(recent, now)

	d.reapStalePeers()
	if d.tunnels.IsRelayPeer(longQuiet) {
		t.Fatal("state for a node with no tunnel, quiet for 10 minutes, was kept")
	}
	if _, ok := d.tunnels.LastInboundDecrypt(longQuiet); ok {
		t.Fatal("key-exchange state for the quiet orphan was kept")
	}
	if !d.tunnels.IsRelayPeer(flagOnly) {
		t.Fatal("an orphan with no recorded contact was dropped the first time it was seen")
	}
	if _, ok := d.tunnels.LastOutboundSend(recent); !ok {
		t.Fatal("state with contact just now was dropped")
	}

	// peerReapIdleTimeout after it was first seen, the flag-only orphan goes.
	d.orphanSeen[flagOnly] = now.Add(-peerReapIdleTimeout - time.Second)
	d.reapStalePeers()
	if d.tunnels.IsRelayPeer(flagOnly) {
		t.Fatal("an orphaned relay flag outlived peerReapIdleTimeout")
	}
	if ids := d.tunnels.routing.PeerIDs(); len(ids) != 1 || ids[0] != recent {
		t.Fatalf("routing holds state for %v, want only the recent node %d", ids, recent)
	}
	if len(d.orphanSeen) != 0 {
		t.Fatalf("orphanSeen still holds %d entries", len(d.orphanSeen))
	}
}
