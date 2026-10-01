// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestPerSourceSYNBucketBurstAndRefill pins the per-source bucket: a fresh
// source may send perSourceSYNBurst SYNs at once, is then held to
// perSourceSYNLimit per second, and never banks more than the burst.
func TestPerSourceSYNBucketBurstAndRefill(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	const src uint32 = 7

	take := func() int {
		n := 0
		for i := 0; i < 2*perSourceSYNBurst; i++ {
			if d.allowSYNFromSource(src) {
				n++
			}
		}
		return n
	}
	rewind := func(by time.Duration) {
		d.perSrcSYNMu.Lock()
		d.perSrcSYN[src].lastFill = time.Now().Add(-by)
		d.perSrcSYNMu.Unlock()
	}

	if got := take(); got != perSourceSYNBurst {
		t.Fatalf("initial burst: %d SYNs allowed, want %d", got, perSourceSYNBurst)
	}
	rewind(time.Second)
	if got := take(); got != perSourceSYNLimit {
		t.Fatalf("after 1s: %d SYNs allowed, want %d", got, perSourceSYNLimit)
	}
	rewind(time.Hour)
	if got := take(); got != perSourceSYNBurst {
		t.Fatalf("after a long idle: %d SYNs allowed, want %d (capacity)", got, perSourceSYNBurst)
	}
}

// TestRejectedSourceDoesNotSpendGlobalSYNTokens floods SYNs from one source
// past its per-source limit and checks the shared bucket was charged only
// for the SYNs that were admitted. With the global bucket charged first,
// every SYN the per-source limiter went on to reject still took a shared
// token, so one source could starve every other peer.
func TestRejectedSourceDoesNotSpendGlobalSYNTokens(t *testing.T) {
	t.Parallel()
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD0061)
	if _, err := d.ports.Bind(9090); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	t.Cleanup(func() { d.ports.Unbind(9090) })

	// Freeze the shared bucket's refill so the count below is exact.
	d.synMu.Lock()
	d.synLastFill = time.Now().Add(time.Hour)
	before := d.synTokens
	d.synMu.Unlock()

	const flood = perSourceSYNBurst + 200
	for i := 0; i < flood; i++ {
		d.handleStreamPacket(&protocol.Packet{
			Version:  protocol.Version,
			Flags:    protocol.FlagSYN,
			Protocol: protocol.ProtoStream,
			Src:      protocol.Addr{Network: 0, Node: peerNode},
			Dst:      protocol.Addr{Network: 0, Node: d.NodeID()},
			SrcPort:  uint16(40000 + i),
			DstPort:  9090,
			Seq:      100,
			Window:   256,
		})
	}

	d.synMu.Lock()
	spent := before - d.synTokens
	d.synMu.Unlock()
	if spent != perSourceSYNBurst {
		t.Fatalf("%d SYNs from one source spent %d shared tokens, want %d (only the admitted ones)", flood, spent, perSourceSYNBurst)
	}
}
