// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// dialTimeoutBurst runs dialWedgeThreshold concurrent dials to one peer that
// never completes a handshake and returns the daemon once every dial has
// spent its full retry budget. during, if set, runs one second into the
// dials.
func dialTimeoutBurst(t *testing.T, before, during func(d *Daemon, peerNode uint32)) *Daemon {
	t.Helper()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xCAFEBABE
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0x33330000)
	if before != nil {
		before(d, peerNode)
	}

	dst := protocol.Addr{Network: 0, Node: peerNode}
	var wg sync.WaitGroup
	for i := 0; i < dialWedgeThreshold; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := d.DialConnectionContext(context.Background(), dst, 1001); !errors.Is(err, protocol.ErrDialTimeout) {
				t.Errorf("dial: err = %v, want ErrDialTimeout", err)
			}
		}()
	}
	if during != nil {
		time.Sleep(time.Second)
		during(d, peerNode)
	}
	wg.Wait()
	return d
}

// TestRxWatchdogDialTimeoutsToAnsweringPeerAreNotAWedge: a burst of dials to
// ONE peer times out while that peer is demonstrably reachable — the tunnel
// keeps decrypting packets from it (it answered the dials that got through
// its SYN limiter and dropped the rest). That says something about the peer,
// not about this node's transport, so the watchdog must not start its
// recovery (beacon + registry re-registration, escalating to a process
// exit). Before the fix every such timeout bumped the global
// consecutiveDialTimeouts and four of them tripped "outbound-dial-wedged".
func TestRxWatchdogDialTimeoutsToAnsweringPeerAreNotAWedge(t *testing.T) {
	if testing.Short() {
		t.Skip("long retry-budget test")
	}
	t.Parallel()

	now := time.Now()
	d := dialTimeoutBurst(t, nil, func(d *Daemon, peerNode uint32) {
		d.tunnels.kx.RecordInboundDecrypt(peerNode)
	})
	if c := d.consecutiveDialTimeouts.Load(); c != 0 {
		t.Errorf("consecutiveDialTimeouts = %d after timeouts to a peer heard from during the dials, want 0", c)
	}

	st := &rxWatchdogState{lastProgress: now, recvSeen: atomic.LoadUint64(&d.tunnels.PktsRecv)}
	atomic.AddUint64(&d.tunnels.PktsRecv, 25)
	if got := d.rxWatchdogTick(st, now.Add(rxWatchdogTickInterval)); got != rxActionProgress {
		t.Fatalf("dial timeouts to an answering peer: action = %q, want %q", got, rxActionProgress)
	}
}

// TestRxWatchdogDialTimeoutsToSilentPeerStillCount keeps the partial-wedge
// detector (2026-07-15) intact: when nothing arrived from the peer during
// the dials — a decrypt from before they started is not evidence — every
// timeout counts and the watchdog recovers even though rx is trickling.
func TestRxWatchdogDialTimeoutsToSilentPeerStillCount(t *testing.T) {
	if testing.Short() {
		t.Skip("long retry-budget test")
	}
	t.Parallel()

	now := time.Now()
	d := dialTimeoutBurst(t, func(d *Daemon, peerNode uint32) {
		d.tunnels.kx.SetLastInboundDecryptForTest(peerNode, time.Now().Add(-time.Minute))
	}, nil)
	if c := d.consecutiveDialTimeouts.Load(); c != dialWedgeThreshold {
		t.Fatalf("consecutiveDialTimeouts = %d after timeouts to a silent peer, want %d", c, dialWedgeThreshold)
	}

	st := &rxWatchdogState{lastProgress: now, recvSeen: atomic.LoadUint64(&d.tunnels.PktsRecv)}
	atomic.AddUint64(&d.tunnels.PktsRecv, 3) // keepalive trickle from other peers
	if got := d.rxWatchdogTick(st, now.Add(rxWatchdogTickInterval)); got != rxActionSoftRecover {
		t.Fatalf("dial timeouts to a silent peer: action = %q, want %q", got, rxActionSoftRecover)
	}
}
