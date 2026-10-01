// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
)

// TestConcurrentDialBurstToOnePeer opens a burst of connections from one
// node to one peer at the same instant — what N parallel `pilotctl
// send-message` to the same destination do. Every dial is legitimate and the
// peer is idle, so every dial must complete, and quickly. When the peer's
// per-source SYN bucket held only 10 tokens it silently dropped the excess
// SYNs; the dialers retransmitted in lock-step (250ms doubling), each wave
// found at most 10 tokens, and a burst of 64 took 9 s with dials timing out.
func TestConcurrentDialBurstToOnePeer(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	for _, burst := range []int{16, 64} {
		var failed atomic.Int32
		var slowest atomic.Int64
		var wg sync.WaitGroup
		start := time.Now()
		for i := 0; i < burst; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				// One IPC client per dial, like separate pilotctl processes:
				// a single Driver runs one request at a time.
				drv, err := driver.Connect(a.SocketPath)
				if err != nil {
					failed.Add(1)
					return
				}
				defer drv.Close()
				conn, err := drv.DialAddr(b.Daemon.Addr(), protocol.PortEcho)
				if err != nil {
					failed.Add(1)
					return
				}
				for d := int64(time.Since(start)); ; {
					old := slowest.Load()
					if d <= old || slowest.CompareAndSwap(old, d) {
						break
					}
				}
				conn.Close()
			}()
		}
		wg.Wait()
		t.Logf("burst=%d failed=%d slowest_success=%s total=%s", burst, failed.Load(),
			time.Duration(slowest.Load()).Truncate(time.Millisecond), time.Since(start).Truncate(time.Millisecond))
		if n := failed.Load(); n != 0 {
			t.Errorf("burst of %d dials to one idle peer: %d failed", burst, n)
		}
		if s := time.Duration(slowest.Load()); s > 2*time.Second {
			t.Errorf("burst of %d dials to one idle peer: slowest successful dial took %s", burst, s.Truncate(time.Millisecond))
		}
		time.Sleep(2 * time.Second) // let the peer's bucket refill between bursts
	}
}
