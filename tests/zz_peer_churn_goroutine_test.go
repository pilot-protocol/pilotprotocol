// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"context"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestPeerChurnDoesNotLeakGoroutines is the running-daemon counterpart of
// TestDaemonShutdownStopsGoroutines: one long-lived daemon talks to a
// stream of short-lived peers, each of which then goes away for good, and
// the goroutine count must not grow with the number of peers it has seen.
//
// Every round starts a peer, opens a stream to its echo port and
// round-trips a message, exchanges datagrams both ways, closes the stream
// and stops the peer (drivers, plugins, daemon). A goroutine per peer or
// per connection that outlived its peer (a retx loop, a keepalive or
// per-peer timer, a dial left pending) would add up round after round.
// The baseline is taken after a warm-up round, so goroutines the
// long-lived daemon starts lazily on first contact are not counted.
func TestPeerChurnDoesNotLeakGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("requires full daemon lifecycle")
	}
	const rounds = 8

	env := NewTestEnv(t)
	// A short TIME_WAIT so a closed stream's state is gone before the count.
	a := env.AddDaemon(func(c *daemon.Config) { c.TimeWaitDuration = 100 * time.Millisecond })

	round := func(i int) {
		t.Helper()
		b := env.AddDaemon()
		bIdx := len(env.daemons) - 1

		conn, err := a.Driver.DialAddrTimeout(b.Daemon.Addr(), protocol.PortEcho, 10*time.Second)
		if err != nil {
			t.Fatalf("round %d: dial echo: %v", i, err)
		}
		msg := []byte("churn")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("round %d: write: %v", i, err)
		}
		got := make([]byte, len(msg))
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("round %d: read echo: %v", i, err)
		}
		_ = conn.Close()
		for j := 0; j < 3; j++ {
			_ = a.Daemon.SendDatagram(b.Daemon.Addr(), protocol.PortEcho, []byte("ping"))
			_ = b.Daemon.SendDatagram(a.Daemon.Addr(), protocol.PortEcho, []byte("pong"))
		}
		time.Sleep(100 * time.Millisecond)

		stopPeer(t, env, bIdx)
	}

	settle := func() int {
		time.Sleep(500 * time.Millisecond) // TIME_WAIT (100ms) + FIN handling
		runtime.GC()
		return runtime.NumGoroutine()
	}

	round(0)
	baseline := settle()
	t.Logf("baseline after warm-up round: %d goroutines", baseline)

	for i := 1; i <= rounds; i++ {
		round(i)
	}

	// Allow stragglers (plugin HTTP clients, ticker drains) to exit, as
	// TestDaemonShutdownStopsGoroutines does. A per-peer leak of even one
	// goroutine shows as >= rounds over baseline and trips the bound.
	const slack = rounds / 2
	deadline := time.Now().Add(10 * time.Second)
	var final int
	for {
		final = settle()
		if final <= baseline+slack || time.Now().After(deadline) {
			break
		}
	}
	t.Logf("after %d more peers: %d goroutines (delta %d)", rounds, final, final-baseline)
	if final > baseline+slack {
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("goroutines grew with peer churn: baseline=%d final=%d after %d peers\n%s",
			baseline, final, rounds, buf[:n])
	}
}

// stopPeer shuts down env's daemon idx the way env.Close does (driver,
// plugins, daemon). It stays in env's lists, so the next AddDaemon gets a
// fresh index and with it a fresh identity (a reused index would reload
// this peer's identity file and come back as the same node); env.Close
// stopping it again is a no-op.
func stopPeer(t *testing.T, env *TestEnv, idx int) {
	t.Helper()
	_ = env.drivers[idx].Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := env.runtimes[idx].StopPlugins(ctx); err != nil {
		t.Logf("peer %d plugin shutdown: %v", idx, err)
	}
	cancel()
	_ = env.daemons[idx].Stop()
}
