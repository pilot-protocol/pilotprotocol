// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestRelayedHandshakeCompletesInSeconds runs a manual trust handshake
// between two private nodes. Neither can resolve the other before trust
// exists, so the request and the approval both travel through the registry
// and each side only learns of them by polling. With one poll per keepalive
// interval (60s) the request reached the target after up to a minute and
// the approval took up to another minute to come back.
//
// The request must be visible as soon as the target's operator asks for
// pending requests, and the approval must reach the requester within a few
// fast-poll periods, without anyone prodding the requester. The thresholds
// are far below one poll interval and far above the 2s fast-poll period.
func TestRelayedHandshakeCompletesInSeconds(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	private := func(c *daemon.Config) { c.Public = false }
	a := env.AddDaemon(private)
	b := env.AddDaemon(private)
	const limit = 20 * time.Second

	start := time.Now()
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "relay latency test"); err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Target side: the operator asks what is pending.
	seen := false
	for time.Since(start) < limit && !seen {
		pending, err := b.Driver.PendingHandshakes()
		if err != nil {
			t.Fatalf("pending: %v", err)
		}
		for _, p := range asList(pending["pending"]) {
			if rec, ok := p.(map[string]interface{}); ok && uint32(rec["node_id"].(float64)) == a.Daemon.NodeID() {
				seen = true
			}
		}
		if !seen {
			time.Sleep(200 * time.Millisecond)
		}
	}
	requestLatency := time.Since(start)
	if !seen {
		t.Fatalf("relayed request not in the target's pending list after %s", limit)
	}

	approved := time.Now()
	if _, err := b.Driver.ApproveHandshake(a.Daemon.NodeID()); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Requester side: nobody asks it anything. In this harness both nodes
	// sit on loopback, so once the target has approved it can usually reach
	// the requester directly and the approval arrives that way, with the
	// requester's fast poll as the fallback. The fast poll on its own is
	// exercised by the scheduler tests in pkg/daemon and was measured
	// between containers that cannot reach each other directly.
	for !a.Daemon.HandshakeService().IsTrusted(b.Daemon.NodeID()) {
		if time.Since(approved) > limit {
			t.Fatalf("relayed approval did not reach the requester within %s", limit)
		}
		time.Sleep(100 * time.Millisecond)
	}
	approvalLatency := time.Since(approved)
	t.Logf("request visible after %s, approval received after %s; registry polls: requester %d, target %d",
		requestLatency.Truncate(time.Millisecond), approvalLatency.Truncate(time.Millisecond),
		a.Daemon.RelayedHandshakePolls(), b.Daemon.RelayedHandshakePolls())

	// Bounded cost: the target polled only when asked (at most one per
	// 2s), the requester only at the fast-poll period while it waited.
	elapsed := time.Since(start)
	if max := uint64(elapsed/time.Second) + 2; a.Daemon.RelayedHandshakePolls() > max || b.Daemon.RelayedHandshakePolls() > max {
		t.Errorf("too many registry polls in %s: requester %d, target %d (max %d each)",
			elapsed.Truncate(time.Millisecond), a.Daemon.RelayedHandshakePolls(), b.Daemon.RelayedHandshakePolls(), max)
	}

	// Once trusted, the requester stops polling fast.
	settled := a.Daemon.RelayedHandshakePolls()
	time.Sleep(3 * time.Second)
	if got := a.Daemon.RelayedHandshakePolls(); got > settled+1 {
		t.Errorf("requester kept fast-polling after trust: %d polls in 3s", got-settled)
	}
}

func asList(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
}

// TestRelayedHandshakeReachesUnattendedTarget: nobody asks the target
// anything. The registry has the beacon prompt it, and it polls at once
// instead of at its next once-a-minute tick. The relayed approval reaches
// the requester the same way.
func TestRelayedHandshakeReachesUnattendedTarget(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)
	if !env.HandshakeNotify {
		t.Skip("needs a registry and beacon with the handshake notify hook (rendezvous SetHandshakeNotifier, beacon NotifyNode)")
	}

	private := func(c *daemon.Config) { c.Public = false }
	a := env.AddDaemon(private)
	b := env.AddDaemon(private)
	const limit = 20 * time.Second

	start := time.Now()
	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "unattended target"); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	for b.Daemon.HandshakeService().PendingCount() == 0 {
		if time.Since(start) > limit {
			t.Fatalf("relayed request did not reach the unattended target within %s", limit)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("request reached the target after %s; target polls: %d",
		time.Since(start).Truncate(time.Millisecond), b.Daemon.RelayedHandshakePolls())
	if polls := b.Daemon.RelayedHandshakePolls(); polls > 2 {
		t.Errorf("target polled the registry %d times for one request", polls)
	}
}

// TestWaitForTrustOnTrustedPeerDoesNotPollRegistry pins that asking whether
// a peer is trusted costs no registry round trip once it is. pilotctl asks
// with a zero timeout before every send-message, send-file, connect, ping
// and publish; polling there put up to thirty registry requests a minute on
// a busy node with no handshake in flight, and a three-second stall in front
// of each command whenever the registry was slow.
func TestWaitForTrustOnTrustedPeerDoesNotPollRegistry(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	if _, err := a.Driver.Handshake(b.Daemon.NodeID(), "trusted-wait test"); err != nil {
		t.Fatalf("A handshake: %v", err)
	}
	if _, err := b.Driver.Handshake(a.Daemon.NodeID(), "trusted-wait test"); err != nil {
		t.Fatalf("B handshake: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := a.Driver.WaitForTrust(b.Daemon.NodeID(), 1000)
		if trusted, _ := resp["trusted"].(bool); err == nil && trusted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("A and B did not become trusted")
		}
	}

	before := a.Daemon.RelayedHandshakePolls()
	for i := 0; i < 5; i++ {
		start := time.Now()
		resp, err := a.Driver.WaitForTrust(b.Daemon.NodeID(), 0)
		if err != nil {
			t.Fatalf("WaitForTrust: %v", err)
		}
		if trusted, _ := resp["trusted"].(bool); !trusted {
			t.Fatal("B should be trusted")
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("WaitForTrust on a trusted peer took %v", took)
		}
		// Past the on-demand gap, so a poll would be allowed if one were asked for.
		time.Sleep(2100 * time.Millisecond)
	}
	if got := a.Daemon.RelayedHandshakePolls(); got != before {
		t.Fatalf("five trust checks on a trusted peer caused %d registry polls, want 0", got-before)
	}
}
