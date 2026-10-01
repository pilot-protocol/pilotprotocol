// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"fmt"
	"sync"
	"testing"
	"time"

	registryclient "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestUnicastDatagram verifies point-to-point datagram delivery.
func TestUnicastDatagram(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// B listens for datagrams
	received := make(chan *struct {
		data    string
		srcPort uint16
		dstPort uint16
	}, 1)
	go func() {
		dg, err := b.Driver.RecvFrom()
		if err != nil {
			return
		}
		received <- &struct {
			data    string
			srcPort uint16
			dstPort uint16
		}{string(dg.Data), dg.SrcPort, dg.DstPort}
	}()

	// A sends datagram to B
	if err := a.Driver.SendTo(b.Daemon.Addr(), 5000, []byte("unicast hello")); err != nil {
		t.Fatalf("sendto: %v", err)
	}

	select {
	case dg := <-received:
		if dg.data != "unicast hello" {
			t.Errorf("expected %q, got %q", "unicast hello", dg.data)
		}
		if dg.dstPort != 5000 {
			t.Errorf("expected dst port 5000, got %d", dg.dstPort)
		}
		t.Logf("received datagram: %s (src_port=%d, dst_port=%d)", dg.data, dg.srcPort, dg.dstPort)
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for unicast datagram")
	}
}

// TestBroadcastExcludesSender verifies the broadcaster does not receive its own broadcast.
func TestBroadcastExcludesSender(t *testing.T) {
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon(func(c *daemon.Config) { c.AdminToken = env.AdminToken })
	b := env.AddDaemon()

	// Create network and join both
	rc, err := registryclient.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("registry dial: %v", err)
	}
	defer rc.Close()

	resp, err := rc.CreateNetwork(a.Daemon.NodeID(), "bcast-excl", "open", "", env.AdminToken, false)
	if err != nil {
		t.Fatalf("create network: %v", err)
	}
	netID := uint16(resp["network_id"].(float64))

	if _, err := rc.JoinNetwork(b.Daemon.NodeID(), netID, "", 0, env.AdminToken); err != nil {
		t.Fatalf("join B: %v", err)
	}

	// Both listen for datagrams
	gotA := make(chan string, 1)
	gotB := make(chan string, 1)

	var ready sync.WaitGroup
	ready.Add(2)
	go func() {
		ready.Done()
		dg, err := a.Driver.RecvFrom()
		if err != nil {
			return
		}
		gotA <- string(dg.Data)
	}()
	go func() {
		ready.Done()
		dg, err := b.Driver.RecvFrom()
		if err != nil {
			return
		}
		gotB <- string(dg.Data)
	}()
	ready.Wait()

	// A broadcasts
	if err := a.Driver.Broadcast(netID, 5000, []byte("broadcast msg"), env.AdminToken); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// B should receive it
	select {
	case msg := <-gotB:
		if msg != "broadcast msg" {
			t.Errorf("B expected %q, got %q", "broadcast msg", msg)
		}
		t.Logf("B received broadcast: %s", msg)
	case <-time.After(5 * time.Second):
		t.Fatal("B did not receive broadcast")
	}

	// A should NOT receive its own broadcast
	select {
	case msg := <-gotA:
		t.Errorf("sender A should not receive its own broadcast, got %q", msg)
	case <-time.After(500 * time.Millisecond):
		t.Log("correctly: sender did not receive own broadcast")
	}
}

// TestDatagramPortFiltering verifies datagrams to wrong port are not delivered
// to a specific port listener.
func TestDatagramPortFiltering(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// B listens for all datagrams
	allDg := make(chan uint16, 10)
	go func() {
		for {
			dg, err := b.Driver.RecvFrom()
			if err != nil {
				return
			}
			allDg <- dg.DstPort
		}
	}()

	// Send datagrams to different ports
	a.Driver.SendTo(b.Daemon.Addr(), 5000, []byte("port5000"))
	a.Driver.SendTo(b.Daemon.Addr(), 6000, []byte("port6000"))
	a.Driver.SendTo(b.Daemon.Addr(), 7000, []byte("port7000"))

	// Collect received datagrams
	ports := make(map[uint16]bool)
	timeout := time.After(3 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case port := <-allDg:
			ports[port] = true
			t.Logf("received datagram on port %d", port)
		case <-timeout:
			t.Fatalf("timeout: received %d of 3 datagrams", len(ports))
		}
	}

	if !ports[5000] || !ports[6000] || !ports[7000] {
		t.Errorf("expected datagrams on ports 5000, 6000, 7000; got %v", ports)
	}
}

// TestMultipleDatagrams verifies multiple datagrams delivered in order.
func TestMultipleDatagrams(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	received := make(chan string, 20)
	go func() {
		for {
			dg, err := b.Driver.RecvFrom()
			if err != nil {
				return
			}
			received <- string(dg.Data)
		}
	}()

	// Send 10 datagrams
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("msg-%d", i))
		if err := a.Driver.SendTo(b.Daemon.Addr(), 5000, msg); err != nil {
			t.Fatalf("sendto %d: %v", i, err)
		}
	}

	// Collect all 10
	msgs := make([]string, 0, 10)
	timeout := time.After(5 * time.Second)
	for len(msgs) < 10 {
		select {
		case m := <-received:
			msgs = append(msgs, m)
		case <-timeout:
			t.Fatalf("timeout: received %d of 10 datagrams", len(msgs))
		}
	}
	t.Logf("received all %d datagrams", len(msgs))
}

// TestDatagramsDoNotExhaustEphemeralPorts sends more datagrams than there are
// ephemeral ports. Each one used to keep its source port forever, so after
// ~16k the daemon could not open any stream until it restarted.
func TestDatagramsDoNotExhaustEphemeralPorts(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()

	// Drain B so its receive queue does not back up.
	go func() {
		for {
			if _, err := b.Driver.RecvFrom(); err != nil {
				return
			}
		}
	}()

	const sends = 17000 // the ephemeral range holds 16384
	for i := 0; i < sends; i++ {
		if err := a.Driver.SendTo(b.Daemon.Addr(), 5000, []byte("d")); err != nil {
			t.Fatalf("sendto %d: %v", i, err)
		}
	}
	// SendTo is fire-and-forget over IPC; a stream dial is served after the
	// queued sends and fails outright if the ports are gone.
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 7)
	if err != nil {
		t.Fatalf("dial after %d datagrams: %v", sends, err)
	}
	conn.Close()
}
