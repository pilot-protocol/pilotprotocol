// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// peerEndpoint returns the endpoint d currently holds for nodeID, or "".
func peerEndpoint(d *daemon.Daemon, nodeID uint32) string {
	for _, p := range d.Tunnels().PeerList() {
		if p.NodeID == nodeID {
			return p.Endpoint
		}
	}
	return ""
}

// TestAddrChangeRecoveryTeachesPeerNewSource checks the peer half of the
// address-change recovery: after a node's address changed, the peer must
// learn where the node now is from the recovery itself, not 25 s later from
// the node's next NAT keepalive.
//
// The harness runs every daemon on loopback and cannot give one a new
// address, so the address change itself is not reproduced here (that is
// covered by the Docker lab run described in the changelog entry). What is
// reproduced is the state the peer is left in: B's entry for A is pointed at
// an address nobody listens on, which is exactly what B holds after A has
// moved. The recovery on A then has to put A's real source address back into
// B's table.
func TestAddrChangeRecoveryTeachesPeerNewSource(t *testing.T) {
	env := NewTestEnv(t)
	encrypted := func(cfg *daemon.Config) { cfg.Encrypt = true }
	a := env.AddDaemon(encrypted)
	b := env.AddDaemon(encrypted)

	// Establish the encrypted tunnel in both directions with one echo.
	ln, err := b.Driver.Listen(8140)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n])
	}()
	conn, err := a.Driver.DialAddr(b.Daemon.Addr(), 8140)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	conn.Close()

	aID := a.Daemon.NodeID()
	_, aPort, err := net.SplitHostPort(a.Daemon.TunnelAddr().String())
	if err != nil {
		t.Fatalf("tunnel addr: %v", err)
	}
	real := peerEndpoint(b.Daemon, aID)
	if _, port, _ := net.SplitHostPort(real); port != aPort {
		t.Fatalf("B's endpoint for A before the test = %q, want A's tunnel port %s", real, aPort)
	}

	// "A moved": B still holds an address A is no longer at. A reserved,
	// closed loopback port stands in for the old address.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve stale addr: %v", err)
	}
	stale := dead.LocalAddr().(*net.UDPAddr)
	dead.Close()
	// Let the echo connection's teardown finish first: any frame A still
	// sends for it would correct B's entry and hide what the recovery does.
	time.Sleep(2 * time.Second)
	b.Daemon.Tunnels().AddPeer(aID, stale)

	// Nothing corrects B on its own in the short run: A is idle, and its
	// keepalive toward B is up to 25 s away.
	time.Sleep(1500 * time.Millisecond)
	if got := peerEndpoint(b.Daemon, aID); got != stale.String() {
		t.Fatalf("B's endpoint for A healed without the recovery (%q); the test cannot tell what fixed it", got)
	}

	start := time.Now()
	a.Daemon.RecoverFromAddrChange()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if got := peerEndpoint(b.Daemon, aID); got == real {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("B still holds %q for A 3s after A's recovery, want %q",
				peerEndpoint(b.Daemon, aID), real)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("B learned A's source address %v after the recovery started", time.Since(start).Truncate(time.Millisecond))
}
