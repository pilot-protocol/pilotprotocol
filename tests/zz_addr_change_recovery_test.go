// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
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
// an address that never answers, which is exactly what B holds after A has
// moved. The recovery on A then has to put A's real source address back into
// B's table, before anything else in the test could have.
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

	aID, bID := a.Daemon.NodeID(), b.Daemon.NodeID()
	_, aPort, err := net.SplitHostPort(a.Daemon.TunnelAddr().String())
	if err != nil {
		t.Fatalf("tunnel addr: %v", err)
	}
	real := peerEndpoint(b.Daemon, aID)
	if _, port, _ := net.SplitHostPort(real); port != aPort {
		t.Fatalf("B's endpoint for A before the test = %q, want A's tunnel port %s", real, aPort)
	}

	// "A moved": B still holds an address A is no longer at. A loopback
	// socket that never answers stands in for the old address; it stays open
	// so B's sends to it vanish silently, as they would at a real old
	// address, instead of drawing ICMP errors.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("reserve stale addr: %v", err)
	}
	defer dead.Close()
	stale := dead.LocalAddr().(*net.UDPAddr)
	// Let the echo connection's teardown finish first: any frame A still
	// sends for it would correct B's entry and hide what the recovery does.
	// Not much longer, though; see naturalHeal below.
	time.Sleep(2 * time.Second)
	poisoned := time.Now()
	b.Daemon.Tunnels().AddPeer(aID, stale)

	// The earliest anything but the recovery could correct B: AddPeer
	// starts a key exchange with A (also sent through the beacon, so it
	// reaches A), retransmitted every RekeyRetransmitInterval, and A may
	// answer one from its real address once it has heard nothing from B for
	// KeyExchangeReplyStaleThreshold. With the 2 s pause above, the first
	// send A could answer goes out about 4 s after the poisoning. (In
	// practice A's next keepalive is what corrects B, over 20 s later; this
	// is the lower bound.) The recovery has to have healed B before then, or
	// the test could not tell which one did it. A slow runner only eats into
	// the recovery's share of those 4 s, which needs a few milliseconds.
	lastFromB, ok := a.Daemon.Tunnels().LastInboundDecrypt(bID)
	if !ok {
		t.Fatal("A has never decrypted a frame from B; the echo did not run over the tunnel")
	}
	naturalHeal := poisoned
	for naturalHeal.Sub(lastFromB) < keyexchange.KeyExchangeReplyStaleThreshold {
		naturalHeal = naturalHeal.Add(keyexchange.RekeyRetransmitInterval)
	}
	deadline := naturalHeal.Add(-250 * time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	if got := peerEndpoint(b.Daemon, aID); got != stale.String() {
		t.Fatalf("B's endpoint for A healed before the recovery ran (%q): echo traffic was still in flight", got)
	}

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		daemon.RecoverFromAddrChangeForTest(a.Daemon)
	}()
	defer func() {
		// The registry half of the recovery may still be running; let it
		// finish before the environment is torn down.
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("recovery did not return")
		}
	}()

	for peerEndpoint(b.Daemon, aID) != real {
		if time.Now().After(deadline) {
			t.Fatalf("B still holds %q for A %v after A's recovery started, want %q "+
				"(B's own key exchange could correct it from %v after the poisoning, so a later heal proves nothing)",
				peerEndpoint(b.Daemon, aID), time.Since(start).Truncate(time.Millisecond), real,
				naturalHeal.Sub(poisoned).Truncate(time.Millisecond))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("B learned A's source address %v after the recovery started (B alone could not have before %v after the poisoning)",
		time.Since(start).Truncate(time.Millisecond), naturalHeal.Sub(poisoned).Truncate(time.Millisecond))
}
