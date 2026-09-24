// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// First contact from a fresh node to a service (the onboarding query to
// list-agents). Measured on clean GitHub runners, the first query failed
// most of the time; three daemon-side causes are pinned here:
//
//  1. Lost key-exchange reply deadlock. A node answers a new peer's PILA
//     once. If that reply is lost, our retransmits carry the same X25519
//     key, the peer treats them as same-session keepalives and never
//     answers again: it holds a session for us, we hold none. Reproduced
//     against the live v1.13.5 fleet (list-agents, randomfox): with the
//     first reply dropped, no key in ~100 s, 4 of 4 runs; with the key
//     request, the key arrived 5-6 s later, 4 of 4.
//  2. The private-node SYN gate dropped the service's dial-back reply
//     (about 50 "SYN rejected: untrusted source" per failed query).
//  3. The dial spent its SYN retries, and queued duplicate SYNs, while
//     the key exchange was still running.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// kxProxy forwards UDP frames between a client tunnel and a service
// tunnel on loopback, so a test can lose or delay what the service sends
// back, the way a lossy or congested path does. The service sees every
// client frame as coming from the proxy.
type kxProxy struct {
	conn    *net.UDPConn
	service *net.UDPAddr

	mu            sync.Mutex
	client        *net.UDPAddr
	dropFirstPILA bool      // drop the service's first PILA to the client
	holdUntil     time.Time // buffer service->client frames until then
	held          [][]byte
	droppedPILA   int
}

func newKXProxy(t *testing.T, service *net.UDPAddr) *kxProxy {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &kxProxy{conn: c, service: service}
	t.Cleanup(func() { c.Close() })
	go p.run()
	return p
}

func (p *kxProxy) addr() *net.UDPAddr { return p.conn.LocalAddr().(*net.UDPAddr) }

func (p *kxProxy) run() {
	buf := make([]byte, 65535)
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		frame := append([]byte(nil), buf[:n]...)
		if from.Port == p.service.Port && from.IP.Equal(p.service.IP) {
			p.mu.Lock()
			client := p.client
			if p.dropFirstPILA && n >= 4 && bytes.Equal(frame[:4], protocol.TunnelMagicAuthEx[:]) {
				p.dropFirstPILA = false
				p.droppedPILA++
				p.mu.Unlock()
				continue
			}
			if time.Now().Before(p.holdUntil) {
				p.held = append(p.held, frame)
				p.mu.Unlock()
				continue
			}
			p.mu.Unlock()
			if client != nil {
				p.conn.WriteToUDP(frame, client)
			}
			continue
		}
		p.mu.Lock()
		p.client = from
		p.mu.Unlock()
		p.conn.WriteToUDP(frame, p.service)
	}
}

// hold buffers everything the service sends until d has passed, then
// delivers it in order.
func (p *kxProxy) hold(d time.Duration) {
	p.mu.Lock()
	p.holdUntil = time.Now().Add(d)
	p.mu.Unlock()
	time.AfterFunc(d+20*time.Millisecond, func() {
		p.mu.Lock()
		held, client := p.held, p.client
		p.held = nil
		p.mu.Unlock()
		for _, f := range held {
			if client != nil {
				p.conn.WriteToUDP(f, client)
			}
		}
	})
}

// newFirstContactPair builds a client and a service daemon on loopback
// with authenticated identities, the client reaching the service through
// a kxProxy. No key exchange has happened yet.
func newFirstContactPair(t *testing.T, clientCfg, serviceCfg Config, clientID, serviceID uint32) (client, service *Daemon, proxy *kxProxy) {
	t.Helper()
	client, service = New(clientCfg), New(serviceCfg)
	keys := map[uint32]ed25519.PublicKey{
		clientID:  startAuthLoopbackTunnel(t, client.tunnels, clientID),
		serviceID: startAuthLoopbackTunnel(t, service.tunnels, serviceID),
	}
	client.tunnels.SetPeerVerifyFunc(registryKeys(keys))
	service.tunnels.SetPeerVerifyFunc(registryKeys(keys))
	client.setNodeID_testhelper(clientID)
	service.setNodeID_testhelper(serviceID)
	proxy = newKXProxy(t, tunnelUDPAddr(t, service.tunnels))
	return client, service, proxy
}

// TestFirstContactLostKeyReplyRecoversWithKeyRequest is cause 1: the
// service's one reply to our first PILA is lost. A plain same-key PILA
// retransmit is answered with silence (the deadlock); the retransmit's
// key request makes the service send its key again, and the service
// stops retransmitting once our PILA confirms we have it.
func TestFirstContactLostKeyReplyRecoversWithKeyRequest(t *testing.T) {
	t.Parallel()
	const clientID, serviceID = uint32(0x0C01), uint32(0x0C02)
	client, service, proxy := newFirstContactPair(t, Config{}, Config{Public: true}, clientID, serviceID)
	a, b := client.tunnels, service.tunnels
	proxy.dropFirstPILA = true

	a.AddPeer(serviceID, proxy.addr())
	waitUntil(t, "service installs our key", func() bool { return b.HasCrypto(clientID) })
	time.Sleep(keyexchange.DuplicateHandshakeDebounce + 100*time.Millisecond)
	if a.HasCrypto(serviceID) {
		t.Fatal("setup: the service's reply should have been lost")
	}

	// The deadlock: the same PILA again is a same-session keepalive to the
	// service, which stays silent.
	if err := a.writeFrame(serviceID, proxy.addr(), a.buildAuthKeyExchangeFrame()); err != nil {
		t.Fatalf("writeFrame: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if a.HasCrypto(serviceID) {
		t.Fatal("a same-key PILA was answered; the deadlock this test pins no longer exists")
	}

	// Our retransmit, due now, carries the key request.
	a.kx.InjectPendingRekeyForTest(serviceID, &keyexchange.PendingRekeyState{
		FirstSentAt: time.Now().Add(-10 * time.Second),
		LastSentAt:  time.Now().Add(-5 * time.Second),
		Attempts:    1,
	})
	a.rekeyRetransmitTick()
	waitUntil(t, "client installs the service's key", func() bool { return a.HasCrypto(serviceID) })
	if got := a.kx.KeyRequestsSent(); got < 1 {
		t.Fatalf("key requests sent = %d, want >= 1", got)
	}
	// Our PILA in answer to the service's key confirms the session, which
	// ends the service's own retransmits of its reply.
	waitUntil(t, "service stops retransmitting its key", func() bool { return !b.kx.PendingRekeyHas(clientID) })
}

// TestFirstContactKeyRequestNotSentWhileSessionUp: a retransmit to a
// peer we already hold a session key for (an ordinary rekey) carries no
// key request.
func TestFirstContactKeyRequestNotSentWhileSessionUp(t *testing.T) {
	t.Parallel()
	const clientID, serviceID = uint32(0x0C11), uint32(0x0C12)
	client, service, proxy := newFirstContactPair(t, Config{}, Config{Public: true}, clientID, serviceID)
	a, b := client.tunnels, service.tunnels

	a.AddPeer(serviceID, proxy.addr())
	waitUntil(t, "handshake", func() bool { return a.HasCrypto(serviceID) && b.HasCrypto(clientID) })
	a.kx.InjectPendingRekeyForTest(serviceID, &keyexchange.PendingRekeyState{
		FirstSentAt: time.Now().Add(-10 * time.Second),
		LastSentAt:  time.Now().Add(-5 * time.Second),
		Attempts:    3,
	})
	a.rekeyRetransmitTick()
	if got := a.kx.KeyRequestsSent(); got != 0 {
		t.Fatalf("key requests sent with a session up = %d, want 0", got)
	}
}

// TestNoKeyFrameFromPeerSendsKeyRequest: an encrypted frame from a peer
// we hold no key for proves the peer holds a session for us; the rekey
// request we answer it with carries a key request too, on the first try.
func TestNoKeyFrameFromPeerSendsKeyRequest(t *testing.T) {
	t.Parallel()
	a := NewTunnelManager()
	startAuthLoopbackTunnel(t, a, 0x0C21)
	peer, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerID = uint32(0x0C22)
	a.mu.Lock()
	a.peers[peerID] = peerAddr
	a.mu.Unlock()

	if !a.maybeRequestRekey(peerID, peerAddr) {
		t.Fatal("rekey request not sent")
	}
	var magics [][]byte
	for {
		f := readOneFrame(t, peer)
		if f == nil {
			break
		}
		magics = append(magics, f[:4])
	}
	var pila, pilk int
	for _, m := range magics {
		switch {
		case bytes.Equal(m, protocol.TunnelMagicAuthEx[:]):
			pila++
		case bytes.Equal(m, protocol.TunnelMagicKeyEx[:]):
			pilk++
		}
	}
	if pila != 1 || pilk != 1 {
		t.Fatalf("frames sent: %d PILA, %d PILK; want 1 and 1", pila, pilk)
	}
}

// startRouteLoop runs d's packet dispatch the way Start does.
func startRouteLoop(t *testing.T, d *Daemon) {
	t.Helper()
	go d.routeLoop()
	t.Cleanup(func() { d.stopOnce.Do(func() { close(d.stopCh) }) })
}

// pendingFrames returns how many frames the tunnel holds for node while
// it waits for the key exchange.
func pendingFrames(tm *TunnelManager, node uint32) int {
	tm.pendMu.Lock()
	defer tm.pendMu.Unlock()
	return len(tm.pending[node])
}

// TestDialWaitsForKeyWithoutQueuingDuplicateSYNs is cause 3: while the
// key exchange with a slow peer runs, the dial keeps one SYN queued (sent
// the moment the key arrives) instead of retransmitting into the queue
// and burning its retry budget, and it completes once the key is in.
func TestDialWaitsForKeyWithoutQueuingDuplicateSYNs(t *testing.T) {
	t.Parallel()
	const clientID, serviceID = uint32(0x0C31), uint32(0x0C32)
	client, service, proxy := newFirstContactPair(t, Config{Encrypt: true}, Config{Public: true, Encrypt: true}, clientID, serviceID)
	if _, err := service.ports.Bind(protocol.PortDataExchange); err != nil {
		t.Fatalf("bind: %v", err)
	}
	startRouteLoop(t, client)
	startRouteLoop(t, service)

	// The service's key-exchange reply takes 2.5 s to come back: past the
	// old direct phase and several SYN retransmits.
	proxy.hold(2500 * time.Millisecond)
	client.tunnels.AddPeer(serviceID, proxy.addr())

	type result struct {
		conn *Connection
		err  error
	}
	done := make(chan result, 1)
	go func() {
		c, err := client.DialConnectionContext(context.Background(), protocol.Addr{Node: serviceID}, protocol.PortDataExchange)
		done <- result{c, err}
	}()

	time.Sleep(2 * time.Second)
	if client.tunnels.IsEncrypted(serviceID) {
		t.Fatal("setup: key exchange should still be held up")
	}
	if n := pendingFrames(client.tunnels, serviceID); n != 1 {
		t.Fatalf("frames queued for the peer during key exchange = %d, want exactly the one SYN", n)
	}
	select {
	case r := <-done:
		t.Fatalf("dial returned during key exchange: %v", r.err)
	default:
	}

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("dial: %v", r.err)
		}
		r.conn.Mu.Lock()
		st := r.conn.State
		r.conn.Mu.Unlock()
		if st != StateEstablished {
			t.Fatalf("state = %v, want ESTABLISHED", st)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("dial did not complete after the key exchange finished")
	}
}

// TestDialKeyExchangeErrorWrapsDialTimeout: callers that only check for
// a dial timeout keep working with the more specific error.
func TestDialKeyExchangeErrorWrapsDialTimeout(t *testing.T) {
	t.Parallel()
	if !errors.Is(ErrDialKeyExchange, protocol.ErrDialTimeout) {
		t.Fatal("ErrDialKeyExchange must wrap protocol.ErrDialTimeout")
	}
	if got := ErrDialKeyExchange.Error(); got != "dial timeout: key exchange with peer did not complete" {
		t.Fatalf("message = %q", got)
	}
}

// TestDialViaRelayWhenKeyArrivedOnlyOverRelay: the relay is the only path
// a peer has proven when its key came in over the relay and nothing was
// ever decrypted from its direct address.
func TestKeyArrivedViaRelayOnly(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	const peer = uint32(0x0C41)
	if tm.KeyArrivedViaRelayOnly(peer) {
		t.Fatal("unknown peer reported relay-only")
	}
	tm.keyViaRelay.Store(peer, true)
	if !tm.KeyArrivedViaRelayOnly(peer) {
		t.Fatal("key via relay, no direct traffic: want relay-only")
	}
	tm.routing.RecordDirectRecv(peer, time.Now())
	if tm.KeyArrivedViaRelayOnly(peer) {
		t.Fatal("a direct decrypt proves the direct path")
	}
	tm.keyViaRelay.Store(peer, false)
	tm.routing.RemovePeer(peer)
	if tm.KeyArrivedViaRelayOnly(peer) {
		t.Fatal("key via direct: not relay-only")
	}
	tm.keyViaRelay.Store(peer, true)
	tm.RemovePeer(peer)
	if tm.KeyArrivedViaRelayOnly(peer) {
		t.Fatal("RemovePeer must forget the key path")
	}
}

// --- cause 2: the reply window in the private-node SYN gate ---

func synFrom(peer, self uint32, dstPort uint16) *protocol.Packet {
	return newStreamSYNPkt(peer, self, 50000, dstPort, 100)
}

func TestReplyWindowAdmitsDialBackFromContactedPeer(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0C51)
	if _, err := d.ports.Bind(protocol.PortDataExchange); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Before we contact the peer, its SYN is dropped silently.
	d.handleStreamPacket(synFrom(peerNode, d.NodeID(), protocol.PortDataExchange))
	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("SYN from a peer we never contacted was answered (flags=%d)", pkt.Flags)
	}
	if n := d.ports.TotalActiveConnections(); n != 0 {
		t.Fatalf("connections = %d, want 0", n)
	}

	// We dial it (or send it a handshake): its reply dial-back is admitted.
	d.noteOutboundContact(peerNode)
	d.handleStreamPacket(synFrom(peerNode, d.NodeID(), protocol.PortDataExchange))
	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil || !pkt.HasFlag(protocol.FlagSYN) || !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("reply SYN from a contacted peer not answered with SYN-ACK: %+v", pkt)
	}
	if n := d.ports.TotalActiveConnections(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
}

func TestReplyWindowAdmitsHandshakeAccept(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0C52)
	if _, err := d.ports.Bind(protocol.PortHandshake); err != nil {
		t.Fatalf("bind: %v", err)
	}
	d.noteOutboundContact(peerNode)
	d.handleStreamPacket(synFrom(peerNode, d.NodeID(), protocol.PortHandshake))
	if pkt := readPacket(t, peerConn, 500*time.Millisecond); pkt == nil || !pkt.HasFlag(protocol.FlagACK) {
		t.Fatalf("handshake accept from a contacted peer not answered: %+v", pkt)
	}
}

func TestReplyWindowOnlyCoversReplyPorts(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0C53)
	if _, err := d.ports.Bind(8080); err != nil {
		t.Fatalf("bind: %v", err)
	}
	d.noteOutboundContact(peerNode)
	d.handleStreamPacket(synFrom(peerNode, d.NodeID(), 8080))
	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("SYN to a non-reply port admitted by the reply window (flags=%d)", pkt.Flags)
	}
}

func TestReplyWindowExpires(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0C54)
	if _, err := d.ports.Bind(protocol.PortDataExchange); err != nil {
		t.Fatalf("bind: %v", err)
	}
	d.outbound.note(peerNode, time.Now().Add(-replyWindow-time.Second))
	d.handleStreamPacket(synFrom(peerNode, d.NodeID(), protocol.PortDataExchange))
	if pkt := readPacket(t, peerConn, 150*time.Millisecond); pkt != nil {
		t.Fatalf("SYN admitted after the reply window expired (flags=%d)", pkt.Flags)
	}
	d.outbound.prune(time.Now())
	if n := d.outbound.len(); n != 0 {
		t.Fatalf("expired entry not pruned: %d left", n)
	}
}

func TestReplyWindowTableIsBounded(t *testing.T) {
	t.Parallel()
	var o outboundContacts
	now := time.Now()
	for i := 0; i < maxReplyWindowPeers; i++ {
		o.note(uint32(i+1), now)
	}
	o.note(0xFFFF0001, now)
	if o.len() != maxReplyWindowPeers {
		t.Fatalf("table grew past its bound: %d", o.len())
	}
	if o.recent(0xFFFF0001, now) {
		t.Fatal("a peer past the bound must fall back to the trust check")
	}
	// Once old entries expire, new peers fit again.
	later := now.Add(replyWindow + time.Second)
	o.note(0xFFFF0002, later)
	if !o.recent(0xFFFF0002, later) {
		t.Fatal("expired entries were not pruned to make room")
	}
}

// TestDialOpensReplyWindow: a dial records the contact before its first
// SYN, so a fast service's reply cannot beat it.
func TestDialOpensReplyWindow(t *testing.T) {
	t.Parallel()
	d, peerNode, _ := setupDaemonWithPeer(t, Config{Public: false})
	d.setNodeID_testhelper(0xABCD0C55)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, _ = d.DialConnectionContext(ctx, protocol.Addr{Node: peerNode}, protocol.PortDataExchange)
	if !d.replyWindowAdmits(peerNode, protocol.PortDataExchange) {
		t.Fatal("dialing a peer must open its reply window")
	}
}

// TestKeyInstallDoesNotWaitOnRegistryTrustCheck: installing a new
// peer's key (and flushing the SYN queued behind it) must not wait on a
// registry round trip. The only trust question on that path is whether
// the tunnel.established event may name the peer, and local trust
// answers it.
func TestKeyInstallDoesNotWaitOnRegistryTrustCheck(t *testing.T) {
	t.Parallel()
	var trustCalls sync.Map
	rc, stop := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		n, _ := trustCalls.LoadOrStore(typ, new(int))
		*(n.(*int))++
		return map[string]interface{}{"trusted": false}
	})
	defer stop()
	d := New(Config{Encrypt: true})
	d.regConn.Store(rc)
	startAuthLoopbackTunnel(t, d.tunnels, 0x0C61)

	const peerID = uint32(0x0C62)
	data, peerPub, _, _ := buildAuthKXFrame(t, peerID)
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) { return peerPub, nil })
	d.tunnels.handleAuthKeyExchange(data, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}, false)
	if !d.tunnels.HasCrypto(peerID) {
		t.Fatal("key not installed")
	}
	trustCalls.Range(func(k, v any) bool {
		if typ := k.(string); typ != "" && bytes.Contains([]byte(typ), []byte("trust")) {
			t.Errorf("key install made %d registry %q call(s)", *(v.(*int)), typ)
		}
		return true
	})
}
