// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// --- helpers ---

// newSendDataFixture returns a daemon + peer UDP socket + established connection
// wired so that sendSegment delivers to the peer socket.
func newSendDataFixture(t *testing.T, peerNode uint32) (*Daemon, *net.UDPConn, *Connection) {
	t.Helper()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.tunnels.Close() })

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peerConn.Close() })
	d.AddTunnelPeer(peerNode, peerConn.LocalAddr().(*net.UDPAddr))

	conn := d.ports.NewConnection(2000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.SendSeq = 1000
	conn.CongWin = InitialCongWin
	conn.PeerRecvWin = 1 << 20
	return d, peerConn, conn
}

func readOneSegment(t *testing.T, pc *net.UDPConn, dur time.Duration) *protocol.Packet {
	t.Helper()
	pc.SetReadDeadline(time.Now().Add(dur))
	buf := make([]byte, 65535)
	n, _, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n < 4 {
		t.Fatalf("short packet: %d bytes", n)
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return pkt
}

// --- SendData ---

func TestSendDataNonEstablishedReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn := d.ports.NewConnection(1, protocol.Addr{Network: 0, Node: 1}, 1)
	conn.State = StateSynSent
	if err := d.SendData(conn, []byte("x")); err == nil {
		t.Fatal("expected error for non-established connection")
	}
}

func TestSendDataNoDelayUsesSendDataImmediate(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD0D0D0D0
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = true

	payload := []byte("fast-path")
	if err := d.SendData(conn, payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", pkt.Payload, payload)
	}
}

func TestSendDataNagleBuffersAndFlushesImmediatelyWithNoInflight(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD1D1D1D1
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	// No Unacked entries → Nagle flushes right away

	payload := []byte("small-write")
	if err := d.SendData(conn, payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != string(payload) {
		t.Fatalf("payload = %q, want %q", pkt.Payload, payload)
	}
}

// --- nagleFlush ---

func TestNagleFlushEmptyBufIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn := d.ports.NewConnection(1, protocol.Addr{Network: 0, Node: 1}, 1)
	conn.State = StateEstablished
	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
}

func TestNagleFlushFullMSSSendsSegment(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD2D2D2D2
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = make([]byte, SendSegmentSize)
	for i := range conn.NagleBuf {
		conn.NagleBuf[i] = byte('A' + (i % 26))
	}

	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if len(pkt.Payload) != SendSegmentSize {
		t.Fatalf("payload len = %d, want %d", len(pkt.Payload), SendSegmentSize)
	}
	conn.NagleMu.Lock()
	remaining := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if remaining != 0 {
		t.Fatalf("NagleBuf remaining = %d, want 0", remaining)
	}
}

func TestNagleFlushSubMSSWithUnackedBlocksThenNagleChFlushes(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD3D3D3D3
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = []byte("pending-small")
	// Simulate in-flight so Nagle blocks.
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{
		data:     []byte("inflight"),
		seq:      500,
		sentAt:   time.Now(),
		attempts: 1,
	})
	conn.RetxMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- d.nagleFlush(conn) }()

	// Signal that all data is ACKed.
	time.Sleep(10 * time.Millisecond)
	conn.RetxMu.Lock()
	conn.Unacked = conn.Unacked[:0]
	conn.RetxMu.Unlock()
	select {
	case conn.NagleCh <- struct{}{}:
	default:
		t.Fatal("NagleCh send should not block")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("nagleFlush: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("nagleFlush did not return")
	}

	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if string(pkt.Payload) != "pending-small" {
		t.Fatalf("payload = %q, want 'pending-small'", pkt.Payload)
	}
}

func TestNagleFlushDoesNotWaitForAHeldWrite(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD4D4D4D4
	d, _, conn := newSendDataFixture(t, peerNode)
	conn.NoDelay = false
	conn.NagleBuf = []byte("held")
	conn.RetxStop = make(chan struct{})
	// A short segment in flight, so the write is held.
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{
		data: []byte("x"), seq: 1, sentAt: time.Now(), attempts: 1,
	})
	conn.RetxMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- d.nagleFlush(conn) }()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("nagleFlush: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("nagleFlush waited for the held write instead of returning")
	}
	conn.NagleMu.Lock()
	buffered := string(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if buffered != "held" {
		t.Fatalf("buffer = %q, want the held write still in it", buffered)
	}
	close(conn.RetxStop) // lets the flusher go
}

// --- Stop / doStop ---

func TestStopIsIdempotent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := d.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
	// stopCh must be closed.
	select {
	case <-d.stopCh:
	default:
		t.Fatal("stopCh should be closed after Stop()")
	}
}

func TestDoStopWithEstablishedConnectionSendsFIN(t *testing.T) {
	t.Parallel()
	const peerNode uint32 = 0xD5D5D5D5
	d, pc, conn := newSendDataFixture(t, peerNode)
	conn.SendSeq = 7777

	// doStop sends FIN to established conns.
	done := make(chan struct{})
	go func() {
		d.doStop()
		close(done)
	}()

	pkt := readOneSegment(t, pc, 500*time.Millisecond)
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Fatalf("expected FlagFIN, got flags=%b", pkt.Flags)
	}
	if pkt.Seq != 7777 {
		t.Fatalf("FIN seq = %d, want 7777", pkt.Seq)
	}

	select {
	case <-done:
	case <-time.After(4 * time.Second): // doStop may wait up to 3s for deregister
		t.Fatal("doStop did not return")
	}

	// Connection should be removed.
	if got := d.ports.FindConnection(2000, conn.RemoteAddr, 80); got != nil {
		t.Fatal("connection should be removed after doStop")
	}
}

func TestDoStopWithNoConnectionsCompletesCleanly(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		d.doStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("doStop did not return")
	}
}

// --- per-layer heartbeat loops (T4.3) ---
//
// The legacy heartbeatLoop was split into four goroutines per P9/P10:
// trustRepublishLoop (L5/L8), tunnelKeepaliveLoop (L4), handshakePollLoop
// (L11), and observabilityHeartbeatLoop (L11). Each loop must independently
// honor d.stopCh. The first three exit-only tests use a 1-hour ticker so the
// ticker never fires; the jitter sleep is bounded at 5 s. The richer per-loop
// tests further down use a short ticker and assert side-effects.

func TestTrustRepublishLoopExitsOnStopCh(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 1 * time.Hour})
	done := make(chan struct{})
	go func() {
		d.trustRepublishLoop()
		close(done)
	}()
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("trustRepublishLoop did not exit after stopCh close")
	}
}

func TestTunnelKeepaliveLoopExitsOnStopCh(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 1 * time.Hour})
	done := make(chan struct{})
	go func() {
		d.tunnelKeepaliveLoop()
		close(done)
	}()
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("tunnelKeepaliveLoop did not exit after stopCh close")
	}
}

func TestHandshakePollLoopExitsOnStopCh(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 1 * time.Hour})
	done := make(chan struct{})
	go func() {
		d.handshakePollLoop()
		close(done)
	}()
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("handshakePollLoop did not exit after stopCh close")
	}
}

// TestTunnelKeepaliveLoopFiresOnTickerAndStopsOnStopCh exercises both halves
// of the loop: the ticker path (one tick must arrive within ~ jitter +
// interval) and the stopCh path (loop must exit promptly).
//
// We can't easily observe the side-effect (RegisterWithBeacon) without
// standing up a beacon, but we can drive the goroutine with a short ticker,
// observe that it sits in the select (no panic), then close stopCh and
// verify exit. To keep the test fast, KeepaliveInterval is set tight and
// the jitter (max 5 s) is the dominant wait — accepted budget is 7 s.
func TestTunnelKeepaliveLoopFiresOnTickerAndStopsOnStopCh(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 50 * time.Millisecond})
	done := make(chan struct{})
	start := time.Now()
	go func() {
		d.tunnelKeepaliveLoop()
		close(done)
	}()
	// Sleep past the 0-5 s startup jitter plus several ticker periods so we
	// know the loop has executed its select at least once. If it had
	// panicked the goroutine would have torn down already.
	time.Sleep(5*time.Second + 200*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Logf("loop running for %s before stop", elapsed)
	}
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("tunnelKeepaliveLoop did not exit within 1s after stopCh close")
	}
}

// TestObservabilityHeartbeatLoopPublishesAgentHeartbeat subscribes to the
// daemon's bus and asserts that the loop publishes one "agent.heartbeat"
// event per tick, with the expected payload shape (address + node_id).
//
// To avoid waiting on the 0-5 s startup jitter we drive publishHeartbeatEvent
// directly first (proving the publish wiring), then start the loop with a
// short ticker and verify a second event arrives via the ticker path. This
// exercises both the wire format (byte-equivalent payload across both call
// sites) and the loop's actual fire path.
func TestObservabilityHeartbeatLoopPublishesAgentHeartbeat(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 50 * time.Millisecond})

	ch, cancel := d.bus.Subscribe("agent.heartbeat")
	defer cancel()

	// 1. Direct publish — proves wiring + payload independent of the loop.
	d.publishHeartbeatEvent()
	select {
	case ev := <-ch:
		if ev.Topic != "agent.heartbeat" {
			t.Fatalf("topic = %q, want agent.heartbeat", ev.Topic)
		}
		if _, ok := ev.Payload["node_id"]; !ok {
			t.Fatalf("payload missing node_id: %v", ev.Payload)
		}
		if _, ok := ev.Payload["address"]; !ok {
			t.Fatalf("payload missing address: %v", ev.Payload)
		}
		// Payload must be exactly {address, node_id}; extra keys would
		// drift the wire contract.
		if len(ev.Payload) != 2 {
			t.Fatalf("payload has %d keys, want 2: %v", len(ev.Payload), ev.Payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("publishHeartbeatEvent did not deliver to subscriber")
	}

	// 2. Ticker path — start the loop and verify it fires on its own.
	done := make(chan struct{})
	go func() {
		d.observabilityHeartbeatLoop()
		close(done)
	}()
	// Wait past startup jitter (max 5 s) + a couple of ticks.
	select {
	case ev := <-ch:
		if ev.Topic != "agent.heartbeat" {
			t.Fatalf("ticker tick topic = %q, want agent.heartbeat", ev.Topic)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("observabilityHeartbeatLoop did not publish within 7s")
	}

	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("observabilityHeartbeatLoop did not exit within 1s after stopCh close")
	}
}

// TestTrustRepublishLoopFiresAndStops drives the loop with a short ticker
// and a nil regConn so each tick takes the early-continue path. Verifies
// the loop survives a handful of ticks past startup jitter and exits within
// 1 s of stopCh close.
func TestTrustRepublishLoopFiresAndStops(t *testing.T) {
	t.Parallel()
	d := New(Config{KeepaliveInterval: 50 * time.Millisecond})
	// regConn is nil — each tick hits the `if d.reg() == nil { continue }`
	// branch. We're only verifying the loop body executes without panicking
	// and exits on stopCh.
	done := make(chan struct{})
	go func() {
		d.trustRepublishLoop()
		close(done)
	}()
	// Wait past 0-5 s startup jitter so we know the goroutine has entered
	// the for-select.
	time.Sleep(5*time.Second + 200*time.Millisecond)
	close(d.stopCh)
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("trustRepublishLoop did not exit within 1s after stopCh close")
	}
}
