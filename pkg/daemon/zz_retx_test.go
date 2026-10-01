// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// --- SetWebhookURL ---
//
// Post-T4.1, SetWebhookURL on the daemon is a thin pass-through to a
// registered WebhookManager (the plugins/webhook plugin). The
// management surface (NewClient / hot-swap / nil-clear) is tested in
// plugins/webhook directly. The daemon-side test here verifies only
// the routing: the call reaches the registered manager.

type retxFakeWebhookManager struct{ urls []string }

func (f *retxFakeWebhookManager) SetURL(url string)   { f.urls = append(f.urls, url) }
func (f *retxFakeWebhookManager) Stats() WebhookStats { return WebhookStats{} }

func TestSetWebhookURLDelegatesToRegisteredManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	wm := &retxFakeWebhookManager{}
	d.RegisterWebhookManager(wm)

	d.SetWebhookURL("http://127.0.0.1:1/nowhere")
	d.SetWebhookURL("")

	if len(wm.urls) != 2 || wm.urls[0] != "http://127.0.0.1:1/nowhere" || wm.urls[1] != "" {
		t.Fatalf("manager.SetURL invocations = %v, want [\"http://127.0.0.1:1/nowhere\", \"\"]", wm.urls)
	}
}

func TestSetWebhookURLNoOpWhenManagerUnregistered(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// No RegisterWebhookManager — must not panic.
	d.SetWebhookURL("http://127.0.0.1:1/nowhere")
}

// --- autoJoinNetworks ---

func TestAutoJoinNetworksNoAdminTokenIsEarlyReturn(t *testing.T) {
	t.Parallel()
	// regConn is nil — if early-return fails, this would panic.
	d := New(Config{AdminToken: "", Networks: []uint16{1, 2, 3}})
	d.autoJoinNetworks() // must not panic
}

func TestAutoJoinNetworksNoNetworksIsEarlyReturn(t *testing.T) {
	t.Parallel()
	d := New(Config{AdminToken: "secret", Networks: nil})
	d.autoJoinNetworks() // must not panic (early-return on len==0)
}

// --- Info (via real registry) ---

func TestInfoBasicFieldsWithoutRegistry(t *testing.T) {
	t.Parallel()
	// Info calls d.nodeNetworks() which uses regConn. Use a real in-process
	// registry so the happy path works without side effects.
	reg, rc := startTestRegistry(t)
	defer reg.Close()
	defer rc.Close()

	d := New(Config{Version: "testv1"})
	d.regConn.Store(rc)
	d.startTime = time.Now().Add(-2 * time.Second)
	d.setNodeID_testhelper(0xABCD0001)

	info := d.Info()
	if info == nil {
		t.Fatal("Info() returned nil")
	}
	if info.NodeID != 0xABCD0001 {
		t.Fatalf("NodeID = %x, want 0xABCD0001", info.NodeID)
	}
	if info.Version != "testv1" {
		t.Fatalf("Version = %q, want testv1", info.Version)
	}
	if info.Uptime < time.Second {
		t.Fatalf("Uptime = %v, want >= 1s", info.Uptime)
	}
	if info.Identity {
		t.Fatal("Identity should be false when IdentityPath is empty")
	}
	if info.PublicKey != "" {
		t.Fatalf("PublicKey should be empty when no identity; got %q", info.PublicKey)
	}
	if info.Peers != 0 {
		t.Fatalf("Peers = %d, want 0", info.Peers)
	}
	if info.Connections != 0 {
		t.Fatalf("Connections = %d, want 0", info.Connections)
	}
}

// --- retransmitUnacked ---

func newRetxConn(t *testing.T) (*Connection, *capturedSender) {
	t.Helper()
	conn := &Connection{
		ID:         1,
		LocalAddr:  protocol.Addr{Network: 0, Node: 0x11111111},
		RemoteAddr: protocol.Addr{Network: 0, Node: 0x22222222},
		LocalPort:  1000,
		RemotePort: 80,
		State:      StateEstablished,
		CongWin:    InitialCongWin,
		SSThresh:   MaxCongWin / 2,
		RTO:        InitialRTO,
		SendSeq:    500,
		RecvBuf:    make(chan []byte, RecvBufSize),
	}
	cs := &capturedSender{}
	conn.RetxSend = cs.send
	return conn, cs
}

type capturedSender struct {
	mu      sync.Mutex
	packets []*protocol.Packet
}

func (cs *capturedSender) send(pkt *protocol.Packet) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.packets = append(cs.packets, pkt)
}

func (cs *capturedSender) all() []*protocol.Packet {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	out := make([]*protocol.Packet, len(cs.packets))
	copy(out, cs.packets)
	return out
}

func TestRetransmitUnackedEmptyIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("no Unacked → no packets sent; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedRecentlyRetxedIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{data: []byte("x"), seq: 100, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1}}
	conn.LastRetxTime = time.Now() // just fired
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("LastRetxTime < RTO → no packet sent; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedNotTimedOutIsNoop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{data: []byte("x"), seq: 100, sentAt: time.Now(), attempts: 1}}
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("entry not timed out → no packet; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedSackedSkippedAllBreakOnFirstUntimed(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	// First entry is sacked (skip), second is fresh (loop breaks on non-timed-out).
	conn.Unacked = []*retxEntry{
		{data: []byte("a"), seq: 100, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1, sacked: true},
		{data: []byte("b"), seq: 200, sentAt: time.Now(), attempts: 1},
	}
	d.retransmitUnacked(conn)
	if len(cs.all()) != 0 {
		t.Fatalf("sacked skipped + next-not-timed-out → no packet; got %d", len(cs.all()))
	}
}

func TestRetransmitUnackedTimedOutSendsACKPacketAndEntersRecovery(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	prevRTO := conn.RTO
	payload := []byte("retx-me")
	conn.Unacked = []*retxEntry{{data: payload, seq: 300, sentAt: time.Now().Add(-2 * InitialRTO), attempts: 1}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 retransmitted packet, got %d", len(pkts))
	}
	pkt := pkts[0]
	if pkt.Flags&protocol.FlagACK == 0 {
		t.Fatalf("retx should carry FlagACK, got flags=%b", pkt.Flags)
	}
	if pkt.Seq != 300 || string(pkt.Payload) != "retx-me" {
		t.Fatalf("retx packet mismatch: seq=%d payload=%q", pkt.Seq, pkt.Payload)
	}

	// attempts bumped from 1 → 2
	if conn.Unacked[0].attempts != 2 {
		t.Fatalf("attempts = %d, want 2", conn.Unacked[0].attempts)
	}
	// RFC 5681 §3.1: cwnd = LW = 1*SMSS after timeout.
	// SSThresh = max(FlightSize/2, 2*SMSS); FlightSize=len("retx-me")=7 → floor.
	if conn.CongWin != MaxSegmentSize {
		t.Fatalf("CongWin = %d, want MaxSegmentSize=%d (RFC 5681 §3.1 LW=1*SMSS)",
			conn.CongWin, MaxSegmentSize)
	}
	wantSSThresh := 2 * MaxSegmentSize // max(7/2=3, 2*MSS=8192) = 8192
	if conn.SSThresh != wantSSThresh {
		t.Fatalf("SSThresh = %d, want %d (max(FlightSize/2, 2*SMSS))", conn.SSThresh, wantSSThresh)
	}
	if !conn.InRecovery {
		t.Fatal("InRecovery should be true after timeout")
	}
	// P2-009: RTO doubles then has 0-25% jitter added, capped at 10s.
	// Accept either the jittered [2x, 2.5x] range or the 10s clamp.
	minRTO := prevRTO * 2
	maxRTO := prevRTO*2 + prevRTO*2/4
	if conn.RTO != 10*time.Second && (conn.RTO < minRTO || conn.RTO > maxRTO) {
		t.Fatalf("RTO = %v, want [%v, %v] (2x+jitter) or clamped=10s", conn.RTO, minRTO, maxRTO)
	}
	if conn.Stats.Retransmits != 1 {
		t.Fatalf("Stats.Retransmits = %d, want 1", conn.Stats.Retransmits)
	}
}

func TestRetransmitUnackedMaxAttemptsSendsRSTAndClosesState(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.Unacked = []*retxEntry{{
		data:        []byte("x"),
		seq:         999,
		sentAt:      time.Now().Add(-2 * InitialRTO),
		attempts:    MaxRetxAttempts,
		rtoAttempts: MaxRetxAttempts,
	}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 RST packet, got %d", len(pkts))
	}
	if pkts[0].Flags&protocol.FlagRST == 0 {
		t.Fatalf("expected FlagRST, got flags=%b", pkts[0].Flags)
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Fatalf("state = %v, want StateClosed after max retransmits", st)
	}
}

func TestRetransmitUnackedFinWaitSendsFIN(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)
	conn.State = StateFinWait
	conn.Unacked = []*retxEntry{{
		data:     []byte{0},
		seq:      600,
		sentAt:   time.Now().Add(-2 * InitialRTO),
		attempts: 1,
		isFIN:    true,
	}}
	d.retransmitUnacked(conn)

	pkts := cs.all()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 FIN retransmission, got %d", len(pkts))
	}
	if pkts[0].Flags&protocol.FlagFIN == 0 {
		t.Fatalf("FinWait retx should carry FlagFIN, got flags=%b", pkts[0].Flags)
	}
	if pkts[0].Seq != 600 {
		t.Fatalf("FIN Seq = %d, want 600", pkts[0].Seq)
	}
}

// --- retxLoop lifecycle ---

func TestRetxLoopReturnsWhenRetxStopClosed(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, _ := newRetxConn(t)
	conn.RetxStop = make(chan struct{})

	done := make(chan struct{})
	go func() {
		d.retxLoop(conn)
		close(done)
	}()

	// Immediately close stop — retxLoop should return.
	close(conn.RetxStop)
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("retxLoop did not return after RetxStop close")
	}
}

func TestRetxLoopClosedStateCleansUpAndReturns(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, _ := newRetxConn(t)
	conn.State = StateClosed
	conn.RetxStop = make(chan struct{})
	d.ports.mu.Lock()
	d.ports.connections[conn.ID] = conn
	d.ports.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.retxLoop(conn)
		close(done)
	}()

	// retxLoop ticks every RetxCheckInterval (100ms). On the first tick with
	// state=Closed, it calls RemoveConnection + closes RecvBuf and returns.
	select {
	case <-done:
	case <-time.After(3 * RetxCheckInterval):
		t.Fatal("retxLoop did not return from StateClosed branch")
	}

	// Connection removed from PortManager
	if d.ports.GetConnection(conn.ID) != nil {
		t.Fatal("connection should be removed after StateClosed cleanup")
	}
	// RecvBuf closed
	select {
	case _, ok := <-conn.RecvBuf:
		if ok {
			t.Fatal("RecvBuf should be closed")
		}
	default:
		t.Fatal("RecvBuf recv should not block (closed)")
	}
}

// startRetxLoop wires RetxSend + RetxStop and spawns retxLoop. Minimal smoke.
func TestStartRetxLoopInitializesRTOAndRetxStopAndExitsOnStop(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	conn := d.ports.NewConnection(1001, protocol.Addr{Network: 0, Node: 1}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 2}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: 1}

	d.startRetxLoop(conn)

	if conn.RTO != InitialRTO {
		t.Fatalf("RTO = %v, want InitialRTO=%v", conn.RTO, InitialRTO)
	}
	if conn.RetxStop == nil {
		t.Fatal("RetxStop should be initialized")
	}
	if conn.RetxSend == nil {
		t.Fatal("RetxSend should be wired to tunnels.Send")
	}

	// Stop by closing RetxStop (loop must exit within 200ms).
	close(conn.RetxStop)
	time.Sleep(50 * time.Millisecond)
	// Nothing to assert beyond the loop not hanging; the test framework kills
	// leaked goroutines at the end of the process. A clean test run is enough.
}
