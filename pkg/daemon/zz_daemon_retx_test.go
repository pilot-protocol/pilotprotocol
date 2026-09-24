// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// newDaemonRetxConn returns a Connection prepared for retransmission tests with
// a RetxSend capturer. Callers must close conn.RetxStop themselves if they
// start the retransmission goroutine.
func newDaemonRetxConn(t *testing.T) (*Connection, *capturedRetx) {
	t.Helper()
	cap := &capturedRetx{}
	conn := &Connection{
		ID:         1,
		LocalAddr:  protocol.Addr{Node: 42},
		LocalPort:  5678,
		RemoteAddr: protocol.Addr{Node: 99},
		RemotePort: 3000,
		State:      StateEstablished,
		SendSeq:    1000,
		RecvAck:    2000,
		CongWin:    InitialCongWin,
		SSThresh:   MaxCongWin / 2,
		RTO:        InitialRTO,
		WindowCh:   make(chan struct{}, 1),
		RetxStop:   make(chan struct{}),
		RetxSend:   cap.Send,
		RecvBuf:    make(chan []byte, RecvBufSize),
	}
	return conn, cap
}

type capturedRetx struct {
	mu  sync.Mutex
	pkt []*protocol.Packet
}

func (c *capturedRetx) Send(p *protocol.Packet) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pkt = append(c.pkt, p)
}

func (c *capturedRetx) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pkt)
}

func (c *capturedRetx) Last() *protocol.Packet {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pkt) == 0 {
		return nil
	}
	return c.pkt[len(c.pkt)-1]
}

// --- retransmitUnacked ------------------------------------------------------

func TestRetransmitUnackedEmptyListReturns(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)

	d.retransmitUnacked(conn)

	if captured.Len() != 0 {
		t.Errorf("expected 0 packets, got %d", captured.Len())
	}
}

func TestRetransmitUnackedWithinRTOWindowReturns(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	// Pretend we retransmitted 10ms ago — RTO is 1s so we're inside the window.
	conn.LastRetxTime = time.Now().Add(-10 * time.Millisecond)
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: []byte("x"), sentAt: time.Now().Add(-1 * time.Hour)},
	}
	d.retransmitUnacked(conn)

	if captured.Len() != 0 {
		t.Errorf("within-RTO window: expected no packets, got %d", captured.Len())
	}
}

func TestRetransmitUnackedAllSackedSkipsAll(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: []byte("a"), sentAt: time.Now().Add(-1 * time.Hour), sacked: true},
		{seq: 1001, data: []byte("b"), sentAt: time.Now().Add(-1 * time.Hour), sacked: true},
	}
	d.retransmitUnacked(conn)

	if captured.Len() != 0 {
		t.Errorf("all-sacked: expected no packets, got %d", captured.Len())
	}
}

func TestRetransmitUnackedFirstNonSackedNotTimedOutBreaks(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	// Fresh entry — inside RTO.
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: []byte("fresh"), sentAt: time.Now(), sacked: false},
	}
	d.retransmitUnacked(conn)

	if captured.Len() != 0 {
		t.Errorf("fresh segment: expected no packets, got %d", captured.Len())
	}
}

func TestRetransmitUnackedTimedOutResendsAndEntersRecovery(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	conn.CongWin = InitialCongWin * 4 // something to halve
	entry := &retxEntry{
		seq:      1000,
		data:     []byte("lost"),
		sentAt:   time.Now().Add(-1 * time.Hour),
		attempts: 0,
	}
	conn.Unacked = []*retxEntry{entry}
	priorRTO := conn.RTO

	d.retransmitUnacked(conn)

	if captured.Len() != 1 {
		t.Fatalf("expected 1 retransmitted packet, got %d", captured.Len())
	}
	pkt := captured.Last()
	if pkt.Flags&protocol.FlagACK == 0 {
		t.Errorf("FlagACK missing, flags=%x", pkt.Flags)
	}
	if pkt.Seq != 1000 {
		t.Errorf("Seq = %d, want 1000", pkt.Seq)
	}
	if string(pkt.Payload) != "lost" {
		t.Errorf("Payload = %q, want %q", pkt.Payload, "lost")
	}
	if entry.attempts != 1 {
		t.Errorf("attempts = %d, want 1", entry.attempts)
	}
	if !conn.InRecovery {
		t.Error("expected InRecovery to be true after loss event")
	}
	if conn.CongWin != MaxSegmentSize {
		t.Errorf("CongWin = %d, want MaxSegmentSize=%d after timeout (RFC 5681 §3.1)", conn.CongWin, MaxSegmentSize)
	}
	if conn.RTO <= priorRTO {
		t.Errorf("RTO = %v, expected doubled from %v", conn.RTO, priorRTO)
	}
	if conn.LastRetxTime.IsZero() {
		t.Error("LastRetxTime should have been set")
	}
	if conn.Stats.Retransmits != 1 {
		t.Errorf("Retransmits = %d, want 1", conn.Stats.Retransmits)
	}
}

func TestRetransmitUnackedMaxAttemptsSendsRSTAndCloses(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	conn.Unacked = []*retxEntry{
		{
			seq:         1000,
			data:        []byte("dead"),
			sentAt:      time.Now().Add(-1 * time.Hour),
			attempts:    MaxRetxAttempts,
			rtoAttempts: MaxRetxAttempts,
		},
	}

	d.retransmitUnacked(conn)

	if captured.Len() != 1 {
		t.Fatalf("expected 1 RST packet, got %d", captured.Len())
	}
	pkt := captured.Last()
	if pkt.Flags&protocol.FlagRST == 0 {
		t.Errorf("expected FlagRST, flags=%x", pkt.Flags)
	}
	if pkt.Payload != nil {
		t.Errorf("RST should not carry payload, got %d bytes", len(pkt.Payload))
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Errorf("State = %v, want StateClosed", st)
	}
}

func TestRetransmitUnackedFinWaitSendsFinInsteadOfData(t *testing.T) {
	t.Parallel()
	d := &Daemon{ports: NewPortManager()}
	conn, captured := newDaemonRetxConn(t)
	conn.State = StateFinWait
	conn.Unacked = []*retxEntry{
		{seq: 1234, data: nil, isFIN: true, sentAt: time.Now().Add(-1 * time.Hour), attempts: 0},
	}

	d.retransmitUnacked(conn)

	if captured.Len() != 1 {
		t.Fatalf("expected 1 FIN packet, got %d", captured.Len())
	}
	pkt := captured.Last()
	if pkt.Flags&protocol.FlagFIN == 0 {
		t.Errorf("expected FlagFIN, flags=%x", pkt.Flags)
	}
	if pkt.Flags&protocol.FlagACK != 0 {
		t.Errorf("FlagACK should NOT be set on FIN retransmit, flags=%x", pkt.Flags)
	}
	if pkt.Seq != 1234 {
		t.Errorf("Seq = %d, want 1234", pkt.Seq)
	}
}

// --- startRetxLoop ---------------------------------------------------------

func TestStartRetxLoopInitializesRTOAndRetxSend(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(5678, protocol.Addr{Node: peerNode}, 3000)
	conn.LocalAddr = protocol.Addr{Node: 42}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.Mu.Unlock()

	d.startRetxLoop(conn)

	if conn.RTO != InitialRTO {
		t.Errorf("RTO = %v, want InitialRTO=%v", conn.RTO, InitialRTO)
	}
	if conn.RetxSend == nil {
		t.Fatal("RetxSend must be set")
	}

	// Stop the goroutine cleanly so it doesn't leak.
	close(conn.RetxStop)

	// Smoke-test the callback: with no peer registered in d.tunnels, Send returns
	// error; we just verify no panic.
	conn.RetxSend(&protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoStream, Src: conn.LocalAddr, Dst: conn.RemoteAddr})
}

// --- sendSegment happy path ------------------------------------------------

func TestSendSegmentHappyPathSendsDataFrameAndAdvancesSeq(t *testing.T) {
	t.Parallel()
	d, peer := newPacketDaemon(t, nil)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	const peerNode = uint32(99)
	d.tunnels.AddPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(5678, protocol.Addr{Node: peerNode}, 3000)
	conn.LocalAddr = protocol.Addr{Node: 42}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 500
	conn.RecvAck = 300
	conn.Mu.Unlock()

	// Pre-populate delayed ACK state — sendSegment must reset it.
	conn.AckMu.Lock()
	conn.PendingACKs = 2
	conn.ACKTimer = time.AfterFunc(10*time.Second, func() {})
	conn.AckMu.Unlock()

	payload := []byte("hello-segment")
	if err := d.sendSegment(conn, payload); err != nil {
		t.Fatalf("sendSegment: %v", err)
	}

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no data frame received")
	}
	if string(frame[:4]) != "PILT" {
		t.Fatalf("missing PILT magic: %x", frame[:4])
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pkt.Flags&protocol.FlagACK == 0 {
		t.Errorf("FlagACK missing, flags=%x", pkt.Flags)
	}
	if pkt.Protocol != protocol.ProtoStream {
		t.Errorf("Protocol = %d, want ProtoStream", pkt.Protocol)
	}
	if pkt.Seq != 500 {
		t.Errorf("Seq = %d, want 500", pkt.Seq)
	}
	if pkt.Ack != 300 {
		t.Errorf("Ack = %d, want 300", pkt.Ack)
	}
	if string(pkt.Payload) != string(payload) {
		t.Errorf("Payload = %q, want %q", pkt.Payload, payload)
	}

	// Verify SendSeq advanced by payload length.
	conn.Mu.Lock()
	seq := conn.SendSeq
	conn.Mu.Unlock()
	if seq != 500+uint32(len(payload)) {
		t.Errorf("SendSeq = %d, want %d", seq, 500+uint32(len(payload)))
	}

	// Delayed ACK state must be reset.
	conn.AckMu.Lock()
	pending := conn.PendingACKs
	timer := conn.ACKTimer
	conn.AckMu.Unlock()
	if pending != 0 {
		t.Errorf("PendingACKs = %d, want 0", pending)
	}
	if timer != nil {
		t.Errorf("ACKTimer = %v, want nil", timer)
	}

	// Unacked should have exactly one entry tracking this segment.
	conn.RetxMu.Lock()
	n := len(conn.Unacked)
	var unackedSeq uint32
	if n > 0 {
		unackedSeq = conn.Unacked[0].seq
	}
	conn.RetxMu.Unlock()
	if n != 1 {
		t.Errorf("Unacked len = %d, want 1", n)
	}
	if unackedSeq != 500 {
		t.Errorf("Unacked[0].seq = %d, want 500", unackedSeq)
	}
}

func TestSendSegmentRetxStopClosedAbortsZeroWinProbe(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)

	// Construct a connection with an EXHAUSTED window so sendSegment blocks in
	// the zero-window probe loop, then close RetxStop to trigger the
	// ErrConnClosed branch.
	conn := &Connection{
		LocalAddr:   protocol.Addr{Node: 42},
		RemoteAddr:  protocol.Addr{Node: 99},
		LocalPort:   5678,
		RemotePort:  3000,
		State:       StateEstablished,
		SendSeq:     500,
		RecvAck:     200,
		CongWin:     MaxSegmentSize, // small
		PeerRecvWin: 1,              // peer says window is full
		RetxStop:    make(chan struct{}),
		WindowCh:    make(chan struct{}, 1),
		RecvBuf:     make(chan []byte, RecvBufSize),
	}
	// Pre-fill Unacked so BytesInFlight >= EffectiveWindow (= 1).
	conn.Unacked = []*retxEntry{
		{seq: 100, data: []byte("x"), sentAt: time.Now(), attempts: 1},
	}

	// Kick off sendSegment in a goroutine; it should block in the probe loop
	// until we close RetxStop.
	errCh := make(chan error, 1)
	go func() {
		errCh <- d.sendSegment(conn, []byte("never-sent"))
	}()

	// Give the goroutine a moment to enter the wait loop.
	time.Sleep(50 * time.Millisecond)
	close(conn.RetxStop)

	select {
	case err := <-errCh:
		if err != protocol.ErrConnClosed {
			t.Errorf("err = %v, want protocol.ErrConnClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendSegment did not return after RetxStop closed")
	}

	// SendSeq must not have advanced (we never sent).
	if conn.SendSeq != 500 {
		t.Errorf("SendSeq = %d, want 500 (unchanged)", conn.SendSeq)
	}
}
