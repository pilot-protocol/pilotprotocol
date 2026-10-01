// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// readLargeFrame reads one UDP datagram with a 64KB buffer (sufficient for
// full-MSS payloads + header). readOneFrame's 2KB buffer truncates them.
func readLargeFrame(t *testing.T, c *net.UDPConn) []byte {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 65536)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out
}

// setupSendDataConn wires a daemon + peer listener + connection ready for
// SendData/sendDataImmediate/nagleFlush tests. The returned connection is in
// StateEstablished with SendSeq=500, RecvAck=300, CongWin=InitialCongWin so
// sendSegment has room to write.
func setupSendDataConn(t *testing.T) (*Daemon, *net.UDPConn, *Connection) {
	t.Helper()
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
	return d, peer, conn
}

// ---------------------------------------------------------------------------
// SendData state guard + dispatch branches
// ---------------------------------------------------------------------------

func TestSendDataNotEstablishedReturnsError(t *testing.T) {
	t.Parallel()
	d, _, conn := setupSendDataConn(t)
	conn.Mu.Lock()
	conn.State = StateSynSent
	conn.Mu.Unlock()

	err := d.SendData(conn, []byte("x"))
	if err == nil {
		t.Fatal("want error when state != StateEstablished")
	}
}

func TestSendDataNoDelayRoutesImmediate(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)
	conn.NoDelay = true

	if err := d.SendData(conn, []byte("hello")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no frame received")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "hello" {
		t.Errorf("Payload=%q, want 'hello'", pkt.Payload)
	}
	// Nagle buffer must NOT have been used.
	conn.NagleMu.Lock()
	n := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if n != 0 {
		t.Errorf("NagleBuf size=%d, want 0 under NoDelay", n)
	}
}

func TestSendDataNagleSmallNoUnackedSendsImmediately(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)
	// NoDelay=false by default; Unacked empty by default.

	if err := d.SendData(conn, []byte("abc")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no frame received")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "abc" {
		t.Errorf("Payload=%q, want 'abc'", pkt.Payload)
	}
	// After sendSegment, NagleBuf should be empty.
	conn.NagleMu.Lock()
	remaining := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if remaining != 0 {
		t.Errorf("NagleBuf=%d, want 0 after flush", remaining)
	}
}

func TestSendDataNagleFullMSSSegmentEmitsSingleFrame(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)

	payload := bytes.Repeat([]byte{0x61}, SendSegmentSize) // exactly one MSS
	if err := d.SendData(conn, payload); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	frame := readLargeFrame(t, peer)
	if frame == nil {
		t.Fatal("no frame received")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if len(pkt.Payload) != SendSegmentSize {
		t.Errorf("Payload size=%d, want %d", len(pkt.Payload), SendSegmentSize)
	}
}

// ---------------------------------------------------------------------------
// sendDataImmediate segmentation
// ---------------------------------------------------------------------------

func TestSendDataImmediateEmptyDataNoFrames(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)

	if err := d.sendDataImmediate(conn, nil); err != nil {
		t.Fatalf("sendDataImmediate: %v", err)
	}
	// No frame should be sent.
	peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 4096)
	n, _, err := peer.ReadFromUDP(buf)
	if err == nil {
		t.Errorf("expected timeout, got %d bytes", n)
	}
}

// ---------------------------------------------------------------------------
// nagleFlush direct branches
// ---------------------------------------------------------------------------

func TestNagleFlushEmptyBufReturnsNilWithoutSend(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)

	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
	peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1024)
	if n, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Errorf("expected no frames, got %d bytes", n)
	}
}

func TestNagleFlushWaitsForNagleChWhenUnackedPresent(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)

	// Queue sub-MSS data in Nagle buffer.
	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, []byte("waiting")...)
	conn.NagleMu.Unlock()

	// Pre-populate Unacked so nagleFlush must wait.
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{seq: 1, data: []byte("x"), sentAt: time.Now(), attempts: 1}}
	conn.RetxMu.Unlock()

	errCh := make(chan error, 1)
	go func() { errCh <- d.nagleFlush(conn) }()

	// Wake it by signaling NagleCh after a short delay.
	time.Sleep(20 * time.Millisecond)
	select {
	case conn.NagleCh <- struct{}{}:
	default:
		t.Fatal("NagleCh not ready for signal")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("nagleFlush: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("nagleFlush did not return after NagleCh signal")
	}

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no frame received after NagleCh wake")
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "waiting" {
		t.Errorf("Payload=%q, want 'waiting'", pkt.Payload)
	}
}

func TestHeldTailIsDroppedWhenConnectionStops(t *testing.T) {
	t.Parallel()
	d, _, conn := setupSendDataConn(t)
	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, []byte("small")...)
	conn.NagleMu.Unlock()
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{seq: 1, data: []byte("x"), sentAt: time.Now(), attempts: 1}}
	conn.RetxMu.Unlock()
	conn.RetxStop = make(chan struct{})

	// The short write is held behind the unacknowledged short segment; the
	// caller is not made to wait for it.
	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
	flusher := func() bool {
		conn.NagleMu.Lock()
		defer conn.NagleMu.Unlock()
		return conn.tailFlusher
	}
	if !flusher() {
		t.Fatal("a held tail should leave a flusher waiting to send it")
	}

	// The connection stopping ends the wait without sending.
	close(conn.RetxStop)
	deadline := time.Now().Add(2 * time.Second)
	for flusher() {
		if time.Now().After(deadline) {
			t.Fatal("the flusher did not exit after RetxStop closed")
		}
		time.Sleep(time.Millisecond)
	}
	conn.RetxMu.Lock()
	sent := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if sent != 1 {
		t.Errorf("%d segments tracked, want only the one that was already in flight", sent)
	}
}

func TestNagleFlushNagleTimeoutFlushesEventually(t *testing.T) {
	t.Parallel()
	d, peer, conn := setupSendDataConn(t)
	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, []byte("tick")...)
	conn.NagleMu.Unlock()
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{seq: 1, data: []byte("x"), sentAt: time.Now(), attempts: 1}}
	conn.RetxMu.Unlock()

	// nagleFlush leaves the held write in the buffer and returns; it goes
	// out when NagleTimeout has passed with the short segment ahead of it
	// still unacknowledged.
	start := time.Now()
	if err := d.nagleFlush(conn); err != nil {
		t.Fatalf("nagleFlush: %v", err)
	}
	if returned := time.Since(start); returned >= NagleTimeout {
		t.Errorf("nagleFlush took %v to return: it waited for the held write", returned)
	}

	frame := readOneFrame(t, peer)
	if frame == nil {
		t.Fatal("no frame received after Nagle timeout")
	}
	if elapsed := time.Since(start); elapsed < NagleTimeout-5*time.Millisecond {
		t.Errorf("held write was sent too early: %v (want >= %v)", elapsed, NagleTimeout)
	}
	pkt, err := protocol.Unmarshal(frame[4:])
	if err != nil {
		t.Fatal(err)
	}
	if string(pkt.Payload) != "tick" {
		t.Errorf("Payload=%q, want 'tick'", pkt.Payload)
	}
}
