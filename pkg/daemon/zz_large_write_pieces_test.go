// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// ackEverything stands in for a peer that acknowledges at once: it keeps
// emptying the connection's retransmission queue and waking the sender.
func ackEverything(t *testing.T, conn *Connection) {
	t.Helper()
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop) })
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(time.Millisecond):
			}
			conn.RetxMu.Lock()
			conn.Unacked = nil
			conn.RetxMu.Unlock()
			select {
			case conn.WindowCh <- struct{}{}:
			default:
			}
			select {
			case conn.NagleCh <- struct{}{}:
			default:
			}
		}
	}()
}

// A write larger than nagleWritePiece goes through the send buffer piece by
// piece. Two writers on one connection must still each come out whole and in
// one run: without a per-connection write lock, review saw a 70000-byte
// write leave as A×65536 B×100 A×4464, and writers retrying ErrSendBufFull
// put parts of their writes on the wire twice.
func TestConcurrentLargeWritesDoNotInterleave(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xDADA0001)
	conn.NoDelay = false
	conn.CongWin = MaxCongWin
	ackEverything(t, conn)

	const size = 3*nagleWritePiece + 777
	writes := map[byte][]byte{'A': bytes.Repeat([]byte{'A'}, size), 'B': bytes.Repeat([]byte{'B'}, size), 'C': bytes.Repeat([]byte{'C'}, size)}
	var wg sync.WaitGroup
	for _, w := range writes {
		wg.Add(1)
		go func(w []byte) {
			defer wg.Done()
			if err := d.SendData(conn, w); err != nil {
				t.Errorf("SendData: %v", err)
			}
		}(w)
	}

	type seg struct {
		seq  uint32
		data []byte
	}
	var segs []seg
	total := 0
	for total < len(writes)*size {
		pkt := readOneSegment(t, pc, 5*time.Second)
		segs = append(segs, seg{pkt.Seq, pkt.Payload})
		total += len(pkt.Payload)
	}
	wg.Wait()
	if total != len(writes)*size {
		t.Fatalf("%d bytes on the wire for %d written", total, len(writes)*size)
	}
	sort.Slice(segs, func(i, j int) bool { return seqAfter(segs[j].seq, segs[i].seq) })
	var stream []byte
	for _, s := range segs {
		stream = append(stream, s.data...)
	}
	runs := 0
	for i := range stream {
		if i == 0 || stream[i] != stream[i-1] {
			runs++
		}
	}
	if runs != len(writes) {
		t.Fatalf("the stream holds %d runs of bytes for %d writes: writes were interleaved", runs, len(writes))
	}
}

// Whether a short remainder may be held is decided from the whole write, not
// from each piece: the last piece of a large write is short, and it must
// leave with the write rather than wait for an ACK. Nagle holds a short
// remainder only while an earlier short segment is unacknowledged, so one is
// left in flight first.
func TestLargeWriteSendsItsLastPieceAtOnce(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xDADA0002)
	conn.NoDelay = false
	conn.CongWin = MaxCongWin
	conn.PeerRecvWin = 1 << 20

	// A short write goes out and is never acknowledged.
	if err := d.SendData(conn, make([]byte, 10)); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	readOneSegment(t, pc, 2*time.Second)

	const size = nagleWritePiece + 1
	if err := d.SendData(conn, make([]byte, size)); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	conn.NagleMu.Lock()
	held := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if held != 0 {
		t.Fatalf("%d bytes of a %d-byte write were held back", held, size)
	}
	got := 0
	for got < size {
		got += len(readOneSegment(t, pc, 2*time.Second).Payload)
	}
}

// nagleWritePiece is a whole number of segments, so only the last piece of a
// write can end in a short segment.
var _ [0]struct{} = [nagleWritePiece % SendSegmentSize]struct{}{}

// newUnreachableConn returns an established connection, starting at sequence
// 1000, to a peer the daemon has no tunnel to: every send fails, after the
// segment has been given its sequence number and tracked for retransmission.
func newUnreachableConn(t *testing.T, peer uint32) (*Daemon, *Connection) {
	t.Helper()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })
	conn := d.ports.NewConnection(2003, protocol.Addr{Network: 0, Node: peer}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peer}
	conn.RemotePort = 80
	conn.SendSeq = 1000
	conn.CongWin = MaxCongWin
	conn.PeerRecvWin = 1 << 20
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })
	return d, conn
}

// trackedStream returns the data segments awaiting acknowledgement, joined
// in sequence order from 1000, and fails if they leave a gap.
func trackedStream(t *testing.T, conn *Connection) []byte {
	t.Helper()
	conn.RetxMu.Lock()
	defer conn.RetxMu.Unlock()
	var stream []byte
	for _, e := range conn.Unacked {
		if e.isFIN {
			continue
		}
		if want := uint32(1000 + len(stream)); e.seq != want {
			t.Fatalf("tracked segment at seq %d, want %d: the stream has a gap", e.seq, want)
		}
		stream = append(stream, e.data...)
	}
	return stream
}

// A tunnel send error part-way through a large write used to end the write:
// the failed segment is tracked and retransmitted, but the pieces not yet
// buffered were dropped, and the connection's next write took their place in
// the stream. Every byte of the write must be given a sequence number, in
// order, and the write reported done: the retransmit loop repairs the error.
func TestLargeWriteSurvivesTunnelSendErrors(t *testing.T) {
	t.Parallel()
	d, conn := newUnreachableConn(t, 0xDADA0003)
	ackEverything(t, conn)

	const size = 200000
	if err := d.SendData(conn, make([]byte, size)); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	conn.Mu.Lock()
	sent := int(conn.SendSeq - 1000)
	conn.Mu.Unlock()
	conn.NagleMu.Lock()
	buffered := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if sent != size || buffered != 0 {
		t.Fatalf("%d bytes given sequence numbers and %d buffered, of a %d-byte write", sent, buffered, size)
	}
}

// The same for a write of one piece or less, and so for the last piece of a
// large one. A send error on its first segment used to return at once and
// leave the rest of it in the send buffer, where nothing sends it: only a
// held short remainder has a goroutine waiting to flush it. send-message
// then waited for the receiver's idle timeout.
func TestWriteOfOnePieceSurvivesTunnelSendErrors(t *testing.T) {
	t.Parallel()
	for _, size := range []int{10, 3*SendSegmentSize + 10, nagleWritePiece} {
		d, conn := newUnreachableConn(t, 0xDADA0005)
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i * 7)
		}
		if err := d.SendData(conn, data); err != nil {
			t.Errorf("%d-byte write: SendData: %v", size, err)
		}
		conn.NagleMu.Lock()
		buffered := len(conn.NagleBuf)
		conn.NagleMu.Unlock()
		if buffered != 0 {
			t.Errorf("%d-byte write: %d bytes left in the send buffer with nothing to send them", size, buffered)
		}
		if got := trackedStream(t, conn); !bytes.Equal(got, data) {
			t.Errorf("%d-byte write: %d bytes given sequence numbers, want all of them", size, len(got))
		}
	}
}

// Closing sends what is left in the send buffer ahead of the FIN. A send
// error on its first segment used to drop the rest, and the FIN took its
// place in the stream. Every byte must be given a sequence number, and the
// FIN the one after the last of them.
func TestCloseCommitsTheWholeTailDespiteSendErrors(t *testing.T) {
	t.Parallel()
	d, conn := newUnreachableConn(t, 0xDADA0006)
	// More than a segment can be left: a writer's piece, appended but not yet
	// flushed, joins a held remainder.
	tail := make([]byte, 2*SendSegmentSize+100)
	for i := range tail {
		tail[i] = byte(i * 7)
	}
	conn.NagleMu.Lock()
	conn.NagleBuf = append(conn.NagleBuf, tail...)
	conn.NagleMu.Unlock()

	d.CloseConnection(conn)

	if got := trackedStream(t, conn); !bytes.Equal(got, tail) {
		t.Fatalf("%d bytes of a %d-byte tail given sequence numbers before the FIN", len(got), len(tail))
	}
	// The FIN's sequence number comes directly after the tail. It is sent
	// once the data is acknowledged (sendFINAfterData), never here.
	conn.Mu.Lock()
	next := conn.SendSeq
	conn.Mu.Unlock()
	if want := uint32(1000 + len(tail) + 1); next != want {
		t.Fatalf("SendSeq after close = %d, want %d: the FIN reserved directly after the tail", next, want)
	}
}

// A large write blocked on the window must not go on sending after the
// connection is closed: only the piece already in the buffer may follow.
func TestLargeWriteStopsWhenTheConnectionCloses(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xDADA0004)
	conn.NoDelay = false
	conn.CongWin = InitialCongWin

	done := make(chan error, 1)
	go func() { done <- d.SendData(conn, make([]byte, 4*nagleWritePiece)) }()
	// The first piece fills the window and blocks.
	readOneSegment(t, pc, 2*time.Second)
	time.Sleep(50 * time.Millisecond)
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.Mu.Unlock()
	ackEverything(t, conn)

	select {
	case err := <-done:
		if err == nil {
			t.Error("a write cut short by a close reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the write did not return after the close")
	}
	conn.Mu.Lock()
	sent := int(conn.SendSeq - 1000)
	conn.Mu.Unlock()
	if sent > nagleWritePiece {
		t.Fatalf("%d bytes sent after a close; at most the buffered piece (%d) may be", sent, nagleWritePiece)
	}
}
