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

// A tunnel send error part-way through a large write used to end the write:
// the failed segment is tracked and retransmitted, but the pieces not yet
// buffered were dropped, and the connection's next write took their place in
// the stream. Every byte of the write must be committed to the stream — given
// a sequence number, or still in the send buffer — in order.
func TestLargeWriteSurvivesTunnelSendErrors(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })
	const peer uint32 = 0xDADA0003 // no tunnel to it: every send fails
	conn := d.ports.NewConnection(2003, protocol.Addr{Network: 0, Node: peer}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peer}
	conn.RemotePort = 80
	conn.SendSeq = 1000
	conn.CongWin = MaxCongWin
	conn.PeerRecvWin = 1 << 20
	t.Cleanup(func() { d.ports.RemoveConnection(conn.ID) })
	ackEverything(t, conn)

	const size = 200000
	_ = d.SendData(conn, make([]byte, size)) // the last piece's error is reported
	conn.Mu.Lock()
	sent := int(conn.SendSeq - 1000)
	conn.Mu.Unlock()
	conn.NagleMu.Lock()
	buffered := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if sent+buffered != size {
		t.Fatalf("%d bytes given sequence numbers and %d buffered, of a %d-byte write: the rest was dropped", sent, buffered, size)
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
