// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"sort"
	"sync"
	"testing"
	"time"
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
// from each piece: the last piece of a 65537-byte write is one byte, and it
// must leave with the write rather than wait for an ACK.
func TestLargeWriteSendsItsLastPieceAtOnce(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xDADA0002)
	conn.NoDelay = false
	conn.CongWin = MaxCongWin
	conn.PeerRecvWin = 1 << 20

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
	if nagleWritePiece%SendSegmentSize != 0 {
		t.Fatalf("nagleWritePiece (%d) is not a whole number of %d-byte segments", nagleWritePiece, SendSegmentSize)
	}
}
