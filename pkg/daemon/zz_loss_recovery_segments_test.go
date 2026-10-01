// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// In fast recovery the congestion window grows by one segment per duplicate
// ACK, which is how the segments that have left the network are accounted
// for. Leaving the SACKed ones out of the amount in flight as well counted
// each of them twice: every duplicate ACK released two new segments, the
// amount outstanding doubled each round trip while the hole stayed open, and
// the peer's reorder buffer overflowed.
func TestWindowCountsSACKedBytesInFastRecovery(t *testing.T) {
	t.Parallel()
	const segs = 10
	unacked := func() []*retxEntry {
		out := make([]*retxEntry, segs)
		for i := range out {
			out[i] = &retxEntry{seq: uint32(1000 + i*SendSegmentSize), data: make([]byte, SendSegmentSize), attempts: 1}
			out[i].sacked = i > 0 // the first is the hole, the rest are at the peer
		}
		return out
	}
	// The window as fast recovery leaves it after segs-1 duplicate ACKs:
	// exactly what is outstanding.
	c := &Connection{PeerRecvWin: 1 << 20, CongWin: segs * SendSegmentSize, Unacked: unacked()}

	c.InRecovery, c.FastRecovery = true, true
	if c.WindowAvailable() {
		t.Fatalf("fast recovery, %d segments outstanding against a window of %d: window should be closed", segs, segs)
	}
	c.CongWin += SendSegmentSize // one more duplicate ACK
	if !c.WindowAvailable() {
		t.Fatal("fast recovery: one more duplicate ACK should release one more segment")
	}

	// Outside fast recovery nothing inflates the window, and a SACKed
	// segment is simply no longer in flight.
	c.InRecovery, c.FastRecovery = false, false
	c.CongWin = 2 * SendSegmentSize
	if !c.WindowAvailable() {
		t.Fatal("outside fast recovery, one unSACKed segment against a window of two: window should be open")
	}
}

// When the oldest outstanding segment is lost, every later one waits in the
// peer's reorder buffer. That buffer holds MaxOOOBuf segments and drops the
// rest without a word, so a sender past it loses segments on a clean path and
// then recovers them one timeout at a time.
func TestWindowClosesAtPeerReorderCapacity(t *testing.T) {
	t.Parallel()
	outstanding := func(n int) []*retxEntry {
		out := make([]*retxEntry, n)
		for i := range out {
			out[i] = &retxEntry{seq: uint32(1000 + i*10), data: make([]byte, 10), attempts: 1}
		}
		return out
	}
	c := &Connection{PeerRecvWin: MaxRecvWin, CongWin: MaxCongWin}

	c.Unacked = outstanding(MaxSegmentsOutstanding - 1)
	if !c.WindowAvailable() {
		t.Fatalf("%d segments outstanding: window should be open", MaxSegmentsOutstanding-1)
	}
	c.Unacked = outstanding(MaxSegmentsOutstanding)
	if c.WindowAvailable() {
		t.Fatalf("%d segments outstanding, as many as the peer can hold out of order: window should be closed", MaxSegmentsOutstanding)
	}
	if MaxSegmentsOutstanding > MaxOOOBuf {
		t.Fatalf("MaxSegmentsOutstanding %d exceeds the reorder buffer, %d", MaxSegmentsOutstanding, MaxOOOBuf)
	}
}

// After a retransmission timeout, each further segment missing from that
// window used to wait for a timeout of its own, and the timeout doubles each
// time. Thirty missing segments took minutes; the connection was abandoned
// first.
func TestPartialAckInTimeoutRecoveryRetransmitsNextSegment(t *testing.T) {
	t.Parallel()
	const (
		seqA = uint32(1000)
		seqB = seqA + SendSegmentSize
		seqC = seqB + SendSegmentSize
		end  = seqC + SendSegmentSize
	)
	setup := func() (*Connection, *capturedSender) {
		c := newAckTestConn(t)
		cs := &capturedSender{}
		c.RetxSend = cs.send
		c.LastAck = seqA
		// Timeout recovery: entered by the retransmission timer, not by
		// duplicate ACKs.
		c.InRecovery, c.FastRecovery = true, false
		c.RecoveryPoint = end
		c.SSThresh = 2 * SendSegmentSize
		c.CongWin = SendSegmentSize
		sent := time.Now().Add(-2 * time.Second)
		c.Unacked = []*retxEntry{
			{seq: seqA, data: make([]byte, SendSegmentSize), attempts: 2, sentAt: time.Now()}, // the timer's retransmission
			{seq: seqB, data: make([]byte, SendSegmentSize), attempts: 1, sentAt: sent},
			{seq: seqC, data: make([]byte, SendSegmentSize), attempts: 1, sentAt: sent},
		}
		return c, cs
	}

	// The ACK for the retransmission stops at seqB: the peer does not have it.
	c, cs := setup()
	c.ProcessAck(seqB, true)
	pkts := cs.all()
	if len(pkts) != 1 || pkts[0].Seq != seqB {
		t.Fatalf("partial ACK in timeout recovery: retransmitted %d segments, want exactly the next missing one (seq %d)", len(pkts), seqB)
	}
	if !c.InRecovery {
		t.Fatal("partial ACK should leave the connection in recovery")
	}
	// The next partial ACK moves on to seqC.
	c.ProcessAck(seqC, true)
	if pkts = cs.all(); len(pkts) != 2 || pkts[1].Seq != seqC {
		t.Fatalf("second partial ACK: %d retransmissions in total, want 2 with the last for seq %d", len(pkts), seqC)
	}

	// An ACK for the whole window ends recovery and retransmits nothing.
	c, cs = setup()
	c.ProcessAck(end, true)
	if n := len(cs.all()); n != 0 {
		t.Fatalf("full ACK in timeout recovery retransmitted %d segments, want none", n)
	}
	if c.InRecovery {
		t.Fatal("full ACK should end recovery")
	}

	// Outside recovery an ACK retransmits nothing.
	c, cs = setup()
	c.InRecovery = false
	c.ProcessAck(seqB, true)
	if n := len(cs.all()); n != 0 {
		t.Fatalf("ACK outside recovery retransmitted %d segments, want none", n)
	}
}
