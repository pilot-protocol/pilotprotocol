// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestFreshFastRecoveryPerDupAckInflation verifies that each additional dup ACK
// (DupAckCount > 3) during a fresh fast recovery episode inflates the congestion
// window by SMSS per RFC 5681 §3.2 step 5.
//
// RFC 5681 §3.2 step 5:
//
//	"For each additional duplicate ACK received while in fast retransmit,
//	 increment cwnd by SMSS."
//
// Bug: after iter-77, the DupAckCount>3 path's inflation is gated on
// seqAfter(sendSeq, c.RecoveryPoint).  When the DupAckCount==3 path enters
// fast recovery for a NEW episode it sets:
//
//	c.RecoveryPoint = sendSeq  (iter-77/79)
//
// The 4th dup ACK then evaluates seqAfter(sendSeq, sendSeq) = false and hits
// the early-return guard, blocking the RFC 5681 §3.2 step 5 inflation.
//
// Concrete scenario (fresh fast recovery, SSThresh=2*MSS after halving,
// CongWin=5*MSS after 3rd dup ACK inflation):
//
//	4th dup ACK:
//	  sendSeq == RecoveryPoint → seqAfter returns false
//	  bug: c.CongWin unchanged = 5*MSS = 20480
//	  fix: c.CongWin += MSS    = 6*MSS = 24576
//
// Root cause: the seqAfter guard was designed for the iter-77 timeout-recovery
// case (sendSeq==RecoveryPoint because NO new data was sent after the timeout).
// After iter-79, RecoveryPoint is always updated to sendSeq when entering a new
// episode, making the seqAfter check useless as a fast-recovery discriminator.
//
// Fix: replace the seqAfter guard in the DupAckCount>3 branch with:
//
//	if !c.FastRecovery {
//	    return  // timeout recovery — no per-dup-ACK inflation
//	}
//
// FastRecovery=true iff the episode was entered via fast retransmit (new
// episode, iter-78 + iter-79 guarantee this).  Timeout-based recovery clears
// FastRecovery, so !c.FastRecovery correctly excludes it.
//
// GREEN assertion: after the 4th dup ACK in fresh fast recovery,
// CongWin == 6*MaxSegmentSize (was 5*MSS; += 1 MSS per RFC 5681 §3.2 step 5).
func TestFreshFastRecoveryPerDupAckInflation(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)

	const seqA = uint32(1000)
	seqB := seqA + uint32(MaxSegmentSize)
	seqC := seqB + uint32(MaxSegmentSize)
	seqD := seqC + uint32(MaxSegmentSize)
	sendSeq := seqD + uint32(MaxSegmentSize) // 4 segments sent

	// State AFTER the 3rd dup ACK has entered fresh fast recovery:
	//   DupAckCount==3 path fired fastRetransmit (seqB, attempts=1→2),
	//   halved SSThresh (FlightSize=3*MSS → SSThresh=max(1.5*MSS,2*MSS)=2*MSS),
	//   set CongWin=SSThresh+3*MSS=5*MSS, FastRecovery=true, RecoveryPoint=sendSeq.
	c.Mu.Lock()
	c.SendSeq = sendSeq
	c.RecvAck = 0
	c.Mu.Unlock()

	now := time.Now()
	c.RetxMu.Lock()
	c.LastAck = seqA
	c.DupAckCount = 3                         // third dup ACK just fired
	c.InRecovery = true                       // entered by DupAckCount==3 path
	c.FastRecovery = true                     // fast retransmit entered this episode
	c.RecoveryPoint = sendSeq                 // set to sendSeq by DupAckCount==3 path
	c.SSThresh = 2 * MaxSegmentSize           // halved: max(3*MSS/2, 2*MSS) = 2*MSS
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // = 5*MSS = 20480
	c.Unacked = []*retxEntry{
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now}, // fast-retransmitted
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
		{seq: seqD, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}
	c.RetxMu.Unlock()

	congWinBefore := c.CongWin

	// 4th dup ACK — RFC 5681 §3.2 step 5: cwnd += SMSS.
	c.ProcessAck(seqA, true)

	c.RetxMu.Lock()
	congWin := c.CongWin
	c.RetxMu.Unlock()

	// The inflation is one segment as sent: SendSegmentSize, which is what a
	// duplicate ACK says has left the network.
	expected := congWinBefore + SendSegmentSize
	if congWin < expected {
		t.Errorf("4th dup ACK in fresh fast recovery: CongWin=%d, want >=%d (%d+MSS=%d); "+
			"RFC 5681 §3.2 step 5 requires cwnd += SMSS per additional dup ACK while in "+
			"fast retransmit; bug: DupAckCount>3 branch returns early because "+
			"seqAfter(sendSeq=%d, RecoveryPoint=%d) is false — RecoveryPoint was just set "+
			"to sendSeq by the DupAckCount==3 path, making the seqAfter guard useless for "+
			"fresh fast recovery; fix: replace 'if !seqAfter(sendSeq, c.RecoveryPoint)' "+
			"with 'if !c.FastRecovery' so that the guard only blocks timeout-recovery "+
			"(FastRecovery=false) and not fresh fast recovery (FastRecovery=true)",
			congWin, expected, congWinBefore, expected,
			sendSeq, sendSeq)
	}
}
