// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestFastRecoveryPostPartialAckDupAckInflation verifies that each duplicate
// ACK received while still in fast recovery (InRecovery=true, FastRecovery=true)
// after a partial ACK has reset DupAckCount to 0 inflates cwnd by SMSS per
// RFC 5681 §3.2 step 5.
//
// RFC 5681 §3.2 step 5:
//
//	"For each additional duplicate ACK received while in fast retransmit,
//	 increment cwnd by SMSS."
//
// "While in fast retransmit" means InRecovery=true && FastRecovery=true.
// The 3-dup-ACK threshold is only the ENTRY condition for fast recovery; once
// inside fast recovery, EVERY subsequent dup ACK is "received while in fast
// retransmit" and MUST inflate cwnd by SMSS — including those at DupAckCount
// 1 and 2 that arrive after a partial ACK has reset the counter to 0.
//
// Bug: the per-dup-ACK inflation in ProcessAck is gated on DupAckCount > 3.
// After a partial ACK resets DupAckCount to 0 (new-ACK path, line ~805), the
// first two subsequent dup ACKs reach DupAckCount=1 and DupAckCount=2, which
// match neither the DupAckCount==3 branch (fast-retransmit entry) nor the
// DupAckCount>3 branch (step-5 inflation).  CongWin is not incremented.
//
// Concrete scenario (state after a neutral 1-SMSS partial ACK):
//
//	InRecovery=true, FastRecovery=true, DupAckCount=0, CongWin=5*MSS=20480
//
//	1st dup ACK after partial ACK (DupAckCount becomes 1):
//	  RFC 5681 §3.2 step 5: CongWin += MSS → 6*MSS = 24576
//	  bug: DupAckCount==3 is false, DupAckCount>3 is false → CongWin = 20480
//
// Root cause: the DupAckCount>3 guard was designed for the initial entry
// sequence (three dup ACKs to enter fast recovery, then >3 to inflate each
// subsequent one).  After a partial ACK resets DupAckCount to 0, the >3
// threshold is wrong — inflation must fire for every dup ACK while
// InRecovery && FastRecovery, regardless of the current count.
//
// Fix: add a branch before the DupAckCount==3 check that handles DupAckCount
// in [1, 2] when already in fast recovery:
//
//	if c.DupAckCount < 3 && c.InRecovery && c.FastRecovery && len(c.Unacked) > 0 {
//	    c.CongWin += MaxSegmentSize
//	    // cap and signal WindowCh
//	    return
//	}
//
// GREEN assertion: after the 1st dup ACK with DupAckCount=0 starting state,
// CongWin == 5*MSS + MSS = 6*MSS = 24576.
func TestFastRecoveryPostPartialAckDupAckInflation(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.RetxSend = func(_ *protocol.Packet) {} // fast-retransmit in same episode is a no-op

	const (
		seqA = uint32(1000)
		seqB = seqA + uint32(MaxSegmentSize) // 5096 — partial-ACK acked seqA; LastAck=seqB
		seqC = seqB + uint32(MaxSegmentSize) // 9192
	)
	recoveryPoint := seqC + uint32(MaxSegmentSize) // 13288 — not yet reached

	// State after a neutral 1-SMSS partial ACK during fast recovery:
	//   seqA was cumulatively acked and removed from Unacked.
	//   DupAckCount reset to 0 by the new-ACK path in ProcessAck.
	//   CongWin: deflated by MSS, add-back MSS (bytesAcked==SMSS, neutral) → 5*MSS.
	c.LastAck = seqB  // partial ACK advanced LastAck to seqB
	c.DupAckCount = 0 // reset by the new-ACK path
	c.InRecovery = true
	c.FastRecovery = true
	c.RecoveryPoint = recoveryPoint
	c.SSThresh = 2 * MaxSegmentSize           // 8192
	c.CongWin = c.SSThresh + 3*MaxSegmentSize // 5*MSS = 20480

	now := time.Now()
	c.Unacked = []*retxEntry{
		// seqA was removed; seqB is now the first unacked (attempts=2: was fast-retransmitted)
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now},
		// seqC: outstanding
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}

	congWinBefore := c.CongWin // 20480

	// 1st dup ACK after the partial-ACK reset (ack==seqB==LastAck → dup-ACK path).
	// BytesInFlight = 2*MSS > 0 → counting proceeds; DupAckCount: 0 → 1.
	// RFC 5681 §3.2 step 5 ("while in fast retransmit"): cwnd += SMSS.
	c.ProcessAck(seqB, true)

	// The inflation is one segment as sent: SendSegmentSize, which is what a
	// duplicate ACK says has left the network.
	if c.CongWin < congWinBefore+SendSegmentSize {
		t.Errorf("1st dup ACK after partial-ACK DupAckCount reset: CongWin=%d, want >=%d "+
			"(%d+MSS=%d); RFC 5681 §3.2 step 5 requires cwnd += SMSS for every dup ACK "+
			"'while in fast retransmit' (InRecovery=true, FastRecovery=true); "+
			"bug: after a partial ACK resets DupAckCount to 0, the dup ACK reaches "+
			"DupAckCount=1 which matches neither DupAckCount==3 (fast-retransmit entry) "+
			"nor DupAckCount>3 (step-5 inflation) — the inflation is silently skipped; "+
			"the 3-dup threshold is the ENTRY condition only, not a per-inflation gate; "+
			"fix: add 'if DupAckCount<3 && InRecovery && FastRecovery' branch before the "+
			"DupAckCount==3 check to inflate cwnd += MSS for counts 1-2 inside fast recovery",
			c.CongWin, congWinBefore+SendSegmentSize,
			congWinBefore, congWinBefore+SendSegmentSize)
	}
}
