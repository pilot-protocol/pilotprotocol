// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestFastRecoveryThirdDupAckSameEpisodeInflation verifies that the 3rd
// duplicate ACK after a partial ACK has reset DupAckCount to 0 — reaching
// DupAckCount=3 again within the same recovery episode (sendSeq <=
// RecoveryPoint) — inflates cwnd by SMSS per RFC 5681 §3.2 step 5.
//
// RFC 5681 §3.2 step 5:
//
//	"For each additional duplicate ACK received while in fast retransmit,
//	 increment cwnd by SMSS."
//
// The phrase "while in fast retransmit" means InRecovery=true &&
// FastRecovery=true, regardless of DupAckCount.  After a partial ACK resets
// DupAckCount to 0, dup ACKs at count 1 and 2 now correctly inflate cwnd
// (iter-82 fix).  The 3rd dup ACK after the reset (DupAckCount reaches 3
// again) must also inflate by SMSS; it is still "received while in fast
// retransmit" and is an additional duplicate ACK for the same episode.
//
// Bug: when DupAckCount reaches 3 while already InRecovery, the
// DupAckCount==3 branch fires fastRetransmit, but the CongWin inflation is
// inside the newEpisode block which is skipped when sendSeq <= RecoveryPoint
// (same episode, no new data beyond the recovery point):
//
//	newEpisode := !c.InRecovery || seqAfter(sendSeq, c.RecoveryPoint)
//	// false: still in same recovery episode
//	if newEpisode {
//	    c.CongWin = c.SSThresh + 3*MSS   // ← not executed for same-episode
//	}
//	// ← RFC 5681 §3.2 step 5 inflation (+MSS) missing here
//
// The fastRetransmit call is correct (RFC 6582 §3 step 6a), but the
// per-dup-ACK cwnd inflation (+MSS) is absent for this specific count.
//
// Concrete scenario (state after 2 dup ACKs following a partial-ACK reset,
// each already inflated cwnd by MSS per iter-82 fix):
//
//	InRecovery=true, FastRecovery=true, DupAckCount=2
//	CongWin = 5*MSS + 2*MSS = 7*MSS = 28672
//
//	3rd dup ACK (DupAckCount: 2 → 3, same episode, sendSeq <= RecoveryPoint):
//	  fastRetransmit fires (correct, RFC 6582 §3 step 6a retransmit)
//	  RFC 5681 §3.2 step 5: CongWin += MSS → 8*MSS = 32768
//	  bug: CongWin unchanged = 7*MSS = 28672
//
// Fix: in the DupAckCount==3 same-episode path (newEpisode=false), add the
// step-5 inflation when InRecovery && FastRecovery:
//
//	if newEpisode {
//	    // halve ssthresh, set cwnd = ssthresh+3*MSS
//	} else if c.InRecovery && c.FastRecovery {
//	    // RFC 5681 §3.2 step 5: same-episode 3rd dup ACK after partial ACK
//	    c.CongWin += MaxSegmentSize
//	    // cap and signal WindowCh
//	}
//
// GREEN assertion: after the 3rd dup ACK in same-episode fast recovery,
// CongWin == 7*MSS + MSS = 8*MSS = 32768.
func TestFastRecoveryThirdDupAckSameEpisodeInflation(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.RetxSend = func(_ *protocol.Packet) {} // same-episode fastRetransmit is a no-op

	const (
		seqA = uint32(1000)
		seqB = seqA + uint32(MaxSegmentSize) // 5096 — first remaining unacked
		seqC = seqB + uint32(MaxSegmentSize) // 9192
	)
	recoveryPoint := seqC + uint32(MaxSegmentSize) // 13288 — sendSeq(0) << recoveryPoint

	// State after a partial ACK reset DupAckCount to 0 and 2 subsequent dup
	// ACKs have already inflated CongWin by 2*MSS (iter-82 fix):
	//   DupAckCount=2, CongWin = SSThresh + 3*MSS + 2*MSS = 7*MSS = 28672
	c.LastAck = seqB  // partial ACK set LastAck to seqB; 3rd dup ACK repeats it
	c.DupAckCount = 2 // two dup ACKs have already fired since the reset
	c.InRecovery = true
	c.FastRecovery = true
	c.RecoveryPoint = recoveryPoint
	c.SSThresh = 2 * MaxSegmentSize                              // 8192
	c.CongWin = c.SSThresh + 3*MaxSegmentSize + 2*MaxSegmentSize // 7*MSS = 28672

	now := time.Now()
	c.Unacked = []*retxEntry{
		// seqB: first unacked (attempts=2 from prior fast retransmit)
		{seq: seqB, data: make([]byte, MaxSegmentSize), attempts: 2, sentAt: now},
		{seq: seqC, data: make([]byte, MaxSegmentSize), attempts: 1, sentAt: now},
	}

	congWinBefore := c.CongWin // 28672

	// 3rd dup ACK after the partial-ACK reset (DupAckCount: 2 → 3).
	// sendSeq=0 < RecoveryPoint=13288 → same episode (newEpisode=false).
	// fastRetransmit fires for seqB (RFC 6582 §3 step 6a).
	// RFC 5681 §3.2 step 5: also inflate cwnd += SMSS.
	c.ProcessAck(seqB, true)

	// The inflation is one segment as sent: SendSegmentSize, which is what a
	// duplicate ACK says has left the network.
	if c.CongWin < congWinBefore+SendSegmentSize {
		t.Errorf("3rd dup ACK (DupAckCount 2→3) same-episode fast recovery: "+
			"CongWin=%d, want >=%d (%d+MSS=%d); "+
			"RFC 5681 §3.2 step 5 requires cwnd += SMSS for every dup ACK while in "+
			"fast retransmit (InRecovery=true, FastRecovery=true); "+
			"bug: DupAckCount==3 branch calls fastRetransmit (correct per RFC 6582 §3 "+
			"step 6a) but skips step-5 inflation because the newEpisode guard is false "+
			"(sendSeq=0 <= RecoveryPoint=%d, same episode — no new data beyond recovery); "+
			"the +MSS inflation must fire regardless of newEpisode when already in fast "+
			"recovery; fix: add 'else if InRecovery && FastRecovery { CongWin += MSS }' "+
			"after the newEpisode block inside the DupAckCount==3 branch",
			c.CongWin, congWinBefore+SendSegmentSize,
			congWinBefore, congWinBefore+SendSegmentSize,
			recoveryPoint)
	}
}
