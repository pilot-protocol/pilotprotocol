// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// These tests pin the transport-throughput fixes from the 2026-08 overlay
// benchmark investigation (fleet round-trip goodput was ~0.2 MB/s best case
// with multi-minute stalls):
//
//  1. Timeout-based recovery must retransmit ACK-clocked — historically only
//     fast recovery got partial-ACK retransmits (RFC 6582 §3 step 6a), so a
//     window collapse after an RTO drained multi-segment losses at ONE
//     segment per backed-off RTO (~1.3 KB/s observed live).
//  2. retransmitLost may resend a burst of known-lost (below-SACK-frontier)
//     segments per ACK event, bounded by cwnd and maxRetxBurst.
//  3. The receiver's out-of-order buffer must cover a full congestion window,
//     otherwise one loss with >MaxOOOBuf segments in flight silently drops
//     every later in-window segment (loss amplification).

// throughputFixConn builds a Connection in timeout-style recovery with a
// run of consecutive un-SACKed entries (the "hole") followed by SACKed
// entries (the frontier proof), capturing retransmitted seqs.
func throughputFixConn(t *testing.T, holeSegs, sackedSegs int) (*Connection, *[]uint32) {
	t.Helper()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }

	seq := uint32(1000)
	for i := 0; i < holeSegs; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{
			seq: seq, data: make([]byte, MaxSegmentSize),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(),
		})
		seq += MaxSegmentSize
	}
	for i := 0; i < sackedSegs; i++ {
		c.Unacked = append(c.Unacked, &retxEntry{
			seq: seq, data: make([]byte, MaxSegmentSize),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(), sacked: true,
		})
		seq += MaxSegmentSize
	}
	c.LastAck = 1000
	c.RecoveryPoint = seq // everything sent so far is inside the loss window
	return c, &sent
}

// TestTimeoutRecoveryPartialAckRetransmitsAckClocked: a partial ACK during
// timeout recovery (InRecovery=true, FastRecovery=false) must retransmit
// lost segments instead of leaving them to the backed-off RTO timer.
func TestTimeoutRecoveryPartialAckRetransmitsAckClocked(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 8, 4)
	c.InRecovery = true
	c.FastRecovery = false // timeout-entered recovery
	c.CongWin = 4 * MaxSegmentSize
	c.SSThresh = InitialSSThresh

	// Partial ACK: first hole segment arrives (e.g. via an RTO retransmit),
	// cumulative ACK advances one segment but stays below RecoveryPoint.
	c.ProcessAck(1000+MaxSegmentSize, true)

	if len(*sent) == 0 {
		t.Fatalf("partial ACK in timeout recovery retransmitted nothing — " +
			"recovery is left to the backed-off RTO timer at one segment per " +
			"up-to-10s RTO (the throughput-collapse crawl)")
	}
	// The new hole head must be among the retransmissions.
	if (*sent)[0] != 1000+uint32(MaxSegmentSize) {
		t.Errorf("first retransmit seq = %d, want hole head %d",
			(*sent)[0], 1000+MaxSegmentSize)
	}
	// Bounded by cwnd (4 segments): the ACK freed one segment of budget and
	// cwnd grew via slow start, but the burst must stay in the same order of
	// magnitude — never the whole 7-segment hole beyond the window.
	if len(*sent) > c.CongWin/MaxSegmentSize+1 {
		t.Errorf("retransmitted %d segments, want <= cwnd budget %d",
			len(*sent), c.CongWin/MaxSegmentSize+1)
	}
}

// TestRetransmitLostRespectsSackFrontier: only the hole head plus un-SACKed
// segments BELOW the highest SACKed sequence are eligible; segments above
// the frontier may still be in flight and belong to the RTO timer.
func TestRetransmitLostRespectsSackFrontier(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	var sent []uint32
	c.RetxSend = func(p *protocol.Packet) { sent = append(sent, p.Seq) }

	const mss = MaxSegmentSize
	mk := func(seq uint32, sacked bool) *retxEntry {
		return &retxEntry{seq: seq, data: make([]byte, mss),
			attempts: 1, sentAt: time.Now(), origSentAt: time.Now(), sacked: sacked}
	}
	// hole(1000), hole(1000+mss), SACKed(1000+2m) — frontier = 1000+3m —
	// then un-SACKed above the frontier (still plausibly in flight).
	c.Unacked = []*retxEntry{
		mk(1000, false),
		mk(1000+1*mss, false),
		mk(1000+2*mss, true),
		mk(1000+3*mss, false),
		mk(1000+4*mss, false),
	}

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 100)
	c.RetxMu.Unlock()

	if n != 2 || len(sent) != 2 {
		t.Fatalf("retransmitLost sent %d (%v), want exactly the 2 below-frontier holes", n, sent)
	}
	if sent[0] != 1000 || sent[1] != 1000+1*mss {
		t.Errorf("retransmitted %v, want [1000 %d]", sent, 1000+1*mss)
	}
}

// TestRetransmitLostNoFrontierSendsHeadOnly: with no SACK information there
// is no loss evidence beyond the cumulative-ACK gap head — exactly one
// segment goes out (the historical fastRetransmit contract).
func TestRetransmitLostNoFrontierSendsHeadOnly(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 6, 0) // all un-SACKed, no frontier

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 100)
	c.RetxMu.Unlock()

	if n != 1 || len(*sent) != 1 || (*sent)[0] != 1000 {
		t.Fatalf("retransmitLost with no SACK frontier sent %d (%v), want just head seq 1000", n, *sent)
	}
}

// TestRetransmitLostBurstCap: one ACK event may never dump more than
// maxRetxBurst segments onto an already-lossy path, regardless of cwnd.
func TestRetransmitLostBurstCap(t *testing.T) {
	t.Parallel()
	c, sent := throughputFixConn(t, 100, 4) // 100-segment hole below the frontier

	c.RetxMu.Lock()
	n := c.retransmitLost(0, 1000)
	c.RetxMu.Unlock()

	if n != maxRetxBurst || len(*sent) != maxRetxBurst {
		t.Fatalf("retransmitLost sent %d segments, want burst cap %d", n, maxRetxBurst)
	}
}

// TestTimeoutRecoveryHoleDrainsInBoundedRounds reproduces the observed
// worst case — a ~180-segment contiguous hole (a full pre-collapse window
// lost at once) with the tail SACKed — and drives ACK-clocked recovery to
// completion. Each round models one RTT: the retransmissions from the
// previous partial ACK arrive, the receiver's cumulative ACK advances over
// them, and the next partial ACK triggers the next burst.
//
// Before the fix, round one retransmits nothing (timeout recovery had no
// partial-ACK retransmit path), the loop makes no progress, and the hole
// drains at one segment per backed-off RTO — 180 segments × up to 10 s.
// After the fix the budget grows with slow start and is capped by
// maxRetxBurst, so the hole must drain within ~hole/maxRetxBurst + log
// rounds ≈ 10 RTTs.
func TestTimeoutRecoveryHoleDrainsInBoundedRounds(t *testing.T) {
	t.Parallel()
	const holeSegs = 180
	c, sent := throughputFixConn(t, holeSegs, 8)
	c.InRecovery = true
	c.FastRecovery = false
	c.CongWin = MaxSegmentSize // post-RTO collapse (RFC 5681 §3.1 LW)
	c.SSThresh = InitialSSThresh

	// The RTO timer delivers the head segment; the first partial ACK follows.
	ack := uint32(1000) + MaxSegmentSize
	rounds := 0
	for {
		rounds++
		*sent = (*sent)[:0]
		c.ProcessAck(ack, true)
		if !c.InRecovery {
			break
		}
		if len(*sent) == 0 {
			t.Fatalf("round %d: partial ACK at seq %d retransmitted nothing — "+
				"recovery stalled with %d unacked entries (pre-fix crawl)",
				rounds, ack, len(c.Unacked))
		}
		// All retransmitted segments are consecutive from the hole head, so
		// the next cumulative ACK advances over every one of them. When the
		// hole is fully covered, the receiver holds the SACKed tail too and
		// the cumulative ACK jumps straight past it (to RecoveryPoint).
		ack += uint32(len(*sent)) * MaxSegmentSize
		if seqAfterOrEqual(ack, 1000+uint32(holeSegs)*MaxSegmentSize) {
			ack = c.RecoveryPoint
		}
		if rounds > 40 {
			t.Fatalf("hole not drained after %d rounds (ack=%d, unacked=%d)",
				rounds, ack, len(c.Unacked))
		}
	}
	// Slow-start budget growth with one ACK per RTT drains 180 segments in
	// ~15 rounds (1+3+5+... capped at maxRetxBurst). Real transfers see
	// multiple ACKs per RTT, so this is the conservative upper bound.
	if rounds > 20 {
		t.Errorf("180-segment hole took %d ACK rounds (RTTs) to drain, want <= 20", rounds)
	}
}

// TestAckClockedRetransmitsNeverTriggerRST pins the give-up semantics: the
// MaxRetxAttempts RST budget counts only RTO-timer retransmissions
// (rtoAttempts), never ACK-clocked ones. Found live in the A/B rig: a
// spurious RTO put the connection in timeout recovery, each partial ACK
// retransmitted the head (inflating attempts), and within 8×RTOMin ≈ 1.6 s
// the RTO tick RST'd a connection whose ACKs were arriving fine.
func TestAckClockedRetransmitsNeverTriggerRST(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	c := newAckTestConn(t)
	var pkts []*protocol.Packet
	c.RetxSend = func(p *protocol.Packet) { q := *p; pkts = append(pkts, &q) }
	c.Mu.Lock()
	c.State = StateEstablished
	c.Mu.Unlock()
	// Head segment already retransmitted 8× by the ACK-clocked path
	// (attempts inflated) but never by the RTO timer (rtoAttempts 0).
	c.Unacked = []*retxEntry{{
		seq: 1000, data: make([]byte, MaxSegmentSize),
		attempts: MaxRetxAttempts, rtoAttempts: 0,
		sentAt: time.Now().Add(-2 * InitialRTO), origSentAt: time.Now().Add(-2 * InitialRTO),
	}}
	c.RTO = InitialRTO

	d.retransmitUnacked(c)

	for _, p := range pkts {
		if p.Flags&protocol.FlagRST != 0 {
			t.Fatalf("RTO tick sent RST for a segment with rtoAttempts=0 — " +
				"ACK-clocked retransmissions must not consume the give-up budget")
		}
	}
	c.Mu.Lock()
	st := c.State
	c.Mu.Unlock()
	if st != StateEstablished {
		t.Fatalf("connection state = %v, want Established (no give-up)", st)
	}
}

// TestNewAckResetsRTOGiveUpBudget: any new cumulative ACK proves the peer is
// alive, so the per-segment RTO give-up counter must reset — RST fires only
// after MaxRetxAttempts consecutive ACK-free RTO retransmissions.
func TestNewAckResetsRTOGiveUpBudget(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.RetxSend = func(*protocol.Packet) {}
	const mss = MaxSegmentSize
	c.LastAck = 1000
	c.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, mss), attempts: 1, sentAt: time.Now(), origSentAt: time.Now()},
		{seq: 1000 + mss, data: make([]byte, mss), attempts: 5, rtoAttempts: 5, sentAt: time.Now(), origSentAt: time.Now()},
	}

	c.ProcessAck(1000+mss, true) // acks the first segment — progress

	if len(c.Unacked) != 1 {
		t.Fatalf("Unacked = %d entries, want 1", len(c.Unacked))
	}
	if got := c.Unacked[0].rtoAttempts; got != 0 {
		t.Fatalf("surviving segment rtoAttempts = %d after new ACK, want 0 (budget reset on progress)", got)
	}
}

// TestOOOBufferCoversFullCongestionWindow pins the structural relation that
// caused the loss amplification: the receiver must be able to buffer at
// least a full congestion window of out-of-order segments, or one lost
// segment with a full window in flight silently drops everything behind it.
func TestOOOBufferCoversFullCongestionWindow(t *testing.T) {
	t.Parallel()
	if MaxOOOBuf*MaxSegmentSize < MaxCongWin {
		t.Fatalf("MaxOOOBuf (%d segs = %d bytes) < MaxCongWin (%d bytes): "+
			"a single loss with a full window in flight overflows the OOO "+
			"buffer and every later in-window segment is silently dropped",
			MaxOOOBuf, MaxOOOBuf*MaxSegmentSize, MaxCongWin)
	}
}

// TestInitialSSThreshBoundsSlowStartBurst pins the slow-start hard stop:
// with HyStart RTT-rise detection as the primary (adaptive) exit, the
// static threshold is only a backstop — but it must still exist, below
// the full window, for paths that give no RTT signal before tail-drop.
func TestInitialSSThreshBoundsSlowStartBurst(t *testing.T) {
	t.Parallel()
	if InitialSSThresh > MaxCongWin/2 {
		t.Fatalf("InitialSSThresh (%d) > MaxCongWin/2 (%d): slow start could "+
			"double a full MaxCongWin into path queues in one RTT with no "+
			"hard stop before the ceiling", InitialSSThresh, MaxCongWin/2)
	}
}

// TestHyStartExitsSlowStartOnRTTRise: while in slow start, a round whose
// min RTT rises by >= eta over the previous round's min (with enough
// samples) must set SSThresh = CongWin — exiting at discovered capacity
// instead of doubling to the static threshold (RFC 9406 rationale).
func TestHyStartExitsSlowStartOnRTTRise(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.RetxSend = func(*protocol.Packet) {}
	const mss = MaxSegmentSize
	c.CongWin = 20 * mss
	c.SSThresh = InitialSSThresh
	c.LastAck = 1000

	// Feed ACK rounds with controlled RTT samples: origSentAt in the past
	// determines the sample. Round 1: ~30 ms baseline. Round 2: ~60 ms
	// (queue building). Each entry acked individually = one sample each.
	seq := uint32(1000)
	feedRound := func(rtt time.Duration) {
		for i := 0; i < hsMinSamples+1; i++ {
			c.Unacked = []*retxEntry{{
				seq: seq, data: make([]byte, mss), attempts: 1,
				sentAt: time.Now(), origSentAt: time.Now().Add(-rtt),
			}}
			// Force round boundaries to line up: hsRoundEnd is snd_nxt at
			// round start; keep SendSeq one flight ahead.
			c.Mu.Lock()
			c.SendSeq = seq + uint32((hsMinSamples+1))*mss
			c.Mu.Unlock()
			seq += mss
			c.ProcessAck(seq, true)
		}
	}
	feedRound(30 * time.Millisecond) // establishes hsLastMinRTT ≈ 30 ms
	feedRound(30 * time.Millisecond) // stable round — must NOT exit
	if c.SSThresh != InitialSSThresh {
		t.Fatalf("stable RTT triggered HyStart exit: SSThresh=%d", c.SSThresh)
	}
	// ACK rounds don't align with feed batches (rollover happens mid-batch
	// and the first raised-RTT round inherits earlier low samples), so feed
	// several rounds of elevated RTT — at least one full 8-sample round of
	// pure 60 ms measurements must occur and trigger the exit.
	feedRound(60 * time.Millisecond)
	feedRound(60 * time.Millisecond)
	feedRound(60 * time.Millisecond) // RTT rise >> eta — must exit by now
	if c.SSThresh == InitialSSThresh {
		t.Fatalf("60ms-over-30ms RTT rise did not trigger HyStart slow-start exit")
	}
	if c.SSThresh > c.CongWin {
		t.Fatalf("HyStart exit set SSThresh=%d above CongWin=%d", c.SSThresh, c.CongWin)
	}
}
