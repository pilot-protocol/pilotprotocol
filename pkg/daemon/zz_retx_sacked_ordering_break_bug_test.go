// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"
)

// TestRetransmitUnackedBreakSkipsTimedOutEntryAfterRecentNonSacked verifies
// that retransmitUnacked correctly retransmits a timed-out segment even when
// it follows a non-sacked, non-timed-out segment in the Unacked slice.
//
// Bug (pre-v1.9.1): retransmitUnacked uses a `break` to stop scanning when
// the first non-sacked entry has not timed out:
//
//	for _, e := range conn.Unacked {
//	    if e.sacked {
//	        continue
//	    }
//	    if now.Sub(e.sentAt) > conn.RTO {
//	        // retransmit and return
//	    }
//	    break   // ← assumes remaining entries also haven't timed out
//	}
//
// The comment "segments are ordered by time; if first hasn't timed out, none
// have" is correct only when Unacked entries are in strict sentAt order.
// That ordering invariant breaks when:
//  1. A leading segment is SACKed (skipped by continue).
//  2. The first non-sacked entry is recent (sentAt updated by a prior
//     retransmit of that exact segment).
//  3. A later non-sacked entry was originally sent much earlier (sentAt
//     predates the retransmit) and is therefore timed out.
//
// Concretely:
//
//	Unacked[0]: sacked=true,  sentAt=T-2s  (very old, SACK-skipped)
//	Unacked[1]: sacked=false, sentAt=T-50ms (recently retransmitted; B)
//	Unacked[2]: sacked=false, sentAt=T-2s  (original send; C — timed out)
//
// With RTO=200ms:
//
//	Entry[0] sacked → continue
//	Entry[1] B: now-50ms = 50ms NOT > 200ms → break (before C is checked!)
//	Entry[2] C: timed out but NEVER REACHED
//
// Consequence: C sits in Unacked indefinitely, never retransmitted until B
// is finally ACKed (removing it from Unacked) and C becomes the first entry.
// Under sustained packet loss at 1% on a 10 Mbps link this can delay
// retransmission of C by multiple additional RTO cycles, extending per-stream
// completion time by 2–4× the expected recovery time.
//
// Fix (v1.9.1): replace the `break` with a plain `continue` (fall through to
// the next entry).  The loop already returns after retransmitting a single
// segment; the break optimisation is only safe when entries are strictly
// ordered by sentAt, which the retransmit mechanism violates.
//
// GREEN assertion: after one call to retransmitUnacked with the Unacked slice
// above, entry C (timed out) is retransmitted.  Against unpatched code B's
// non-timeout fires the break and no packet is sent.
func TestRetransmitUnackedBreakSkipsTimedOutEntryAfterRecentNonSacked(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	conn, cs := newRetxConn(t)

	// Use the minimum RTO so the test is not time-sensitive.
	conn.RTO = RTOMin

	now := time.Now()
	conn.Unacked = []*retxEntry{
		// A: sacked — should be skipped via continue. Sent within the RTO:
		// a SACKed head that has gone a whole RTO is resent as parked at
		// the receiver (TestRetransmitUnackedResendsAStaleSackedHead).
		{seq: 1000, data: []byte("A"), attempts: 1, sacked: true,
			sentAt: now.Add(-50 * time.Millisecond)},
		// B: not sacked, recently retransmitted — sentAt updated to recent time
		//    (50ms ago, well within RTO=200ms — this entry is NOT timed out)
		{seq: 2000, data: []byte("B"), attempts: 2, sacked: false,
			sentAt: now.Add(-50 * time.Millisecond)},
		// C: not sacked, originally sent 2*RTO ago — timed out!
		//    Positioned AFTER B in the slice because seqs are ordered, but
		//    C's sentAt predates B's retransmit. The 'break' on B hides C.
		{seq: 3000, data: []byte("C"), attempts: 1, sacked: false,
			sentAt: now.Add(-2 * RTOMin)},
	}

	d.retransmitUnacked(conn)

	pkts := cs.all()

	// FIXED: C is timed out and must be retransmitted.
	// FAILS against unpatched code: no packet is sent because B (not timed out)
	// fires the break before C is ever checked.
	if len(pkts) == 0 {
		t.Errorf("retransmitUnacked with [A(sacked), B(recent,not-timeout), C(timed-out)]: " +
			"expected 1 retransmit (C), got 0; " +
			"'break' after B fires before C is checked — sacked entry A causes " +
			"B to be the first non-sacked entry examined; B's sentAt is recent " +
			"(retransmit updated it) so it is not timed out and the break fires; " +
			"C's older sentAt makes it timed out but it is never reached; " +
			"fix: replace 'break' with 'continue' so all non-sacked entries " +
			"are checked for timeout regardless of ordering")
	}
	if len(pkts) == 1 && string(pkts[0].Payload) != "C" {
		t.Errorf("expected retransmit of C, got payload %q", string(pkts[0].Payload))
	}
}
