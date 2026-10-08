// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestRTTUpdateSkippedForSackedSegments verifies that a once-sent segment
// (attempts==1) that was previously SACKed contributes an RTT sample when it
// is finally covered by a cumulative ACK.
//
// Bug (pre-v1.9.1): ProcessAck's RTT-update condition is:
//
//	if e.attempts == 1 && !e.sacked {
//	    rtt := time.Since(e.sentAt)
//	    c.updateRTT(rtt)
//	}
//
// The intent of !e.sacked was to avoid using the cumulative-ACK arrival time
// as an RTT sample for a segment that the receiver already confirmed via SACK
// (the cumulative ACK may arrive long after the SACK, over-estimating RTT).
//
// However, when the receiver reports all in-flight segments via SACK — the
// common path for burst transfers over lossy links — every Unacked entry has
// sacked=true at the time the cumulative ACK arrives.  None of them match the
// RTT-update condition, so c.updateRTT is never called.  c.SRTT stays at 0,
// and c.RTO is clamped to RTOMin (200 ms) rather than converging toward the
// actual path RTT.  On a LAN connection with 1 ms round-trip time the sender
// permanently uses RTOMin=200 ms instead of the ~4 ms it would converge to
// with good RTT data — a 50× over-estimate that forces spurious retransmission
// much too early and inflates recovery time.
//
// Fix (v1.9.1): remove the !e.sacked guard from the RTT-update condition:
//
//	if e.attempts == 1 {
//	    rtt := time.Since(e.sentAt)
//	    c.updateRTT(rtt)
//	}
//
// A sacked-then-cumulative-ACKed segment was sent exactly once, so the RTT
// sample (sentAt → cumulative ACK) is valid per RFC 6298 §2 (no retransmit
// ambiguity). The cumulative ACK may be slightly delayed relative to the SACK,
// but this is a conservative (upper-bound) estimate that the EWMA smooths out.
// The alternative — leaving SRTT=0 / RTO=InitialRTO forever on SACK-heavy
// connections — is far worse for performance.
//
// That holds only while nothing before them was resent. When the same ACK
// also covers a resent segment, the once-sent ones behind it were held back
// by the repair and the sample is not smoothed out: RTO went from 437ms to
// 4.5s after a parked head was resent. Such an ACK gives no sample (v1.17.1,
// TestAckAfterParkedHeadRecoveryTakesNoRTTSample).
//
// GREEN assertion: after ProcessAck with a cumulative ACK covering a
// once-sent sacked entry (attempts=1, sacked=true), conn.SRTT is positive.
// Against unpatched code SRTT stays at 0 because !e.sacked prevents the call.
func TestRTTUpdateSkippedForSackedSegments(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	conn := pm.NewConnection(7150, protocol.Addr{}, 80)
	t.Cleanup(func() { pm.RemoveConnection(conn.ID) })

	const segLen = 1000

	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.SRTT = 0 // initial state — no RTT measurements yet
	conn.RTTVAR = 0
	conn.RTO = InitialRTO
	conn.Unacked = []*retxEntry{
		{
			seq:      1000,
			data:     make([]byte, segLen),
			attempts: 1,
			sacked:   true,                                  // peer reported this segment via SACK already
			sentAt:   time.Now().Add(-5 * time.Millisecond), // sent 5ms ago
		},
	}
	conn.RetxMu.Unlock()

	// Cumulative ACK covers the sacked segment.
	conn.ProcessAck(1000+segLen, true)

	conn.RetxMu.Lock()
	srtt := conn.SRTT
	conn.RetxMu.Unlock()

	// FIXED: once-sent sacked segments contribute a valid RTT sample.
	// FAILS against unpatched code: SRTT=0 because !e.sacked prevents
	// updateRTT — connections that see all their segments SACKed before
	// the cumulative ACK stay at SRTT=0/RTO=InitialRTO forever, using a
	// 1s retransmit timeout on connections that may have 1ms RTT.
	if srtt == 0 {
		t.Errorf("ProcessAck with sacked segment (attempts=1, sacked=true): SRTT=0 " +
			"after cumulative ACK covers the segment; " +
			"'!e.sacked' guard prevents updateRTT for segments the peer already " +
			"confirmed via SACK, so when all in-flight data is SACKed before the " +
			"cumulative ACK arrives (common on SACK-heavy connections), the sender " +
			"never refines SRTT from InitialRTO=1s, causing spurious retransmission " +
			"and slow loss recovery; fix: remove the !e.sacked condition — " +
			"once-sent segments (attempts==1) always yield valid RTT samples per " +
			"RFC 6298 regardless of SACK state")
	}
}
