// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// --- DecodeSACK ---

func TestDecodeSACKRoundTripWithEncodeSACK(t *testing.T) {
	t.Parallel()
	blocks := []SACKBlock{
		{Left: 1000, Right: 2000},
		{Left: 3000, Right: 4000},
	}
	data := EncodeSACK(blocks)
	got, ok := DecodeSACK(data)
	if !ok {
		t.Fatal("DecodeSACK returned ok=false on valid data")
	}
	if len(got) != 2 {
		t.Fatalf("got %d blocks, want 2", len(got))
	}
	for i, b := range got {
		if b != blocks[i] {
			t.Fatalf("block %d = %+v, want %+v", i, b, blocks[i])
		}
	}
}

func TestDecodeSACKShortPayloadReturnsNotOK(t *testing.T) {
	t.Parallel()
	if _, ok := DecodeSACK([]byte("ABC")); ok {
		t.Fatal("short payload should return ok=false")
	}
}

func TestDecodeSACKWrongMagicReturnsNotOK(t *testing.T) {
	t.Parallel()
	if _, ok := DecodeSACK([]byte("NOPE\x01\x00\x00\x00\x00\x00\x00\x00\x00")); ok {
		t.Fatal("wrong magic should return ok=false")
	}
}

func TestDecodeSACKZeroCountReturnsNotOK(t *testing.T) {
	t.Parallel()
	// "SACK" + 0 count
	if _, ok := DecodeSACK([]byte("SACK\x00")); ok {
		t.Fatal("n=0 should return ok=false")
	}
}

func TestDecodeSACKTooManyBlocksReturnsNotOK(t *testing.T) {
	t.Parallel()
	// "SACK" + 5 count (max is 4)
	buf := append([]byte("SACK"), 0x05)
	buf = append(buf, make([]byte, 5*8)...)
	if _, ok := DecodeSACK(buf); ok {
		t.Fatal("n>4 should return ok=false")
	}
}

func TestDecodeSACKTruncatedBlocksReturnsNotOK(t *testing.T) {
	t.Parallel()
	// "SACK" + count=2 but only 8 bytes of data
	buf := append([]byte("SACK"), 0x02)
	buf = append(buf, make([]byte, 8)...) // need 16
	if _, ok := DecodeSACK(buf); ok {
		t.Fatal("truncated should return ok=false")
	}
}

// --- ConnState.String ---

func TestConnStateStringAllKnownValues(t *testing.T) {
	t.Parallel()
	cases := map[ConnState]string{
		StateClosed:      "CLOSED",
		StateListen:      "LISTEN",
		StateSynSent:     "SYN_SENT",
		StateSynReceived: "SYN_RECV",
		StateEstablished: "ESTABLISHED",
		StateFinWait:     "FIN_WAIT",
		StateCloseWait:   "CLOSE_WAIT",
		StateTimeWait:    "TIME_WAIT",
	}
	for st, want := range cases {
		if got := st.String(); got != want {
			t.Errorf("ConnState(%d).String() = %q, want %q", st, got, want)
		}
	}
	if got := ConnState(99).String(); got != "unknown" {
		t.Errorf("unknown state = %q, want 'unknown'", got)
	}
}

// --- Unbind ---

func TestUnbindRemovesListenerAndClosesAcceptCh(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	ln, err := pm.Bind(1234)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	pm.Unbind(1234)

	if pm.GetListener(1234) != nil {
		t.Fatal("GetListener(1234) should be nil after Unbind")
	}
	// AcceptCh should be closed — a recv returns immediately.
	select {
	case _, ok := <-ln.AcceptCh:
		if ok {
			t.Fatal("AcceptCh should be closed")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("AcceptCh recv should not block")
	}
}

func TestUnbindUnknownPortIsNoop(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	pm.Unbind(9999) // should not panic
}

// --- ConnectionCountForPort / TotalActiveConnections ---

func TestConnectionCountForPortCountsOnlyActiveOnThatPort(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c1 := pm.NewConnection(80, protocol.Addr{}, 0)
	c1.State = StateEstablished
	c2 := pm.NewConnection(80, protocol.Addr{}, 0)
	c2.State = StateClosed // should NOT count
	c3 := pm.NewConnection(80, protocol.Addr{}, 0)
	c3.State = StateTimeWait // should NOT count
	c4 := pm.NewConnection(443, protocol.Addr{}, 0)
	c4.State = StateEstablished // wrong port

	if got := pm.ConnectionCountForPort(80); got != 1 {
		t.Fatalf("ConnectionCountForPort(80) = %d, want 1", got)
	}
	if got := pm.ConnectionCountForPort(443); got != 1 {
		t.Fatalf("ConnectionCountForPort(443) = %d, want 1", got)
	}
}

func TestTotalActiveConnectionsCountsOnlyActive(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c1 := pm.NewConnection(80, protocol.Addr{}, 0)
	c1.State = StateEstablished
	c2 := pm.NewConnection(443, protocol.Addr{}, 0)
	c2.State = StateSynSent
	c3 := pm.NewConnection(444, protocol.Addr{}, 0)
	c3.State = StateClosed
	c4 := pm.NewConnection(445, protocol.Addr{}, 0)
	c4.State = StateTimeWait

	if got := pm.TotalActiveConnections(); got != 2 {
		t.Fatalf("TotalActiveConnections = %d, want 2", got)
	}
}

// --- FindConnection ---

func TestFindConnectionMatchAndMiss(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	remote := protocol.Addr{Network: 7, Node: 0xABCD}
	c := pm.NewConnection(80, remote, 1000)

	got := pm.FindConnection(80, remote, 1000)
	if got != c {
		t.Fatal("FindConnection should return matching connection")
	}
	// Different remote port → miss
	if pm.FindConnection(80, remote, 2000) != nil {
		t.Fatal("FindConnection wrong remote port should return nil")
	}
	// Different local port → miss
	if pm.FindConnection(443, remote, 1000) != nil {
		t.Fatal("FindConnection wrong local port should return nil")
	}
	// Different remote addr → miss
	other := protocol.Addr{Network: 7, Node: 0xBEEF}
	if pm.FindConnection(80, other, 1000) != nil {
		t.Fatal("FindConnection wrong remote addr should return nil")
	}
}

// --- StaleConnections / IdleConnections / AllConnections ---

func TestStaleConnectionsAndTimeWaitExpiry(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	cClosed := pm.NewConnection(1, protocol.Addr{}, 0)
	cClosed.State = StateClosed
	cCloseWait := pm.NewConnection(2, protocol.Addr{}, 0)
	cCloseWait.State = StateCloseWait
	cExpiredTimeWait := pm.NewConnection(3, protocol.Addr{}, 0)
	cExpiredTimeWait.State = StateTimeWait
	cExpiredTimeWait.LastActivity = time.Now().Add(-1 * time.Hour)
	cFreshTimeWait := pm.NewConnection(4, protocol.Addr{}, 0)
	cFreshTimeWait.State = StateTimeWait
	cFreshTimeWait.LastActivity = time.Now()
	cEstab := pm.NewConnection(5, protocol.Addr{}, 0)
	cEstab.State = StateEstablished

	stale := pm.StaleConnections(30 * time.Second)
	found := map[uint32]bool{}
	for _, c := range stale {
		found[c.ID] = true
	}
	if !found[cClosed.ID] || !found[cCloseWait.ID] || !found[cExpiredTimeWait.ID] {
		t.Fatalf("expected stale IDs (closed, close-wait, expired-time-wait) in %v", found)
	}
	if found[cFreshTimeWait.ID] {
		t.Fatalf("fresh TIME_WAIT should not be stale")
	}
	if found[cEstab.ID] {
		t.Fatal("ESTABLISHED should not be stale")
	}
}

func TestIdleConnectionsOnlyReturnsIdleEstablished(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	cActive := pm.NewConnection(1, protocol.Addr{}, 0)
	cActive.State = StateEstablished
	cActive.LastActivity = time.Now()

	cIdle := pm.NewConnection(2, protocol.Addr{}, 0)
	cIdle.State = StateEstablished
	cIdle.LastActivity = time.Now().Add(-1 * time.Hour)

	cIdleButClosed := pm.NewConnection(3, protocol.Addr{}, 0)
	cIdleButClosed.State = StateClosed
	cIdleButClosed.LastActivity = time.Now().Add(-1 * time.Hour)

	idle := pm.IdleConnections(30 * time.Second)
	if len(idle) != 1 {
		t.Fatalf("IdleConnections returned %d, want 1", len(idle))
	}
	if idle[0].ID != cIdle.ID {
		t.Fatalf("expected cIdle, got %d", idle[0].ID)
	}
}

func TestAllConnectionsReturnsEveryRegisteredConnection(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	_ = pm.NewConnection(1, protocol.Addr{}, 0)
	_ = pm.NewConnection(2, protocol.Addr{}, 0)
	_ = pm.NewConnection(3, protocol.Addr{}, 0)

	all := pm.AllConnections()
	if len(all) != 3 {
		t.Fatalf("AllConnections returned %d, want 3", len(all))
	}
}

// --- seqAfter / seqAfterOrEqual ---

func TestSeqAfterWrapAroundArithmetic(t *testing.T) {
	t.Parallel()
	// a > b cases
	if !seqAfter(100, 50) {
		t.Fatal("100 should be after 50")
	}
	// Wraparound: a=1, b=0xFFFFFFFE — (1 - 0xFFFFFFFE) as int32 = 3 > 0
	if !seqAfter(1, 0xFFFFFFFE) {
		t.Fatal("1 should be after 0xFFFFFFFE (wrap)")
	}
	// Equal
	if seqAfter(50, 50) {
		t.Fatal("50 should NOT be after 50")
	}
	// Behind
	if seqAfter(50, 100) {
		t.Fatal("50 should NOT be after 100")
	}
}

func TestSeqAfterOrEqualBoundary(t *testing.T) {
	t.Parallel()
	if !seqAfterOrEqual(50, 50) {
		t.Fatal("50 >= 50")
	}
	if !seqAfterOrEqual(100, 50) {
		t.Fatal("100 >= 50")
	}
	if seqAfterOrEqual(50, 100) {
		t.Fatal("50 should not be >= 100")
	}
}

// --- hasOOOSeg ---

func TestHasOOOSegFindAndMiss(t *testing.T) {
	t.Parallel()
	c := &Connection{
		OOOBuf: []*recvSegment{{seq: 1000, data: []byte("a")}, {seq: 2000, data: []byte("b")}},
	}
	if !c.hasOOOSeg(1000) {
		t.Fatal("should find seq 1000")
	}
	if !c.hasOOOSeg(2000) {
		t.Fatal("should find seq 2000")
	}
	if c.hasOOOSeg(3000) {
		t.Fatal("should not find seq 3000")
	}
}

// --- updateRTT ---

func TestUpdateRTTFirstMeasurementSetsSRTTAndRTTVAR(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.updateRTT(100 * time.Millisecond)
	if c.SRTT != 100*time.Millisecond {
		t.Fatalf("SRTT = %v, want 100ms", c.SRTT)
	}
	if c.RTTVAR != 50*time.Millisecond {
		t.Fatalf("RTTVAR = %v, want 50ms (RTT/2)", c.RTTVAR)
	}
	// RTO = SRTT + max(G, 4*RTTVAR) = 100ms + 200ms = 300ms
	if c.RTO != 300*time.Millisecond {
		t.Fatalf("RTO = %v, want 300ms", c.RTO)
	}
}

func TestUpdateRTTClampsToRTOMin(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.updateRTT(1 * time.Millisecond)
	if c.RTO < RTOMin {
		t.Fatalf("RTO = %v should be clamped to at least RTOMin=%v", c.RTO, RTOMin)
	}
}

func TestUpdateRTTClampsToRTOMax(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.updateRTT(30 * time.Second)
	if c.RTO > RTOMax {
		t.Fatalf("RTO = %v should be clamped to at most RTOMax=%v", c.RTO, RTOMax)
	}
}

func TestUpdateRTTSubsequentMeasurementBlendsSRTT(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	c.updateRTT(100 * time.Millisecond)
	// Subsequent: SRTT = 7/8 * 100 + 1/8 * 200 = 87.5 + 25 = 112.5ms
	c.updateRTT(200 * time.Millisecond)
	want := time.Duration(112500000) // 112.5ms in ns
	// Allow 1ms tolerance
	diff := c.SRTT - want
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Millisecond {
		t.Fatalf("SRTT = %v, want ≈%v (diff=%v)", c.SRTT, want, diff)
	}
}

// --- ProcessAck ---

func newAckTestConn(t *testing.T) *Connection {
	t.Helper()
	return &Connection{
		CongWin:  InitialCongWin,
		SSThresh: MaxCongWin / 2,
		WindowCh: make(chan struct{}, 1),
		NagleCh:  make(chan struct{}, 1),
	}
}

func TestProcessAckRemovesAckedSegments(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, 100), sentAt: time.Now().Add(-50 * time.Millisecond), attempts: 1},
		{seq: 1100, data: make([]byte, 100), sentAt: time.Now().Add(-50 * time.Millisecond), attempts: 1},
	}

	c.ProcessAck(1100, true)
	if len(c.Unacked) != 1 {
		t.Fatalf("Unacked = %d, want 1", len(c.Unacked))
	}
	if c.Unacked[0].seq != 1100 {
		t.Fatalf("remaining entry seq = %d, want 1100", c.Unacked[0].seq)
	}
	if c.LastAck != 1100 {
		t.Fatalf("LastAck = %d, want 1100", c.LastAck)
	}
	// SRTT should have been updated from the acked segment.
	if c.SRTT == 0 {
		t.Fatal("SRTT should have been updated by ProcessAck")
	}
}

func TestProcessAckBehindLastAckIsNoop(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 5000
	c.Unacked = []*retxEntry{{seq: 5000, data: make([]byte, 100), attempts: 1, sentAt: time.Now()}}

	c.ProcessAck(1000, true) // way behind
	if len(c.Unacked) != 1 {
		t.Fatal("stale ACK should be ignored")
	}
	if c.LastAck != 5000 {
		t.Fatalf("LastAck changed: %d", c.LastAck)
	}
}

func TestProcessAckDupAckOnlyCountsOnPureACK(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	// Dup-ACK counting requires data in flight (RFC 5681 §3.2); add an unacked
	// segment so the dup-ACK path is active.
	c.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, 100), attempts: 1, sentAt: time.Now()},
	}

	// pureACK=false — should NOT increment dup count
	c.ProcessAck(1000, false)
	if c.DupAckCount != 0 {
		t.Fatalf("DupAckCount = %d on data packet, want 0", c.DupAckCount)
	}

	// pureACK=true — each call increments
	c.ProcessAck(1000, true)
	c.ProcessAck(1000, true)
	if c.DupAckCount != 2 {
		t.Fatalf("DupAckCount = %d after 2 pure dup ACKs, want 2", c.DupAckCount)
	}
}

func TestProcessAckThirdDupACKTriggersFastRetransmit(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.CongWin = 40000
	c.SSThresh = 20000
	var sent []*protocol.Packet
	c.RetxSend = func(pkt *protocol.Packet) {
		sent = append(sent, pkt)
	}
	c.Unacked = []*retxEntry{
		{seq: 1000, data: []byte("one"), attempts: 1, sentAt: time.Now()},
	}

	c.ProcessAck(1000, true)
	c.ProcessAck(1000, true)
	c.ProcessAck(1000, true) // 3rd — fast retx

	if len(sent) != 1 {
		t.Fatalf("fast retransmit should have fired 1 packet, got %d", len(sent))
	}
	if sent[0].Seq != 1000 {
		t.Fatalf("fast retx Seq = %d, want 1000", sent[0].Seq)
	}
	// Multiplicative decrease: SSThresh = max(FlightSize/2, 2*SMSS).
	// FlightSize = len("one") = 3; FlightSize/2 = 1 < 2*MSS = 8192 → floor applies.
	// CongWin = SSThresh + three segments as sent (fast-recovery inflation:
	// each duplicate ACK is one SendSegmentSize segment leaving the network).
	wantSSThresh := 2 * MaxSegmentSize // max(3/2=1, 2*MSS=8192)
	if c.SSThresh != wantSSThresh {
		t.Fatalf("SSThresh = %d, want %d (max(FlightSize/2, 2*SMSS))", c.SSThresh, wantSSThresh)
	}
	if c.CongWin != wantSSThresh+3*SendSegmentSize {
		t.Fatalf("CongWin = %d, want %d", c.CongWin, wantSSThresh+3*SendSegmentSize)
	}
	if c.Stats.FastRetx != 1 {
		t.Fatalf("Stats.FastRetx = %d, want 1", c.Stats.FastRetx)
	}
}

func TestProcessAckGrowsCongWinInSlowStart(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.CongWin = 4000 // < SSThresh → slow start
	c.SSThresh = 50000
	c.Unacked = []*retxEntry{{seq: 1000, data: make([]byte, 1000), attempts: 1, sentAt: time.Now()}}

	c.ProcessAck(2000, true)
	// Slow start: CongWin += bytesAcked (1000)
	if c.CongWin != 5000 {
		t.Fatalf("CongWin = %d, want 5000 (slow-start +1000)", c.CongWin)
	}
}

func TestProcessAckGrowsCongWinInCongestionAvoidance(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.CongWin = 50000
	c.SSThresh = 20000 // CongWin >= SSThresh → CA
	c.Unacked = []*retxEntry{{seq: 1000, data: make([]byte, 1000), attempts: 1, sentAt: time.Now()}}

	c.ProcessAck(2000, true)
	// CA: increment = MSS * bytesAcked / CongWin = 4096*1000/50000 = 81 (floor)
	want := 50000 + 4096*1000/50000
	if c.CongWin != want {
		t.Fatalf("CongWin = %d, want %d", c.CongWin, want)
	}
}

func TestProcessAckClampsCongWinToMaxCongWin(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.CongWin = MaxCongWin - 100
	c.SSThresh = MaxCongWin / 2
	c.Unacked = []*retxEntry{{seq: 1000, data: make([]byte, 10000), attempts: 1, sentAt: time.Now()}}

	c.ProcessAck(11000, true)
	if c.CongWin > MaxCongWin {
		t.Fatalf("CongWin = %d exceeds MaxCongWin=%d", c.CongWin, MaxCongWin)
	}
}

func TestProcessAckExitsRecoveryAtRecoveryPoint(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.LastAck = 1000
	c.InRecovery = true
	c.RecoveryPoint = 1500
	c.Unacked = []*retxEntry{{seq: 1000, data: make([]byte, 500), attempts: 1, sentAt: time.Now()}}

	c.ProcessAck(1500, true)
	if c.InRecovery {
		t.Fatal("should have exited recovery when ACK reaches RecoveryPoint")
	}
}

// --- ProcessSACK ---

func TestProcessSACKMarksCoveredSegmentsAsSacked(t *testing.T) {
	t.Parallel()
	c := newAckTestConn(t)
	c.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, 100)}, // [1000,1100)
		{seq: 1100, data: make([]byte, 100)}, // [1100,1200)
		{seq: 1200, data: make([]byte, 100)}, // [1200,1300)
	}

	// SACK block covers [1100, 1200) only
	c.ProcessSACK([]SACKBlock{{Left: 1100, Right: 1200}})

	if c.Unacked[0].sacked {
		t.Fatal("[1000,1100) should not be sacked")
	}
	if !c.Unacked[1].sacked {
		t.Fatal("[1100,1200) should be sacked")
	}
	if c.Unacked[2].sacked {
		t.Fatal("[1200,1300) should not be sacked")
	}
	if c.Stats.SACKRecv != 1 {
		t.Fatalf("Stats.SACKRecv = %d, want 1", c.Stats.SACKRecv)
	}
}

// --- DeliverInOrder ---

func TestDeliverInOrderInOrderSegmentDelivers(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 1000,
	}
	ack := c.DeliverInOrder(1000, []byte("hello"))
	if ack != 1005 {
		t.Fatalf("ack = %d, want 1005", ack)
	}
	select {
	case data := <-c.RecvBuf:
		if string(data) != "hello" {
			t.Fatalf("delivered %q, want 'hello'", data)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("expected data in RecvBuf")
	}
}

func TestDeliverInOrderOutOfOrderBuffersAndDoesNotDeliver(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 1000,
	}
	ack := c.DeliverInOrder(1100, []byte("late"))
	if ack != 1000 {
		t.Fatalf("ack = %d, want 1000 (ExpectedSeq unchanged)", ack)
	}
	if len(c.OOOBuf) != 1 {
		t.Fatalf("OOOBuf = %d, want 1", len(c.OOOBuf))
	}
	if len(c.RecvBuf) != 0 {
		t.Fatal("OOO segment should not be delivered")
	}
}

func TestDeliverInOrderThenFillGapDeliversBoth(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 1000,
	}
	// Buffer OOO segment at 1005
	c.DeliverInOrder(1005, []byte("WORLD"))
	// Fill gap with in-order segment at 1000
	ack := c.DeliverInOrder(1000, []byte("hello"))
	if ack != 1010 {
		t.Fatalf("ack = %d, want 1010 (1000+5+5)", ack)
	}
	// Both "hello" and "WORLD" delivered.
	var collected []string
	for i := 0; i < 2; i++ {
		select {
		case data := <-c.RecvBuf:
			collected = append(collected, string(data))
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("expected 2 deliveries, got %d", len(collected))
		}
	}
	if collected[0] != "hello" || collected[1] != "WORLD" {
		t.Fatalf("delivery order wrong: %v", collected)
	}
}

func TestDeliverInOrderDuplicateSegmentIsIgnored(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 2000,
	}
	// Seq behind ExpectedSeq → duplicate, ignored
	ack := c.DeliverInOrder(1500, []byte("stale"))
	if ack != 2000 {
		t.Fatalf("ack = %d, want 2000", ack)
	}
	if len(c.RecvBuf) != 0 {
		t.Fatal("duplicate should not be delivered")
	}
	if len(c.OOOBuf) != 0 {
		t.Fatal("duplicate should not be buffered")
	}
}

func TestDeliverInOrderOOODeduplicatesSameSeq(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 1000,
	}
	c.DeliverInOrder(1100, []byte("A"))
	c.DeliverInOrder(1100, []byte("B"))

	if len(c.OOOBuf) != 1 {
		t.Fatalf("OOOBuf = %d, want 1 (dedup on seq)", len(c.OOOBuf))
	}
}

func TestDeliverInOrderOnClosedRecvBufReturnsExpectedSeq(t *testing.T) {
	t.Parallel()
	c := &Connection{
		RecvBuf:     make(chan []byte, 10),
		ExpectedSeq: 1000,
	}
	c.CloseRecvBuf()

	ack := c.DeliverInOrder(1000, []byte("won't arrive"))
	if ack != 1000 {
		t.Fatalf("ack = %d, want 1000 (closed)", ack)
	}
}

// --- fastRetransmit (pure, called under RetxMu) ---

func TestFastRetransmitResendsFirstNonSackedEntry(t *testing.T) {
	t.Parallel()
	c := &Connection{
		Unacked: []*retxEntry{
			{seq: 1000, data: []byte("sacked-data"), sacked: true, attempts: 1},
			{seq: 2000, data: []byte("retx-this"), attempts: 1},
		},
	}
	var captured *protocol.Packet
	c.RetxSend = func(pkt *protocol.Packet) { captured = pkt }
	c.RecvBuf = make(chan []byte, 1)

	c.RetxMu.Lock()
	c.fastRetransmit(0)
	c.RetxMu.Unlock()

	if captured == nil {
		t.Fatal("fastRetransmit did not send")
	}
	if captured.Seq != 2000 {
		t.Fatalf("retx Seq = %d, want 2000 (first non-sacked)", captured.Seq)
	}
	if c.Unacked[1].attempts != 2 {
		t.Fatalf("attempts = %d, want 2", c.Unacked[1].attempts)
	}
}

func TestFastRetransmitNoUnackedIsNoop(t *testing.T) {
	t.Parallel()
	c := &Connection{}
	// Should not panic.
	c.RetxMu.Lock()
	c.fastRetransmit(0)
	c.RetxMu.Unlock()
}
