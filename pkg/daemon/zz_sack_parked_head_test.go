// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// End-to-end check of a receiver that parks the segment at its cumulative
// ACK (its application stopped reading) while the sender has SACK marks
// for it. Two real Daemons; every stream packet goes through the real
// handleStreamPacket on both sides. A→B data and B→A ACKs travel over
// loopback UDP through pumps this test controls:
//   - the first transmission of one chosen segment is dropped (a hole),
//   - B→A packets are held until A has put every original segment on the
//     wire (the segments were sent while the window was open),
//   - B's application has stopped reading: RecvBuf is pre-filled with
//     placeholder chunks, and the reader starts only at resumeAt.

import (
	"bytes"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

var parkedDummy = []byte("DUMMY")

type parkedCfg struct {
	segs        int           // segments the sender writes
	holeIdx     int           // segment whose first transmission is dropped
	freeSlots   int           // RecvBuf slots left free at the start
	leaked      int           // stale OOOBuf entries injected below ExpectedSeq
	bigCwnd     bool          // start with a warmed-up congestion window
	resumeAt    time.Duration // when B's application starts reading
	deadline    time.Duration
	extraWrites int // segments written after the transfer completes
}

type parkedResult struct {
	completed   bool
	elapsed     time.Duration
	rst         bool
	expectedSeq uint32
	oooAfter    []*recvSegment
	retx        uint64
	got         []byte
	want        []byte
}

func parkedSock(t *testing.T) *net.UDPConn {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func parkedRead(c *net.UDPConn) *protocol.Packet {
	buf := make([]byte, 65536)
	c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil || n < 4 {
		return nil
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		return nil
	}
	return pkt
}

func runParkedTransfer(t *testing.T, cfg parkedCfg) parkedResult {
	const idA, idB uint32 = 0xA0000001, 0xB0000001
	const portA, portB uint16 = 5000, 6000
	const isnA uint32 = 100000

	A := New(Config{Public: true})
	B := New(Config{Public: true})
	for _, d := range []*Daemon{A, B} {
		if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		dd := d
		t.Cleanup(func() { dd.tunnels.Close() })
	}
	A.setNodeID_testhelper(idA)
	B.setNodeID_testhelper(idB)
	pa := parkedSock(t) // A → B traffic lands here
	pb := parkedSock(t) // B → A traffic lands here
	A.AddTunnelPeer(idB, pa.LocalAddr().(*net.UDPAddr))
	B.AddTunnelPeer(idA, pb.LocalAddr().(*net.UDPAddr))

	cA := A.ports.NewConnection(portA, protocol.Addr{Node: idB}, portB)
	cA.LocalAddr = protocol.Addr{Node: idA}
	cA.State = StateEstablished
	cA.SendSeq = isnA
	cA.RecvAck = 1
	cA.NoDelay = true
	if cfg.bigCwnd {
		cA.CongWin = MaxCongWin
		cA.SSThresh = MaxCongWin
	}

	cB := B.ports.NewConnection(portB, protocol.Addr{Node: idA}, portA)
	cB.LocalAddr = protocol.Addr{Node: idB}
	cB.State = StateEstablished
	cB.SendSeq = 1
	cB.RecvAck = isnA
	cB.ExpectedSeq = isnA
	for i := 0; i < RecvBufSize-cfg.freeSlots; i++ {
		cB.RecvBuf <- parkedDummy
	}
	for i := 0; i < cfg.leaked; i++ {
		// Stale duplicates below ExpectedSeq, as left by earlier recoveries.
		cB.OOOBuf = append(cB.OOOBuf, &recvSegment{
			seq:  isnA - uint32((i+1)*10*SendSegmentSize),
			data: make([]byte, SendSegmentSize),
		})
	}

	A.startRetxLoop(cA)
	t.Cleanup(func() { A.ports.RemoveConnection(cA.ID) })

	holeSeq := isnA + uint32(cfg.holeIdx*SendSegmentSize)
	var originals atomic.Int64
	gate := make(chan struct{})
	var gateOnce sync.Once
	stop := make(chan struct{})
	var wg sync.WaitGroup

	// A → B pump: the receiver's routeLoop (single goroutine).
	wg.Add(1)
	go func() {
		defer wg.Done()
		dropped := false
		seen := map[uint32]bool{}
		for {
			select {
			case <-stop:
				return
			default:
			}
			pkt := parkedRead(pa)
			if pkt == nil {
				continue
			}
			if len(pkt.Payload) > 0 && pkt.HasFlag(protocol.FlagACK) && !pkt.HasFlag(protocol.FlagSYN) {
				if !seen[pkt.Seq] {
					seen[pkt.Seq] = true
					if n := originals.Add(1); n == int64(cfg.segs) {
						gateOnce.Do(func() { close(gate) })
					}
				}
				if pkt.Seq == holeSeq && !dropped {
					dropped = true
					continue
				}
			}
			B.handleStreamPacket(pkt)
		}
	}()
	// B → A pump: held until every original segment is on the wire.
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-gate:
		case <-stop:
			return
		}
		for {
			select {
			case <-stop:
				return
			default:
			}
			if pkt := parkedRead(pb); pkt != nil {
				A.handleStreamPacket(pkt)
			}
		}
	}()

	want := make([]byte, cfg.segs*SendSegmentSize)
	for i := range want {
		want[i] = byte(i*7 + i/SendSegmentSize)
	}
	go func() {
		if err := A.SendData(cA, want); err != nil {
			t.Logf("SendData: %v", err)
		}
	}()
	// Safety: open the gate anyway if the window stopped the burst.
	go func() {
		select {
		case <-time.After(2 * time.Second):
			gateOnce.Do(func() { close(gate) })
		case <-stop:
		}
	}()

	// B's application: stopped, resumes reading at resumeAt.
	var gotMu sync.Mutex
	var got []byte
	done := make(chan struct{})
	start := time.Now()
	go func() {
		select {
		case <-time.After(cfg.resumeAt):
		case <-stop:
			return
		}
		for {
			select {
			case b, ok := <-cB.RecvBuf:
				if !ok {
					return
				}
				if bytes.Equal(b, parkedDummy) {
					continue
				}
				gotMu.Lock()
				got = append(got, b...)
				n := len(got)
				gotMu.Unlock()
				if n >= len(want) {
					close(done)
					return
				}
			case <-stop:
				return
			}
		}
	}()

	snapshot := func(tag string) {
		cA.RetxMu.Lock()
		nUn, nS := len(cA.Unacked), 0
		var headSeq uint32
		var headAtt int
		headS := false
		for _, e := range cA.Unacked {
			if e.sacked {
				nS++
			}
		}
		if nUn > 0 {
			headSeq, headAtt, headS = cA.Unacked[0].seq, cA.Unacked[0].attempts, cA.Unacked[0].sacked
		}
		rto, lastAck := cA.RTO, cA.LastAck
		cA.RetxMu.Unlock()
		cA.Mu.Lock()
		st, retx := cA.State, cA.Stats.Retransmits
		cA.Mu.Unlock()
		cB.RecvMu.Lock()
		exp, ooo := cB.ExpectedSeq, len(cB.OOOBuf)
		cB.RecvMu.Unlock()
		gotMu.Lock()
		g := len(got)
		gotMu.Unlock()
		t.Logf("%s t=%5.1fs A{state=%v lastAck=+%d unacked=%d sacked=%d head=+%d headSacked=%v headAtt=%d rto=%v retx=%d} B{expected=+%d ooo=%d appGot=%d/%d}",
			tag, time.Since(start).Seconds(), st, lastAck-isnA, nUn, nS, headSeq-isnA, headS, headAtt, rto.Round(time.Millisecond), retx,
			exp-isnA, ooo, g/SendSegmentSize, cfg.segs)
	}

	res := parkedResult{want: want}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	timeout := time.After(cfg.deadline)
loop:
	for {
		select {
		case <-done:
			res.completed = true
			res.elapsed = time.Since(start)
			break loop
		case <-tick.C:
			snapshot("..")
			cA.Mu.Lock()
			closed := cA.State == StateClosed
			cA.Mu.Unlock()
			if closed {
				res.rst = true
				break loop
			}
		case <-timeout:
			break loop
		}
	}
	// Let the final ACK land, then look at the receiver's reorder buffer.
	time.Sleep(300 * time.Millisecond)
	snapshot("end")

	if res.completed && cfg.extraWrites > 0 {
		// After recovery: does the receiver still answer every segment at
		// once with a SACK (hasOOO stays true)?
		cB.Mu.Lock()
		t.Logf("before %d more segments: B SACK blocks sent so far = %d", cfg.extraWrites, cB.Stats.SACKSent)
		cB.Mu.Unlock()
		extra := make([]byte, cfg.extraWrites*SendSegmentSize)
		go A.SendData(cA, extra)
		go func() {
			for i := 0; i < cfg.extraWrites; i++ {
				select {
				case <-cB.RecvBuf:
				case <-time.After(2 * time.Second):
					return
				}
			}
		}()
		time.Sleep(500 * time.Millisecond)
		cB.Mu.Lock()
		t.Logf("after %d more segments: B SACK blocks sent so far = %d", cfg.extraWrites, cB.Stats.SACKSent)
		cB.Mu.Unlock()
	}

	cB.RecvMu.Lock()
	res.expectedSeq = cB.ExpectedSeq - isnA
	for _, s := range cB.OOOBuf {
		res.oooAfter = append(res.oooAfter, s)
		t.Logf("B OOOBuf entry: seq=+%d (ExpectedSeq=+%d) behind=%v", s.seq-isnA, cB.ExpectedSeq-isnA, seqAfter(cB.ExpectedSeq, s.seq))
	}
	cB.RecvMu.Unlock()
	cA.Mu.Lock()
	res.retx = cA.Stats.Retransmits
	cA.Mu.Unlock()
	gotMu.Lock()
	res.got = append([]byte(nil), got...)
	gotMu.Unlock()

	close(stop)
	wg.Wait()
	return res
}

func parkedEnvInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil {
		return v
	}
	return def
}

// One hole; the receiver's application stalls while the segments after it
// drain, so the segment at ExpectedSeq is parked and SACKed. The transfer
// must complete once the application reads again. Before the fix the
// sender never resent the parked segment and the transfer stood still.
func TestParkedHeadIsResentAndTheTransferCompletes(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second transfer")
	}
	res := runParkedTransfer(t, parkedCfg{
		segs:        20,
		holeIdx:     2,
		freeSlots:   4,
		resumeAt:    time.Duration(parkedEnvInt("PROBE_RESUME", 3)) * time.Second,
		deadline:    time.Duration(parkedEnvInt("PROBE_DEADLINE", 20)) * time.Second,
		extraWrites: 4,
	})
	t.Logf("completed=%v elapsed=%v rst=%v retransmits=%d", res.completed, res.elapsed.Round(time.Millisecond), res.rst, res.retx)
	if !res.completed {
		t.Fatalf("transfer did not complete: receiver ExpectedSeq=+%d of %d", res.expectedSeq, len(res.want))
	}
	if !bytes.Equal(res.got[:len(res.want)], res.want) {
		t.Fatal("delivered bytes differ from what was sent")
	}
	for _, s := range res.oooAfter {
		if seqAfter(res.expectedSeq+100000, s.seq) {
			t.Errorf("stale reorder-buffer entry left behind the cumulative ACK: seq=+%d", s.seq-100000)
		}
	}
}

// As above with a full window (128 segments), the hole at the first
// segment, and stale entries already in the receiver's reorder buffer (as
// earlier recoveries left them). The full reorder buffer drops the last
// segment, so not everything is SACKed; the parked head must still be
// resent. Waiting for every segment to be SACKed ended in a reset at 51s.
func TestParkedHeadIsResentWithUnsackedSegmentsBehindIt(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second transfer")
	}
	res := runParkedTransfer(t, parkedCfg{
		segs:      MaxSegmentsOutstanding,
		holeIdx:   0,
		freeSlots: 1,
		leaked:    parkedEnvInt("PROBE_LEAKED", 2),
		bigCwnd:   true,
		resumeAt:  3 * time.Second,
		deadline:  time.Duration(parkedEnvInt("PROBE_DEADLINE", 60)) * time.Second,
	})
	t.Logf("completed=%v elapsed=%v rst=%v retransmits=%d", res.completed, res.elapsed.Round(time.Millisecond), res.rst, res.retx)
	if !res.completed {
		t.Fatalf("transfer did not complete (rst=%v): receiver ExpectedSeq=+%d of %d", res.rst, res.expectedSeq, len(res.want))
	}
	if !bytes.Equal(res.got[:len(res.want)], res.want) {
		t.Fatal("delivered bytes differ from what was sent")
	}
}
