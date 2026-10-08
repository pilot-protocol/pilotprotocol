// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// finTestConn is an established connection on d to peerNode, ports 55555
// (local) and 443 (remote), expecting the peer's data at seq 1000.
func finTestConn(t *testing.T, d *Daemon, peerNode uint32) *Connection {
	t.Helper()
	conn := d.ports.NewConnection(55555, protocol.Addr{Network: 0, Node: peerNode}, 443)
	conn.LocalAddr = protocol.Addr{Network: 0, Node: d.NodeID()}
	conn.Mu.Lock()
	conn.State = StateEstablished
	conn.SendSeq = 42
	conn.Mu.Unlock()
	conn.RecvMu.Lock()
	conn.ExpectedSeq = 1000
	conn.RecvMu.Unlock()
	return conn
}

func finTestData(peerNode, self uint32, seq uint32, payload string) *protocol.Packet {
	pkt := streamPacket(protocol.FlagACK, peerNode, self, 443, 55555, seq, 42)
	pkt.Payload = []byte(payload)
	return pkt
}

// A FIN that overtook a lost segment used to close the stream at once, so
// the reader saw EOF with the segment missing, and the FIN-ACK made the
// sender drop it. Under loss, a writer that closed right after its last
// write lost the end of it: in the lab, 4 in 30 pub/sub events at 5% loss
// never reached the broker while the publisher reported success. The FIN
// now waits for the data before it.
func TestEarlyFINIsHeldUntilTheDataBeforeItArrives(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD00F1)
	conn := finTestConn(t, d, peerNode)

	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1000, "abcde"))
	// Drain what the first segment caused, so the packets checked below are
	// the FIN's.
	for readPacket(t, peerConn, 150*time.Millisecond) != nil {
	}
	// [1005,1010) is lost; the FIN at 1010 arrives first.
	d.handleStreamPacket(streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 1010, 0))

	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateEstablished {
		t.Fatalf("state = %v after a FIN ahead of missing data, want it still established", st)
	}
	conn.RecvMu.Lock()
	closed := conn.RecvClosed
	conn.RecvMu.Unlock()
	if closed {
		t.Fatal("the receive side was closed with data still missing")
	}
	pkt := readPacket(t, peerConn, 300*time.Millisecond)
	if pkt == nil {
		t.Fatal("no ACK in reply to the early FIN")
	}
	if pkt.HasFlag(protocol.FlagFIN) || pkt.Ack != 1005 {
		t.Fatalf("reply to the early FIN: flags=%d ack=%d, want a plain ACK asking for 1005 (a FIN-ACK makes the sender drop the missing data)", pkt.Flags, pkt.Ack)
	}

	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1005, "fghij"))

	var got []byte
	for b := range conn.RecvBuf {
		got = append(got, b...)
	}
	if string(got) != "abcdefghij" {
		t.Fatalf("reader got %q, want every byte before EOF", got)
	}
	var finack *protocol.Packet
	for finack == nil {
		pkt := readPacket(t, peerConn, time.Second)
		if pkt == nil {
			t.Fatal("no FIN-ACK once the data had arrived")
		}
		if pkt.HasFlag(protocol.FlagFIN) {
			finack = pkt
		}
	}
	if !finack.HasFlag(protocol.FlagACK) || finack.Ack != 1011 {
		t.Fatalf("FIN-ACK flags=%d ack=%d, want FIN|ACK acknowledging 1011", finack.Flags, finack.Ack)
	}
	conn.Mu.Lock()
	st = conn.State
	conn.Mu.Unlock()
	if st != StateTimeWait {
		t.Fatalf("state = %v after the FIN was handled, want TIME_WAIT", st)
	}
}

// A connection this side has already closed discards the peer's data, so
// the peer's FIN is handled at once even if data before it is missing.
func TestFINOnAClosingConnectionIsAcceptedAtOnce(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD00F2)
	conn := finTestConn(t, d, peerNode)
	conn.Mu.Lock()
	conn.State = StateFinWait
	conn.Mu.Unlock()

	d.handleStreamPacket(streamPacket(protocol.FlagFIN|protocol.FlagACK, peerNode, d.NodeID(), 443, 55555, 1010, 43))

	pkt := readPacket(t, peerConn, 500*time.Millisecond)
	if pkt == nil || !pkt.HasFlag(protocol.FlagFIN) {
		t.Fatalf("got %v, want a FIN-ACK at once", pkt)
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateTimeWait {
		t.Fatalf("state = %v, want TIME_WAIT", st)
	}
}

// Closing with data unacknowledged sends the FIN once the data is
// acknowledged, and after finLinger at the latest.
func TestCloseSendsTheFINAfterTheLingerIfNothingIsAcknowledged(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xD9D90003)
	d.finLinger = 300 * time.Millisecond
	conn.NoDelay = true
	if err := d.SendData(conn, []byte("unacknowledged")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	readOneSegment(t, pc, 2*time.Second) // the data
	start := time.Now()
	d.CloseConnection(conn)
	fin := readOneSegment(t, pc, 2*time.Second)
	if fin.Flags&protocol.FlagFIN == 0 {
		t.Fatalf("next packet flags %#x, want the FIN", fin.Flags)
	}
	if waited := time.Since(start); waited < 250*time.Millisecond {
		t.Fatalf("FIN sent after %s with the data unacknowledged, want it held for the linger", waited)
	}
}

// A FIN still waiting for its data when the daemon stops goes out at
// shutdown, as it did when it was sent at close: otherwise the peer is left
// with an open connection until keepalive gives up on it.
func TestStopSendsAFINThatWasWaitingForData(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xD9D90004)
	conn.NoDelay = true
	if err := d.SendData(conn, []byte("unacknowledged")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	readOneSegment(t, pc, 2*time.Second) // the data
	d.CloseConnection(conn)
	conn.Mu.Lock()
	held := conn.heldFIN != nil
	conn.Mu.Unlock()
	if !held {
		t.Fatal("the FIN went out with the data unacknowledged; nothing to test")
	}
	stopped := make(chan struct{})
	go func() { d.Stop(); close(stopped) }()
	fin := readOneSegment(t, pc, 2*time.Second)
	if fin.Flags&protocol.FlagFIN == 0 {
		t.Fatalf("next packet flags %#x, want the FIN", fin.Flags)
	}
	if fin.Seq != 1000+uint32(len("unacknowledged")) {
		t.Fatalf("FIN seq %d, want %d", fin.Seq, 1000+len("unacknowledged"))
	}
	<-stopped
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := pc.ReadFromUDP(make([]byte, 65535)); err == nil {
		t.Fatalf("a second packet (%d bytes) after the FIN: it must go out once", n)
	}
}

// The held FIN goes out from the ACK path as soon as the data before it is
// acknowledged, not on a poll or at the linger.
func TestHeldFINGoesOutWithTheACKOfTheLastData(t *testing.T) {
	t.Parallel()
	const peer = 0xD9D90005
	d, pc, conn := newSendDataFixture(t, peer)
	d.setNodeID_testhelper(0x22222222)
	conn.NoDelay = true
	if err := d.SendData(conn, []byte("payload")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	data := readOneSegment(t, pc, 2*time.Second)
	d.CloseConnection(conn)
	conn.Mu.Lock()
	held := conn.heldFIN != nil
	conn.Mu.Unlock()
	if !held {
		t.Fatal("the FIN went out with the data unacknowledged; nothing to test")
	}
	start := time.Now()
	ack := streamPacket(protocol.FlagACK, peer, d.NodeID(), 80, 2000, 1, data.Seq+uint32(len(data.Payload)))
	ack.Window = 64
	d.handleStreamPacket(ack)
	fin := readOneSegment(t, pc, 2*time.Second)
	if fin.Flags&protocol.FlagFIN == 0 || fin.Seq != data.Seq+uint32(len(data.Payload)) {
		t.Fatalf("after the ACK: flags %#x seq %d, want the FIN at %d", fin.Flags, fin.Seq, data.Seq+uint32(len(data.Payload)))
	}
	if waited := time.Since(start); waited > 500*time.Millisecond {
		t.Fatalf("FIN sent %s after the ACK, want it at once", waited)
	}
}

// A FIN held for data the peer never resends (it was stopped or restarted
// with a segment lost) is handled once nothing has come from the peer for
// finHoldIdle: the reader gets EOF instead of waiting for keepalive to give
// up two minutes later. Data still arriving holds it longer.
func TestHeldPeerFINIsHandledOnceThePeerFallsSilent(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD00F3)
	d.finHoldIdle = time.Second
	conn := finTestConn(t, d, peerNode)

	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1000, "abcde"))
	start := time.Now()
	d.handleStreamPacket(streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 1020, 0))
	// The peer is still there for a while: an out-of-order segment after
	// 250 ms restarts the wait.
	time.Sleep(250 * time.Millisecond)
	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1010, "klmno"))

	var finack *protocol.Packet
	for finack == nil {
		pkt := readPacket(t, peerConn, 3*time.Second)
		if pkt == nil {
			t.Fatal("the held FIN was never handled after the peer fell silent")
		}
		if pkt.HasFlag(protocol.FlagFIN) {
			finack = pkt
		}
	}
	if waited := time.Since(start); waited < 1200*time.Millisecond {
		t.Fatalf("FIN handled %s after it arrived, want the wait restarted by the data at 250 ms (>= 1.25 s)", waited)
	}
	if finack.Ack != 1021 {
		t.Fatalf("FIN-ACK ack=%d, want 1021", finack.Ack)
	}
	var got []byte
	for b := range conn.RecvBuf {
		got = append(got, b...)
	}
	if string(got) != "abcde" {
		t.Fatalf("reader got %q before EOF, want the in-order data only", got)
	}
}

// A SYN on the ports of a connection whose FIN is held is a restarted
// peer dialling again (its ephemeral ports start over), not a resend: a
// peer that sent a FIN is past its SYN. The old connection ends, quietly,
// and the SYN opens a new one. Answered as the old connection, the new
// one's data was acknowledged as duplicates and never delivered.
func TestSYNOnAConnectionWithAHeldFINIsANewConnection(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD00F4)
	if _, err := d.ports.Bind(55555); err != nil {
		t.Fatal(err)
	}
	old := finTestConn(t, d, peerNode)
	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1000, "abcde"))
	d.handleStreamPacket(streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 1010, 0))
	for readPacket(t, peerConn, 150*time.Millisecond) != nil {
	}

	d.handleStreamPacket(streamPacket(protocol.FlagSYN, peerNode, d.NodeID(), 443, 55555, 7000, 0))

	var got []byte
	for b := range old.RecvBuf {
		got = append(got, b...)
	}
	if string(got) != "abcde" {
		t.Fatalf("old reader got %q before EOF, want the in-order data", got)
	}
	cur := d.ports.FindConnection(55555, protocol.Addr{Node: peerNode}, 443)
	if cur == nil || cur.ID == old.ID {
		t.Fatalf("connection on the ports after the SYN = %v, want a new one", cur)
	}
	for {
		pkt := readPacket(t, peerConn, time.Second)
		if pkt == nil {
			t.Fatal("no SYN-ACK for the new connection")
		}
		if pkt.HasFlag(protocol.FlagFIN) {
			t.Fatalf("a FIN (flags %d) went to the peer: it would close its new connection", pkt.Flags)
		}
		if pkt.HasFlag(protocol.FlagSYN) && pkt.HasFlag(protocol.FlagACK) {
			if pkt.Ack != 7001 {
				t.Fatalf("SYN-ACK ack=%d, want 7001: answered as the old connection", pkt.Ack)
			}
			break
		}
	}
}

// A connection that ends some other way while the peer's FIN is held (here
// an RST) stops the hold: no FIN-ACK goes out for it later, where it could
// reach a new connection on the same ports.
func TestHoldEndsWithTheConnection(t *testing.T) {
	t.Parallel()
	d, peerNode, peerConn := setupDaemonWithPeer(t, Config{Public: true})
	d.setNodeID_testhelper(0xABCD00F5)
	d.finHoldIdle = 200 * time.Millisecond
	finTestConn(t, d, peerNode)
	d.handleStreamPacket(finTestData(peerNode, d.NodeID(), 1000, "abcde"))
	d.handleStreamPacket(streamPacket(protocol.FlagFIN, peerNode, d.NodeID(), 443, 55555, 1010, 0))
	d.handleStreamPacket(streamPacket(protocol.FlagRST, peerNode, d.NodeID(), 443, 55555, 0, 0))
	deadline := time.Now().Add(700 * time.Millisecond)
	for time.Now().Before(deadline) {
		if pkt := readPacket(t, peerConn, 100*time.Millisecond); pkt != nil && pkt.HasFlag(protocol.FlagFIN) {
			t.Fatalf("FIN (flags %d) sent for a connection the peer reset", pkt.Flags)
		}
	}
}

// Shutdown can catch a close half done: the FIN held, the state still
// ESTABLISHED. It sends that FIN, at its reserved sequence number, and no
// second one after it, which a receiver would hold for good.
func TestStopSendsOnlyTheHeldFINOfAHalfDoneClose(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xD9D90006)
	conn.Mu.Lock()
	conn.heldFIN = &protocol.Packet{
		Version: protocol.Version, Flags: protocol.FlagFIN, Protocol: protocol.ProtoStream,
		Src: conn.LocalAddr, Dst: conn.RemoteAddr, SrcPort: conn.LocalPort, DstPort: conn.RemotePort,
		Seq: 1000,
	}
	conn.SendSeq = 1001 // reserved, as CloseConnection does
	conn.Mu.Unlock()
	d.Stop()
	fin := readOneSegment(t, pc, 2*time.Second)
	if fin.Flags&protocol.FlagFIN == 0 || fin.Seq != 1000 {
		t.Fatalf("at stop: flags %#x seq %d, want the held FIN at 1000", fin.Flags, fin.Seq)
	}
	pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _, err := pc.ReadFromUDP(make([]byte, 65535)); err == nil {
		t.Fatalf("a second packet (%d bytes) after the held FIN", n)
	}
}

// End to end over two daemons: a writer that closes right after its last
// write, with one segment's first transmission lost, still gets every byte
// to the reader before EOF. finLinger 0 sends the FIN at once, as senders up
// to v1.17.0 do, so only the receiver's rule protects the data.
func TestWriteThenCloseSurvivesALostSegment(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-second transfer")
	}
	for _, tc := range []struct {
		name   string
		linger time.Duration
	}{
		{"FIN at once (old senders)", 0},
		{"FIN after the data is acknowledged", defaultFinLinger},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, want := runWriteThenClose(t, tc.linger)
			if !bytes.Equal(got, want) {
				t.Fatalf("reader got %d of %d bytes before EOF", len(got), len(want))
			}
		})
	}
}

func runWriteThenClose(t *testing.T, linger time.Duration) (got, want []byte) {
	const idA, idB uint32 = 0xA0000F01, 0xB0000F01
	const portA, portB uint16 = 5100, 6100
	const isnA uint32 = 200000

	A := New(Config{Public: true})
	B := New(Config{Public: true})
	A.finLinger = linger
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

	cB := B.ports.NewConnection(portB, protocol.Addr{Node: idA}, portA)
	cB.LocalAddr = protocol.Addr{Node: idB}
	cB.State = StateEstablished
	cB.SendSeq = 1
	cB.RecvAck = isnA
	cB.ExpectedSeq = isnA

	A.startRetxLoop(cA)
	t.Cleanup(func() { A.ports.RemoveConnection(cA.ID) })

	lostSeq := isnA + SendSegmentSize // the second segment's first send
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { // A → B, with one segment lost once
		defer wg.Done()
		dropped := false
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
			if len(pkt.Payload) > 0 && pkt.Seq == lostSeq && !dropped {
				dropped = true
				continue
			}
			B.handleStreamPacket(pkt)
		}
	}()
	go func() { // B → A
		defer wg.Done()
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
	t.Cleanup(func() { close(stop); wg.Wait() })

	want = make([]byte, 3*SendSegmentSize+100)
	for i := range want {
		want[i] = byte(i*13 + i/SendSegmentSize)
	}
	if err := A.SendData(cA, want); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	A.CloseConnection(cA)

	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for b := range cB.RecvBuf {
			mu.Lock()
			got = append(got, b...)
			mu.Unlock()
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		mu.Lock()
		n := len(got)
		mu.Unlock()
		t.Fatalf("reader still open after 15s with %d of %d bytes", n, len(want))
	}
	return got, want
}
