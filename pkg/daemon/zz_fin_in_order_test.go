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
	for {
		pkt := readPacket(t, peerConn, 300*time.Millisecond)
		if pkt == nil {
			t.Fatal("no ACK asking for the missing data")
		}
		if pkt.HasFlag(protocol.FlagFIN) {
			t.Fatal("a FIN-ACK went out with data still missing: the sender would drop it")
		}
		if pkt.Ack == 1005 {
			break // the ACK that asks for [1005,1010)
		}
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		for b := range cB.RecvBuf {
			got = append(got, b...)
		}
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatalf("reader still open after 15s with %d of %d bytes", len(got), len(want))
	}
	return got, want
}
