// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// --- routeLoop ---

// routeLoop drains tunnels.RecvCh and dispatches via handlePacket. Push a ping
// directly into recvCh and verify a pong comes back (proves dispatch works),
// then close the channel to unblock the loop.
func TestRouteLoopDispatchesPingAndExitsOnClose(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)

	const peerNode uint32 = 0xFEED0001
	d.AddTunnelPeer(peerNode, peerAddr)

	done := make(chan struct{})
	go func() {
		d.routeLoop()
		close(done)
	}()

	// Push a ping packet into the internal recvCh.
	ping := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    0,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Network: 0, Node: peerNode},
		Dst:      protocol.Addr{Network: 0, Node: 0},
		SrcPort:  1234,
		DstPort:  protocol.PortPing,
		Seq:      100,
	}
	d.tunnels.recvCh <- &IncomingPacket{Packet: ping, From: peerAddr}

	// Expect pong on peer socket.
	peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected pong: %v", err)
	}
	pong, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal pong: %v", err)
	}
	if pong.Flags&protocol.FlagACK == 0 || pong.Ack != 101 {
		t.Fatalf("expected ACK with Ack=101, got flags=%b Ack=%d", pong.Flags, pong.Ack)
	}

	// Close the tunnel to stop routeLoop.
	d.tunnels.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("routeLoop did not exit after tunnels.Close()")
	}
}

// --- sendDelayedACK ---

func TestSendDelayedACKClearsPendingAndEmitsPureACK(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xDEAD77AA
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x11111111}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.SendSeq = 400
	conn.RecvAck = 500
	conn.AckMu.Lock()
	conn.PendingACKs = 2
	conn.ACKTimer = time.AfterFunc(time.Hour, func() {}) // never fires; sendDelayedACK must Stop it
	conn.AckMu.Unlock()

	d.sendDelayedACK(conn)

	// Verify counter cleared + timer cleared
	conn.AckMu.Lock()
	if conn.PendingACKs != 0 {
		t.Fatalf("PendingACKs = %d, want 0", conn.PendingACKs)
	}
	if conn.ACKTimer != nil {
		t.Fatal("ACKTimer should be nil after sendDelayedACK")
	}
	conn.AckMu.Unlock()

	// Verify pure-ACK packet landed on peer socket with the right fields.
	peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected ACK: %v", err)
	}
	ack, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ack.Flags&protocol.FlagACK == 0 {
		t.Fatalf("expected FlagACK, got flags=%b", ack.Flags)
	}
	if ack.Seq != 400 || ack.Ack != 500 {
		t.Fatalf("Seq=%d Ack=%d, want 400/500", ack.Seq, ack.Ack)
	}
	if len(ack.Payload) != 0 {
		t.Fatalf("pure ACK should have no payload; got %d bytes", len(ack.Payload))
	}
}

func TestSendDelayedACKWithSACKBlocksIncludesSACKPayload(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xDEAD77BB
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x22222222}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.SendSeq = 1000
	conn.RecvAck = 2000

	// Seed an out-of-order segment so SACKBlocks returns non-empty.
	conn.RecvMu.Lock()
	conn.OOOBuf = []*recvSegment{{seq: 3000, data: []byte("oo-data")}}
	conn.RecvMu.Unlock()

	d.sendDelayedACK(conn)

	peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected ACK: %v", err)
	}
	ack, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ack.Payload) == 0 {
		t.Fatal("ACK should carry encoded SACK blocks in payload")
	}
	if conn.Stats.SACKSent == 0 {
		t.Fatal("Stats.SACKSent should increment")
	}
}

// --- sendDataImmediate + sendSegment ---

func TestSendDataImmediateEmptyDataNoSegments(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xAAAA0001
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33333333}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.CongWin = InitialCongWin
	conn.SSThresh = MaxCongWin / 2

	if err := d.sendDataImmediate(conn, nil); err != nil {
		t.Fatalf("sendDataImmediate(nil): %v", err)
	}
	peerConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 2048)
	if _, _, err := peerConn.ReadFromUDP(buf); err == nil {
		t.Fatal("no segment should be sent for empty data")
	}
}

func TestSendDataImmediateSendsSingleSegmentUnderMSS(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xAAAA0002
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x44444444}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.CongWin = InitialCongWin
	conn.SSThresh = MaxCongWin / 2
	conn.RetxStop = make(chan struct{})
	conn.SendSeq = 1000
	conn.RecvAck = 50

	payload := []byte("hello-world")
	if err := d.sendDataImmediate(conn, payload); err != nil {
		t.Fatalf("sendDataImmediate: %v", err)
	}

	peerConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 8192)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("expected segment: %v", err)
	}
	pkt, err := protocol.Unmarshal(buf[4:n])
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(pkt.Payload) != "hello-world" {
		t.Fatalf("payload = %q, want hello-world", pkt.Payload)
	}
	if pkt.Seq != 1000 {
		t.Fatalf("Seq = %d, want 1000", pkt.Seq)
	}
	if pkt.Ack != 50 {
		t.Fatalf("Ack = %d, want 50", pkt.Ack)
	}
	// SendSeq should have advanced by the payload length.
	conn.Mu.Lock()
	newSeq := conn.SendSeq
	conn.Mu.Unlock()
	if newSeq != 1000+uint32(len(payload)) {
		t.Fatalf("SendSeq = %d, want 1011", newSeq)
	}
	// Unacked should contain the segment.
	conn.RetxMu.Lock()
	nUnacked := len(conn.Unacked)
	conn.RetxMu.Unlock()
	if nUnacked != 1 {
		t.Fatalf("Unacked = %d, want 1", nUnacked)
	}
}

func TestSendDataImmediateSplitsIntoMSSSegments(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xAAAA0003
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x55555555}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.CongWin = InitialCongWin
	conn.SSThresh = MaxCongWin / 2
	conn.RetxStop = make(chan struct{})
	conn.SendSeq = 0
	conn.RecvAck = 0

	// Payload = 2 full MSS + a small tail.
	payload := make([]byte, 2*SendSegmentSize+10)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	if err := d.sendDataImmediate(conn, payload); err != nil {
		t.Fatalf("sendDataImmediate: %v", err)
	}

	// Collect 3 frames.
	deadline := time.Now().Add(500 * time.Millisecond)
	var sizes []int
	for len(sizes) < 3 {
		rem := time.Until(deadline)
		if rem <= 0 {
			break
		}
		peerConn.SetReadDeadline(time.Now().Add(rem))
		buf := make([]byte, 8192)
		n, _, err := peerConn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		pkt, err := protocol.Unmarshal(buf[4:n])
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		sizes = append(sizes, len(pkt.Payload))
	}
	if len(sizes) != 3 {
		t.Fatalf("got %d segments, want 3; sizes=%v", len(sizes), sizes)
	}
	if sizes[0] != SendSegmentSize || sizes[1] != SendSegmentSize || sizes[2] != 10 {
		t.Fatalf("segment sizes = %v, want [MSS, MSS, 10]", sizes)
	}
}

func TestSendSegmentRetxStopAbortsZeroWindowWait(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	defer d.tunnels.Close()

	peerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	peerAddr := peerConn.LocalAddr().(*net.UDPAddr)
	const peerNode uint32 = 0xAAAA0004
	d.AddTunnelPeer(peerNode, peerAddr)

	conn := d.ports.NewConnection(1000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.State = StateEstablished
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x66666666}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	// Force "window full" by pre-populating Unacked to exceed window.
	conn.CongWin = 10
	conn.SSThresh = MaxCongWin / 2
	conn.PeerRecvWin = 10
	conn.RetxStop = make(chan struct{})
	conn.RetxMu.Lock()
	conn.Unacked = []*retxEntry{{data: make([]byte, 1000), seq: 1, sentAt: time.Now(), attempts: 1}}
	conn.RetxMu.Unlock()

	result := make(chan error, 1)
	go func() {
		result <- d.sendSegment(conn, []byte("more-data"))
	}()

	// Let the wait start, then abort via RetxStop.
	time.Sleep(20 * time.Millisecond)
	close(conn.RetxStop)

	select {
	case err := <-result:
		if err != protocol.ErrConnClosed {
			t.Fatalf("err = %v, want ErrConnClosed", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("sendSegment did not abort on RetxStop close")
	}
}
