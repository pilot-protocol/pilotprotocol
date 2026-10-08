// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

func sendToPayload(dst protocol.Addr, port uint16, data string) []byte {
	p := make([]byte, protocol.AddrSize+2+len(data))
	dst.MarshalTo(p, 0)
	binary.BigEndian.PutUint16(p[protocol.AddrSize:], port)
	copy(p[protocol.AddrSize+2:], data)
	return p
}

// TestIPCSendToConfirmRepliesWithOutcome covers CmdSendToConfirm: OK once
// the datagram is handed to the tunnel, CmdError with the reason when the
// daemon cannot send it, datagrams leaving in the order they were written —
// and the legacy CmdSendTo staying silent on failure, which existing
// drivers depend on (they would hand an unexpected CmdError to an unrelated
// request).
func TestIPCSendToConfirmRepliesWithOutcome(t *testing.T) {
	d, server, socketPath := newIPCTestServer(t)
	const peerNode uint32 = 0xABCD0071
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() {
		d.tunnels.Close()
		peerConn.Close()
	})
	d.setNodeID_testhelper(0x11110071)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()

	peer := protocol.Addr{Network: 0, Node: peerNode}
	reply := func() []byte {
		t.Helper()
		_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
		frame, err := readIPCFrame(connection)
		if err != nil {
			t.Fatalf("read reply: %v", err)
		}
		return frame
	}

	// Sent: interleaved with legacy sends, in order.
	for i, cmd := range []byte{CmdSendTo, CmdSendToConfirm, CmdSendTo, CmdSendToConfirm} {
		if err := writeIPCRequest(connection, cmd, sendToPayload(peer, 5000, string(rune('a'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if frame := reply(); frame[0] != CmdSendToOK || len(frame) != 1 {
			t.Fatalf("confirm reply %d = %x, want CmdSendToOK with no body", i, frame)
		}
	}
	for i := 0; i < 4; i++ {
		pkt := recvPacket(t, peerConn, 2*time.Second)
		if pkt == nil {
			t.Fatalf("datagram %d never reached the peer", i)
		}
		if want := string(rune('a' + i)); string(pkt.Payload) != want || pkt.DstPort != 5000 {
			t.Fatalf("datagram %d = %q to port %d, want %q to port 5000", i, pkt.Payload, pkt.DstPort, want)
		}
	}

	// Not sent: the reason comes back.
	if err := writeIPCRequest(connection, CmdSendToConfirm, sendToPayload(protocol.BroadcastAddr(1), 5000, "x")); err != nil {
		t.Fatal(err)
	}
	if frame := reply(); frame[0] != CmdError || !strings.HasPrefix(string(frame[3:]), "sendto: broadcast address requires admin token") {
		t.Fatalf("failed send reply = %x %q, want CmdError naming the cause", frame[0], frame[1:])
	}
	if err := writeIPCRequest(connection, CmdSendToConfirm, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	// Every error reply starts with "sendto: ": with no request IDs on the
	// IPC, that prefix is how the driver tells a confirmed send's answer
	// from any other request's (common/driver isConfirmAnswer).
	if frame := reply(); frame[0] != CmdError || !strings.HasPrefix(string(frame[3:]), "sendto: ") {
		t.Fatalf("truncated request reply = %x %q, want CmdError starting with \"sendto: \"", frame[0], frame[1:])
	}

	// Legacy CmdSendTo: still no reply, even when the send fails.
	if err := writeIPCRequest(connection, CmdSendTo, sendToPayload(protocol.BroadcastAddr(1), 5000, "x")); err != nil {
		t.Fatal(err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if frame, err := readIPCFrame(connection); err == nil {
		t.Fatalf("legacy CmdSendTo got a reply %x; it must stay fire-and-forget", frame)
	}
}

func TestDaemonFeaturesAdvertiseDgramConfirm(t *testing.T) {
	for _, f := range daemonFeatures {
		if f == "dgram_confirm" {
			return
		}
	}
	t.Fatalf("daemonFeatures = %v, want dgram_confirm listed", daemonFeatures)
}
