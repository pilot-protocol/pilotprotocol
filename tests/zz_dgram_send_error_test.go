// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// TestSendToConfirmReportsDaemonSendFailure sends a datagram the daemon
// cannot send (the destination node is not registered, so no tunnel can be
// set up). The legacy CmdSendTo is fire-and-forget: the daemon only logs
// "IPC datagram send failed" and Driver.SendTo reports success. A client
// that asks with CmdSendToConfirm gets the daemon's error back, and an OK
// for a datagram that was sent. Speaks the IPC frames directly so it does
// not depend on a driver release that knows the new command.
func TestSendToConfirmReportsDaemonSendFailure(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	a := env.AddDaemon()
	b := env.AddDaemon()
	missing := protocol.Addr{Network: 0, Node: 0x00DEAD01}

	if err := a.Daemon.SendDatagram(missing, 5000, []byte("x")); err == nil {
		t.Fatal("setup: daemon.SendDatagram to an unregistered node succeeded")
	}
	if err := a.Driver.SendTo(missing, 5000, []byte("x")); err != nil {
		t.Fatalf("legacy SendTo must stay fire-and-forget, got %v", err)
	}

	conn, err := net.Dial("unix", a.SocketPath)
	if err != nil {
		t.Fatalf("dial daemon socket: %v", err)
	}
	defer conn.Close()
	confirm := func(dst protocol.Addr) []byte {
		t.Helper()
		frame := make([]byte, 1+protocol.AddrSize+2+1)
		frame[0] = daemon.CmdSendToConfirm
		dst.MarshalTo(frame, 1)
		binary.BigEndian.PutUint16(frame[1+protocol.AddrSize:], 5000)
		frame[len(frame)-1] = 'x'
		if err := ipcutil.Write(conn, frame); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
		reply, err := ipcutil.Read(conn)
		if err != nil || len(reply) == 0 {
			t.Fatalf("read reply: %v", err)
		}
		return reply
	}

	if reply := confirm(missing); reply[0] != daemon.CmdError || !strings.Contains(string(reply), "node not found") {
		t.Errorf("confirmed send to an unregistered node: reply %x %q, want CmdError naming the cause", reply[0], reply[1:])
	}
	if reply := confirm(b.Daemon.Addr()); reply[0] != daemon.CmdSendToOK {
		t.Errorf("confirmed send to a live peer: reply %x %q, want CmdSendToOK", reply[0], reply[1:])
	}
}
