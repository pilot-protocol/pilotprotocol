// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// infoHostname runs one info request and returns the hostname in the reply.
func infoHostname(t *testing.T, s *IPCServer) string {
	t.Helper()
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() { s.handleInfo(ic, 0) })
	if reply[0] != CmdInfoOK {
		t.Fatalf("opcode = 0x%02X, want CmdInfoOK", reply[0])
	}
	var info map[string]interface{}
	if err := json.Unmarshal(reply[1:], &info); err != nil {
		t.Fatalf("info json: %v", err)
	}
	h, _ := info["hostname"].(string)
	return h
}

// A burst of info requests shares one reply for infoReplyTTL; a request
// after that sees current state again. Not parallel: it reads the
// package-level TTL.
func TestInfoReplyIsSharedWithinTTLThenRebuilt(t *testing.T) {
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"networks": []interface{}{float64(0)}}
	})
	defer cleanup()
	d, s := newSimpleHandlerDaemon(t, client)

	d.config.Hostname = "before"
	if got := infoHostname(t, s); got != "before" {
		t.Fatalf("first reply hostname = %q, want before", got)
	}

	d.config.Hostname = "after"
	if got := infoHostname(t, s); got != "before" {
		t.Fatalf("reply inside the TTL was rebuilt (hostname %q); concurrent senders would each rebuild it", got)
	}

	s.infoMu.Lock()
	s.infoAt = time.Now().Add(-2 * infoReplyTTL)
	s.infoMu.Unlock()
	if got := infoHostname(t, s); got != "after" {
		t.Fatalf("reply after the TTL still stale (hostname %q)", got)
	}
}

// With reuse turned off every request is built fresh.
func TestInfoReplyReuseCanBeTurnedOff(t *testing.T) {
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"networks": []interface{}{float64(0)}}
	})
	defer cleanup()
	d, s := newSimpleHandlerDaemon(t, client)

	prev := infoReplyTTL
	infoReplyTTL = 0
	t.Cleanup(func() { infoReplyTTL = prev })

	d.config.Hostname = "one"
	_ = infoHostname(t, s)
	d.config.Hostname = "two"
	if got := infoHostname(t, s); got != "two" {
		t.Fatalf("hostname = %q, want two with reuse off", got)
	}
}

// A RST for a connection still in SYN_SENT must wake the dialer at once.
// The dial loop's ticker is only a 250 ms backstop now; before, a refused
// dial was noticed by a 10 ms poll that ran for every dialing connection.
func TestResetWakesAWaitingDial(t *testing.T) {
	t.Parallel()
	d, _ := newPacketDaemon(t, nil)

	remote := protocol.Addr{Network: 0, Node: 77}
	conn := d.ports.NewConnection(41000, remote, protocol.PortDataExchange)
	conn.Mu.Lock()
	conn.State = StateSynSent
	conn.Mu.Unlock()

	d.handleStreamPacket(&protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoStream,
		Flags:    protocol.FlagRST,
		Src:      remote,
		Dst:      protocol.Addr{Network: 0, Node: 42},
		SrcPort:  protocol.PortDataExchange,
		DstPort:  41000,
	})

	select {
	case <-conn.DialCh:
	default:
		t.Fatal("RST did not signal the dialer; it would wait for the backstop tick")
	}
	conn.Mu.Lock()
	st := conn.State
	conn.Mu.Unlock()
	if st != StateClosed {
		t.Fatalf("state = %v, want CLOSED", st)
	}
}
