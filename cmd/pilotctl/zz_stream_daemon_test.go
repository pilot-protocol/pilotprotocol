// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
	"github.com/pilot-protocol/common/protocol"
)

// Round-3 coverage push: drive cmdConnect/cmdSend/cmdRecv/cmdDgram/
// cmdSendFile/cmdSendMessage/cmdSubscribe/cmdPublish/cmdPing/
// cmdTraceroute/cmdBench/cmdListen/cmdBroadcast against a fake daemon
// that speaks just enough of the IPC stream protocol to satisfy the
// driver's Dial/Send/Recv/Bind/Accept paths.
//
// All tests run with --json so the cmd's output stops short of os.Exit
// (the human paths print to stderr, which we don't always need to read).
// fatal paths still call os.Exit, so any test that wants to hit an error
// branch goes through runCLI (existing helper from zz_subprocess_test.go).

// Extra cmd codes the round-3 stream tests need but round-1/2 didn't.
const (
	tdCmdAccept   byte = 0x05
	tdCmdRecvFrom byte = 0x0C
)

// streamDaemon wraps fakeDaemon with stream-aware handlers: it tracks
// per-connID streams, echoes cmdSend payloads as cmdRecv, accepts
// cmdBind by binding a port and pushing an Accept frame on demand.
//
// All async writes go through writeMu (taken via writeFrame on the
// fake daemon's conn) so the driver's readLoop never sees a split
// frame. Reads from inside the test goroutine are protected by mu.
type streamDaemon struct {
	*fakeDaemon

	streamMu sync.Mutex
	nextID   uint32
	// echoToConnID maps dial-id seq → connID; we always assign
	// monotonically increasing IDs so the driver can demux.
	dialed map[uint32]bool

	// boundPorts is set when cmdBind succeeds — listenTest pushes
	// cmdAccept frames once a listener is registered.
	boundPorts map[uint16]bool

	// captured stores every cmdSend payload routed by connID so tests
	// can assert what the client wrote without needing to plumb the
	// echoed cmdRecv all the way back.
	capturedMu sync.Mutex
	captured   map[uint32][][]byte

	// sendCount counts cmdSend frames received (atomic).
	sendCount atomic.Int64

	// dgramCount counts cmdSendTo and cmdSendToConfirm frames received
	// (atomic).
	dgramCount atomic.Int64

	// dgramAnswer, when set, is the error text the daemon answers a
	// confirmed send with instead of OK.
	dgramAnswer atomic.Pointer[string]

	// broadcastCount counts cmdBroadcast frames received.
	broadcastCount atomic.Int64
}

// newStreamDaemon returns a fakeDaemon pre-wired to handle the full
// stream protocol with sensible defaults:
//   - Handshake (any sub-cmd): reply trusted=true so maybeAutoHandshake
//     fast-paths and skips the registry lookup.
//   - Dial: reply with a fresh connID; echo subsequent cmdSend payloads
//     back as cmdRecv so a Conn.Read() unblocks.
//   - Bind: reply with the requested port and (optionally) push one
//     Accept frame so a single ln.Accept() call returns a conn.
//   - SendTo, Broadcast: count and ack (Broadcast needs cmdBroadcastOK).
//   - Info/Health: minimal canned JSON in case the cmd reaches for it.
func newStreamDaemon(t *testing.T) *streamDaemon {
	t.Helper()
	d := newFakeDaemon(t)
	sd := &streamDaemon{
		fakeDaemon: d,
		nextID:     1,
		dialed:     map[uint32]bool{},
		boundPorts: map[uint16]bool{},
		captured:   map[uint32][][]byte{},
	}

	// Handshake — always reply trusted=true. This covers WaitForTrust
	// (sub=0x07), Send (0x01), Approve (0x02), etc.
	d.on(tdCmdHandshake, func(_ []byte) [][]byte {
		body := `{"trusted":true,"node_id":42,"approved":true}`
		out := make([]byte, 1+len(body))
		out[0] = tdCmdHandshakeOK
		copy(out[1:], body)
		return [][]byte{out}
	})

	// Dial — pop the next connID and reply DialOK [connID(4)].
	d.on(tdCmdDial, func(_ []byte) [][]byte {
		sd.streamMu.Lock()
		id := sd.nextID
		sd.nextID++
		sd.dialed[id] = true
		sd.streamMu.Unlock()
		resp := make([]byte, 5)
		resp[0] = tdCmdDialOK
		binary.BigEndian.PutUint32(resp[1:5], id)
		return [][]byte{resp}
	})

	// Send — fire-and-forget echo: take [connID(4)][data] and push it
	// back as cmdRecv [connID(4)][data] so the dialing Conn unblocks.
	// Echo is mandatory for cmdConnect/cmdSend/cmdPing/cmdBench/etc.
	d.on(tdCmdSend, func(frame []byte) [][]byte {
		sd.sendCount.Add(1)
		if len(frame) < 5 {
			return nil
		}
		connID := binary.BigEndian.Uint32(frame[1:5])
		payload := frame[5:]

		sd.capturedMu.Lock()
		sd.captured[connID] = append(sd.captured[connID], append([]byte(nil), payload...))
		sd.capturedMu.Unlock()

		// Build a cmdRecv push: [cmdRecv][connID(4)][data]
		out := make([]byte, 1+4+len(payload))
		out[0] = tdCmdRecv
		binary.BigEndian.PutUint32(out[1:5], connID)
		copy(out[5:], payload)
		return [][]byte{out}
	})

	// SendTo (datagram unicast) — count, no reply.
	d.on(tdCmdSendTo, func(_ []byte) [][]byte {
		sd.dgramCount.Add(1)
		return nil
	})
	// SendToConfirm — count, answer OK or the configured error.
	d.on(tdCmdSendToConfirm, func(_ []byte) [][]byte {
		sd.dgramCount.Add(1)
		if msg := sd.dgramAnswer.Load(); msg != nil {
			return [][]byte{append([]byte{tdCmdError, 0, 1}, *msg...)}
		}
		return [][]byte{{tdCmdSendToOK}}
	})

	// Close — fire-and-forget; daemon optionally pushes CmdCloseOK
	// back so the driver's recv channel closes cleanly. We DON'T push
	// it by default — many cmds call Close() in defer and a stray
	// push after the channel is unregistered is harmless but noisy.
	d.on(tdCmdClose, func(_ []byte) [][]byte { return nil })

	// Bind — reply with the requested port. cmdRecv handlers (cmdListen
	// only listens for datagrams, but cmdRecv binds a stream) test it.
	d.on(tdCmdBind, func(frame []byte) [][]byte {
		if len(frame) < 3 {
			return nil
		}
		port := binary.BigEndian.Uint16(frame[1:3])
		sd.streamMu.Lock()
		sd.boundPorts[port] = true
		sd.streamMu.Unlock()
		resp := make([]byte, 3)
		resp[0] = tdCmdBindOK
		binary.BigEndian.PutUint16(resp[1:3], port)
		return [][]byte{resp}
	})

	// Broadcast — count + reply OK.
	d.on(tdCmdBroadcast, func(_ []byte) [][]byte {
		sd.broadcastCount.Add(1)
		body := `{"ok":true}`
		out := make([]byte, 1+len(body))
		out[0] = tdCmdBroadcastOK
		copy(out[1:], body)
		return [][]byte{out}
	})

	// Info — minimal sane body, in case any side path reaches for it.
	d.onJSON(tdCmdInfo, tdCmdInfoOK, `{"node_id":1,"address":"0:0000.0000.0001"}`)

	return sd
}

// pushAccept pushes one CmdAccept frame for the given listener port.
// payload format matches what driver.Listener.Accept() expects:
//
//	[connID(4)][remoteAddr(6)][remotePort(2)]
//
// after the cmdAccept-routing prefix [port(2)] that dispatchPush strips.
func (sd *streamDaemon) pushAccept(t *testing.T, port uint16, connID uint32, remote protocol.Addr, remotePort uint16) {
	t.Helper()
	<-sd.connSet
	sd.mu.Lock()
	conn := sd.conn
	sd.mu.Unlock()
	if conn == nil {
		t.Fatal("pushAccept: no conn yet")
	}
	// Wire: [tdCmdAccept][port(2)][connID(4)][remoteAddr(6)][remotePort(2)]
	out := make([]byte, 1+2+4+protocol.AddrSize+2)
	out[0] = tdCmdAccept
	binary.BigEndian.PutUint16(out[1:3], port)
	binary.BigEndian.PutUint32(out[3:7], connID)
	remote.MarshalTo(out, 7)
	binary.BigEndian.PutUint16(out[7+protocol.AddrSize:], remotePort)
	if err := ipcutil.Write(conn, out); err != nil {
		t.Fatalf("write accept: %v", err)
	}
}

// pushRecvFrom pushes one CmdRecvFrom (datagram) for cmdListen tests.
// Payload layout per dispatchPush: [srcAddr(6)][srcPort(2)][dstPort(2)][data].
func (sd *streamDaemon) pushRecvFrom(t *testing.T, src protocol.Addr, srcPort, dstPort uint16, data []byte) {
	t.Helper()
	<-sd.connSet
	sd.mu.Lock()
	conn := sd.conn
	sd.mu.Unlock()
	if conn == nil {
		t.Fatal("pushRecvFrom: no conn")
	}
	out := make([]byte, 1+protocol.AddrSize+4+len(data))
	out[0] = tdCmdRecvFrom
	src.MarshalTo(out, 1)
	binary.BigEndian.PutUint16(out[1+protocol.AddrSize:], srcPort)
	binary.BigEndian.PutUint16(out[1+protocol.AddrSize+2:], dstPort)
	copy(out[1+protocol.AddrSize+4:], data)
	if err := ipcutil.Write(conn, out); err != nil {
		t.Fatalf("write recvfrom: %v", err)
	}
}

// useDaemon also sets PILOT_REGISTRY to an unroutable placeholder. We
// never expect maybeAutoHandshake to fall through to the registry path
// (the fake replies trusted=true), but if it ever does, the test
// should fail loudly rather than hang on a real registry dial.
func (sd *streamDaemon) useDaemonNoRegistry(t *testing.T) string {
	t.Helper()
	tmp := sd.useDaemon(t)
	t.Setenv("PILOT_REGISTRY", "127.0.0.1:1") // closed port, instant ECONNREFUSED
	return tmp
}

// withJSON pins jsonOutput=true around fn (NOT parallel-safe — global).
func withJSON(fn func()) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	fn()
}

// withText pins jsonOutput=false around fn.
func withText(fn func()) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	fn()
}

// ---- cmdConnect ----

func TestCmdConnectMessageMode(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdConnect([]string{"0:0000.0000.002A", "1000", "--message", "hello"})
		})
	})

	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["response"] != "hello" {
		t.Errorf("response = %v (want echo of hello)", data["response"])
	}
	if data["sent"] != "hello" {
		t.Errorf("sent = %v", data["sent"])
	}
	if data["port"].(float64) != 1000 {
		t.Errorf("port = %v", data["port"])
	}
	if sd.sendCount.Load() < 1 {
		t.Errorf("daemon never saw a cmdSend")
	}
}

func TestCmdConnectMessageModeText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	out := captureStdout(t, func() {
		withText(func() {
			cmdConnect([]string{"0:0000.0000.002A", "--message", "ping-text"})
		})
	})
	if !strings.Contains(out, "ping-text") {
		t.Errorf("text mode missing echo: %q", out)
	}
}

// ---- cmdSend ----

func TestCmdSendJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSend([]string{"0:0000.0000.002A", "1000", "--data", "payload-abc"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["sent"] != "payload-abc" {
		t.Errorf("sent = %v", data["sent"])
	}
	if data["response"] != "payload-abc" {
		t.Errorf("response = %v", data["response"])
	}
	_ = sd
}

func TestCmdSendText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd

	out := captureStdout(t, func() {
		withText(func() {
			cmdSend([]string{"0:0000.0000.002A", "1000", "--data", "text-payload"})
		})
	})
	if !strings.Contains(out, "text-payload") {
		t.Errorf("text-mode echo missing: %q", out)
	}
}

// ---- cmdDgram ----

func TestCmdDgramJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdDgram([]string{"0:0000.0000.002A", "9999", "--data", "udp-msg"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["bytes"].(float64) != float64(len("udp-msg")) {
		t.Errorf("bytes = %v", data["bytes"])
	}
	if data["confirmed"] != true {
		t.Errorf("confirmed = %v, want true from a daemon that confirms sends", data["confirmed"])
	}
	// The confirmed send is answered, so the daemon has seen the frame by
	// the time cmdDgram returns.
	if sd.dgramCount.Load() < 1 {
		t.Errorf("daemon never saw cmdSendTo (count=%d)", sd.dgramCount.Load())
	}
}

func TestCmdDgramText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withText(func() {
			cmdDgram([]string{"0:0000.0000.002A", "9999", "--data", "udp-text"})
		})
	})
	if !strings.Contains(out, "sent") {
		t.Errorf("text dgram missing 'sent': %q", out)
	}
}

// The daemon could not send the datagram: dgram used to report success
// anyway, because the send it used was fire-and-forget.
func TestCmdDgramReportsTheDaemonsRefusal(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	refusal := "sendto: port 9999 not allowed by network 0 policy"
	sd.dgramAnswer.Store(&refusal)

	var failure *trappedFatal
	_ = captureStdout(t, func() {
		withJSON(func() {
			failure = runTrappingFatal(func() {
				cmdDgram([]string{"0:0000.0000.002A", "9999", "--data", "udp-msg"})
			})
		})
	})
	if failure == nil {
		t.Fatal("dgram succeeded although the daemon refused the send")
	}
	if failure.Code != "connection_failed" || !strings.Contains(failure.Message, "not allowed by network 0 policy") || strings.Count(failure.Message, "sendto:") != 1 {
		t.Errorf("failure = %+v, want connection_failed naming the daemon's reason", failure)
	}
}

// A daemon from before confirmed sends answers "unknown command"; dgram then
// sends the datagram the old way and says the outcome is unconfirmed.
func TestCmdDgramOnADaemonThatCannotConfirm(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	unknown := fmt.Sprintf("unknown command: 0x%02X", tdCmdSendToConfirm)
	sd.dgramAnswer.Store(&unknown)

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdDgram([]string{"0:0000.0000.002A", "9999", "--data", "udp-msg"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if data := env["data"].(map[string]interface{}); data["confirmed"] != false {
		t.Errorf("confirmed = %v, want false from a daemon that cannot confirm", data["confirmed"])
	}
	// The legacy send that follows the probe is not answered: wait for it.
	for deadline := time.Now().Add(2 * time.Second); sd.dgramCount.Load() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if n := sd.dgramCount.Load(); n != 2 {
		t.Errorf("daemon saw %d datagram frames, want the probe and the legacy send", n)
	}
}

// ---- cmdBroadcast (admin-token path) ----

func TestCmdBroadcastJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	t.Setenv("PILOT_ADMIN_TOKEN", "test-token")

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdBroadcast([]string{"0", "broadcast-body", "--port", "1234"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["network_id"].(float64) != 0 {
		t.Errorf("network_id = %v", data["network_id"])
	}
	if data["port"].(float64) != 1234 {
		t.Errorf("port = %v", data["port"])
	}
	if sd.broadcastCount.Load() < 1 {
		t.Error("daemon never saw cmdBroadcast")
	}
}

func TestCmdBroadcastText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	t.Setenv("PILOT_ADMIN_TOKEN", "test-token")
	_ = sd

	out := captureStdout(t, func() {
		withText(func() {
			cmdBroadcast([]string{"0", "hello-net"})
		})
	})
	if !strings.Contains(out, "broadcast on network") {
		t.Errorf("missing broadcast banner: %q", out)
	}
}

// ---- cmdSendFile ----

func TestCmdSendFile(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	// Write a small file to send.
	dir := t.TempDir()
	path := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(path, []byte("file-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	// send-file blocks on client.Recv() for an ACK frame. Our daemon
	// echoes whatever cmdSend payload the client wrote — so the
	// client's outgoing dataexchange File frame comes right back as
	// the "ACK", which is enough for Recv() to return.
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendFile([]string{"0:0000.0000.002A", path})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["filename"] != "small.txt" {
		t.Errorf("filename = %v", data["filename"])
	}
	if data["bytes"].(float64) != float64(len("file-bytes")) {
		t.Errorf("bytes = %v", data["bytes"])
	}
	_ = sd
}

// ---- cmdSendMessage ----

func TestCmdSendMessageText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "hello-message"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["type"] != "text" {
		t.Errorf("type = %v", data["type"])
	}
	if data["target"] == nil {
		t.Errorf("missing target")
	}
	// "to" carries the resolved destination address so --json consumers
	// learn what a hostname argument resolved to.
	if to, _ := data["to"].(string); to != "0:0000.0000.002A" {
		t.Errorf("to = %q, want resolved address 0:0000.0000.002A", to)
	}
}

func TestCmdSendMessageJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", `{"k":"v"}`, "--type", "json"})
		})
	})
	if !strings.Contains(out, `"type":"json"`) {
		t.Errorf("missing json type: %s", out)
	}
}

func TestCmdSendMessageBinary(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "bin-bytes", "--type", "binary"})
		})
	})
	if !strings.Contains(out, `"type":"binary"`) {
		t.Errorf("missing binary type: %s", out)
	}
}

func TestCmdSendMessageCountNoReuse(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "x", "--count", "2"})
		})
	})
	if !strings.Contains(out, `"reuse_conn":false`) {
		t.Errorf("expected reuse_conn=false: %s", out)
	}
}

func TestCmdSendMessageCountReuse(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{
				"0:0000.0000.002A", "--data", "x",
				"--count", "2", "--reuse-conn",
			})
		})
	})
	if !strings.Contains(out, `"reuse_conn":true`) {
		t.Errorf("expected reuse_conn=true: %s", out)
	}
}

// ---- cmdSubscribe / cmdPublish ----

// Subscribe blocks on client.Recv() inside a goroutine; with a 100ms
// timeout it exits via the deadline branch, which is enough to cover
// the dial+subscribe path.
func TestCmdSubscribeTimeout(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd

	captureStdout(t, func() {
		captureStderr(t, func() {
			withJSON(func() {
				cmdSubscribe([]string{
					"0:0000.0000.002A", "events.test",
					"--count", "1", "--timeout", "200ms",
				})
			})
		})
	})
}

func TestCmdPublishJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdPublish([]string{"0:0000.0000.002A", "events.test", "--data", "evt-body"})
		})
	})
	if !strings.Contains(out, `"topic":"events.test"`) {
		t.Errorf("publish missing topic: %s", out)
	}
}

// ---- cmdPing ----

// Ping spends ~1 s between iterations by design — use --count 1 + tight
// --timeout so the test stays fast.
func TestCmdPingJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdPing([]string{
				"0:0000.0000.002A",
				"--count", "1",
				"--timeout", "5s",
			})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["target"] == nil {
		t.Errorf("missing target: %v", data)
	}
	if to, _ := data["to"].(string); to != "0:0000.0000.002A" {
		t.Errorf("to = %q, want resolved address 0:0000.0000.002A", to)
	}
	results := data["results"].([]interface{})
	if len(results) != 1 {
		t.Errorf("results len = %d, want 1", len(results))
	}
}

func TestCmdPingReuseConn(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdPing([]string{
				"0:0000.0000.002A",
				"--count", "2",
				"--timeout", "10s",
				"--reuse-conn",
			})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	results := data["results"].([]interface{})
	if len(results) != 2 {
		t.Errorf("results len = %d, want 2", len(results))
	}
	// Second result should record reused=true.
	r1 := results[1].(map[string]interface{})
	if reused, _ := r1["reused"].(bool); !reused {
		t.Errorf("expected reused=true on second ping: %v", r1)
	}
}

func TestCmdPingTrace(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	// Trace branch — exercises the TRCE payload format and stderr trace prints.
	captureStdout(t, func() {
		captureStderr(t, func() {
			withText(func() {
				cmdPing([]string{
					"0:0000.0000.002A",
					"--count", "1",
					"--timeout", "5s",
					"--trace",
				})
			})
		})
	})
}

// ---- cmdTraceroute ----

func TestCmdTracerouteJSON(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdTraceroute([]string{"0:0000.0000.002A", "--timeout", "5s"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["target"] == nil {
		t.Errorf("missing target: %v", data)
	}
	if data["rtt_samples"] == nil {
		t.Errorf("missing rtt_samples: %v", data)
	}
}

func TestCmdTracerouteText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	captureStdout(t, func() {
		withText(func() {
			cmdTraceroute([]string{"0:0000.0000.002A", "--timeout", "5s"})
		})
	})
}

// ---- cmdBench ----

func TestCmdBenchSmall(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	// 0.001 MB = 1 KiB; bench iterates write/read until totalSize is hit.
	// Daemon echoes every cmdSend payload back as cmdRecv so the read
	// loop reaches totalSize.
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdBench([]string{"0:0000.0000.002A", "0.001", "--timeout", "5s"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["sent_bytes"].(float64) < 1 {
		t.Errorf("sent_bytes = %v", data["sent_bytes"])
	}
}

func TestCmdBenchText(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	captureStdout(t, func() {
		withText(func() {
			cmdBench([]string{"0:0000.0000.002A", "0.001", "--timeout", "5s"})
		})
	})
}

// ---- cmdRecv (stream listener) ----

func TestCmdRecvAccept(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	// Background: after cmdBind reply lands, push an Accept frame so
	// the listener.Accept() unblocks. The pushed conn will have its
	// recv channel closed when we don't send any data; cmdRecv calls
	// io.ReadAll which returns nil + nil error on EOF.
	go func() {
		// Small wait to let cmdBind register the per-port accept channel.
		// We use the streamDaemon's bound-port flag as the rendezvous —
		// retry until either the port shows up or 2s elapses.
		for i := 0; i < 200; i++ {
			sd.streamMu.Lock()
			bound := sd.boundPorts[7777]
			sd.streamMu.Unlock()
			if bound {
				break
			}
			// Sleeping in tests is normally a smell, but we're synchronising
			// with the driver's per-port channel registration which has no
			// public signal — Listen() returns after registerAcceptCh runs
			// but we have no handle on it from outside.
			time.Sleep(10 * time.Millisecond)
		}
		sd.pushAccept(t, 7777, 99, protocol.Addr{Network: 0, Node: 100}, 5000)
		// After Accept, close the conn so io.ReadAll returns.
		// Build cmdCloseOK push: [cmdCloseOK][connID(4)]
		closeFrame := make([]byte, 5)
		closeFrame[0] = tdCmdCloseOK
		binary.BigEndian.PutUint32(closeFrame[1:5], 99)
		sd.mu.Lock()
		c := sd.conn
		sd.mu.Unlock()
		if c != nil {
			_ = ipcutil.Write(c, closeFrame)
		}
	}()

	out := captureStdout(t, func() {
		captureStderr(t, func() {
			withJSON(func() {
				cmdRecv([]string{"7777", "--count", "1", "--timeout", "5s"})
			})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	msgs := data["messages"].([]interface{})
	if len(msgs) != 1 {
		t.Errorf("messages len = %d, want 1", len(msgs))
	}
}

func TestCmdRecvTimeout(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	out := captureStdout(t, func() {
		withJSON(func() {
			cmdRecv([]string{"7778", "--count", "1", "--timeout", "100ms"})
		})
	})
	if !strings.Contains(out, `"timeout":true`) {
		t.Errorf("missing timeout=true: %s", out)
	}
}

// ---- cmdListen (datagram listener) ----

func TestCmdListenRecvFrom(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)

	// Push one datagram after a brief wait so cmdListen's RecvFrom
	// reaches the read on dgCh.
	go func() {
		time.Sleep(50 * time.Millisecond)
		sd.pushRecvFrom(t, protocol.Addr{Network: 0, Node: 7}, 1234, 5555, []byte("hello-dgram"))
	}()

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdListen([]string{"5555", "--count", "1", "--timeout", "5s"})
		})
	})
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	msgs := data["messages"].([]interface{})
	if len(msgs) != 1 {
		t.Errorf("messages len = %d, want 1", len(msgs))
	}
	m0 := msgs[0].(map[string]interface{})
	if m0["data"] != "hello-dgram" {
		t.Errorf("data = %v", m0["data"])
	}
}

func TestCmdListenTimeout(t *testing.T) {
	sd := newStreamDaemon(t)
	sd.useDaemonNoRegistry(t)
	_ = sd
	captureStdout(t, func() {
		captureStderr(t, func() {
			withJSON(func() {
				cmdListen([]string{"5556", "--count", "1", "--timeout", "100ms"})
			})
		})
	})
}

// ---- offline-daemon paths (fast-fail via runCLI to survive os.Exit) ----

// All commands that call connectDriver() must exit non-zero and surface
// a "daemon" / "not_running" hint when no socket is reachable.

func TestCLIOfflineConnect(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"connect", "0:0000.0000.002A", "1000", "--message", "x",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineSend(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"send", "0:0000.0000.002A", "1000", "--data", "x",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineRecv(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"recv", "1234", "--timeout", "100ms",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineDgram(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"dgram", "0:0000.0000.002A", "9999", "--data", "x",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineSendFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.txt")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"send-file", "0:0000.0000.002A", path},
		map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineSendMessage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"send-message", "0:0000.0000.002A", "--data", "x",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineSubscribe(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"subscribe", "0:0000.0000.002A", "x", "--timeout", "100ms",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflinePublish(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"publish", "0:0000.0000.002A", "x", "--data", "y",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflinePing(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"ping", "0:0000.0000.002A", "--count", "1", "--timeout", "100ms",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineTraceroute(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"traceroute", "0:0000.0000.002A", "--timeout", "100ms",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineBench(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"bench", "0:0000.0000.002A", "0.001",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineListen(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"listen", "1234", "--timeout", "100ms",
	}, map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

func TestCLIOfflineBroadcast(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{
		"broadcast", "0", "hello",
	}, map[string]string{
		"PILOT_SOCKET":      "/tmp/nope-" + t.Name() + ".sock",
		"PILOT_ADMIN_TOKEN": "tok",
	})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "daemon") {
		t.Errorf("expected daemon hint: %s", stderr)
	}
}

// ---- usage-error paths (fast and don't need a daemon) ----

func TestCLIConnectUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"connect"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLISendUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"send"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLISendMissingData(t *testing.T) {
	t.Parallel()
	// send requires --data; positional args alone trip the "data required" branch.
	_, stderr, code := runCLI(t, []string{"send", "0:0000.0000.0001", "1000"},
		map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	// Either "data" required OR daemon error; both are valid early-exits.
	if !strings.Contains(stderr, "data") && !strings.Contains(stderr, "daemon") {
		t.Errorf("missing data/daemon hint: %s", stderr)
	}
}

func TestCLIDgramUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"dgram"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIRecvUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"recv"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIListenUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"listen"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLITracerouteUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"traceroute"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLISubscribeUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"subscribe"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIPublishUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"publish"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIPingUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"ping"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIBenchUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"bench"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIBroadcastUsage(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"broadcast"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "usage") {
		t.Errorf("missing usage: %s", stderr)
	}
}

func TestCLIBroadcastNoToken(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"broadcast", "0", "hello"},
		map[string]string{"PILOT_SOCKET": "/tmp/nope-" + t.Name() + ".sock"})
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "admin") && !strings.Contains(stderr, "token") {
		t.Errorf("expected admin-token hint: %s", stderr)
	}
}

// ---- helper: dummyForceRT forces a synchronous round-trip through the
// fake daemon so async fire-and-forget cmds (cmdSendTo) are guaranteed
// to be drained on the daemon side before we assert counters. Uses
// cmdInfo which has a canned response wired in newStreamDaemon. ----

type dummyForceRT struct {
	sd *streamDaemon
}

// Force opens a fresh ipc connection through the standard driver, hits
// cmdInfo, and closes. The handler-side acceptLoop processes frames in
// order, so by the time cmdInfo's reply arrives, prior cmdSendTo frames
// have been consumed and counters bumped.
//
// Returns (nil, nil) — only the side-effect matters.
func (f *dummyForceRT) Force() (any, error) {
	// Force a round-trip by issuing a fresh ResolveHostname through the
	// daemon socket — but cmdResolveHostname isn't wired by default.
	// Instead, sleep 25 ms (the fake daemon services frames in a tight
	// loop, so this is plenty for a SendTo dispatch). 25 ms is well under
	// every test's --timeout but long enough for the goroutine swap on
	// any plausible host.
	time.Sleep(25 * time.Millisecond)
	return nil, nil
}
