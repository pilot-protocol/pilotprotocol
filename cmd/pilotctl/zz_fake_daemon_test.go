// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/ipcutil"
)

// IPC cmd codes — must match pkg/driver/ipc.go and cmd/daemon/ipc.go.
// Re-declared here as package-local constants so tests don't reach
// into pkg/driver's unexported identifiers.
const (
	tdCmdBind              byte = 0x01
	tdCmdBindOK            byte = 0x02
	tdCmdDial              byte = 0x03
	tdCmdDialOK            byte = 0x04
	tdCmdSend              byte = 0x06
	tdCmdRecv              byte = 0x07
	tdCmdClose             byte = 0x08
	tdCmdCloseOK           byte = 0x09
	tdCmdError             byte = 0x0A
	tdCmdSendTo            byte = 0x0B
	tdCmdInfo              byte = 0x0D
	tdCmdInfoOK            byte = 0x0E
	tdCmdHandshake         byte = 0x0F
	tdCmdHandshakeOK       byte = 0x10
	tdCmdResolveHostname   byte = 0x11
	tdCmdResolveHostnameOK byte = 0x12
	tdCmdSetHostname       byte = 0x13
	tdCmdSetHostnameOK     byte = 0x14
	tdCmdSetVisibility     byte = 0x15
	tdCmdSetVisibilityOK   byte = 0x16
	tdCmdDeregister        byte = 0x17
	tdCmdDeregisterOK      byte = 0x18
	tdCmdSetTags           byte = 0x19
	tdCmdSetTagsOK         byte = 0x1A
	tdCmdSetWebhook        byte = 0x1B
	tdCmdSetWebhookOK      byte = 0x1C
	tdCmdNetwork           byte = 0x1F
	tdCmdNetworkOK         byte = 0x20
	tdCmdHealth            byte = 0x21
	tdCmdHealthOK          byte = 0x22
	tdCmdRotateKey         byte = 0x25
	tdCmdRotateKeyOK       byte = 0x26
	tdCmdBroadcast         byte = 0x29
	tdCmdBroadcastOK       byte = 0x2A
	tdCmdSubmitBadge       byte = 0x2F
	tdCmdSubmitBadgeOK     byte = 0x30
	tdCmdEnrollRecovery    byte = 0x31
	tdCmdEnrollRecoveryOK  byte = 0x32
	tdCmdSendToConfirm     byte = 0x39
	tdCmdSendToOK          byte = 0x3A
)

// shortSock returns a /tmp/ps-XXX.sock path short enough for macOS's
// 104-char unix socket name limit.
func shortSock(t *testing.T) string {
	t.Helper()
	var b [6]byte
	_, _ = rand.Read(b[:])
	p := filepath.Join("/tmp", "ps-"+hex.EncodeToString(b[:])+".sock")
	t.Cleanup(func() { _ = os.Remove(p) })
	return p
}

// fakeDaemon implements just enough of the daemon IPC for cmdXxx tests.
// Pattern: register per-cmd handlers, then point PILOT_SOCKET at d.path
// and call cmdXxx directly.
type fakeDaemon struct {
	t        *testing.T
	ln       net.Listener
	path     string
	mu       sync.Mutex
	conn     net.Conn
	connSet  chan struct{}
	received [][]byte
	handlers map[byte]func(frame []byte) [][]byte
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	path := shortSock(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen unix %q: %v", path, err)
	}
	d := &fakeDaemon{
		t:        t,
		ln:       ln,
		path:     path,
		connSet:  make(chan struct{}),
		handlers: map[byte]func(frame []byte) [][]byte{},
	}
	go d.acceptLoop()
	t.Cleanup(d.close)
	return d
}

func (d *fakeDaemon) acceptLoop() {
	conn, err := d.ln.Accept()
	if err != nil {
		return
	}
	d.mu.Lock()
	d.conn = conn
	d.mu.Unlock()
	close(d.connSet)

	for {
		frame, err := ipcutil.Read(conn)
		if err != nil {
			return
		}
		if len(frame) < 1 {
			continue
		}
		cmd := frame[0]
		d.mu.Lock()
		d.received = append(d.received, frame)
		h := d.handlers[cmd]
		d.mu.Unlock()
		if h == nil {
			continue
		}
		for _, r := range h(frame) {
			_ = ipcutil.Write(conn, r)
		}
	}
}

// on registers a handler that returns one or more frames for cmd.
// Each returned frame should start with the reply cmd byte (e.g.
// tdCmdHealthOK) followed by the JSON payload.
func (d *fakeDaemon) on(cmd byte, h func(frame []byte) [][]byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[cmd] = h
}

// onJSON is a convenience: respond to cmd with a single
// [replyCmd][json] frame.
func (d *fakeDaemon) onJSON(cmd, replyCmd byte, jsonBody string) {
	d.on(cmd, func(_ []byte) [][]byte {
		out := make([]byte, 1+len(jsonBody))
		out[0] = replyCmd
		copy(out[1:], jsonBody)
		return [][]byte{out}
	})
}

func (d *fakeDaemon) close() {
	_ = d.ln.Close()
	select {
	case <-d.connSet:
	case <-time.After(100 * time.Millisecond):
	}
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

// useDaemon points PILOT_SOCKET at d.path for the rest of the test
// and isolates HOME so config writes are sandboxed. Returns the tmp
// home path for tests that want to seed config files.
func (d *fakeDaemon) useDaemon(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("PILOT_SOCKET", d.path)
	return tmp
}
