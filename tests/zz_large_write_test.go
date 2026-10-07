// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"
	"time"
)

// One stream write larger than the daemon's send buffer (MaxNagleBuf, 256 KB)
// was refused with "send buffer full". An IPC send has no reply, so the
// client was told nothing: a 1 MB message was dropped while the sender
// reported success. The write is now fed through the buffer in pieces.
func TestSingleWriteLargerThanSendBufferIsDelivered(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	const port = 5103
	payload := make([]byte, 1<<20)
	for i := range payload {
		payload[i] = byte(i * 131)
	}
	want := sha256.Sum256(payload)

	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, buf); err != nil {
			got <- nil
			return
		}
		got <- buf
	}()

	conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if n, err := conn.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}

	select {
	case buf := <-got:
		if buf == nil {
			t.Fatal("receiver did not get the whole payload")
		}
		if sum := sha256.Sum256(buf); !bytes.Equal(sum[:], want[:]) {
			t.Fatal("payload arrived corrupted")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a 1 MB write was not delivered within 20s")
	}
}
