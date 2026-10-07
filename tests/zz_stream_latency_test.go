// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// A request written as two small writes (a header, then a body) is how a
// data-exchange frame crosses a stream. Nagle holds the second write until the
// first is ACKed, and on a connection's first exchange that lone segment's ACK
// waits for the receiver's delayed-ACK timer: 40ms with both ends idle when
// the timer was 40ms, on top of a dial that polled for its handshake every
// 10ms. One message per connection is the common case (`pilotctl
// send-message`), so every message paid both.
//
// Not parallel, and judged on the fastest round: a timer in the path puts a
// floor under every round, while load only adds to some of them.
func TestFirstExchangeOnAConnectionIsNotDelayed(t *testing.T) {
	requireRealNetwork(t)
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	const port = 5101
	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				req := make([]byte, 8+200)
				if _, err := io.ReadFull(conn, req); err != nil {
					return
				}
				_, _ = conn.Write(req[:28])
			}()
		}
	}()

	// Stay under the receiver's per-source limit of 10 new connections a
	// second, which would otherwise be what this measures.
	const rounds = 8
	header, body, reply := make([]byte, 8), make([]byte, 200), make([]byte, 28)
	fastest := time.Hour
	for i := 0; i < rounds; i++ {
		start := time.Now()
		conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := conn.Write(body); err != nil {
			t.Fatalf("write body: %v", err)
		}
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("read reply: %v", err)
		}
		if d := time.Since(start); d < fastest {
			fastest = d
		}
		conn.Close()
	}
	t.Logf("fastest of %d dial + write-write-read exchanges: %v", rounds, fastest)
	// The 10ms dial poll plus the 40ms delayed ACK kept every round above
	// 50ms.
	if fastest > 25*time.Millisecond {
		t.Errorf("fastest exchange took %v, want under 25ms", fastest)
	}
}

// A write larger than one segment ends in a short tail. Nagle holds that tail
// until everything before it is ACKed, and when the full segments are an odd
// number the last one's ACK waits for the receiver's delayed-ACK timer. At
// 40ms that was one stall per 48KB file chunk, capping any transfer near
// 1.5 MB/s.
func TestLargeWritesDoNotStallOnDelayedACK(t *testing.T) {
	requireRealNetwork(t)
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	const port = 5102
	const chunk = 48*1024 + 20 // a data-exchange file chunk plus its framing
	const chunks = 10
	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, err = io.CopyN(io.Discard, conn, chunk*chunks)
			conn.Close()
			received <- err
		}
	}()

	// Judged on the fastest of three runs: the timer puts a floor under
	// every run (one 40ms stall per chunk is 400ms here), load only adds.
	fastest := time.Hour
	buf := make([]byte, chunk)
	for run := 0; run < 3; run++ {
		conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		start := time.Now()
		for i := 0; i < chunks; i++ {
			if _, err := conn.Write(buf); err != nil {
				t.Fatalf("write chunk %d: %v", i, err)
			}
		}
		select {
		case err := <-received:
			if err != nil {
				t.Fatalf("receive: %v", err)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("timeout receiving chunks")
		}
		if d := time.Since(start); d < fastest {
			fastest = d
		}
		conn.Close()
	}
	rate := float64(chunk*chunks) / fastest.Seconds() / (1 << 20)
	t.Logf("fastest run: %d chunks of %d bytes in %v (%.1f MB/s)", chunks, chunk, fastest, rate)
	if fastest > 200*time.Millisecond {
		t.Errorf("%d chunks took %v at best, want under 200ms: each large write is stalling on a delayed ACK", chunks, fastest)
	}
}

// A message of a few kilobytes crosses as two to four segments, the last one
// short. Held until the ones before it are ACKed, that tail waits for the
// receiver's delayed-ACK timer whenever the full segments are an odd number —
// one segment for a 2 KB message — so the message arrives a timer late: 5ms
// from a current peer, 40ms from an older one.
//
// Measured on a connection's first write, the one-message-per-connection
// case. Later writes on the same connection can be let through by a wake-up
// left over from the previous exchange's last ACK.
func TestFirstWriteOfAFewSegmentsIsNotDelayed(t *testing.T) {
	requireRealNetwork(t)
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	const port = 5103
	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	// The first four bytes of a request say how long it is.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				head := make([]byte, 4)
				if _, err := io.ReadFull(conn, head); err != nil {
					return
				}
				size := int(binary.BigEndian.Uint32(head))
				if _, err := io.ReadFull(conn, make([]byte, size-4)); err != nil {
					return
				}
				_, _ = conn.Write([]byte{1})
			}()
		}
	}()

	// Judged on the fastest of six connections per size: a timer in the path
	// puts a floor under every one of them, load only adds to some.
	reply := make([]byte, 1)
	for _, size := range []int{2000, 3000, 4096} {
		request := make([]byte, size)
		binary.BigEndian.PutUint32(request, uint32(size))
		fastest := time.Hour
		for round := 0; round < 6; round++ {
			conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			start := time.Now()
			if _, err := conn.Write(request); err != nil {
				t.Fatalf("write %d bytes: %v", size, err)
			}
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatalf("read reply to %d bytes: %v", size, err)
			}
			if d := time.Since(start); d < fastest {
				fastest = d
			}
			conn.Close()
		}
		t.Logf("fastest first %d-byte write and 1-byte reply: %v", size, fastest)
		// The delayed-ACK timer is 5ms; an exchange that waits for it
		// cannot finish sooner.
		if fastest > 4*time.Millisecond {
			t.Errorf("fastest first %d-byte exchange took %v, want under 4ms: its last segment is waiting for a delayed ACK", size, fastest)
		}
	}
}

// A program streaming 4 KB writes — a default bufio.Writer does — sends three
// full segments and a short tail per write. Held until everything before it
// was ACKed, each tail waited for the receiver's delayed-ACK timer on the
// third segment: 5ms a write against a current peer, 40ms against an older
// one, so 1 MB took 1.3s or 10s. The receiver here only reads, so no data of
// its own carries the ACK back sooner.
func TestStreamOf4KWritesDoesNotStallOnDelayedACK(t *testing.T) {
	requireRealNetwork(t)
	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	const port = 5104
	const writeSize, writes = 4096, 100
	ln, err := a.Driver.Listen(port)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	received := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_, err = io.CopyN(io.Discard, conn, writeSize*writes)
			conn.Close()
			received <- err
		}
	}()

	// Judged on the fastest of three runs: a timer per write puts a floor of
	// 500ms under every run, load only adds.
	fastest := time.Hour
	buf := make([]byte, writeSize)
	for run := 0; run < 3; run++ {
		conn, err := b.Driver.DialAddr(a.Daemon.Addr(), port)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		start := time.Now()
		for i := 0; i < writes; i++ {
			if _, err := conn.Write(buf); err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
		}
		select {
		case err := <-received:
			if err != nil {
				t.Fatalf("receive: %v", err)
			}
		case <-time.After(60 * time.Second):
			t.Fatal("timeout receiving")
		}
		if d := time.Since(start); d < fastest {
			fastest = d
		}
		conn.Close()
	}
	t.Logf("fastest run: %d writes of %d bytes in %v", writes, writeSize, fastest)
	if fastest > 150*time.Millisecond {
		t.Errorf("%d writes of %d bytes took %v at best, want under 150ms: each write is stalling on a delayed ACK", writes, writeSize, fastest)
	}
}
