// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
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
