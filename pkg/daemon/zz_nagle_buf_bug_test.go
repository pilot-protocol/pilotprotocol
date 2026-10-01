// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestSendDataNagleBufGrowsUnbounded reproduces the NagleBuf-OOM bug.
//
// Symptom (theoretical, observed-once-and-cleared in pilot service-agent
// memory profiling): an application that calls SendData faster than the
// network can drain (slow peer, packet loss, full cwnd) accumulates the
// unsent bytes in conn.NagleBuf without bound. There is currently NO
// per-connection send-buffer cap. With many connections in this state,
// daemon RSS climbs linearly with offered-but-undeliverable load until
// the host OOM-kills the process.
//
// Reproducer: a real UDP peer is reachable but never ACKs anything, so
// the daemon's cwnd fills after IW10 (10 × 4 KB = 40 KB). The 11th
// MSS-sized chunk's sendSegment call blocks waiting for cwnd to open
// (which it never will). The single goroutine calling SendData is
// stuck in nagleFlush; meanwhile, the data slice the application
// passed (5 MiB here) sits in conn.NagleBuf, well over any reasonable
// memory budget. Multiple writers would amplify this further.
//
// What v1.9.1's NagleBuf cap fix will change:
//   - introduce MaxNagleBuf = 64 * MaxSegmentSize (256 KB)
//   - SendData returns ErrSendBufFull when len(NagleBuf) + len(data) > MaxNagleBuf
//   - test assertion flips: NagleBuf plateaus at MaxNagleBuf;
//     SendData returns ErrSendBufFull on the oversized write.
//
// This test pins CURRENT (buggy) behavior so the cap patch has a
// concrete regression target. After the fix, the bug-asserting block
// below is replaced with the post-fix block (already drafted in
// comments).
func TestSendDataNagleBufGrowsUnbounded(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xBA5EBA11
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })

	d.setNodeID_testhelper(0x33330000)

	// Build a Connection in StateEstablished, wired to the peer. We
	// don't go through DialConnection; constructing directly keeps the
	// test fast and deterministic.
	conn := d.ports.NewConnection(40000, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33330000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.PeerRecvWin = 1 << 20 // advertise 1 MB receive window so cwnd is the binding constraint
	conn.Mu.Unlock()

	// The cap on NagleBuf is what fixed the OOM. (A single write larger
	// than the cap used to be refused here too; it is now fed through the
	// buffer in pieces — see TestSendDataOversizedWriteStaysWithinNagleCap.)

	// Cap is invariant: a sequence of small writes that, in aggregate,
	// would exceed the cap also rejects the offending one. Send up
	// to the cap, then attempt one more small write — it must reject.
	smallChunk := make([]byte, MaxSegmentSize) // 4 KB
	for i := 0; i < 8; i++ {
		// nagleFlush will drain the initial cwnd's worth into Unacked, so
		// these don't pile up in NagleBuf in steady state. We're only
		// asserting that no individual write violates the cap; runtime
		// flow control (cwnd) handles the steady-state queue depth.
		_ = d.SendData(conn, smallChunk)
	}
	// Now manually fill NagleBuf to MaxNagleBuf - 1 to test the boundary
	// (bypassing the loop above's interaction with nagleFlush + cwnd).
	conn.NagleMu.Lock()
	conn.NagleBuf = make([]byte, MaxNagleBuf-1)
	conn.NagleMu.Unlock()

	// A 2-byte write would push us to MaxNagleBuf+1 — must reject.
	if err := d.SendData(conn, []byte{0, 0}); !errors.Is(err, ErrSendBufFull) {
		t.Errorf("boundary case: expected ErrSendBufFull when (MaxNagleBuf-1)+2 > MaxNagleBuf; got %v", err)
	}

	// And confirm NagleBuf still didn't grow past the cap.
	conn.NagleMu.Lock()
	bufLen := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if bufLen > MaxNagleBuf {
		t.Errorf("NagleBuf grew past cap %d; got %d", MaxNagleBuf, bufLen)
	}

	// Cleanup.
	d.tunnels.Close()
	conn.Mu.Lock()
	conn.State = StateClosed
	conn.Mu.Unlock()
	d.ports.RemoveConnection(conn.ID)
	_ = time.Millisecond // keep `time` import live regardless of what's in cleanup
}

// A write larger than MaxNagleBuf used to be refused with ErrSendBufFull.
// Over IPC that refusal has nowhere to go (a send has no reply), so a client
// writing a 1 MB message lost it while reporting success. SendData now feeds
// such a write through the buffer in pieces and blocks on the window like any
// other write. The OOM guard is unchanged: against a peer that never ACKs,
// NagleBuf must stay within the cap for as long as the write is blocked.
func TestSendDataOversizedWriteStaysWithinNagleCap(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	t.Cleanup(func() { d.tunnels.Close() })

	const peerNode uint32 = 0xBA5EBA12
	peerConn := addPeerOnDaemon(t, d, peerNode)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0x33330001)

	conn := d.ports.NewConnection(40001, protocol.Addr{Network: 0, Node: peerNode}, 80)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0x33330001}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: peerNode}
	conn.RemotePort = 80
	conn.State = StateEstablished
	conn.PeerRecvWin = 1 << 20
	conn.Mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- d.SendData(conn, make([]byte, 5*1024*1024)) }()

	// The peer never ACKs, so the write blocks once the congestion window is
	// full. Watch the buffer while it does.
	maxBuf := 0
	for deadline := time.Now().Add(500 * time.Millisecond); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		conn.NagleMu.Lock()
		if n := len(conn.NagleBuf); n > maxBuf {
			maxBuf = n
		}
		conn.NagleMu.Unlock()
	}
	if maxBuf > MaxNagleBuf {
		t.Errorf("NagleBuf reached %d bytes during an oversized write; cap is %d", maxBuf, MaxNagleBuf)
	}
	select {
	case err := <-done:
		t.Fatalf("a 5 MiB write to a peer that never ACKs returned (%v); it should block on the window", err)
	default:
	}

	// Closing the connection releases the blocked writer with an error.
	d.ports.RemoveConnection(conn.ID)
	select {
	case err := <-done:
		if err == nil {
			t.Error("blocked write returned nil after the connection closed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked write did not return after the connection closed")
	}
}
