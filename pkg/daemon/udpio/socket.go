// SPDX-License-Identifier: AGPL-3.0-or-later

// Package udpio is the L2 datagram-I/O layer of the daemon: it owns the
// *net.UDPConn socket FD and provides "dumb" Send/Recv primitives. No
// wire format of its own — every L1 packet is one UDP datagram.
//
// Per docs/architecture/01-LAYERS.md L2:
//
//	Role:     send and receive UDP frames.
//	Owns:     the *net.UDPConn socket FD; the read-buffer; the close
//	          coordination state.
//	Consumes: L0, L1.
//	Exposes:  Send(frame []byte, dst *net.UDPAddr) error,
//	          Recv() (frame []byte, src *net.UDPAddr, err error).
//
// The readLoop *goroutine* itself lives one layer up (in pkg/daemon —
// L4 dispatch), because it needs to know the magic-byte routing tables
// to call the right per-frame handler. udpio.Socket only provides the
// blocking Recv primitive that loop calls in a tight cycle. This split
// keeps the socket FD ownership inside udpio while the routing decision
// (which-handler-for-which-magic) stays at the layer that owns the
// handler set.
//
// 03-INVARIANTS.md §3 — the conn is unsynchronized: Recv is the single
// reader, Send is the single writer in practice. Same as before
// extraction.
//
// 03-INVARIANTS.md §6 — the unbuffered recvCh contract is preserved.
// Recv() blocks the calling goroutine until a frame arrives, so the
// caller's dispatcher fully consumes one frame before the next ReadFromUDP
// runs. The pool-backed read buffer is reused across Recv calls — the
// returned slice is valid only until the next Recv (caller must copy if
// retention is needed across calls).
//
// 03-INVARIANTS.md §6.5 — internal/pool fold: deferred to a follow-up.
// This package currently imports internal/pool; an external test
// (tests/fuzz_fsutil_pool_test.go) still references pool.GetSmall /
// pool.GetLarge / etc., so the public API can't be deleted in this
// sub-pass without also rewriting that test. Tracked as TODO at the
// pool import site below.
package udpio

import (
	"errors"
	"fmt"
	"net"
	"sync"

	// TODO: fold internal/pool into this package once tests/fuzz_fsutil_pool_test.go
	// is rewritten or relocated. See 03-INVARIANTS.md §6.5.
	"github.com/pilot-protocol/pilotprotocol/internal/pool"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport"
)

// ErrClosed is returned by Recv after Close has been called and any
// in-flight ReadFromUDP has returned. Send returns the underlying
// net.OpError directly; the caller decides how to interpret kernel-
// surfaced ICMP-unreachable errors (see pkg/daemon handleSendError).
//
// Aliased to transport.ErrClosed so both UDP and WSS transports return
// the same sentinel. Callers use errors.Is(err, udpio.ErrClosed) or
// errors.Is(err, transport.ErrClosed) interchangeably.
var ErrClosed = transport.ErrClosed

// Socket owns a *net.UDPConn and the pool-backed read buffer used by
// Recv. It does NOT own a goroutine — the dispatcher goroutine that
// drives Recv() in a loop lives in the caller (pkg/daemon's tunnel.go).
//
// Concurrency:
//   - Recv may be called only from a single goroutine at a time
//     (matches the pre-extraction readLoop ownership model).
//   - Send may be called concurrently with Recv (UDP write does not
//     contend with read on the same FD).
//   - Multiple concurrent Send goroutines are safe for the kernel-
//     level UDP socket, but the higher-level send-error counter that
//     interprets failures lives in tunnel.go and uses tm.mu — see
//     pkg/daemon handleSendError.
//   - Close is idempotent; calling Send/Recv after Close returns
//     ErrClosed (or a wrapped net.OpError indicating the closed conn).
type Socket struct {
	conn *net.UDPConn

	// readBufPtr is a pool-backed slice (LargeBufSize) reused by every
	// Recv call. Allocated lazily on first Recv; returned to the pool
	// on Close.
	readBufMu  sync.Mutex
	readBufPtr *[]byte

	closeOnce sync.Once
}

// Listen resolves addr (e.g. "127.0.0.1:0" for ephemeral) and binds a
// UDP listener. Returns a Socket ready to Send / Recv.
func Listen(addr string) (*Socket, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve: %w", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	// Every tunnel shares this one socket. At the kernel default (~200KB on
	// Linux) a few streams sending at once overflow it, and each dropped
	// datagram is a whole segment for the stream layer to recover. Ask for
	// more; the kernel silently caps the request at net.core.rmem_max /
	// wmem_max, so this is best-effort and never an error.
	_ = conn.SetReadBuffer(socketBufferBytes)
	_ = conn.SetWriteBuffer(socketBufferBytes)
	return &Socket{conn: conn}, nil
}

// socketBufferBytes is the kernel buffer size requested for the tunnel socket
// in each direction.
const socketBufferBytes = 4 << 20

// WrapConn adopts an already-bound *net.UDPConn into a Socket. Used by
// tests that build a UDP listener manually (so the test owns
// configuration like SetReadBuffer) and want to drive the same Socket
// API the production path uses.
//
// The Socket takes ownership of conn — Close() will close the conn.
// Tests that need to defer their own conn.Close() should NOT also call
// Socket.Close() on the same conn.
func WrapConn(conn *net.UDPConn) *Socket {
	return &Socket{conn: conn}
}

// Conn returns the underlying *net.UDPConn. Provided for transitional
// in-package callers (DiscoverEndpoint, daemon-side STUN paths) that
// still reach for the raw socket; will be retired once those paths are
// also routed through Send/Recv.
func (s *Socket) Conn() *net.UDPConn {
	if s == nil {
		return nil
	}
	return s.conn
}

// LocalAddr returns the actual bind address (post-bind). Returns nil if
// the socket has been closed or never bound.
func (s *Socket) LocalAddr() *net.UDPAddr {
	if s == nil || s.conn == nil {
		return nil
	}
	if a, ok := s.conn.LocalAddr().(*net.UDPAddr); ok {
		return a
	}
	return nil
}

// Send writes frame to dst as a single UDP datagram. Returns the number
// of bytes written and the underlying io error from net.UDPConn.WriteToUDP.
//
// "Dumb" send: no relay wrapping, no per-peer bookkeeping. The caller
// (pkg/daemon writeFrame) is responsible for relay-vs-direct decisions
// and for translating ICMP-unreachable errors into per-peer counters.
func (s *Socket) Send(frame []byte, dst *net.UDPAddr) (int, error) {
	if s == nil || s.conn == nil {
		return 0, ErrClosed
	}
	return s.conn.WriteToUDP(frame, dst)
}

// Recv reads one UDP datagram into a pool-backed buffer and returns a
// slice referencing that buffer plus the source address.
//
// The returned slice is valid ONLY until the next Recv call on this
// Socket. Callers that need to retain the bytes must copy. The current
// pkg/daemon dispatch path consumes each frame synchronously (handler
// either copies into a fresh allocation before pushing onto recvCh, or
// finishes processing before returning), preserving the §6 unbuffered-
// recvCh contract.
//
// Returns ErrClosed (wrapping the underlying conn-closed OpError) when
// the socket has been Close()d. Returns other read errors verbatim.
func (s *Socket) Recv() ([]byte, *net.UDPAddr, error) {
	if s == nil || s.conn == nil {
		return nil, nil, ErrClosed
	}

	// Lazy buffer allocation on first Recv. The buffer lives for the
	// Socket's lifetime and is returned to the pool on Close.
	s.readBufMu.Lock()
	if s.readBufPtr == nil {
		s.readBufPtr = pool.GetLarge()
	}
	buf := *s.readBufPtr
	s.readBufMu.Unlock()

	n, remote, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Err != nil &&
			opErr.Err.Error() == "use of closed network connection" {
			return nil, nil, ErrClosed
		}
		return nil, nil, err
	}
	return buf[:n], remote, nil
}

// Close shuts down the socket and releases the pool-backed read buffer.
// Idempotent; multiple Close calls return nil after the first.
//
// In-progress Recv on another goroutine will return ErrClosed once the
// kernel-level ReadFromUDP unblocks with the "use of closed network
// connection" error. The caller is responsible for joining their
// dispatcher goroutine.
func (s *Socket) Close() error {
	if s == nil {
		return nil
	}
	var connErr error
	s.closeOnce.Do(func() {
		if s.conn != nil {
			connErr = s.conn.Close()
		}
		s.readBufMu.Lock()
		if s.readBufPtr != nil {
			pool.PutLarge(s.readBufPtr)
			s.readBufPtr = nil
		}
		s.readBufMu.Unlock()
	})
	return connErr
}
