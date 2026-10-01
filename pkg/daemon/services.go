// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// connAdapter wraps a daemon *Connection as a net.Conn so that existing
// service packages (dataexchange, eventstream) that use io.Reader/io.Writer
// can work directly on top of the daemon's port infrastructure.
type connAdapter struct {
	conn   *Connection
	daemon *Daemon
	buf    []byte // leftover from previous RecvBuf read

	// publishFailures counts consecutive WriteEvent failures observed by
	// the eventBroker for THIS subscriber. A subscriber is only removed
	// from broker.subs after maxConsecutivePublishFailures in a row, so a
	// single transient tunnel blip doesn't kill the subscription. Reset
	// to 0 on the first successful WriteEvent. Atomic because publish()
	// runs concurrently across publishers without holding a write lock.
	publishFailures atomic.Uint32

	// readDeadline is the absolute time at which a blocked Read gives up,
	// as UnixNano; 0 means "no deadline" (block forever, the historical
	// behaviour). Stored atomically because SetReadDeadline may be called
	// from a different goroutine than the one parked in Read.
	//
	// Without this, Read blocks on <-RecvBuf with no way out. That made
	// dataexchange's slowloris guard dead code in-daemon: it gates its
	// idle teardown on a `conn.(readDeadliner)` type assertion, which no
	// in-daemon stream satisfied, so DefaultIdleTimeout was never applied
	// and a peer that opened a connection and then went silent pinned the
	// handler goroutine plus the whole Connection (~43 KiB of buffers and
	// stacks) forever. See TestConnAdapterReadDeadline.
	readDeadline atomic.Int64
}

func newConnAdapter(d *Daemon, conn *Connection) *connAdapter {
	return &connAdapter{conn: conn, daemon: d}
}

// SetReadDeadline implements the optional deadline surface that
// dataexchange (and any other frame reader) probes for. A zero time
// clears the deadline. Satisfying this interface is what re-arms the
// idle timeout for in-daemon plugin connections.
func (a *connAdapter) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		a.readDeadline.Store(0)
		return nil
	}
	a.readDeadline.Store(t.UnixNano())
	return nil
}

// errReadDeadlineExceeded is returned by Read when the deadline set via
// SetReadDeadline elapses. It reports Timeout() == true so callers that
// distinguish timeouts from hard failures (net.Error) behave correctly.
type errReadDeadlineExceeded struct{}

func (errReadDeadlineExceeded) Error() string   { return "pilot: read deadline exceeded" }
func (errReadDeadlineExceeded) Timeout() bool   { return true }
func (errReadDeadlineExceeded) Temporary() bool { return true }

var _ net.Error = errReadDeadlineExceeded{}

func (a *connAdapter) Read(p []byte) (int, error) {
	// Drain leftover buffer first
	if len(a.buf) > 0 {
		n := copy(p, a.buf)
		a.buf = a.buf[n:]
		return n, nil
	}

	var data []byte
	var ok bool
	if dl := a.readDeadline.Load(); dl != 0 {
		d := time.Until(time.Unix(0, dl))
		if d <= 0 {
			return 0, errReadDeadlineExceeded{}
		}
		timer := time.NewTimer(d)
		select {
		case data, ok = <-a.conn.RecvBuf:
			timer.Stop()
		case <-timer.C:
			return 0, errReadDeadlineExceeded{}
		}
	} else {
		data, ok = <-a.conn.RecvBuf
	}
	if !ok {
		return 0, io.EOF
	}
	n := copy(p, data)
	if n < len(data) {
		a.buf = data[n:]
	}
	return n, nil
}

// connAdapterWriteDeadline caps how long Write will retry against a
// persistently-full NagleBuf. Beyond this, the slow peer is treated as
// unrecoverable and ErrSendBufFull is surfaced to the caller. Set high
// enough that a normal cwnd-pause (a few RTTs) doesn't time out, but
// short enough that a wedged peer doesn't hang the application forever.
var connAdapterWriteDeadline = 30 * time.Second

func (a *connAdapter) Write(p []byte) (int, error) {
	// v1.9.1 fix: don't surface ErrSendBufFull to net.Conn callers.
	// Iter 4 capped NagleBuf at 32 KB to bound memory under slow peers,
	// but propagating the error directly broke http.ServeConn / io.Copy
	// / bufio — they treat any non-nil Write error as a fatal connection
	// failure. ErrSendBufFull is transient back-pressure (just like a
	// kernel TCP send buffer being full), so block-and-retry until the
	// flush goroutine drains the buffer.
	backoff := 5 * time.Millisecond
	const maxBackoff = 100 * time.Millisecond
	deadline := time.Now().Add(connAdapterWriteDeadline)
	for {
		err := a.daemon.SendData(a.conn, p)
		if err == nil {
			return len(p), nil
		}
		if !errors.Is(err, ErrSendBufFull) {
			return 0, err
		}
		// Bail if the connection itself moved out of Established —
		// retrying would loop forever against a half-closed conn.
		a.conn.Mu.Lock()
		st := a.conn.State
		a.conn.Mu.Unlock()
		if st != StateEstablished {
			return 0, fmt.Errorf("connection no longer established (state=%v)", st)
		}
		if time.Now().After(deadline) {
			return 0, err
		}
		time.Sleep(backoff)
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

func (a *connAdapter) Close() error {
	a.daemon.CloseConnection(a.conn)
	return nil
}

func (a *connAdapter) LocalAddr() net.Addr {
	return pilotAddr{addr: a.conn.LocalAddr, port: a.conn.LocalPort}
}

func (a *connAdapter) RemoteAddr() net.Addr {
	return pilotAddr{addr: a.conn.RemoteAddr, port: a.conn.RemotePort}
}

// pilotAddr implements net.Addr for Pilot Protocol endpoints.
type pilotAddr struct {
	addr protocol.Addr
	port uint16
}

func (p pilotAddr) Network() string { return "pilot" }
func (p pilotAddr) String() string {
	return fmt.Sprintf("%s:%d", p.addr.String(), p.port)
}

// SetDeadline sets the read deadline. The write side has its own bound
// (connAdapterWriteDeadline), so only the read half is honoured here.
func (a *connAdapter) SetDeadline(t time.Time) error { return a.SetReadDeadline(t) }

// SetWriteDeadline is not implemented: Write already fails after
// connAdapterWriteDeadline against a persistently-full send buffer.
// It returns nil (rather than an error) to preserve net.Conn semantics
// for callers that set both deadlines unconditionally.
func (a *connAdapter) SetWriteDeadline(t time.Time) error { return nil }

// startBuiltinServices starts all enabled built-in port services.
func (d *Daemon) startBuiltinServices() {
	if !d.config.DisableEcho {
		if err := d.startEchoService(); err != nil {
			slog.Warn("echo service failed to start", "error", err)
		}
	}
	// dataexchange, eventstream, and tasks (T3.2) are registered L11
	// plugins; cmd/daemon and cmd/pilotctl _daemon-run install them via
	// daemon.RegisterPlugin. The Disable* config flags are honored at
	// the registration site.
}

// startEchoService binds port 7 and echoes back all received data.
func (d *Daemon) startEchoService() error {
	ln, err := d.ports.Bind(protocol.PortEcho)
	if err != nil {
		return err
	}
	d.bgWG.Add(1)
	go func() {
		defer d.bgWG.Done()
		for {
			select {
			case conn, ok := <-ln.AcceptCh:
				if !ok {
					return
				}
				go d.handleEchoConn(conn)
			case <-d.stopCh:
				return
			}
		}
	}()
	slog.Info("echo service listening", "port", protocol.PortEcho)
	return nil
}

func (d *Daemon) handleEchoConn(conn *Connection) {
	// Trust gate on PRIVATE daemons only. Public daemons echo for everyone
	// (matches the SYN/datagram drop policy in daemon.go:2223 / 2636 — only
	// private nodes filter inbound by trust). On private daemons, refuse to
	// echo for untrusted peers; self-pings are always allowed.
	if !d.config.Public && d.handshakes != nil && conn.RemoteAddr.Node != d.NodeID() {
		if !d.handshakeTrusts(conn.RemoteAddr.Node) {
			slog.Debug("echo refused: peer not trusted (private node)",
				"peer_node_id", conn.RemoteAddr.Node)
			d.CloseConnection(conn)
			return
		}
	}
	// Write through connAdapter, not SendData directly: SendData returns
	// ErrSendBufFull the moment the NagleBuf cap is hit, which is routine
	// transient backpressure whenever data arrives faster than the
	// congestion window drains (any bulk transfer). Treating it as fatal
	// silently killed the echo loop mid-transfer while the connection kept
	// ACKing inbound data — the peer saw its payload accepted and nothing
	// echoed back. connAdapter.Write blocks-and-retries with backoff (the
	// v1.9.1 semantics net.Conn callers already rely on) and still fails on
	// real errors: connection no longer established, or a peer stuck past
	// connAdapterWriteDeadline.
	w := &connAdapter{conn: conn, daemon: d}
	for {
		data, ok := <-conn.RecvBuf
		// Capture right after the channel read — before any branching —
		// so the timestamp is as close to the wire as possible.
		recvNs := time.Now().UnixNano()
		if !ok {
			return
		}
		// Trace-mode payload: [T R C E][8-byte sent_at_ns] (12 bytes min).
		// Respond with [T R C E][sent_at_ns][received_at_ns] so the sender
		// can compute one-way and return-trip durations.
		if len(data) >= 12 && data[0] == 'T' && data[1] == 'R' && data[2] == 'C' && data[3] == 'E' {
			resp := make([]byte, 20)
			copy(resp[0:4], data[0:4])
			copy(resp[4:12], data[4:12])
			binary.BigEndian.PutUint64(resp[12:20], uint64(recvNs))
			if _, err := w.Write(resp); err != nil {
				return
			}
			continue
		}
		if _, err := w.Write(data); err != nil {
			return
		}
	}
}
