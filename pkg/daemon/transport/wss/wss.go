// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wss implements pkg/daemon/transport.Transport over a WebSocket
// Secure connection to a Pilot beacon. Used in "compat mode" by daemons
// running in environments where UDP is impractical (Docker on
// Render/Railway/Vercel/Lambda, restrictive corp networks).
//
// Wire model:
//
//   - The daemon opens ONE long-lived wss:// connection to the beacon.
//   - TLS is verified against the embedded Pilot root CA (or the OS
//     trust store if -tls-trust=system).
//   - After upgrade, the daemon completes an Ed25519 challenge so the
//     beacon can authenticate it against the registry's stored pubkey.
//   - Every Pilot UDP packet the daemon would send becomes one binary
//     WS frame; every inbound binary WS frame becomes one Pilot UDP
//     packet returned by Recv. The beacon transparently relays between
//     UDP peers and WSS peers — see docs/SPEC-compat-mode.md §"Transport
//     matrix".
//
// What this transport intentionally does NOT do:
//
//   - No NAT traversal. Compat-mode peers are unreachable for direct UDP
//     by definition; they register with relay_only=true.
//   - No per-peer flow control. The wssTransport is a pipe to the beacon;
//     Pilot's own L3 reliability layer handles retransmits/ordering on
//     top, identical to today's UDP path.
//   - No reconnect during graceful shutdown. Close() is final; the
//     read goroutine exits cleanly and the next Recv returns ErrClosed.
package wss

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport"
)

// DefaultIdlePingInterval is how often the daemon pings the beacon to
// keep the WS connection alive through proxy idle timeouts. 30s is
// short enough for most corporate proxies (which cull at 60-300s) and
// long enough not to flood the link.
const DefaultIdlePingInterval = 30 * time.Second

// DefaultIdlePingTimeout bounds how long a single idle keepalive ping
// may wait for its pong before the connection is treated as half-open.
// On a silently-dead conn (stale NAT/relay mapping, half-open TCP) the
// pong never arrives; without this bound the ping blocks forever, the
// keepalive loop wedges, and the daemon never notices the beacon is
// gone. Kept well under DefaultIdlePingInterval so a slow-but-live link
// is not falsely reconnected. This is the WSS-transport analogue of the
// L4 rx-watchdog: detect a silently-dead inbound path and recover it.
const DefaultIdlePingTimeout = 10 * time.Second

// DefaultDialTimeout caps the time we spend on a single dial attempt
// (DNS + TCP + proxy CONNECT + TLS + WS upgrade + auth challenge).
// Beyond this we fail fast and let the reconnect loop try again.
const DefaultDialTimeout = 20 * time.Second

// DefaultRecvBuffer is the buffered channel size for inbound frames.
// Sized at 256 to absorb modest bursts without backpressure into the
// WS read goroutine; the daemon's dispatcher (single Recv consumer)
// drains it.
const DefaultRecvBuffer = 256

// authChallengeMsg / authReplyMsg / authOKMsg are the JSON shapes for
// the post-upgrade authentication handshake. They live on the text-frame
// channel; everything after auth_ok is binary frames carrying raw
// Pilot packets.
type authChallengeMsg struct {
	Type      string `json:"type"`  // "auth_challenge"
	Nonce     string `json:"nonce"` // 32 random bytes, hex-encoded
	Timestamp int64  `json:"ts"`    // Unix epoch seconds, server-issued (replay window)
}

type authReplyMsg struct {
	Type      string `json:"type"` // "auth_reply"
	NodeID    uint32 `json:"node_id"`
	PublicKey string `json:"public_key"` // base64 Ed25519 pubkey
	Sig       string `json:"sig"`        // base64 Ed25519 signature over "compat_auth:"+node_id+":"+ts+":"+nonce
}

type authOKMsg struct {
	Type string `json:"type"` // "auth_ok"
}

// Config configures a Transport.
type Config struct {
	// URL is the beacon's WSS endpoint, e.g.
	// "wss://beacon-us.pilotprotocol.network/v1/compat".
	URL string

	// TLSConfig pins the trust store. Production builds use a config
	// with RootCAs set to compat.PinnedRoots(); -tls-trust=system uses
	// a config with RootCAs=nil so Go falls back to the OS trust
	// store. Always non-nil — the caller picks the policy.
	TLSConfig *tls.Config

	// DialContext opens the TCP connection to the beacon, e.g. a
	// netproxy.Dialer that tunnels through an HTTP CONNECT proxy by host
	// name, so the beacon name is never resolved locally. TLS (TLSConfig,
	// SNI) then runs end to end with the beacon over that connection;
	// TLSConfig never applies to the proxy itself — an https:// proxy's
	// TLS is the dialer's business, so a pinned beacon trust store cannot
	// reject the operator's proxy certificate. nil dials directly.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Identity provides the Ed25519 keypair used for the auth challenge.
	Identity *crypto.Identity

	// NodeID is the daemon's registered node ID. The auth challenge
	// binds the signature to this nodeID so the beacon can look up the
	// expected pubkey in the registry.
	NodeID uint32

	// IdlePingInterval overrides DefaultIdlePingInterval.
	IdlePingInterval time.Duration

	// IdlePingTimeout overrides DefaultIdlePingTimeout — the per-ping
	// deadline that turns a silently-dead conn into a reconnect.
	IdlePingTimeout time.Duration

	// DialTimeout overrides DefaultDialTimeout.
	DialTimeout time.Duration

	// RecvBuffer overrides DefaultRecvBuffer.
	RecvBuffer int
}

// Transport is the daemon-side WSS implementation of
// transport.Transport. One Transport == one long-lived WSS connection
// to one beacon.
//
// The Transport is safe for one concurrent reader (Recv) and one
// concurrent writer (Send), matching the contract today's UDP socket
// provides to pkg/daemon/tunnel.go.
type Transport struct {
	cfg Config

	// localAddr is a synthetic local address returned by LocalAddr().
	// Higher layers (routing) use it only for log strings; nothing
	// in L4+ keys on the local addr's IP/port for a compat peer.
	localAddr *net.UDPAddr

	// beaconAddr is a synthetic address representing "the beacon" for
	// inbound frames. Every Recv returns this as the src so the
	// dispatcher can distinguish compat-mode traffic without
	// understanding the URL.
	beaconAddr *net.UDPAddr

	// conn is the live WS connection. Replaced atomically by reconnect
	// logic; reads are serialized through the read goroutine, writes
	// through writeMu.
	connMu sync.RWMutex
	conn   *websocket.Conn

	// writeMu serializes WS writes across Send + idle-ping. WS framing
	// requires one writer at a time.
	writeMu sync.Mutex

	// recvCh delivers inbound frames + errors to Recv().
	recvCh chan recvItem

	// closeOnce + closed ensure Close is idempotent and the read
	// goroutine exits exactly once.
	closeOnce sync.Once
	closed    atomic.Bool

	// superviseDoneCh closes when the supervisor goroutine exits.
	// Replaces the old readDoneCh — the supervisor owns the read loop
	// AND the reconnect lifecycle, so its exit is the canonical "done".
	superviseDoneCh chan struct{}

	// lifetimeCtx is cancelled by Close so that any blocking conn.Read
	// or dial-in-progress unwinds promptly. Without this, the
	// underlying websocket library's Read can sit on a closed-but-not-
	// signaled TCP socket for many seconds (observed in tests, where
	// httptest + TLS layers buffer the close).
	lifetimeCtx    context.Context
	lifetimeCancel context.CancelFunc
}

// recvItem is the unit shipped from the read goroutine to Recv().
// frame is nil on error.
type recvItem struct {
	frame []byte
	err   error
}

// Dial opens a WSS connection to the beacon, completes the Ed25519
// auth challenge, and returns a live Transport. Returns a wrapped
// error if any step fails. Caller is responsible for Close().
func Dial(ctx context.Context, cfg Config) (*Transport, error) {
	if cfg.URL == "" {
		return nil, errors.New("wss: URL is required")
	}
	if cfg.TLSConfig == nil {
		return nil, errors.New("wss: TLSConfig is required (caller picks pinned vs system trust)")
	}
	if cfg.Identity == nil {
		return nil, errors.New("wss: Identity is required for auth")
	}
	if cfg.IdlePingInterval == 0 {
		cfg.IdlePingInterval = DefaultIdlePingInterval
	}
	if cfg.IdlePingTimeout == 0 {
		cfg.IdlePingTimeout = DefaultIdlePingTimeout
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.RecvBuffer <= 0 {
		cfg.RecvBuffer = DefaultRecvBuffer
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()

	// Synthetic local + beacon addresses. The IPs are reserved
	// documentation ranges (RFC 5737) so they cannot collide with a
	// real UDP peer. Ports are 0 — they're not meaningful for WS.
	lifetimeCtx, lifetimeCancel := context.WithCancel(context.Background())
	t := &Transport{
		cfg:             cfg,
		localAddr:       &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 0},
		beaconAddr:      &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 0},
		recvCh:          make(chan recvItem, cfg.RecvBuffer),
		superviseDoneCh: make(chan struct{}),
		lifetimeCtx:     lifetimeCtx,
		lifetimeCancel:  lifetimeCancel,
	}

	// First dial happens inline so Dial returns a "ready" Transport.
	// Subsequent reconnects happen in the supervisor goroutine.
	conn, err := t.dialAndAuth(dialCtx)
	if err != nil {
		return nil, err
	}
	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	go t.supervise()
	go t.idlePing()
	return t, nil
}

// dialAndAuth opens a fresh WS connection and completes the Ed25519
// auth handshake. Used by the initial Dial and by the supervisor
// goroutine when reconnecting. Returns the live (authenticated) conn
// or an error. Caller stores the conn under connMu.
func (t *Transport) dialAndAuth(ctx context.Context) (*websocket.Conn, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext:     t.cfg.DialContext,
			TLSClientConfig: t.cfg.TLSConfig.Clone(),
		},
	}
	conn, _, err := websocket.Dial(ctx, t.cfg.URL, &websocket.DialOptions{
		HTTPClient:   httpClient,
		Subprotocols: []string{"pilot.v1"},
	})
	if err != nil {
		return nil, fmt.Errorf("wss dial: %w", err)
	}
	if err := t.runAuth(ctx, conn); err != nil {
		conn.Close(websocket.StatusPolicyViolation, "auth failed")
		return nil, fmt.Errorf("wss auth: %w", err)
	}
	return conn, nil
}

// runAuth performs the post-upgrade challenge/response. Reads one
// text frame (auth_challenge), signs the nonce, writes auth_reply,
// reads auth_ok. Bounded by dialCtx.
func (t *Transport) runAuth(ctx context.Context, conn *websocket.Conn) error {
	msgType, body, err := conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("read challenge: %w", err)
	}
	if msgType != websocket.MessageText {
		return fmt.Errorf("expected text frame for challenge, got %v", msgType)
	}
	var ch authChallengeMsg
	if err := json.Unmarshal(body, &ch); err != nil {
		return fmt.Errorf("parse challenge: %w", err)
	}
	if ch.Type != "auth_challenge" || ch.Nonce == "" {
		return fmt.Errorf("malformed challenge: type=%q nonce-len=%d", ch.Type, len(ch.Nonce))
	}

	// Sign "compat_auth:<nodeID>:<ts>:<nonce>" — same shape the beacon
	// verifies (beacon >= v0.2.6). Binding nodeID + server timestamp +
	// nonce into the signed bytes prevents replay across identities and
	// bounds the auth to the server's freshness window.
	msg := fmt.Sprintf("compat_auth:%d:%d:%s", t.cfg.NodeID, ch.Timestamp, ch.Nonce)
	sig := t.cfg.Identity.Sign([]byte(msg))

	reply := authReplyMsg{
		Type:      "auth_reply",
		NodeID:    t.cfg.NodeID,
		PublicKey: crypto.EncodePublicKey(t.cfg.Identity.PublicKey),
		Sig:       base64.StdEncoding.EncodeToString(sig),
	}
	replyBytes, _ := json.Marshal(reply)
	if err := conn.Write(ctx, websocket.MessageText, replyBytes); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}

	msgType, body, err = conn.Read(ctx)
	if err != nil {
		return fmt.Errorf("read auth_ok: %w", err)
	}
	if msgType != websocket.MessageText {
		return fmt.Errorf("expected text frame for auth_ok, got %v", msgType)
	}
	var ok authOKMsg
	if err := json.Unmarshal(body, &ok); err != nil {
		return fmt.Errorf("parse auth_ok: %w", err)
	}
	if ok.Type != "auth_ok" {
		return fmt.Errorf("auth rejected: %s", string(body))
	}
	return nil
}

// ErrReconnecting is returned by Send while the supervisor is
// re-establishing the WSS connection. Caller's higher-level retry
// loop (key-exchange retransmit, dial-retry, etc.) will refire once
// the conn is back. Distinct from ErrClosed so callers can choose
// to retry instead of tearing down.
var ErrReconnecting = errors.New("wss: reconnecting")

// Send writes frame as one binary WS frame. The dst argument is
// ignored — every send goes to the single beacon at the other end
// of this Transport. Returns (len(frame), nil) on success.
//
// If the underlying conn has died and the supervisor has not yet
// reinstalled a fresh one, Send returns ErrReconnecting immediately
// (without waiting). On a Write error against a live conn, Send
// clears t.conn so future calls don't slam the dead pipe — the
// supervisor's read loop will hit the same break and trigger the
// reconnect sequence.
func (t *Transport) Send(frame []byte, _ *net.UDPAddr) (int, error) {
	if t.closed.Load() {
		return 0, transport.ErrClosed
	}
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()
	if conn == nil {
		return 0, ErrReconnecting
	}
	t.writeMu.Lock()
	err := conn.Write(context.Background(), websocket.MessageBinary, frame)
	t.writeMu.Unlock()
	if err != nil {
		if t.closed.Load() {
			return 0, transport.ErrClosed
		}
		// Mark conn nil so subsequent sends fail fast with
		// ErrReconnecting instead of repeatedly tripping the same
		// error through the dead conn. The supervisor's read loop
		// will independently observe the break and start the
		// reconnect sequence.
		t.connMu.Lock()
		if t.conn == conn {
			t.conn = nil
		}
		t.connMu.Unlock()
		return 0, fmt.Errorf("wss send: %w", err)
	}
	return len(frame), nil
}

// Recv returns the next inbound frame. The src argument is always
// t.beaconAddr — every inbound packet "arrived from the beacon" from
// the daemon's local viewpoint. The Pilot packet header carries the
// real source nodeID.
func (t *Transport) Recv() ([]byte, *net.UDPAddr, error) {
	item, ok := <-t.recvCh
	if !ok {
		return nil, nil, transport.ErrClosed
	}
	if item.err != nil {
		return nil, nil, item.err
	}
	return item.frame, t.beaconAddr, nil
}

// LocalAddr returns a synthetic local address. Used only in log
// messages by upper layers. Never nil.
func (t *Transport) LocalAddr() *net.UDPAddr {
	return t.localAddr
}

// Close shuts down the WSS connection. Idempotent. After Close, the
// supervisor goroutine exits, no further reconnect attempts fire,
// and subsequent Send/Recv calls return ErrClosed.
func (t *Transport) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		// Cancel lifetimeCtx FIRST so the supervisor's in-flight
		// conn.Read / Dial unblock immediately. Without this, the
		// supervisor can sit on a blocked Read for tens of seconds
		// when the underlying TCP isn't cleanly shut down (TLS+
		// httptest in tests; nginx restart in prod).
		t.lifetimeCancel()
		t.connMu.Lock()
		conn := t.conn
		t.conn = nil
		t.connMu.Unlock()
		if conn != nil {
			closeErr = conn.Close(websocket.StatusNormalClosure, "")
		}
		// Wait for supervisor (read loop + reconnect loop) to drain
		// so we don't race on recvCh close.
		<-t.superviseDoneCh
		close(t.recvCh)
	})
	return closeErr
}

// supervise runs the read loop AND drives auto-reconnect. It is the
// only goroutine that mutates t.conn during normal operation.
//
// Loop body, per iteration:
//  1. If we have a live conn, drainReads(conn) blocks until the conn
//     dies or Close fires. If we don't (Send() cleared it on a write
//     error, or the previous reconnect attempt failed), skip straight
//     to the backoff + redial steps.
//  2. Sleep backoff (exponential, capped) — bail on Close.
//  3. dialAndAuth — on success, install new conn and reset backoff;
//     on failure, bump backoff and try again.
//
// Only Close() can stop the supervisor. A failed reconnect attempt
// MUST NOT make the supervisor exit — otherwise a single bad dial
// permanently wedges the transport.
func (t *Transport) supervise() {
	defer close(t.superviseDoneCh)

	const (
		minBackoff = 250 * time.Millisecond
		maxBackoff = 30 * time.Second
	)
	backoff := minBackoff

	for {
		if t.closed.Load() {
			return
		}

		// 1. If a live conn is installed, drain it until the read fails
		// or Close fires. Otherwise (Send cleared it, or last dial
		// failed), skip straight to redial.
		t.connMu.RLock()
		conn := t.conn
		t.connMu.RUnlock()
		if conn != nil {
			t.drainReads(conn)
			if t.closed.Load() {
				return
			}
			slog.Warn("wss transport: connection lost, reconnecting", "backoff", backoff)
			t.connMu.Lock()
			if t.conn == conn {
				t.conn = nil
			}
			t.connMu.Unlock()
			_ = conn.Close(websocket.StatusAbnormalClosure, "reconnecting")
		}

		// 2. Backoff, but wake immediately on Close.
		if t.sleepOrClosed(backoff) {
			return
		}

		// 3. Re-dial + re-auth. Each attempt gets DialTimeout budget,
		// but is also cancelled by Close() via lifetimeCtx so the
		// supervisor never lingers on a dead dial past shutdown.
		dialCtx, cancel := context.WithTimeout(t.lifetimeCtx, t.cfg.DialTimeout)
		newConn, err := t.dialAndAuth(dialCtx)
		cancel()
		if t.closed.Load() {
			// Close raced with a successful reconnect — drop the new
			// conn rather than installing it.
			if newConn != nil {
				_ = newConn.Close(websocket.StatusNormalClosure, "shutting down")
			}
			return
		}
		if err != nil {
			nextBackoff := backoff * 2
			if nextBackoff > maxBackoff {
				nextBackoff = maxBackoff
			}
			slog.Warn("wss transport: reconnect failed", "err", err, "next_backoff", nextBackoff)
			backoff = nextBackoff
			continue
		}

		// Success — install conn, reset backoff, loop back to read.
		t.connMu.Lock()
		t.conn = newConn
		t.connMu.Unlock()
		slog.Info("wss transport: reconnected")
		backoff = minBackoff
	}
}

// drainReads pumps binary frames from the supplied conn into recvCh
// until the read fails or Close fires. Errors during reading are
// surfaced to Recv() ONLY if the transport is being torn down by
// Close — transient errors trigger reconnect instead.
func (t *Transport) drainReads(conn *websocket.Conn) {
	for {
		if t.closed.Load() {
			return
		}
		// lifetimeCtx unblocks this Read on Close even if the TLS+
		// httptest layer is still buffering the peer's close frame.
		msgType, body, err := conn.Read(t.lifetimeCtx)
		if err != nil {
			if t.closed.Load() {
				// Close raced with the read error — surface ErrClosed
				// rather than the underlying conn-closed error so the
				// caller's existing error checks work.
				select {
				case t.recvCh <- recvItem{err: transport.ErrClosed}:
				default:
				}
				return
			}
			// Transient: log + return so supervise() can reconnect.
			// Do NOT surface to Recv — the caller's higher-level retry
			// logic (key-exchange retransmit, dial retry) will refire
			// once supervise installs a fresh conn.
			slog.Debug("wss transport: read error, supervisor will reconnect", "err", err)
			return
		}

		if msgType == websocket.MessageText {
			// Reserved for future control messages. Today: log and
			// continue (don't drop the connection over an unknown
			// control frame — forward compat).
			continue
		}
		if msgType != websocket.MessageBinary {
			continue
		}
		// Copy: the WS library reuses its internal buffer for the next
		// read. Upper layers may retain the slice across Recv calls
		// (e.g. queuing into the per-peer pending buffer).
		frameCopy := make([]byte, len(body))
		copy(frameCopy, body)
		select {
		case t.recvCh <- recvItem{frame: frameCopy}:
		case <-t.superviseDoneCh:
			return
		}
	}
}

// idlePing sends websocket Ping frames at the configured IdlePingInterval
// to keep the WSS connection alive through proxy idle timeouts. Runs until
// Close() fires via lifetimeCtx. Skips pings while the supervisor is
// reconnecting (conn == nil).
//
// Each ping is bounded by IdlePingTimeout. A pong that never arrives —
// the signature of a silently half-open conn (stale NAT/relay mapping,
// half-open TCP the kernel hasn't torn down) — would otherwise block
// this loop forever while it holds writeMu, freezing every Send behind
// it and leaving the dead beacon conn undetected. On a ping error we
// force the conn closed: that unblocks the supervisor's drainReads Read,
// which drives the reconnect. Without this, a half-open beacon link is
// invisible to the transport (Send only fails once there is traffic to
// send, and drainReads sits blocked on a Read that never returns).
func (t *Transport) idlePing() {
	ticker := time.NewTicker(t.cfg.IdlePingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.lifetimeCtx.Done():
			return
		case <-ticker.C:
			if t.closed.Load() {
				return
			}
			t.connMu.RLock()
			conn := t.conn
			t.connMu.RUnlock()
			if conn == nil {
				continue
			}
			pingCtx, cancel := context.WithTimeout(t.lifetimeCtx, t.cfg.IdlePingTimeout)
			t.writeMu.Lock()
			err := conn.Ping(pingCtx)
			t.writeMu.Unlock()
			cancel()
			if err != nil {
				if t.closed.Load() {
					return
				}
				// Half-open conn: the pong timed out. Force the conn
				// closed so the supervisor's blocked drainReads Read
				// returns an error and the reconnect sequence fires.
				// Also clear t.conn so Send fails fast meanwhile.
				slog.Warn("wss transport: idle ping timed out — forcing reconnect",
					"err", err, "timeout", t.cfg.IdlePingTimeout)
				t.connMu.Lock()
				if t.conn == conn {
					t.conn = nil
				}
				t.connMu.Unlock()
				_ = conn.Close(websocket.StatusPolicyViolation, "idle ping timeout")
			}
		}
	}
}

// sleepOrClosed blocks for d, returning true if Close fired during the
// wait. Lets the supervisor abandon a long backoff promptly.
func (t *Transport) sleepOrClosed(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	// Poll closed flag at a coarse cadence so we don't need an explicit
	// notify channel. With max backoff 30s and 100ms poll, Close
	// latency is bounded at 100ms — fine.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-timer.C:
			return false
		case <-tick.C:
			if t.closed.Load() {
				return true
			}
		}
	}
}
