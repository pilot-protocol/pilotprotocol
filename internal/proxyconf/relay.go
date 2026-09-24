// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

// RelayUser is the user name in a Relay's URL. The password is a random
// token, different for every Relay.
const RelayUser = "pilot-relay"

// Relay timeouts. Variables so tests can shorten them.
var (
	// relayRequestTimeout bounds reading a client's CONNECT request.
	relayRequestTimeout = 30 * time.Second
	// relayDialTimeout bounds opening the tunnel upstream, one credential
	// refresh and its retry included (netproxy.Dialer's own limit is 30s).
	relayDialTimeout = 45 * time.Second
	// relayLogEvery rate-limits the WARN for failed CONNECTs: an app that
	// retries in a tight loop must not flood the daemon log.
	relayLogEvery = 10 * time.Second
)

// Relay is a loopback HTTP CONNECT proxy that forwards every tunnel through
// the egress proxy its Resolver picks, with the Resolver's current
// credentials: each CONNECT it accepts is opened upstream by a
// netproxy.Dialer, which refreshes the Resolver and retries once when the
// proxy rejects the credentials (a 407, or an answer so garbled it cannot
// be parsed, which is how Meta Muse's rejections arrive), and whose errors
// never quote the proxy.
//
// The daemon runs one for two kinds of clients:
//
//   - the processes it starts (app-store apps). They inherit the daemon's
//     environment, and a proxy URL in that environment keeps the
//     credentials the daemon was launched with. Where the proxy rotates
//     them (Meta Muse: every few minutes), every new connection such a
//     process opens is then rejected, while the daemon itself, which
//     re-reads its credentials, stays online ("node online, all apps
//     broken"). Pointed at the Relay instead (HTTPS_PROXY=Relay.URL),
//     those processes never hold the proxy's credentials at all.
//   - http.DefaultTransport (see ConfigureTransport), which net/http runs
//     itself: it cannot retry a rejected CONNECT, never sees an answer it
//     cannot parse, and quotes such an answer in its error.
//
// The Relay listens on loopback only and accepts only CONNECT (it never
// sees inside a tunnel; TLS stays end to end). A client must send the
// Relay's own credentials (RelayUser and a random token, both in URL), so
// another local user cannot borrow the daemon's proxy credentials through
// it. Loopback targets are dialed directly and targets the Resolver does
// not proxy (NO_PROXY) go direct too, as they do for the daemon. When a
// tunnel cannot be opened the client gets 502 Bad Gateway (403 when the
// proxy refused the target, 504 on a timeout), with a reason phrase that
// says why without any credentials or text from the proxy.
type Relay struct {
	ln     net.Listener
	r      *netproxy.Resolver
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	token  string
	url    *url.URL
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup

	logMu    sync.Mutex
	lastWarn time.Time
	muted    int
}

// StartRelay starts a Relay for r on a loopback port chosen by the system.
// proxyTLS configures the TLS session with an https:// proxy (nil: the
// system roots), as for DialContext. r must proxy something.
func StartRelay(r *netproxy.Resolver, proxyTLS *tls.Config) (*Relay, error) {
	if !r.Enabled() {
		return nil, errors.New("proxy relay: no proxy to relay to")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		var err6 error
		if ln, err6 = net.Listen("tcp", "[::1]:0"); err6 != nil {
			return nil, fmt.Errorf("proxy relay: listen on loopback: %w", err)
		}
	}
	return startRelayOn(ln, r, proxyTLS)
}

// startRelayOn starts a Relay for r on ln, which it takes over.
func startRelayOn(ln net.Listener, r *netproxy.Resolver, proxyTLS *tls.Config) (*Relay, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		ln.Close()
		return nil, fmt.Errorf("proxy relay: token: %w", err)
	}
	token := hex.EncodeToString(raw)
	ctx, cancel := context.WithCancel(context.Background())
	rl := &Relay{
		ln:     ln,
		r:      r,
		dial:   DialContext(r, proxyTLS),
		token:  token,
		url:    &url.URL{Scheme: "http", User: url.UserPassword(RelayUser, token), Host: ln.Addr().String()},
		ctx:    ctx,
		cancel: cancel,
		conns:  map[net.Conn]struct{}{},
	}
	go rl.serve()
	return rl, nil
}

// URL returns the proxy URL clients use, http://pilot-relay:<token>@host:port.
// It carries the Relay's token: hand it to child processes (HTTPS_PROXY),
// never log it.
func (rl *Relay) URL() *url.URL {
	u := *rl.url
	return &u
}

// Addr returns the "host:port" the Relay listens on.
func (rl *Relay) Addr() string { return rl.ln.Addr().String() }

// Serves reports whether proxyURL, a proxy URL as a refresh command prints
// it, names this Relay. The daemon never lets its own proxy become its
// Relay: the Relay would then forward to itself.
func (rl *Relay) Serves(proxyURL string) bool {
	if rl == nil {
		return false
	}
	s := strings.TrimSpace(proxyURL)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	lhost, lport, _ := net.SplitHostPort(rl.Addr())
	if port != lport {
		return false
	}
	return strings.EqualFold(strings.Trim(host, "[]"), lhost) || IsLoopbackHost(host)
}

// Close stops the Relay: it stops accepting, closes every open tunnel and
// waits for their goroutines to finish.
func (rl *Relay) Close() error {
	if rl == nil {
		return nil
	}
	rl.mu.Lock()
	if rl.closed {
		rl.mu.Unlock()
		return nil
	}
	rl.closed = true
	err := rl.ln.Close()
	for c := range rl.conns {
		c.Close()
	}
	rl.mu.Unlock()
	rl.cancel()
	rl.wg.Wait()
	return err
}

// track registers c so Close can close it; false once the Relay is closed
// (the caller then closes c itself). With add it also counts a goroutine
// Close waits for.
func (rl *Relay) track(c net.Conn, add bool) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if rl.closed {
		return false
	}
	rl.conns[c] = struct{}{}
	if add {
		rl.wg.Add(1)
	}
	return true
}

func (rl *Relay) untrack(c net.Conn) {
	rl.mu.Lock()
	delete(rl.conns, c)
	rl.mu.Unlock()
	c.Close()
}

func (rl *Relay) serve() {
	backoff := 5 * time.Millisecond
	for {
		c, err := rl.ln.Accept()
		if err != nil {
			rl.mu.Lock()
			closed := rl.closed
			rl.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of file descriptors, say: back off and keep serving.
			time.Sleep(backoff)
			if backoff < time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = 5 * time.Millisecond
		if !rl.track(c, true) {
			c.Close()
			return
		}
		go func() {
			defer rl.wg.Done()
			defer rl.untrack(c)
			rl.handle(c)
		}()
	}
}

// relayMaxRequest caps a CONNECT request (line and headers).
const relayMaxRequest = 64 << 10

// handle serves one client connection: one CONNECT, then the tunnel.
func (rl *Relay) handle(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(relayRequestTimeout))
	limited := &io.LimitedReader{R: c, N: relayMaxRequest}
	br := bufio.NewReader(limited)
	req, err := http.ReadRequest(br)
	if err != nil {
		writeRelayStatus(c, http.StatusBadRequest, "")
		return
	}
	limited.N = math.MaxInt64 // the tunnel is not capped
	if req.Method != http.MethodConnect {
		writeRelayStatus(c, http.StatusMethodNotAllowed, "only CONNECT is relayed", "Allow: CONNECT")
		return
	}
	if !rl.authorized(req) {
		writeRelayStatus(c, http.StatusProxyAuthRequired, "", `Proxy-Authenticate: Basic realm="pilot-daemon"`)
		return
	}
	target := req.Host
	if target == "" && req.URL != nil {
		target = req.URL.Host
	}
	if host, port, err := net.SplitHostPort(target); err != nil || host == "" || port == "" {
		writeRelayStatus(c, http.StatusBadRequest, "CONNECT needs host:port")
		return
	}
	if !loopbackAddr(target) {
		// The daemon's proxy settings never name the Relay itself (see
		// Serves), but a loop would tie up a connection per hop until the
		// dial timeout, so refuse one outright.
		if u, err := rl.r.ProxyForAddr(target); err == nil && u != nil && rl.Serves(u.String()) {
			writeRelayStatus(c, http.StatusLoopDetected, "the proxy for "+target+" is this relay")
			return
		}
	}

	ctx, cancel := context.WithTimeout(rl.ctx, relayDialTimeout)
	up, err := rl.dial(ctx, "tcp", target)
	cancel()
	if err != nil {
		rl.warn(target, err)
		writeRelayStatus(c, relayFailureStatus(err), err.Error())
		return
	}
	if !rl.track(up, false) {
		up.Close()
		return
	}
	defer rl.untrack(up)
	_ = c.SetReadDeadline(time.Time{})
	_ = c.SetWriteDeadline(time.Now().Add(relayRequestTimeout))
	if _, err := io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{})
	pipe(c, br, up)
}

// authorized reports whether req carries the Relay's credentials.
func (rl *Relay) authorized(req *http.Request) bool {
	scheme, cred, ok := strings.Cut(strings.TrimSpace(req.Header.Get("Proxy-Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cred))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(raw, []byte(RelayUser+":"+rl.token)) == 1
}

// warn logs a failed CONNECT at WARN, at most once per relayLogEvery; the
// ones in between are counted in the next line. The error is netproxy's,
// which never holds credentials or proxy-supplied text.
func (rl *Relay) warn(target string, err error) {
	rl.logMu.Lock()
	now := time.Now()
	if !rl.lastWarn.IsZero() && now.Sub(rl.lastWarn) < relayLogEvery {
		rl.muted++
		rl.logMu.Unlock()
		return
	}
	muted := rl.muted
	rl.lastWarn, rl.muted = now, 0
	rl.logMu.Unlock()
	args := []any{"target", target, "err", err}
	if muted > 0 {
		args = append(args, "more_failures_not_logged", muted)
	}
	if hint := CredentialHint(err); hint != "" {
		args = append(args, "hint", hint)
	}
	slog.Warn("proxy relay: could not open a tunnel", args...)
}

// relayFailureStatus is the status the Relay answers a CONNECT with when
// the tunnel could not be opened. A 407 from the egress proxy becomes 502:
// the client's own credentials (the Relay's) were fine, and a 407 would
// send it looking in the wrong place.
func relayFailureStatus(err error) int {
	var ce *netproxy.ConnectError
	if errors.As(err, &ce) && ce.StatusCode == http.StatusForbidden {
		return http.StatusForbidden
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return http.StatusGatewayTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

// relayReasonPrefix starts the detail in a Relay's reason phrase.
const relayReasonPrefix = "pilot-daemon proxy relay: "

// writeRelayStatus answers c with an empty response. detail, when set,
// extends the reason phrase (HTTP clients show it: Go's net/http returns
// it as the error text of a failed CONNECT), reduced to printable ASCII.
func writeRelayStatus(c net.Conn, code int, detail string, headers ...string) {
	reason := http.StatusText(code)
	if detail = reasonText(detail); detail != "" {
		reason += " (" + relayReasonPrefix + detail + ")"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", code, reason)
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.WriteString(c, b.String())
}

// reasonText makes s safe for a reason phrase: printable ASCII only, at
// most 300 bytes.
func reasonText(s string) string {
	const max = 300
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < max; i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

// pipe copies client <-> upstream until both directions are done. When one
// side stops sending, its peer's write side is shut down (or, where that is
// not possible, the peer is closed), so the other direction ends too.
func pipe(client net.Conn, clientIn io.Reader, up net.Conn) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(up, clientIn) // clientIn drains what was read with the request first
		closeWrite(up)
	}()
	_, _ = io.Copy(client, up)
	closeWrite(client)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return
		}
	}
	c.Close()
}
