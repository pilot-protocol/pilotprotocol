// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	"golang.org/x/net/http/httpproxy"
)

// DefaultRefreshInterval is how often a command-backed Policy re-runs its
// command. Sandboxes that rotate proxy credentials (Meta Muse: every few
// minutes) accept the previous credentials for a while, and a 407 forces
// an immediate refresh anyway.
const DefaultRefreshInterval = 60 * time.Second

// commandTimeout bounds one run of the proxy command.
const commandTimeout = 10 * time.Second

// commandOutputLimit caps what is read from the proxy command's stdout.
const commandOutputLimit = 64 << 10

// Policy is an outbound proxy policy that can change while the process
// runs. It is either static (a fixed netproxy.Resolver) or backed by a
// command whose stdout is the current proxy URL — for egress proxies whose
// credentials rotate (a long-lived daemon keeps the credentials of its
// launch environment, and the proxy starts answering new CONNECTs with 407
// Proxy Authentication Required a few minutes later).
//
// A command-backed Policy re-runs the command every refresh interval (Run)
// and whenever the proxy rejects the credentials; its dialers and HTTP
// helpers then retry once with the new URL. Connections already open are
// unaffected: established tunnels survive a rotation.
//
// A nil *Policy never proxies. Loopback targets are never proxied.
// Policies are safe for concurrent use.
type Policy struct {
	cur atomic.Pointer[policyState]

	// Command-backed policies only.
	command string
	run     func(ctx context.Context, command string) (string, error)
	exempt  func(scheme, hostport string) bool
	mu      sync.Mutex // serializes refreshes
}

type policyState struct {
	resolver *netproxy.Resolver
	// raw is the command's last URL ("" for the static fallback). Only
	// ever compared, never logged.
	raw string
	gen uint64
}

// Static returns a Policy that always uses r. nil r gives a nil Policy (no
// policy: callers keep their historical behaviour).
func Static(r *netproxy.Resolver) *Policy {
	if r == nil {
		return nil
	}
	p := &Policy{}
	p.cur.Store(&policyState{resolver: r})
	return p
}

// NewCommand returns a Policy backed by command, a shell command line
// (/bin/sh -c; cmd /C on Windows) whose stdout is the current proxy URL,
// http://[user:pass@]host[:port] or https://.... The command runs once now.
// Its URL is used for every target except loopback and, with honorNoProxy
// (the -proxy=auto semantics), the NO_PROXY / no_proxy exemptions of this
// process's environment.
//
// When that first run fails, fallback (typically the environment's proxy,
// which was fresh when the process started) is used until a refresh
// succeeds, and the error is returned along with the Policy; the Policy is
// usable either way.
func NewCommand(ctx context.Context, command string, fallback *netproxy.Resolver, honorNoProxy bool) (*Policy, error) {
	return newCommandPolicy(ctx, command, fallback, honorNoProxy, runProxyCommand)
}

func newCommandPolicy(ctx context.Context, command string, fallback *netproxy.Resolver, honorNoProxy bool, run func(context.Context, string) (string, error)) (*Policy, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, errors.New("empty proxy command")
	}
	p := &Policy{command: command, run: run}
	if honorNoProxy {
		p.exempt = noProxyMatcher(noProxyFromEnv())
	}
	p.cur.Store(&policyState{resolver: fallback})
	if _, err := p.refresh(ctx, 0, true); err != nil {
		return p, err
	}
	return p, nil
}

// Refreshable reports whether the Policy re-reads its proxy (it is backed
// by a command).
func (p *Policy) Refreshable() bool { return p != nil && p.command != "" }

// Resolver returns the current resolver (nil when there is none).
func (p *Policy) Resolver() *netproxy.Resolver {
	s := p.state()
	if s == nil {
		return nil
	}
	return s.resolver
}

func (p *Policy) state() *policyState {
	if p == nil {
		return nil
	}
	return p.cur.Load()
}

// Enabled reports whether any target may be proxied. A command-backed
// Policy is always enabled: its next refresh can supply a proxy.
func (p *Policy) Enabled() bool {
	if p == nil {
		return false
	}
	return p.Refreshable() || p.Resolver().Enabled()
}

// Mode reports netproxy.ModeAuto, ModeOff or ModeExplicit for the current
// resolver.
func (p *Policy) Mode() string { return p.Resolver().Mode() }

// Warnings reports the current resolver's skipped environment variables.
func (p *Policy) Warnings() []error { return p.Resolver().Warnings() }

// String describes the Policy for logs, credentials redacted.
func (p *Policy) String() string {
	if p == nil {
		return "none"
	}
	s := p.Resolver().String()
	if p.Resolver() == nil {
		s = "none yet"
	}
	if p.Refreshable() {
		s += " (refreshed from the proxy command)"
	}
	return s
}

// Refresh re-runs the proxy command now. changed reports whether the proxy
// URL differs from the one in use. A static Policy never changes. On error
// the previous proxy stays in use.
func (p *Policy) Refresh(ctx context.Context) (changed bool, err error) {
	if !p.Refreshable() {
		return false, nil
	}
	return p.refresh(ctx, 0, false)
}

// refresh runs the command unless another refresh already replaced the
// state generation `seen` (seen == 0: always run), and installs the new
// URL when it differs. It reports whether the URL in use is now different
// from generation `seen`.
func (p *Policy) refresh(ctx context.Context, seen uint64, initial bool) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cur := p.cur.Load()
	if seen != 0 && cur.gen != seen {
		return true, nil // someone refreshed while we waited
	}
	raw, err := p.run(ctx, p.command)
	if err != nil {
		return false, err
	}
	if raw == cur.raw && cur.raw != "" {
		return false, nil
	}
	r, err := netproxy.Explicit(raw)
	if err != nil {
		return false, fmt.Errorf("proxy command printed an unusable URL: %v", unwrapNetproxy(err))
	}
	next := &policyState{resolver: r, raw: raw, gen: cur.gen + 1}
	p.cur.Store(next)
	if !initial {
		old := "none"
		if cur.resolver != nil {
			old = cur.resolver.String()
		}
		if old != r.String() {
			slog.Info("proxy changed (proxy command)", "proxy", r.String(), "was", old)
		} else {
			slog.Debug("proxy credentials refreshed (proxy command)", "proxy", r.String())
		}
	}
	return true, nil
}

// refreshAfterAuthFailure refreshes after the proxy rejected the
// credentials of generation seen, and reports whether a retry would use a
// different URL.
func (p *Policy) refreshAfterAuthFailure(ctx context.Context, seen uint64) bool {
	if !p.Refreshable() {
		return false
	}
	changed, err := p.refresh(ctx, seen, false)
	if err != nil {
		slog.Warn("proxy rejected the credentials and the proxy command failed; keeping the previous proxy", "err", err)
		return false
	}
	return changed
}

// Run re-runs the proxy command every interval (DefaultRefreshInterval when
// interval <= 0) until ctx ends. It returns at once for a static Policy.
func (p *Policy) Run(ctx context.Context, interval time.Duration) {
	if !p.Refreshable() {
		return
	}
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := p.Refresh(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("proxy command failed; keeping the previous proxy", "err", err)
			}
		}
	}
}

// bypass reports whether target (host, port) goes direct whatever the
// resolver says: loopback always, and for a command-backed Policy the
// NO_PROXY exemptions.
func (p *Policy) bypass(scheme, host, port string) bool {
	if IsLoopbackHost(host) {
		return true
	}
	return p != nil && p.exempt != nil && p.exempt(scheme, net.JoinHostPort(host, port))
}

// Proxies reports whether a TCP connection to addr ("host:port") would go
// through a proxy. A command-backed Policy proxies every target it does
// not exempt, also before its command first succeeds.
func (p *Policy) Proxies(addr string) bool {
	if !p.Enabled() {
		return false
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || p.bypass("https", host, port) {
		return false
	}
	if p.Refreshable() {
		return true
	}
	u, err := p.Resolver().ProxyForAddr(addr)
	return err == nil && u != nil
}

// DialContext returns a dial function that tunnels through the proxy the
// Policy picks for each target (CONNECT by host name) and dials loopback
// and unproxied targets directly. When the proxy rejects the credentials
// (407) of a command-backed Policy, the command is re-run and the dial is
// retried once with the new URL. proxyTLS configures the TLS session with
// an https:// proxy (nil: system roots); it never applies to the target.
func (p *Policy) DialContext(proxyTLS *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	var direct net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, err := net.SplitHostPort(addr); err == nil && p.bypass("https", host, port) {
			return direct.DialContext(ctx, network, addr)
		}
		s := p.state()
		var r *netproxy.Resolver
		var gen uint64
		if s != nil {
			r, gen = s.resolver, s.gen
		}
		conn, err := (&netproxy.Dialer{Resolver: r, TLSConfig: proxyTLS}).DialContext(ctx, network, addr)
		if err == nil || !IsProxyAuthError(err) || !p.refreshAfterAuthFailure(ctx, gen) {
			return conn, err
		}
		slog.Info("proxy rejected the credentials; retrying with refreshed ones", "target", addr)
		return (&netproxy.Dialer{Resolver: p.Resolver(), TLSConfig: proxyTLS}).DialContext(ctx, network, addr)
	}
}

// RequestProxy returns an http.Transport.Proxy function that follows the
// Policy's current resolver and never proxies loopback targets. nil for a
// nil Policy (net/http's own environment handling then applies wherever
// the caller leaves Proxy unset).
func (p *Policy) RequestProxy() func(*http.Request) (*url.URL, error) {
	if p == nil {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil {
			return nil, nil
		}
		scheme := "https"
		port := req.URL.Port()
		switch strings.ToLower(req.URL.Scheme) {
		case "http", "ws":
			scheme = "http"
			if port == "" {
				port = "80"
			}
		default:
			if port == "" {
				port = "443"
			}
		}
		if p.bypass(scheme, req.URL.Hostname(), port) {
			return nil, nil
		}
		return p.Resolver().ProxyForRequest(req)
	}
}

// ErrProxyAuth is returned for requests whose proxy CONNECT was answered
// with 407 Proxy Authentication Required (see ConfigureTransport).
var ErrProxyAuth = errors.New("proxy CONNECT: 407 Proxy Authentication Required")

// ConfigureTransport routes tr through the Policy: tr.Proxy follows the
// current resolver, and a 407 answer to a CONNECT makes a command-backed
// Policy refresh at once, so the next connection uses the new credentials
// (the failed request returns ErrProxyAuth; RoundTripper retries it). A nil
// Policy leaves tr alone.
func (p *Policy) ConfigureTransport(tr *http.Transport) {
	if p == nil || tr == nil {
		return
	}
	tr.Proxy = p.RequestProxy()
	if !p.Refreshable() {
		return
	}
	tr.OnProxyConnectResponse = func(ctx context.Context, _ *url.URL, _ *http.Request, resp *http.Response) error {
		if resp.StatusCode != http.StatusProxyAuthRequired {
			return nil
		}
		s := p.state()
		p.refreshAfterAuthFailure(ctx, s.gen)
		return ErrProxyAuth
	}
}

// RoundTripper wraps base (a transport set up with ConfigureTransport) so
// that a request whose CONNECT the proxy rejected with 407 is retried once
// when the refreshed Policy has a different URL. Requests with a body are
// retried only when it can be replayed (GetBody). For a Policy that cannot
// refresh it returns base.
func (p *Policy) RoundTripper(base http.RoundTripper) http.RoundTripper {
	if !p.Refreshable() || base == nil {
		return base
	}
	return &retryAuthTransport{p: p, base: base}
}

type retryAuthTransport struct {
	p    *Policy
	base http.RoundTripper
}

func (t *retryAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	s := t.p.state()
	resp, err := t.base.RoundTrip(req)
	if err == nil || !IsProxyAuthError(err) {
		return resp, err
	}
	if s.gen == t.p.state().gen && !t.p.refreshAfterAuthFailure(req.Context(), s.gen) {
		return resp, err
	}
	retry := req
	if req.Body != nil && req.Body != http.NoBody {
		if req.GetBody == nil {
			return resp, err
		}
		body, berr := req.GetBody()
		if berr != nil {
			return resp, err
		}
		retry = req.Clone(req.Context())
		retry.Body = body
	}
	return t.base.RoundTrip(retry)
}

// IsProxyAuthError reports whether err is a proxy's rejection of the
// credentials: a 407 answer to CONNECT, or the malformed status line some
// sandbox egress proxies send in its place.
func IsProxyAuthError(err error) bool {
	if err == nil {
		return false
	}
	var ce *netproxy.ConnectError
	if errors.As(err, &ce) {
		return ce.StatusCode == http.StatusProxyAuthRequired
	}
	if errors.Is(err, ErrProxyAuth) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "Proxy Authentication Required") ||
		strings.Contains(msg, "malformed HTTP status code")
}

// runProxyCommand runs command with the platform shell and returns the
// first line of its stdout, validated as an http(s) proxy URL. Neither the
// output nor stderr is ever included in errors or logs.
func runProxyCommand(ctx context.Context, command string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	// #nosec G204 -- the operator's own -proxy-cmd / PILOT_PROXY_CMD /
	// config.json proxy_cmd, run with the daemon's own privileges.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command) // #nosec G204
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", "-c", command) // #nosec G204
	}
	cmd.Env = commandEnv(os.Environ())
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("proxy command timed out after %s", commandTimeout)
		}
		return "", fmt.Errorf("proxy command failed: %v", err)
	}
	line := strings.TrimSpace(out.String())
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return "", errors.New("proxy command printed nothing")
	}
	s, err := Normalize(line)
	if err != nil {
		return "", fmt.Errorf("proxy command output: %v", err)
	}
	if s == Auto || s == Off {
		return "", errors.New("proxy command output: want an http:// or https:// proxy URL")
	}
	return s, nil
}

// commandEnv is the proxy command's environment: this process's, minus the
// daemon secrets the command has no business seeing.
func commandEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "PILOT_ADMIN_TOKEN", "PILOT_WEBHOOK_SECRET":
			continue
		}
		out = append(out, kv)
	}
	return out
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := commandOutputLimit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func noProxyFromEnv() string {
	for _, k := range []string{"NO_PROXY", "no_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// noProxyMatcher returns a NO_PROXY matcher (net/http semantics: host
// names match themselves and their subdomains, ".x" and "*.x" subdomains
// only, IPs, CIDRs, optional ":port", "*" everything), nil for an empty
// list.
func noProxyMatcher(list string) func(scheme, hostport string) bool {
	if strings.TrimSpace(list) == "" {
		return nil
	}
	entries := strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' })
	for i, e := range entries {
		if strings.HasPrefix(e, "*.") {
			entries[i] = e[1:]
		}
	}
	const sentinel = "http://proxy.invalid"
	pf := (&httpproxy.Config{HTTPProxy: sentinel, HTTPSProxy: sentinel, NoProxy: strings.Join(entries, ",")}).ProxyFunc()
	return func(scheme, hostport string) bool {
		if scheme != "http" {
			scheme = "https"
		}
		u, err := pf(&url.URL{Scheme: scheme, Host: hostport})
		return err == nil && u == nil
	}
}
