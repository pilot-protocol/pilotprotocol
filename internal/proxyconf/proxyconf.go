// SPDX-License-Identifier: AGPL-3.0-or-later

// Package proxyconf holds the -proxy rules that pilot-daemon and pilotctl
// share on top of github.com/pilot-protocol/common/netproxy: which
// spellings a proxy setting accepts, how it is shown without credentials,
// and the loopback exemption every outbound path applies.
//
// A proxy setting is one of:
//
//   - "auto" (or empty): the proxy from the environment (HTTPS_PROXY,
//     https_proxy, ALL_PROXY, all_proxy, honouring NO_PROXY). Whether auto
//     applies at all for a given transport is the caller's policy.
//   - "off", or one of its aliases "none", "no", "false", "direct": never
//     use a proxy.
//   - an explicit "http://[user:pass@]host[:port]" or "https://..." URL.
//
// Anything else — a bare word such as "proxy", a host:port without a
// scheme, or another scheme — is rejected, so a typo can never turn into a
// proxy host name. Errors and display strings never contain credentials.
//
// Rotating credentials are mostly netproxy's business: a Resolver with a
// refresh source (the -proxy-cmd / $PILOT_PROXY_CMD / config.json proxy_cmd
// setting; see CommandSource) re-reads the proxy URL every
// netproxy.DefaultRefreshInterval and whenever a proxy rejects the
// credentials, and netproxy's Dialer and RefreshingTransport retry that
// connection once with the new ones. This package adds the loopback rule on
// top, and the Relay: a loopback CONNECT proxy that gives the processes the
// daemon starts, which cannot re-read anything, the same refreshed
// credentials.
package proxyconf

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/pilot-protocol/common/netproxy"
)

// The normalized setting values.
const (
	Auto = netproxy.ModeAuto
	Off  = netproxy.ModeOff
)

// EnvRefreshCommand is the environment variable holding the proxy refresh
// command (netproxy.EnvRefreshCommand, "PILOT_PROXY_CMD").
const EnvRefreshCommand = netproxy.EnvRefreshCommand

// offAliases are accepted, case-insensitively, as "off". "none" is what the
// daemon's startup log prints when nothing is proxied, so operators copy it.
var offAliases = map[string]bool{
	"off": true, "none": true, "no": true, "false": true, "direct": true,
}

// Normalize maps a proxy setting to Auto, Off, or the trimmed explicit
// proxy URL, which it validates. The error never includes credentials.
func Normalize(spec string) (string, error) {
	s := strings.TrimSpace(spec)
	lower := strings.ToLower(s)
	switch {
	case lower == "" || lower == Auto:
		return Auto, nil
	case offAliases[lower]:
		return Off, nil
	}
	scheme, _, ok := strings.Cut(s, "://")
	if !ok {
		return "", fmt.Errorf("invalid proxy %q: use auto, off, or an http:// or https:// proxy URL", Redact(s))
	}
	switch strings.ToLower(scheme) {
	case "http", "https":
	default:
		return "", fmt.Errorf("invalid proxy %q: the scheme must be http or https", Redact(s))
	}
	if _, err := netproxy.Explicit(s); err != nil {
		return "", fmt.Errorf("invalid proxy %q: %v", Redact(s), unwrapNetproxy(err))
	}
	return s, nil
}

// Resolve builds the resolver for a proxy setting (see Normalize): Auto
// reads the environment, Off never proxies, a URL proxies everything. It
// applies no transport policy. opts are netproxy's (for example
// netproxy.WithRefreshCommand for rotating credentials); they do not apply
// to Off. With a refresh command, Resolve runs it once before returning.
func Resolve(spec string, opts ...netproxy.Option) (*netproxy.Resolver, error) {
	s, err := Normalize(spec)
	if err != nil {
		return nil, err
	}
	return netproxy.NewResolver(s, opts...)
}

// HasCredentials reports whether an explicit proxy setting carries userinfo.
// netproxy takes everything before the last '@' as credentials, so any '@'
// counts — including in a value url.Parse would misread (an unescaped '/',
// '?' or '#' in the password).
func HasCredentials(spec string) bool {
	return strings.Contains(spec, "@")
}

// Redact renders a proxy setting for display: "auto", "off" and URLs
// without credentials unchanged (URLs reduced to scheme://host:port),
// userinfo replaced by "***". Values that do not parse keep only what
// follows the last '@'.
func Redact(spec string) string {
	s := strings.TrimSpace(spec)
	lower := strings.ToLower(s)
	if lower == "" || lower == Auto || offAliases[lower] {
		return s
	}
	if strings.Contains(s, "://") {
		if r, err := netproxy.Explicit(s); err == nil {
			return r.String()
		}
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		prefix := ""
		if j := strings.Index(s, "://"); j >= 0 && j < i {
			prefix = s[:j+3]
		}
		return prefix + "***@" + s[i+1:]
	}
	return s
}

// IsLoopbackHost reports whether host (a name or IP literal, optionally in
// brackets) is this machine: localhost, *.localhost or a loopback address.
// Such targets are never sent to a proxy, even an explicit one — the proxy
// would reach its own loopback, and the request would leave the host.
func IsLoopbackHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// loopbackAddr reports whether addr ("host:port") is on this machine.
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && IsLoopbackHost(host)
}

// ProxyFor returns the proxy (redacted, for logs and hints) a TCP dial of
// addr goes through, "" for a direct dial: loopback targets always, and
// targets r does not proxy (nil r, Off, NO_PROXY under auto). It reads r's
// current settings and never waits for a refresh.
func ProxyFor(r *netproxy.Resolver, addr string) string {
	if !r.Enabled() || loopbackAddr(addr) {
		return ""
	}
	u, err := r.ProxyForAddr(addr)
	if err != nil || u == nil {
		return ""
	}
	return netproxy.Redact(u)
}

// Proxies reports whether a TCP dial of addr goes through a proxy (see
// ProxyFor).
func Proxies(r *netproxy.Resolver, addr string) bool {
	return ProxyFor(r, addr) != ""
}

// RequestProxy returns an http.Transport.Proxy function that follows r
// (its current, refreshed settings) but never proxies loopback targets.
// nil for a nil resolver (net/http's own environment handling then applies
// wherever the caller leaves Proxy unset).
func RequestProxy(r *netproxy.Resolver) func(*http.Request) (*url.URL, error) {
	if r == nil {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		if req == nil || req.URL == nil || IsLoopbackHost(req.URL.Hostname()) {
			return nil, nil
		}
		return r.ProxyForRequest(req)
	}
}

// DialContext returns a dial function that tunnels through the proxy r
// picks for each target (CONNECT by host name, never resolved locally) and
// dials loopback targets, and targets r does not proxy, directly. It is a
// netproxy.Dialer: when the proxy rejects the credentials (407), r
// refreshes (re-running its refresh command, if any) and the dial is
// retried once when that produced different credentials. proxyTLS
// configures the TLS session with an https:// proxy — never the target's
// TLS, which the caller runs end to end over the returned conn; nil
// verifies the proxy against the system roots.
func DialContext(r *netproxy.Resolver, proxyTLS *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &netproxy.Dialer{Resolver: r, TLSConfig: proxyTLS}
	var direct net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if loopbackAddr(addr) {
			return direct.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
}

// RoundTripper returns the transport for an HTTP client that follows r: a
// netproxy.RefreshingTransport over a copy of base (http.DefaultTransport's
// settings when nil), so new connections always carry r's current
// credentials and a request whose CONNECT got 407 is retried once after
// the refresh, plus the loopback rule: requests to this machine use a
// direct copy of base. base's own Proxy and OnProxyConnectResponse are
// replaced. A nil r returns base (nil: http.DefaultTransport).
func RoundTripper(r *netproxy.Resolver, base *http.Transport) http.RoundTripper {
	if r == nil {
		if base == nil {
			return http.DefaultTransport
		}
		return base
	}
	if base == nil {
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			base = dt
		} else {
			base = &http.Transport{}
		}
	}
	// Drop what ConfigureTransport may have installed on base (the daemon
	// configures http.DefaultTransport in place): RefreshingTransport sets
	// its own Proxy, and a CONNECT hook that already turns a 407 into an
	// error would hide the rejection from RefreshingTransport's retry.
	base = base.Clone()
	base.Proxy = nil
	base.OnProxyConnectResponse = nil
	direct := base.Clone()
	return &loopbackSplit{direct: direct, proxied: netproxy.RefreshingTransport(base, r)}
}

// loopbackSplit sends loopback requests direct and everything else through
// the refreshing proxy transport.
type loopbackSplit struct {
	direct  *http.Transport
	proxied http.RoundTripper
}

func (t *loopbackSplit) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL != nil && IsLoopbackHost(req.URL.Hostname()) {
		return t.direct.RoundTrip(req)
	}
	return t.proxied.RoundTrip(req)
}

// CloseIdleConnections closes both transports' idle connections.
func (t *loopbackSplit) CloseIdleConnections() {
	t.direct.CloseIdleConnections()
	if c, ok := t.proxied.(interface{ CloseIdleConnections() }); ok {
		c.CloseIdleConnections()
	}
}

// ConfigureTransport routes tr (in place) through r, for transports that
// cannot be wrapped — http.DefaultTransport, which plugin HTTP clients use
// or clone. tr.Proxy follows r's current settings, loopback always direct.
//
// relay, when set, is the URL of a Relay for r (Relay.URL): requests that
// net/http tunnels with CONNECT (https://, wss://) then go to the proxy
// through it, and the Relay's netproxy.Dialer handles a rejection of the
// credentials — a 407, or a CONNECT answer so garbled it cannot be parsed
// (Meta Muse's form) — by refreshing r and retrying the tunnel once, so the
// request succeeds, and no proxy-supplied text reaches an error. Plain
// http:// requests, which a proxy forwards rather than tunnels, keep going
// to the proxy r names. The daemon passes its Relay whenever it proxies.
//
// Without a relay, a 407 answer to a CONNECT refreshes r before the
// request fails, so the next request carries the new credentials, and the
// refusal fails with a *netproxy.ConnectError, whose message never quotes
// the proxy's reason phrase. An answer net/http cannot parse fails with
// net/http's own error (which quotes the offending status text) and
// refreshes nothing: net/http never passes it to this hook. (Wrapped
// clients, see RoundTripper, handle both forms and also retry the failed
// request.) A nil r leaves tr alone.
func ConfigureTransport(tr *http.Transport, r *netproxy.Resolver, relay *url.URL) {
	if tr == nil || r == nil {
		return
	}
	direct := RequestProxy(r)
	relayHost := ""
	if relay == nil {
		tr.Proxy = direct
	} else {
		via := *relay
		relayHost = via.Host
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			u, err := direct(req)
			if err != nil || u == nil || !tunnelled(req) {
				return u, err
			}
			v := via
			return &v, nil
		}
	}
	next := tr.OnProxyConnectResponse
	tr.OnProxyConnectResponse = func(ctx context.Context, proxyURL *url.URL, connectReq *http.Request, res *http.Response) error {
		if next != nil {
			if err := next(ctx, proxyURL, connectReq, res); err != nil {
				return err
			}
		}
		if res.StatusCode == http.StatusOK {
			return nil
		}
		ce := &netproxy.ConnectError{Target: connectReq.Host, StatusCode: res.StatusCode}
		if relayHost != "" && proxyURL != nil && proxyURL.Host == relayHost {
			// The relay's own answer: its reason phrase carries why the
			// tunnel upstream failed, in netproxy's words.
			if detail := relayDetail(res.Status); detail != "" {
				return &relayRefusal{ConnectError: ce, detail: detail}
			}
			return ce
		}
		if res.StatusCode == http.StatusProxyAuthRequired {
			_ = r.Refresh(ctx) // failures keep the last good settings; netproxy reports them
		}
		return ce
	}
}

// relayRefusal is a Relay's refusal of a CONNECT as ConfigureTransport
// reports it: the netproxy error the Relay met upstream (detail, which
// never holds credentials or proxy-supplied text), and the Relay's own
// status as the ConnectError it unwraps to.
type relayRefusal struct {
	*netproxy.ConnectError
	detail string
}

func (e *relayRefusal) Error() string { return e.detail }

func (e *relayRefusal) Unwrap() error { return e.ConnectError }

// relayDetail extracts the reason writeRelayStatus put in a Relay's status
// line ("502 Bad Gateway (pilot-daemon proxy relay: <detail>)"), "" when
// there is none. It is passed through reasonText again: the status line
// came over a socket.
func relayDetail(status string) string {
	const marker = " (" + relayReasonPrefix
	i := strings.Index(status, marker)
	if i < 0 || !strings.HasSuffix(status, ")") {
		return ""
	}
	return reasonText(status[i+len(marker) : len(status)-1])
}

// tunnelled reports whether net/http reaches req's target through a
// CONNECT tunnel when it uses a proxy.
func tunnelled(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	switch strings.ToLower(req.URL.Scheme) {
	case "https", "wss":
		return true
	}
	return false
}

// AuthRejected reports whether err is a proxy's refusal of the credentials
// (407 Proxy Authentication Required on CONNECT).
func AuthRejected(err error) bool {
	var ce *netproxy.ConnectError
	return errors.As(err, &ce) && ce.StatusCode == http.StatusProxyAuthRequired
}

// UnreadableConnectReply reports whether err is netproxy's report of a
// CONNECT answer it could not parse. Some egress proxies (Meta Muse's)
// answer wrong or expired credentials this way; HTTP clients show it as
// "malformed HTTP status code". netproxy's Dialer and RefreshingTransport
// treat it as a rejection of the credentials (refresh, retry once); its
// error type is unexported, so this matches the fixed wording netproxy
// gives it ("read CONNECT response: <fault> (response text withheld)").
func UnreadableConnectReply(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "read CONNECT response: ") && strings.Contains(msg, "(response text withheld)")
}

// rotatingProxyHint ends CredentialHint. It covers both a daemon
// without a proxy command and one whose command is already set (and then
// printed the credentials the proxy refused), so it never sends an
// operator who set -proxy-cmd off to set it again.
const rotatingProxyHint = "if the proxy rotates its credentials, the daemon needs -proxy-cmd ($PILOT_PROXY_CMD, config.json proxy_cmd), a command that prints the current proxy URL; when one is set, check what it prints from a fresh shell"

// CredentialHint explains a proxy's rejection of the credentials — a 407,
// or an answer that could not be parsed — for a log line or error; "" for
// any other error.
func CredentialHint(err error) string {
	switch {
	case AuthRejected(err):
		return "the proxy rejected its credentials (407), also after re-reading them: check HTTPS_PROXY / -proxy; " + rotatingProxyHint
	case UnreadableConnectReply(err):
		return "the proxy's answer to CONNECT could not be parsed, which is how some egress proxies (Meta Muse's) reject wrong or expired credentials: check the credentials in HTTPS_PROXY / -proxy; " + rotatingProxyHint
	}
	return ""
}

// unwrapNetproxy drops netproxy's "netproxy: " prefix for messages that
// already say which setting failed.
func unwrapNetproxy(err error) string {
	msg := err.Error()
	var ee *netproxy.EnvError
	if errors.As(err, &ee) {
		msg = ee.Err.Error()
	}
	return strings.TrimPrefix(msg, "netproxy: ")
}
