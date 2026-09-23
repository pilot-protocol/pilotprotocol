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
// reads the environment now, Off never proxies, a URL proxies everything.
// It applies no transport policy.
func Resolve(spec string) (*netproxy.Resolver, error) {
	s, err := Normalize(spec)
	if err != nil {
		return nil, err
	}
	switch s {
	case Auto:
		return netproxy.FromEnvironment()
	case Off:
		return netproxy.Off(), nil
	}
	return netproxy.Explicit(s)
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

// RequestProxy returns an http.Transport.Proxy function that follows r but
// never proxies loopback targets. nil for a nil resolver (net/http's own
// environment handling then applies wherever the caller leaves Proxy
// unset).
func RequestProxy(r *netproxy.Resolver) func(*http.Request) (*url.URL, error) {
	if r == nil {
		return nil
	}
	return func(req *http.Request) (*url.URL, error) {
		if req != nil && req.URL != nil && IsLoopbackHost(req.URL.Hostname()) {
			return nil, nil
		}
		return r.ProxyForRequest(req)
	}
}

// DialContext returns a dial function that tunnels through the proxy r
// picks for each target (CONNECT by host name, never resolved locally) and
// dials loopback targets, and targets r does not proxy, directly.
// proxyTLS configures the TLS session with an https:// proxy — never the
// target's TLS, which the caller runs end to end over the returned conn;
// nil verifies the proxy against the system roots.
func DialContext(r *netproxy.Resolver, proxyTLS *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &netproxy.Dialer{Resolver: r, TLSConfig: proxyTLS}
	var direct net.Dialer
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err == nil && IsLoopbackHost(host) {
			return direct.DialContext(ctx, network, addr)
		}
		return d.DialContext(ctx, network, addr)
	}
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
