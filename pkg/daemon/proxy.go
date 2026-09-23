// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// ProxyPolicy is an outbound proxy policy that can change while the daemon
// runs: a fixed resolver (StaticProxyPolicy) or one refreshed from a
// command (NewCommandProxyPolicy) for egress proxies that rotate their
// credentials. Config.ProxyPolicy takes precedence over Config.Proxy.
type ProxyPolicy = proxyconf.Policy

// StaticProxyPolicy wraps a fixed resolver. nil gives nil (no policy).
func StaticProxyPolicy(r *netproxy.Resolver) *ProxyPolicy { return proxyconf.Static(r) }

// NewCommandProxyPolicy returns a policy whose proxy URL is the stdout of
// command (run with /bin/sh -c), re-run every refresh interval and when the
// proxy answers 407 (see proxyconf.NewCommand). fallback serves until the
// command first succeeds; the error reports a failed first run and is not
// fatal: the policy is usable either way. honorNoProxy applies the
// environment's NO_PROXY (the -proxy=auto semantics).
func NewCommandProxyPolicy(ctx context.Context, command string, fallback *netproxy.Resolver, honorNoProxy bool) (*ProxyPolicy, error) {
	return proxyconf.NewCommand(ctx, command, fallback, honorNoProxy)
}

// ResolveProxy turns a -proxy setting into the daemon's outbound proxy
// resolver (Config.Proxy) for the given transport mode:
//
//   - "auto" or "": with transportMode "compat", the proxy from the
//     environment — HTTPS_PROXY / https_proxy, falling back to ALL_PROXY /
//     all_proxy, with NO_PROXY / no_proxy honoured. With any other transport
//     it returns nil: no policy, the daemon dials exactly as it always has.
//   - "off" (or "none", "no", "false", "direct"): a policy that never
//     proxies. Unlike nil, it also stops the daemon's HTTP fetches from
//     following proxy environment variables.
//   - "http://[user:pass@]host:port" or "https://...": that proxy for every
//     outbound TCP/HTTP connection, whatever the transport.
//
// Any other value (a bare word, a host:port without a scheme, another
// scheme) is an error. Loopback targets are never proxied, whatever the
// policy. Errors never echo proxy credentials.
func ResolveProxy(spec, transportMode string) (*netproxy.Resolver, error) {
	s, err := proxyconf.Normalize(spec)
	if err != nil {
		return nil, err
	}
	if s == proxyconf.Auto && transportMode != "compat" {
		return nil, nil
	}
	return proxyconf.Resolve(s)
}

// proxyAutoSpec is the -proxy default: the environment's proxy, in compat
// mode only.
const proxyAutoSpec = proxyconf.Auto

// proxyTLSConfig is the TLS configuration for the session with an https://
// proxy itself. The proxy is verified against the system roots (or the
// test seam), never against the pinned roots the beacon or registry trust
// settings select: those pin Pilot's servers, not the operator's proxy.
func (d *Daemon) proxyTLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.config.systemRoots}
}

// proxyPolicy is the daemon's outbound proxy policy: Config.ProxyPolicy,
// else Config.Proxy, else nil (no policy).
func (d *Daemon) proxyPolicy() *ProxyPolicy {
	if d.config.ProxyPolicy != nil {
		return d.config.ProxyPolicy
	}
	return proxyconf.Static(d.config.Proxy)
}

// proxyDialer returns the dial function for raw TCP connections the daemon
// opens itself (the registry, the compat WSS beacon), or nil when there is
// no policy or it proxies nothing. Loopback targets are dialed directly.
func (d *Daemon) proxyDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialerFor(d.proxyPolicy())
}

// dialerFor is proxyDialer for an arbitrary policy.
func (d *Daemon) dialerFor(policy *ProxyPolicy) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !policy.Enabled() {
		return nil
	}
	return policy.DialContext(d.proxyTLSConfig())
}

// registryDialOptions routes every registry connection — the primary, each
// pool member and every reconnect — through the proxy policy. With no policy,
// or one that proxies nothing, the client keeps its direct dial.
func (d *Daemon) registryDialOptions() []registry.DialOption {
	dial := d.proxyDialer()
	if dial == nil {
		return nil
	}
	return []registry.DialOption{registry.WithDialer(dial)}
}

// httpProxyFunc returns the http.Transport.Proxy function for HTTP fetches
// the daemon makes itself, or nil when there is no policy. Loopback targets
// always go direct.
func (d *Daemon) httpProxyFunc() func(*http.Request) (*url.URL, error) {
	return d.proxyPolicy().RequestProxy()
}

// newHTTPClient returns a client for daemon-owned HTTP fetches. Without a
// proxy policy it is a plain client on http.DefaultTransport, as before;
// with one, its transport routes through the policy (and, for a refreshed
// policy, retries a request whose CONNECT got 407 once with the new
// credentials).
func (d *Daemon) newHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{Timeout: timeout}
	if policy := d.proxyPolicy(); policy != nil {
		var tr *http.Transport
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			tr = base.Clone()
		} else {
			tr = &http.Transport{}
		}
		policy.ConfigureTransport(tr)
		client.Transport = policy.RoundTripper(tr)
	}
	return client
}

// startProxyRefresh keeps a command-backed proxy policy current for the
// daemon's lifetime (no-op otherwise).
func (d *Daemon) startProxyRefresh() {
	if p := d.proxyPolicy(); p.Refreshable() {
		go p.Run(d.ctx, d.config.ProxyRefreshInterval)
	}
}
