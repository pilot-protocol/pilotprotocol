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

// ResolveProxy turns a -proxy setting into the daemon's outbound proxy
// policy (Config.Proxy) for the given transport mode:
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

// proxyDialer returns the dial function for raw TCP connections the daemon
// opens itself (the registry, the compat WSS beacon), or nil when there is
// no policy or it proxies nothing. Loopback targets are dialed directly.
func (d *Daemon) proxyDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialerFor(d.config.Proxy)
}

// dialerFor is proxyDialer for an arbitrary policy.
func (d *Daemon) dialerFor(policy *netproxy.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !policy.Enabled() {
		return nil
	}
	return proxyconf.DialContext(policy, d.proxyTLSConfig())
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
	return proxyconf.RequestProxy(d.config.Proxy)
}

// newHTTPClient returns a client for daemon-owned HTTP fetches. Without a
// proxy policy it is a plain client on http.DefaultTransport, as before;
// with one, its transport routes through the policy.
func (d *Daemon) newHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{Timeout: timeout}
	if proxy := d.httpProxyFunc(); proxy != nil {
		var tr *http.Transport
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			tr = base.Clone()
		} else {
			tr = &http.Transport{}
		}
		tr.Proxy = proxy
		client.Transport = tr
	}
	return client
}
