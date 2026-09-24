// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// ResolveProxy turns a -proxy setting into the daemon's outbound proxy
// resolver (Config.Proxy) for the given transport mode:
//
//   - "auto" or "": with transportMode "compat", the proxy from the
//     environment — HTTPS_PROXY / https_proxy, falling back to ALL_PROXY /
//     all_proxy, with NO_PROXY / no_proxy honoured. With any other transport
//     it returns nil: no proxy, the daemon dials exactly as it always has.
//   - "off" (or "none", "no", "false", "direct"): a resolver that never
//     proxies. Unlike nil, it also stops the daemon's HTTP fetches from
//     following proxy environment variables.
//   - "http://[user:pass@]host:port" or "https://...": that proxy for every
//     outbound TCP/HTTP connection, whatever the transport.
//
// opts are passed to netproxy.NewResolver. For an egress proxy that
// rotates its credentials, pass a refresh source — netproxy.WithRefreshCommand,
// or netproxy.WithRefreshFunc over proxyconf.CommandSource as pilot-daemon
// does for -proxy-cmd: its output then supplies the proxy URL — the
// explicit one, or under auto the environment's (NO_PROXY still honoured)
// — re-read every netproxy.DefaultRefreshInterval and whenever the proxy
// rejects the credentials (407, or a CONNECT answer that cannot be
// parsed), after which the rejected connection is retried once. With a
// refresh source, ResolveProxy runs it once before returning; a failing
// run leaves the launch-time proxy in use (the error goes to
// netproxy.WithRefreshErrorHandler).
//
// Any other value (a bare word, a host:port without a scheme, another
// scheme) is an error. Loopback targets are never proxied, whatever the
// resolver says. Errors never echo proxy credentials.
func ResolveProxy(spec, transportMode string, opts ...netproxy.Option) (*netproxy.Resolver, error) {
	s, err := proxyconf.Normalize(spec)
	if err != nil {
		return nil, err
	}
	if s == proxyconf.Auto && transportMode != TransportCompat {
		return nil, nil
	}
	return proxyconf.Resolve(s, opts...)
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
// no proxy resolver or it proxies nothing. Loopback targets are dialed
// directly. It reads the resolver's current settings on every dial, and a
// 407 refreshes them and retries the dial once (netproxy.Dialer).
func (d *Daemon) proxyDialer() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialerFor(d.config.Proxy)
}

// dialerFor is proxyDialer for an arbitrary resolver.
func (d *Daemon) dialerFor(r *netproxy.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !r.Enabled() {
		return nil
	}
	return proxyconf.DialContext(r, d.proxyTLSConfig())
}

// registryDialOptions routes every registry connection — the primary, each
// pool member and every reconnect — through the proxy resolver. With none,
// or one that proxies nothing, the client keeps its direct dial.
func (d *Daemon) registryDialOptions() []registry.DialOption {
	dial := d.proxyDialer()
	if dial == nil {
		return nil
	}
	return []registry.DialOption{registry.WithDialer(dial)}
}

// newHTTPClient returns a client for daemon-owned HTTP fetches. Without a
// proxy resolver it is a plain client on http.DefaultTransport, as before;
// with one, its transport is a netproxy.RefreshingTransport: every new
// connection carries the resolver's current credentials, and a request
// whose CONNECT got 407 is retried once after the refresh. Loopback
// targets always go direct.
func (d *Daemon) newHTTPClient(timeout time.Duration) *http.Client {
	client := &http.Client{Timeout: timeout}
	if d.config.Proxy != nil {
		var base *http.Transport
		if d.config.systemRoots != nil { // test seam only
			if dt, ok := http.DefaultTransport.(*http.Transport); ok {
				base = dt.Clone()
				base.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: d.config.systemRoots}
			}
		}
		client.Transport = proxyconf.RoundTripper(d.config.Proxy, base)
	}
	return client
}
