// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	registry "github.com/pilot-protocol/common/registry/client"
)

// ResolveProxy turns a -proxy setting into the daemon's outbound proxy
// policy (Config.Proxy) for the given transport mode:
//
//   - "auto" or "": with transportMode "compat", the proxy from the
//     environment — HTTPS_PROXY / https_proxy, falling back to ALL_PROXY /
//     all_proxy, with NO_PROXY / no_proxy honoured. With any other transport
//     it returns nil: no policy, the daemon dials exactly as it always has.
//   - "off": a policy that never proxies. Unlike nil, it also stops the
//     daemon's HTTP fetches from following proxy environment variables.
//   - "http://[user:pass@]host:port" or "https://...": that proxy for every
//     outbound TCP/HTTP connection, whatever the transport.
//
// Errors never echo proxy credentials.
func ResolveProxy(spec, transportMode string) (*netproxy.Resolver, error) {
	s := strings.TrimSpace(spec)
	if (s == "" || strings.EqualFold(s, netproxy.ModeAuto)) && transportMode != "compat" {
		return nil, nil
	}
	return netproxy.Parse(s)
}

// registryDialOptions routes every registry connection — the primary, each
// pool member and every reconnect — through the proxy policy. With no policy,
// or one that proxies nothing, the client keeps its direct dial.
func (d *Daemon) registryDialOptions() []registry.DialOption {
	if !d.config.Proxy.Enabled() {
		return nil
	}
	return []registry.DialOption{registry.WithDialer(netproxy.NewDialer(d.config.Proxy).DialContext)}
}

// httpProxyFunc returns the http.Transport.Proxy function for connections
// the daemon makes over HTTP(S) or WSS, or nil when there is no policy.
func (d *Daemon) httpProxyFunc() func(*http.Request) (*url.URL, error) {
	if d.config.Proxy == nil {
		return nil
	}
	return d.config.Proxy.ProxyForRequest
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
