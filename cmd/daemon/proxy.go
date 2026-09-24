// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// resolveProxy resolves -proxy and -proxy-cmd for the transport (see
// daemon.ResolveProxy). A malformed -proxy value is an error. Under "auto"
// only an unusable HTTPS_PROXY / https_proxy (the variable that names the
// TLS proxy) can fail; that costs the proxy, not the daemon: it is logged
// and the daemon dials directly, as it did before -proxy existed. Unusable
// HTTP_PROXY / ALL_PROXY values are skipped by netproxy and only logged.
//
// -proxy-cmd (a command whose output is the current proxy URL) makes the
// resolver follow rotating credentials (netproxy.WithRefreshCommand): it
// supplies the URL wherever -proxy would use one — the explicit URL, or
// with auto (compat only) the environment's proxy, NO_PROXY still
// honored — and is re-run every 60s and whenever the proxy answers 407,
// after which the rejected connection is retried once. It is ignored with
// -proxy=off, and with auto on udp (no proxy). A failing run is logged
// once per run of failures, and the last good URL (at first, the launch
// environment's proxy or the explicit URL) stays in use.
func resolveProxy(spec, command, transport string) (*netproxy.Resolver, error) {
	s, err := proxyconf.Normalize(spec)
	if err != nil {
		return nil, err
	}
	command = strings.TrimSpace(command)
	if command != "" && s == proxyconf.Off {
		slog.Warn("ignoring -proxy-cmd: -proxy=off")
		command = ""
	}
	if command != "" && s == proxyconf.Auto && transport != daemon.TransportCompat {
		slog.Info("-proxy-cmd not used: -proxy=auto proxies -transport=compat only", "transport", transport)
		command = ""
	}
	var opts []netproxy.Option
	if command != "" {
		opts = append(opts,
			netproxy.WithRefreshCommand(command),
			netproxy.WithRefreshErrorHandler(func(err error) {
				slog.Warn("-proxy-cmd failed; keeping the last good proxy URL (at first the launch-time proxy)", "err", err)
			}))
	}
	r, err := daemon.ResolveProxy(s, transport, opts...)
	if err != nil {
		if s != proxyconf.Auto {
			return nil, err
		}
		slog.Warn("proxy environment is malformed; dialing directly", "err", err)
		return nil, nil
	}
	logProxyWarnings(r)
	return r, nil
}

func logProxyWarnings(r *netproxy.Resolver) {
	for _, w := range r.Warnings() {
		slog.Warn("ignoring unusable proxy environment variable", "err", w)
	}
}

// describeProxy renders the resolved proxy for the startup log line.
// Credentials are always redacted.
func describeProxy(spec, transport string, r *netproxy.Resolver) string {
	if r != nil {
		return r.String()
	}
	if isAutoProxy(spec) && transport != daemon.TransportCompat {
		return "none (-proxy=auto applies to -transport=compat only)"
	}
	return "none"
}

// installDefaultTransportProxy makes net/http's shared DefaultTransport
// follow the proxy resolver. Every HTTP client the daemon wires in without
// a transport of its own — catalogue pins, skillinject, trustedagents,
// webhook, enterprise-control clients — uses DefaultTransport (or a clone
// of it), and not all of them accept an injected client. Each new
// connection takes the resolver's current settings, so rotated
// credentials (-proxy-cmd) reach these clients too, and a 407 answer
// refreshes them at once so the next request succeeds (see
// proxyconf.ConfigureTransport). Loopback targets (a local webhook or
// sidecar) always go direct. nil leaves DefaultTransport alone (net/http's
// own proxy environment handling). Call before any goroutine issues a
// request.
func installDefaultTransportProxy(r *netproxy.Resolver) {
	if r == nil {
		return
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		slog.Warn("http.DefaultTransport is not an *http.Transport; plugin HTTP clients do not follow -proxy")
		return
	}
	proxyconf.ConfigureTransport(tr, r)
}

func isAutoProxy(spec string) bool {
	s, err := proxyconf.Normalize(spec)
	return err == nil && s == proxyconf.Auto
}
