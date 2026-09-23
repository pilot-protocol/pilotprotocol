// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// newCommandPolicy is daemon.NewCommandProxyPolicy (a test seam).
var newCommandPolicy = daemon.NewCommandProxyPolicy

// resolveProxyPolicy resolves -proxy and -proxy-cmd for the transport (see
// daemon.ResolveProxy). A malformed -proxy value is an error. Under "auto"
// only an unusable HTTPS_PROXY / https_proxy (the variable that names the
// TLS proxy) can fail; that costs the proxy, not the daemon: it is logged
// and the daemon dials directly, as it did before -proxy existed. Unusable
// HTTP_PROXY / ALL_PROXY values are skipped by netproxy and only logged.
//
// -proxy-cmd (a command whose stdout is the current proxy URL) makes the
// policy refresh itself, for egress proxies that rotate credentials: it
// supplies the URL wherever -proxy would use one — the explicit URL, or
// with auto (compat only) the environment's proxy, NO_PROXY still
// honored. It is ignored with -proxy=off, and with auto on udp (no proxy).
// A failing first run is logged and the launch environment's proxy (or the
// explicit URL) serves until the command succeeds.
func resolveProxyPolicy(spec, command, transport string) (*proxyconf.Policy, error) {
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
	if command == "" {
		r, err := daemon.ResolveProxy(s, transport)
		if err != nil {
			if s != proxyconf.Auto {
				return nil, err
			}
			slog.Warn("proxy environment is malformed; dialing directly", "err", err)
			return nil, nil
		}
		logProxyWarnings(r)
		return proxyconf.Static(r), nil
	}
	var fallback *netproxy.Resolver
	if s == proxyconf.Auto {
		if fallback, err = netproxy.FromEnvironment(); err != nil {
			slog.Warn("proxy environment is malformed; waiting for -proxy-cmd", "err", err)
			fallback = nil
		}
		logProxyWarnings(fallback)
	} else if fallback, err = netproxy.Explicit(s); err != nil {
		return nil, err
	}
	policy, err := newCommandPolicy(context.Background(), command, fallback, s == proxyconf.Auto)
	if err != nil {
		slog.Warn("-proxy-cmd failed; using the launch-time proxy until it succeeds", "err", err)
	}
	return policy, nil
}

func logProxyWarnings(r *netproxy.Resolver) {
	for _, w := range r.Warnings() {
		slog.Warn("ignoring unusable proxy environment variable", "err", w)
	}
}

// describeProxy renders the resolved policy for the startup log line.
// Credentials are always redacted.
func describeProxy(spec, transport string, policy *proxyconf.Policy) string {
	if policy != nil {
		return policy.String()
	}
	if isAutoProxy(spec) && transport != daemon.TransportCompat {
		return "none (-proxy=auto applies to -transport=compat only)"
	}
	return "none"
}

// installDefaultTransportProxy makes net/http's shared DefaultTransport
// follow the policy. Every HTTP client the daemon wires in without a
// transport of its own — catalogue pins, skillinject, trustedagents,
// webhook, enterprise-control clients — uses DefaultTransport, and not all
// of them accept an injected client. Loopback targets (a local webhook or
// sidecar) always go direct. With a refreshed policy (-proxy-cmd), a 407
// answer refreshes the credentials at once, so the next request succeeds.
// nil leaves DefaultTransport alone (net/http's own proxy environment
// handling). Call before any goroutine issues a request.
func installDefaultTransportProxy(policy *proxyconf.Policy) {
	if policy == nil {
		return
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		slog.Warn("http.DefaultTransport is not an *http.Transport; plugin HTTP clients do not follow -proxy")
		return
	}
	policy.ConfigureTransport(tr)
}

func isAutoProxy(spec string) bool {
	s, err := proxyconf.Normalize(spec)
	return err == nil && s == proxyconf.Auto
}
