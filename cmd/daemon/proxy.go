// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"net/http"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// resolveProxyPolicy resolves -proxy for the transport (see
// daemon.ResolveProxy). A malformed -proxy value is an error. Under "auto"
// only an unusable HTTPS_PROXY / https_proxy (the variable that names the
// TLS proxy) can fail; that costs the proxy, not the daemon: it is logged
// and the daemon dials directly, as it did before -proxy existed. Unusable
// HTTP_PROXY / ALL_PROXY values are skipped by netproxy and only logged.
func resolveProxyPolicy(spec, transport string) (*netproxy.Resolver, error) {
	policy, err := daemon.ResolveProxy(spec, transport)
	if err != nil {
		if !isAutoProxy(spec) {
			return nil, err
		}
		slog.Warn("proxy environment is malformed; dialing directly", "err", err)
		return nil, nil
	}
	for _, w := range policy.Warnings() {
		slog.Warn("ignoring unusable proxy environment variable", "err", w)
	}
	return policy, nil
}

// describeProxy renders the resolved policy for the startup log line.
// Credentials are always redacted.
func describeProxy(spec, transport string, policy *netproxy.Resolver) string {
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
// sidecar) always go direct. nil leaves DefaultTransport alone (net/http's
// own proxy environment handling). Call before any goroutine issues a
// request.
func installDefaultTransportProxy(policy *netproxy.Resolver) {
	if policy == nil {
		return
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		slog.Warn("http.DefaultTransport is not an *http.Transport; plugin HTTP clients do not follow -proxy")
		return
	}
	tr.Proxy = proxyconf.RequestProxy(policy)
}

func isAutoProxy(spec string) bool {
	s, err := proxyconf.Normalize(spec)
	return err == nil && s == proxyconf.Auto
}
