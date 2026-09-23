// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// Compiled-in production endpoints. -registry and -beacon default to these
// raw TCP / UDP addresses (pilotctl passes the same values explicitly);
// compat mode swaps the registry for its TLS host name on :443.
const (
	defaultRegistryAddr = "34.71.57.205:9000"
	defaultBeaconAddr   = "34.71.57.205:9001"
	compatRegistryAddr  = "registry.pilotprotocol.network:443"
)

// transportDefault is the -transport default: $PILOT_TRANSPORT when it
// names a transport, otherwise "udp". An unknown value is ignored with a
// warning, as pkg/daemon has always treated it.
func transportDefault() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("PILOT_TRANSPORT")))
	switch v {
	case "udp", "compat":
		return v
	case "":
	default:
		slog.Warn("ignoring unknown PILOT_TRANSPORT value", "value", v, "valid", "udp, compat")
	}
	return "udp"
}

// compatKeepsRegistry reports whether a -transport=compat daemon keeps its
// configured registry instead of switching to compatRegistryAddr. Only an
// explicit choice (the -registry flag or $PILOT_REGISTRY) is kept, and the
// compiled-in raw-TCP default never counts as one: pilotctl passes it on
// every `daemon start`, and a UDP-blocked host behind a CONNECT-only egress
// proxy cannot reach it.
func compatKeepsRegistry(addr string, setByFlag, setByEnv bool) bool {
	return (setByFlag || setByEnv) && strings.TrimSpace(addr) != defaultRegistryAddr
}

// resolveProxyPolicy resolves -proxy for the transport (see
// daemon.ResolveProxy). A malformed explicit proxy URL is an error; a
// malformed proxy environment under "auto" only costs the proxy: it is
// logged and the daemon dials directly, as it did before -proxy existed.
func resolveProxyPolicy(spec, transport string) (*netproxy.Resolver, error) {
	policy, err := daemon.ResolveProxy(spec, transport)
	if err != nil {
		if !isAutoProxy(spec) {
			return nil, err
		}
		slog.Warn("proxy environment is malformed; dialing directly", "err", err)
		return nil, nil
	}
	return policy, nil
}

// describeProxy renders the resolved policy for the startup log line.
// Credentials are always redacted.
func describeProxy(spec, transport string, policy *netproxy.Resolver) string {
	if policy != nil {
		return policy.String()
	}
	if isAutoProxy(spec) && transport != "compat" {
		return "none (-proxy=auto applies to -transport=compat only)"
	}
	return "none"
}

// installDefaultTransportProxy makes net/http's shared DefaultTransport
// follow the policy. Every HTTP client the daemon wires in without a
// transport of its own — catalogue pins, skillinject, trustedagents,
// webhook, enterprise-control clients — uses DefaultTransport, and not all
// of them accept an injected client. nil leaves DefaultTransport alone
// (net/http's own proxy environment handling). Call before any goroutine
// issues a request.
func installDefaultTransportProxy(policy *netproxy.Resolver) {
	if policy == nil {
		return
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		slog.Warn("http.DefaultTransport is not an *http.Transport; plugin HTTP clients do not follow -proxy")
		return
	}
	tr.Proxy = policy.ProxyForRequest
}

func isAutoProxy(spec string) bool {
	s := strings.TrimSpace(spec)
	return s == "" || strings.EqualFold(s, netproxy.ModeAuto)
}
