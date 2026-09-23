// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pilot-protocol/common/netproxy"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// registryRoute is how pilotctl reaches the registry for its own commands
// (lookup, register, rotate-key, the auto-handshake visibility check,
// recovery, ...). It follows the same network the daemon uses, so nothing
// pilotctl does bypasses an egress proxy:
//
//   - the proxy comes from $PILOT_PROXY, else config.json "proxy", else
//     "auto" — the environment's HTTPS_PROXY / ALL_PROXY (honouring
//     NO_PROXY). pilotctl is a short-lived client whose HTTP calls already
//     follow HTTPS_PROXY, so auto applies whatever the daemon's transport;
//     set proxy=off to dial directly. Loopback registries are never
//     proxied.
//   - the compiled-in raw-TCP registry (34.71.57.205:9000) is replaced by
//     registry.pilotprotocol.network:443 over TLS when the registry would
//     be proxied (proxies allow CONNECT to :443 only) or the transport is
//     compat (UDP-blocked hosts are usually TCP-443-only too). That
//     address always uses TLS, verified against the system roots, or
//     pinned to registry_fingerprint / $PILOT_REGISTRY_FINGERPRINT when
//     one is configured (sandboxes without a CA bundle).
type registryRoute struct {
	Addr        string
	TLS         bool
	Fingerprint string // non-empty: pinned trust
	Proxy       *netproxy.Resolver
	// Switched: Addr replaced the raw-TCP default.
	Switched bool
	// FallbackTLS: Addr is the raw-TCP default dialed directly; on failure
	// dialRegistry retries the compat TLS registry (UDP- and TCP/9000-
	// blocked hosts with direct TCP 443).
	FallbackTLS bool
}

// proxied reports whether dialing r.Addr goes through a proxy.
func (r registryRoute) proxied() bool {
	return r.proxyFor(r.Addr) != ""
}

// proxyFor returns the redacted proxy for target, "" for a direct dial.
func (r registryRoute) proxyFor(target string) string {
	if !r.Proxy.Enabled() {
		return ""
	}
	if host, _, err := net.SplitHostPort(target); err == nil && proxyconf.IsLoopbackHost(host) {
		return ""
	}
	u, err := r.Proxy.ProxyForAddr(target)
	if err != nil || u == nil {
		return ""
	}
	return netproxy.Redact(u)
}

// pilotctlProxySpec is the proxy setting for pilotctl's own connections:
// $PILOT_PROXY, then config.json "proxy", then auto.
func pilotctlProxySpec(cfg map[string]interface{}) string {
	if v := strings.TrimSpace(os.Getenv("PILOT_PROXY")); v != "" {
		return v
	}
	if s, ok := cfg["proxy"].(string); ok && strings.TrimSpace(s) != "" {
		return s
	}
	return proxyconf.Auto
}

// configuredTransport is $PILOT_TRANSPORT, else config.json "transport",
// normalized; "" when neither is set or the value is unknown.
func configuredTransport(cfg map[string]interface{}) string {
	v := strings.TrimSpace(os.Getenv("PILOT_TRANSPORT"))
	if v == "" {
		v, _ = cfg["transport"].(string)
	}
	t, err := normalizeTransport(v)
	if err != nil {
		return ""
	}
	return t
}

// registryFingerprintSetting is $PILOT_REGISTRY_FINGERPRINT, else
// config.json "registry_fingerprint" — used only when trust is pinned
// ($PILOT_REGISTRY_TRUST / config.json "registry_trust", defaulting to
// pinned when a fingerprint is configured).
func registryFingerprintSetting(cfg map[string]interface{}) string {
	fp := strings.TrimSpace(os.Getenv("PILOT_REGISTRY_FINGERPRINT"))
	if fp == "" {
		fp, _ = cfg["registry_fingerprint"].(string)
	}
	trust := strings.TrimSpace(os.Getenv("PILOT_REGISTRY_TRUST"))
	if trust == "" {
		trust, _ = cfg["registry_trust"].(string)
	}
	if strings.EqualFold(strings.TrimSpace(trust), "system") {
		return ""
	}
	return strings.TrimSpace(fp)
}

// planRegistryRoute resolves how to reach addr. The error is an invalid
// proxy setting.
func planRegistryRoute(addr string) (registryRoute, error) {
	cfg := loadConfig()
	policy, err := proxyconf.Resolve(pilotctlProxySpec(cfg))
	if err != nil {
		return registryRoute{}, err
	}
	r := registryRoute{Addr: strings.TrimSpace(addr), Proxy: policy}
	if r.Addr == productionRegistryAddr {
		if configuredTransport(cfg) == "compat" || r.proxyFor(compatRegistryAddr) != "" {
			r.Addr = compatRegistryAddr
			r.Switched = true
		} else {
			r.FallbackTLS = true
		}
	}
	if strings.EqualFold(r.Addr, compatRegistryAddr) {
		r.TLS = true
		r.Fingerprint = registryFingerprintSetting(cfg)
	}
	return r, nil
}

// dial opens the registry connection the route describes.
func (r registryRoute) dial() (*registry.Client, error) {
	var opts []registry.DialOption
	if r.Proxy.Enabled() {
		opts = append(opts, registry.WithDialer(proxyconf.DialContext(r.Proxy, nil)))
	}
	if !r.TLS {
		return registry.Dial(r.Addr, opts...)
	}
	if r.Fingerprint != "" {
		return registry.DialTLSPinned(r.Addr, r.Fingerprint, opts...)
	}
	return registry.DialTLS(r.Addr, &tls.Config{MinVersion: tls.VersionTLS12}, opts...)
}

// dialRegistry connects to the registry at addr along its registryRoute,
// retrying the compat TLS registry once when a direct dial of the raw-TCP
// default fails. The returned route is the one that was tried last.
func dialRegistry(addr string) (*registry.Client, registryRoute, error) {
	route, err := planRegistryRoute(addr)
	if err != nil {
		return nil, route, err
	}
	rc, err := route.dial()
	if err == nil || !route.FallbackTLS {
		return rc, route, err
	}
	fallback := route
	fallback.Addr, fallback.TLS, fallback.Switched, fallback.FallbackTLS = compatRegistryAddr, true, true, false
	fallback.Fingerprint = registryFingerprintSetting(loadConfig())
	if rc, ferr := fallback.dial(); ferr == nil {
		return rc, fallback, nil
	}
	return nil, route, err
}

// registryDialHint says what to check after a failed registry dial.
func registryDialHint(route registryRoute) string {
	if p := route.proxyFor(route.Addr); p != "" {
		return fmt.Sprintf("the registry %s is reached through the proxy %s: check that it allows CONNECT to %s and that its credentials are right; if this host can reach the registry directly, set PILOT_PROXY=off (or pilotctl config --set proxy=off)",
			route.Addr, p, route.Addr)
	}
	if route.TLS {
		return fmt.Sprintf("check outbound TCP 443 to %s; if TLS verification fails, point SSL_CERT_FILE at a CA bundle or set PILOT_REGISTRY_FINGERPRINT", route.Addr)
	}
	return fmt.Sprintf("check that the registry is running at %s, or set PILOT_REGISTRY", route.Addr)
}

// connectRegistryAt dials addr or exits with a hint.
func connectRegistryAt(addr, what string) *registry.Client {
	rc, route, err := dialRegistry(addr)
	if err != nil {
		if route.Addr == "" {
			fatalCode("invalid_argument", "%s: %v", what, err)
		}
		fatalHint("connection_failed", registryDialHint(route),
			"%s: cannot reach registry at %s: %v", what, route.Addr, err)
	}
	return rc
}
