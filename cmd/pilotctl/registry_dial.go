// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/netproxy"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// registryRoute is one way pilotctl reaches the registry for its own
// commands (lookup, register, rotate-key, the auto-handshake visibility
// check, recovery, ...). planRegistryRoutes lists the routes to try, in
// order, following the rules pilot-daemon applies, so pilotctl dials the
// way the daemon on this host does:
//
//   - proxy: $PILOT_PROXY, else config.json "proxy", else "auto". An
//     explicit http(s):// URL proxies every registry dial (except
//     loopback), whatever the transport; "off" never proxies. "auto" uses
//     the environment's HTTPS_PROXY / ALL_PROXY (honoring NO_PROXY) only
//     where the daemon would: when the transport is compat — the running
//     daemon's (asked over IPC), else $PILOT_TRANSPORT / config.json. On a
//     udp host that merely exports a proxy (corporate hosts, where private
//     registries live) the registry is dialed directly, as the daemon
//     does. With the transport unknown (no daemon answering, nothing
//     configured) the production registry is tried through the
//     environment's proxy first — a proxy that accepts the CONNECT is the
//     stronger signal: sandboxes such as Meta Muse accept a direct TCP
//     connection with a network guard that then breaks the first request —
//     and directly over raw TCP second, a connection that is only used when
//     the peer does not talk first (see probedDirectDial). A private
//     raw-TCP registry is never sent to the environment's proxy unless the
//     transport is compat.
//   - address: the compiled-in raw-TCP registry (34.71.57.205:9000) is
//     replaced by registry.pilotprotocol.network:443 over TLS whenever it
//     would be proxied (proxies allow CONNECT to :443 only) or the
//     transport is compat; a direct raw-TCP attempt falls back to that TLS
//     registry. That address always uses TLS, verified against the system
//     roots, or pinned to registry_fingerprint / $PILOT_REGISTRY_FINGERPRINT
//     when one is configured (sandboxes without a CA bundle).
type registryRoute struct {
	Addr        string
	TLS         bool
	Fingerprint string // non-empty: pinned trust
	Proxy       *netproxy.Resolver
	// Switched: Addr replaced the raw-TCP default.
	Switched bool
	// Probe: a direct raw-TCP fallback, used only when the peer does not
	// talk before the first request (probedDirectDial).
	Probe bool
}

// proxied reports whether dialing r.Addr goes through a proxy.
func (r registryRoute) proxied() bool {
	return r.proxyFor(r.Addr) != ""
}

// proxyFor returns the redacted proxy for target, "" for a direct dial.
func (r registryRoute) proxyFor(target string) string {
	return proxyFor(r.Proxy, target)
}

func proxyFor(p *netproxy.Resolver, target string) string {
	if !p.Enabled() {
		return ""
	}
	if host, _, err := net.SplitHostPort(target); err == nil && proxyconf.IsLoopbackHost(host) {
		return ""
	}
	u, err := p.ProxyForAddr(target)
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

// runningDaemonTransport asks the daemon on this host which transport it
// runs ("udp" or "compat"); "" when no daemon answers or it predates the
// info field. A test seam.
var runningDaemonTransport = func() string {
	d, err := driver.Connect(getSocket())
	if err != nil {
		return ""
	}
	defer d.Close()
	info, err := d.Info()
	if err != nil {
		return ""
	}
	t, _ := info["transport"].(string)
	switch t {
	case "udp", "compat":
		return t
	}
	return ""
}

// effectiveTransportFor is the transport the daemon on this host uses:
// the running daemon's, else an explicitly configured udp or compat, else
// "" (unknown: auto, or nothing configured and no daemon).
func effectiveTransportFor(cfg map[string]interface{}) string {
	if t := runningDaemonTransport(); t != "" {
		return t
	}
	switch t := configuredTransport(cfg); t {
	case "udp", "compat":
		return t
	}
	return ""
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

// planRegistryRoutes returns the routes to reach addr, in the order to try
// them (see registryRoute). The error is an invalid proxy setting.
func planRegistryRoutes(addr string) ([]registryRoute, error) {
	cfg := loadConfig()
	spec, err := proxyconf.Normalize(pilotctlProxySpec(cfg))
	if err != nil {
		return nil, err
	}
	addr = strings.TrimSpace(addr)
	fp := registryFingerprintSetting(cfg)
	route := func(a string, p *netproxy.Resolver) registryRoute {
		r := registryRoute{Addr: a, Proxy: p}
		if strings.EqualFold(a, compatRegistryAddr) {
			r.TLS, r.Fingerprint = true, fp
		}
		if a == compatRegistryAddr && addr == productionRegistryAddr {
			r.Switched = true
		}
		return r
	}
	isDefault := addr == productionRegistryAddr

	var policy *netproxy.Resolver // the proxy that applies, nil = direct
	var transport string
	switch spec {
	case proxyconf.Off:
		transport = configuredTransport(cfg)
	case proxyconf.Auto:
		env, envErr := netproxy.FromEnvironment()
		if envErr == nil && !env.Enabled() {
			// No proxy in the environment: nothing to decide.
			transport = configuredTransport(cfg)
			break
		}
		transport = effectiveTransportFor(cfg)
		if transport != "compat" && !(transport == "" && isDefault) {
			// udp, or unknown with a private registry: direct only,
			// exactly as the daemon dials. The environment's proxy is
			// not even parsed, so a malformed one cannot matter.
			break
		}
		if envErr != nil {
			return nil, envErr
		}
		if transport == "compat" {
			policy = env
			break
		}
		// Unknown transport, production registry: the TLS registry
		// through the environment's proxy first, then direct raw TCP.
		// Direct first would lose to a sandbox network guard, which
		// accepts the TCP connection and only fails the first request,
		// so the proxied route would never be tried.
		tlsRoute := route(compatRegistryAddr, nil)
		if proxyFor(env, compatRegistryAddr) == "" {
			// NO_PROXY exempts the registry: nothing is proxied.
			return []registryRoute{route(addr, nil), tlsRoute}, nil
		}
		tlsRoute.Proxy = env
		raw := route(addr, nil)
		raw.Probe = true
		return []registryRoute{tlsRoute, raw}, nil
	default:
		explicit, err := proxyconf.Resolve(spec)
		if err != nil {
			return nil, err
		}
		policy = explicit
		transport = configuredTransport(cfg)
	}

	if isDefault {
		if transport == "compat" || proxyFor(policy, compatRegistryAddr) != "" {
			routes := []registryRoute{route(compatRegistryAddr, policy)}
			if spec == proxyconf.Auto && proxyFor(policy, compatRegistryAddr) != "" {
				routes = append(routes, route(compatRegistryAddr, nil))
			}
			return routes, nil
		}
		return []registryRoute{route(addr, policy), route(compatRegistryAddr, policy)}, nil
	}
	routes := []registryRoute{route(addr, policy)}
	if spec == proxyconf.Auto && proxyFor(policy, addr) != "" {
		// compat through the environment's proxy failed: the host may
		// still reach the registry directly.
		routes = append(routes, route(addr, nil))
	}
	return routes, nil
}

// rawDirectDial opens a direct TCP connection (a test seam).
var rawDirectDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// guardProbeWait is how long probedDirectDial watches a fresh connection.
const guardProbeWait = 300 * time.Millisecond

// errNotRegistry marks a direct connection whose peer is not a registry.
var errNotRegistry = errors.New("not a Pilot registry")

// probedDirectDial dials addr directly and hands back the connection only
// when the peer stays silent for guardProbeWait, as a registry does until it
// gets a request. A peer that sends first or closes at once — the network
// guard of a sandbox whose only way out is its HTTPS proxy answers direct
// connections with a policy message — fails the dial, so dialRegistry
// reports the proxied route's error rather than a broken pipe from the
// guard. The check costs guardProbeWait, and it only runs on the direct
// fallback after the proxied route failed.
func probedDirectDial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := rawDirectDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if err := c.SetReadDeadline(time.Now().Add(guardProbeWait)); err != nil {
		c.Close()
		return nil, err
	}
	var b [1]byte
	n, err := c.Read(b[:])
	var ne net.Error
	if n == 0 && errors.As(err, &ne) && ne.Timeout() {
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	c.Close()
	if n > 0 {
		return nil, fmt.Errorf("%w at %s: it sent data before any request (a network guard?)", errNotRegistry, addr)
	}
	return nil, fmt.Errorf("%w at %s: it closed the connection before any request (a network guard?): %v", errNotRegistry, addr, err)
}

// dial opens the registry connection the route describes.
func (r registryRoute) dial() (*registry.Client, error) {
	var opts []registry.DialOption
	switch {
	case r.Proxy.Enabled():
		opts = append(opts, registry.WithDialer(proxyconf.DialContext(r.Proxy, nil)))
	case r.Probe && !r.TLS:
		opts = append(opts, registry.WithDialer(probedDirectDial))
	}
	if !r.TLS {
		return registry.Dial(r.Addr, opts...)
	}
	if r.Fingerprint != "" {
		return registry.DialTLSPinned(r.Addr, r.Fingerprint, opts...)
	}
	return registry.DialTLS(r.Addr, &tls.Config{MinVersion: tls.VersionTLS12}, opts...)
}

// dialRegistry connects to the registry at addr along the first working
// route of planRegistryRoutes. On failure the route and error reported are
// the first proxied attempt's (a proxy refusing the CONNECT is the likely
// cause), else the first attempt's.
func dialRegistry(addr string) (*registry.Client, registryRoute, error) {
	routes, err := planRegistryRoutes(addr)
	if err != nil {
		return nil, registryRoute{}, err
	}
	var failed registryRoute
	var firstErr error
	for i, route := range routes {
		rc, err := route.dial()
		if err == nil {
			return rc, route, nil
		}
		if i == 0 || (route.proxied() && !failed.proxied()) {
			failed, firstErr = route, err
		}
	}
	return nil, failed, firstErr
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
