// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// launchEnvironment is the environment the daemon was started with, taken
// before exportAppProxy points the proxy variables at the proxy relay. The
// -proxy-cmd refresh command runs in it, and a remote restart re-execs the
// daemon with it: a new daemon inheriting the relay (which dies with this
// one) as its proxy would have no way out.
var launchEnvironment = os.Environ()

// activeProxyRelay is the running proxy relay, nil before startProxyRelay
// (and when none runs).
var activeProxyRelay atomic.Pointer[proxyconf.Relay]

// proxyCommandFor returns the -proxy-cmd the resolver for transport uses,
// "" when it uses none: none is set, -proxy=off (ignored, with a warning
// when warn is set), or -proxy=auto on a transport other than compat
// (auto proxies nothing there).
func proxyCommandFor(spec, command, transport string, warn bool) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	s, err := proxyconf.Normalize(spec)
	if err != nil {
		return ""
	}
	switch {
	case s == proxyconf.Off:
		if warn {
			slog.Warn("ignoring -proxy-cmd: -proxy=off")
		}
		return ""
	case s == proxyconf.Auto && transport != daemon.TransportCompat:
		if warn {
			slog.Info("-proxy-cmd not used: -proxy=auto proxies -transport=compat only", "transport", transport)
		}
		return ""
	}
	return command
}

// resolveProxy resolves -proxy and -proxy-cmd for the transport (see
// daemon.ResolveProxy). A malformed -proxy value is an error. Under "auto"
// only an unusable HTTPS_PROXY / https_proxy (the variable that names the
// TLS proxy) can fail; that costs the proxy, not the daemon: it is logged
// and the daemon dials directly, as it did before -proxy existed. Unusable
// HTTP_PROXY / ALL_PROXY values are skipped by netproxy and only logged.
//
// -proxy-cmd (a command whose output is the current proxy URL) makes the
// resolver follow rotating credentials (netproxy.WithRefreshFunc over
// proxyRefreshSource): it supplies the URL wherever -proxy would use one —
// the explicit URL, or with auto (compat only) the environment's proxy,
// NO_PROXY still honored — and is re-run every 60s and whenever the proxy
// rejects the credentials (407, or an answer that cannot be parsed), after
// which the rejected connection is retried once. It is ignored with
// -proxy=off, and with auto on udp (no proxy). A failing run is logged
// once per run of failures, and the last good URL (at first, the launch
// environment's proxy or the explicit URL) stays in use.
func resolveProxy(spec, command, transport string) (*netproxy.Resolver, error) {
	s, err := proxyconf.Normalize(spec)
	if err != nil {
		return nil, err
	}
	command = proxyCommandFor(s, command, transport, true)
	var opts []netproxy.Option
	if command != "" {
		opts = append(opts,
			netproxy.WithRefreshFunc(proxyRefreshSource(command)),
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

// proxyRefreshSource runs the -proxy-cmd command in the launch environment
// (proxyconf.CommandSource), never in the one exportAppProxy changed, and
// refuses a URL that names the daemon's own proxy relay: the relay would
// then forward to itself.
func proxyRefreshSource(command string) func(ctx context.Context) (string, error) {
	run := proxyconf.CommandSource(command, launchEnvironment)
	return func(ctx context.Context) (string, error) {
		out, err := run(ctx)
		if err != nil {
			return "", err
		}
		if activeProxyRelay.Load().Serves(out) {
			return "", errors.New("refresh command printed the daemon's own proxy relay; it must print the egress proxy's URL")
		}
		return out, nil
	}
}

func logProxyWarnings(r *netproxy.Resolver) {
	for _, w := range r.Warnings() {
		slog.Warn("ignoring unusable proxy environment variable", "err", w)
	}
}

// describeProxy renders the resolved proxy for the startup log line.
// Credentials are always redacted. The refresh source is -proxy-cmd run by
// proxyRefreshSource, which netproxy only knows as a callback; the line
// says "command", which is what pilotctl daemon start looks for.
func describeProxy(spec, transport string, r *netproxy.Resolver) string {
	if r != nil {
		return strings.Replace(r.String(), "(credentials refreshed by callback)", "(credentials refreshed by command)", 1)
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
// credentials (-proxy-cmd) reach these clients too. With the proxy relay
// running (relay != nil: whenever the daemon proxies), https requests are
// tunnelled through it, so a rejected CONNECT — also one whose answer
// cannot be parsed, Meta Muse's form — is refreshed (with -proxy-cmd) and
// retried once instead of failing, and no error ever quotes the proxy's
// answer (net/http's own does); without it a 407 still refreshes the
// credentials for the next request (see proxyconf.ConfigureTransport).
// Loopback targets (a local webhook or sidecar) always go direct. nil
// leaves DefaultTransport alone (net/http's own proxy environment
// handling). Call before any goroutine issues a request.
func installDefaultTransportProxy(r *netproxy.Resolver, relay *proxyconf.Relay) {
	if r == nil {
		return
	}
	tr, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		slog.Warn("http.DefaultTransport is not an *http.Transport; plugin HTTP clients do not follow -proxy")
		return
	}
	var via *url.URL
	if relay != nil {
		via = relay.URL()
	}
	proxyconf.ConfigureTransport(tr, r, via)
}

// appProxyVars are the proxy variables exportAppProxy points at the proxy
// relay: the ones HTTPS clients read (Go's net/http prefers the upper-case
// one, curl the lower-case one; both are set). HTTP_PROXY / http_proxy are
// left alone: the relay carries CONNECT tunnels only, and a proxy that
// forwards plain http:// requests keeps receiving them as before.
var appProxyVars = []string{"HTTPS_PROXY", "https_proxy"}

// startProxyRelay starts the daemon's loopback CONNECT relay
// (proxyconf.Relay) whenever the daemon proxies (r is enabled): each
// tunnel it is asked for is opened upstream with the resolver's current
// credentials, refreshed and retried once when the proxy rejects them.
// http.DefaultTransport sends its https requests through it (see
// installDefaultTransportProxy).
//
// When the credentials are refreshed (command, the -proxy-cmd in effect,
// is set), the processes the daemon starts — app-store apps, spawned with
// the daemon's environment — get it too (exportAppProxy). Their inherited
// proxy URL would otherwise carry the launch-time credentials, which a
// rotating proxy (Meta Muse) stops accepting within minutes: every app
// that opens a new connection then fails, even after a respawn, while the
// daemon stays online ("node online, all apps broken"). Without a refresh
// command the environment they inherit is exactly what the daemon itself
// uses, and is left alone. A relay that cannot start is logged; plugins
// then talk to the proxy directly and apps keep the launch environment, as
// before.
func startProxyRelay(r *netproxy.Resolver, command string) *proxyconf.Relay {
	if !r.Enabled() {
		return nil
	}
	relay, err := proxyconf.StartRelay(r, nil)
	if err != nil {
		slog.Warn("proxy relay not started; apps keep the launch-time proxy credentials", "err", err)
		return nil
	}
	activeProxyRelay.Store(relay)
	if command == "" {
		slog.Info("proxy relay listening", "addr", relay.Addr())
		return relay
	}
	exportAppProxy(relay.URL().String())
	slog.Info("proxy relay listening", "addr", relay.Addr(),
		"apps", "the apps this daemon starts get HTTPS_PROXY pointing here, so their connections carry the current proxy credentials")
	return relay
}

// exportAppProxy points this process's proxy environment, which the apps
// it starts inherit, at relayURL (it carries the relay's token and is never
// logged): appProxyVars, and $PILOT_PROXY when it holds a proxy URL (a
// pilotctl an app runs reads it first). The daemon itself has read its
// settings already, runs its refresh command in launchEnvironment, and
// re-execs with that on a remote restart.
func exportAppProxy(relayURL string) {
	for _, k := range appProxyVars {
		_ = os.Setenv(k, relayURL)
	}
	if s, err := proxyconf.Normalize(os.Getenv("PILOT_PROXY")); err == nil && s != proxyconf.Auto && s != proxyconf.Off {
		_ = os.Setenv("PILOT_PROXY", relayURL)
	}
}

func isAutoProxy(spec string) bool {
	s, err := proxyconf.Normalize(spec)
	return err == nil && s == proxyconf.Auto
}
