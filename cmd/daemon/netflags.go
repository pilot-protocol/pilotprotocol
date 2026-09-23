// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// Compiled-in production endpoints. -registry and -beacon default to these
// raw TCP / UDP addresses (pilotctl passes the same values explicitly);
// compat mode swaps the registry for its TLS host name on :443.
const (
	defaultRegistryAddr = "34.71.57.205:9000"
	defaultBeaconAddr   = "34.71.57.205:9001"
	compatRegistryAddr  = "registry.pilotprotocol.network:443"
	defaultCompatBeacon = "wss://beacon.pilotprotocol.network/v1/compat"
)

// Where a setting's final value came from, for logs and precedence.
const (
	srcFlag    = "flag"
	srcEnv     = "env"
	srcConfig  = "config"
	srcDefault = "default"
)

// flagSources records which flags the command line set and which
// config.json will set (common/config.ApplyToFlags sets a flag's value
// without marking it as set, so flag.Visit alone cannot tell a config
// value from a default).
type flagSources struct {
	cmdline map[string]bool
	config  map[string]bool
}

// newFlagSources must run after flag.Parse and before config.ApplyToFlags.
// cfg may be nil (no config file).
func newFlagSources(fs *flag.FlagSet, cfg map[string]interface{}) flagSources {
	s := flagSources{cmdline: map[string]bool{}, config: map[string]bool{}}
	fs.Visit(func(f *flag.Flag) { s.cmdline[f.Name] = true })
	fs.VisitAll(func(f *flag.Flag) {
		if s.cmdline[f.Name] {
			return
		}
		v, ok := cfg[f.Name]
		if !ok {
			v, ok = cfg[strings.ReplaceAll(f.Name, "-", "_")]
		}
		if !ok {
			return
		}
		switch v.(type) { // the types ApplyToFlags applies
		case string, float64, bool:
			s.config[f.Name] = true
		}
	})
	return s
}

// explicit reports whether the operator chose the flag's value, on the
// command line or in config.json.
func (s flagSources) explicit(name string) bool {
	return s.cmdline[name] || s.config[name]
}

// envOverConfig resolves a setting whose environment variable beats
// config.json: the command line, then the environment, then config.json
// (already applied to cur by ApplyToFlags), then the flag's default. It
// exists for settings that a launcher hands over per start — pilotctl passes
// a credential-bearing proxy URL as $PILOT_PROXY so it never appears on the
// daemon's argv, and a persistent config.json default must not override it.
func (s flagSources) envOverConfig(name, cur, envVar string) (string, string) {
	if s.cmdline[name] {
		return cur, srcFlag
	}
	if v := strings.TrimSpace(getenv(envVar)); v != "" {
		return v, srcEnv
	}
	if s.config[name] {
		return cur, srcConfig
	}
	return cur, srcDefault
}

// getenv is os.Getenv (a test seam).
var getenv = os.Getenv

// registrySettings is the registry part of the daemon's configuration
// after flags, config.json and the environment are merged.
type registrySettings struct {
	Addr string
	// AddrExplicit: set by -registry, $PILOT_REGISTRY or config.json.
	AddrExplicit  bool
	TLS           bool
	TLSExplicit   bool
	Trust         string
	TrustExplicit bool
	Fingerprint   string
}

// compatKeepsRegistry reports whether a -transport=compat daemon keeps its
// configured registry instead of switching to compatRegistryAddr:
//
//   - an explicit -registry-tls=false keeps the address: the operator asked
//     for the raw TCP registry (the TCP/9000 fallback for hosts where UDP is
//     blocked but TCP 9000 is open);
//   - otherwise only an explicit, non-default address is kept. The
//     compiled-in raw-TCP default never counts as a choice: pilotctl and
//     `pilotctl init`'s config.json pass it on every start, and a
//     UDP-blocked host behind a CONNECT-only egress proxy cannot reach it.
func compatKeepsRegistry(r registrySettings) bool {
	if r.TLSExplicit && !r.TLS {
		return true
	}
	return r.AddrExplicit && strings.TrimSpace(r.Addr) != defaultRegistryAddr
}

// applyRegistryDefaults adapts the registry to the final transport and
// proxy policy (proxied reports whether a TCP dial of an address goes
// through the proxy; nil: never):
//
//   - the compiled-in raw-TCP registry moves to its TLS host name on :443
//     (compatRegistryAddr) unless compatKeepsRegistry, in compat mode and
//     also in udp mode when the registry dial would go through a proxy —
//     egress proxies CONNECT to :443 only (pilotctl's registry route
//     applies the same rule);
//   - TLS is then on unless -registry-tls was chosen; compatRegistryAddr
//     is TLS-only, so TLS is on for it in either transport unless
//     -registry-tls was chosen — an install switched back from compat to
//     udp keeps working;
//   - whenever the registry uses TLS in compat mode or on
//     compatRegistryAddr and -registry-trust was not chosen, trust is
//     "pinned" when a -registry-fingerprint is configured (the fallback
//     for sandboxes without a CA bundle) and "system" otherwise (the
//     production registry has a Let's Encrypt certificate) — also when
//     -registry-tls itself was explicit, as before -proxy existed.
//
// Choices made in config.json or the environment count as explicit, so a
// pinned registry configured there is never overridden.
func applyRegistryDefaults(transport string, r registrySettings, proxied func(addr string) bool) registrySettings {
	moveRegistry := false
	switch {
	case compatKeepsRegistry(r):
	case transport == daemon.TransportCompat:
		moveRegistry = true
	case proxied != nil && proxied(r.Addr):
		moveRegistry = true
	}
	if moveRegistry {
		r.Addr = compatRegistryAddr
		if !r.TLSExplicit {
			r.TLS = true
		}
	}
	onCompatAddr := strings.EqualFold(strings.TrimSpace(r.Addr), compatRegistryAddr)
	if transport == daemon.TransportCompat && !r.TLSExplicit {
		r.TLS = true
	}
	if onCompatAddr && !r.TLSExplicit {
		r.TLS = true
	}
	if r.TLS && !r.TrustExplicit && (transport == daemon.TransportCompat || onCompatAddr) {
		if strings.TrimSpace(r.Fingerprint) != "" {
			r.Trust = "pinned"
		} else {
			r.Trust = "system"
		}
	}
	return r
}

// autoCompatBlocker returns why -transport=auto must not pick compat for
// this configuration ("" when it may): a private registry that compat would
// keep but that is not known to speak TLS, or a private UDP beacon with the
// public compat beacon — compat would silently move such a node onto the
// public network.
func autoCompatBlocker(r registrySettings, beacon string, beaconExplicit, compatBeaconExplicit bool) string {
	if compatKeepsRegistry(r) && !strings.EqualFold(strings.TrimSpace(r.Addr), compatRegistryAddr) && !(r.TLSExplicit && r.TLS) {
		return "custom -registry " + r.Addr + " (raw TCP)"
	}
	if beaconExplicit && strings.TrimSpace(beacon) != defaultBeaconAddr && !compatBeaconExplicit {
		return "custom -beacon " + beacon + " without -compat-beacon"
	}
	return ""
}

// autoProbe is daemon.SelectTransport (a test seam).
var autoProbe = daemon.SelectTransport

// resolveAutoTransport decides -transport=auto (see daemon.SelectTransport)
// for this configuration: compat is only considered when it would reach
// the same network (autoCompatBlocker), and its beacon check runs through
// the proxy compat mode would use (policyFor(compat): -proxy / -proxy-cmd,
// auto = the environment's). The error is a malformed -proxy.
func resolveAutoTransport(reg registrySettings, beacon string, beaconExplicit bool, compatBeacon string, compatBeaconExplicit bool, policyFor func(transport string) (*proxyconf.Policy, error)) (mode, reason string, err error) {
	if why := autoCompatBlocker(reg, beacon, beaconExplicit, compatBeaconExplicit); why != "" {
		return daemon.TransportUDP, why + "; auto stays on udp (pass -transport=compat to force compat)", nil
	}
	policy, err := policyFor(daemon.TransportCompat)
	if err != nil {
		return "", "", err
	}
	var dial func(ctx context.Context, network, addr string) (net.Conn, error)
	if policy.Enabled() {
		dial = policy.DialContext(nil)
	}
	mode, reason = autoProbe(context.Background(), daemon.AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: compatBeacon,
		Dial:            dial,
	})
	return mode, reason, nil
}

// transportDefaultEnv names the transport a daemon uses when neither
// -transport, $PILOT_TRANSPORT nor config.json chooses one. install.sh sets
// it to auto in the service units it writes: unlike -transport=auto on the
// command line or "transport":"auto" in config.json, a daemon that predates
// auto (after a downgrade) ignores it instead of refusing to start.
const transportDefaultEnv = "PILOT_TRANSPORT_DEFAULT"

// defaultTransport is $PILOT_TRANSPORT_DEFAULT when it names a transport,
// else udp.
func defaultTransport() string {
	v := strings.TrimSpace(getenv(transportDefaultEnv))
	if v == "" {
		return daemon.TransportUDP
	}
	t, err := daemon.NormalizeTransport(v)
	if err != nil || t == "" {
		slog.Warn("ignoring unknown "+transportDefaultEnv+" value", "value", v, "valid", "udp, compat, auto")
		return daemon.TransportUDP
	}
	return t
}
