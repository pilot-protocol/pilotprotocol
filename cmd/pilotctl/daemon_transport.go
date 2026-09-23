// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Compiled-in production endpoints. These are the same defaults cmd/daemon
// compiles in; `pilotctl init` and install.sh write them into config.json.
// Both are raw-TCP/UDP endpoints — compat mode (-transport=compat) must not
// be pinned to them, see compatSkipsDefault.
const (
	productionRegistryAddr = "34.71.57.205:9000"
	productionBeaconAddr   = "34.71.57.205:9001"
)

// daemonForwardEnv is the environment `pilotctl daemon start` guarantees to
// hand to pilot-daemon, on both the fork and the --foreground exec path. The
// proxy variables drive the daemon's -proxy=auto resolution (a CONNECT proxy
// is the only way out of sandboxes such as Meta Muse), PILOT_PROXY /
// PILOT_TRANSPORT are the daemon's env-backed flag overrides, and the
// SSL_CERT_* pair lets a sandbox without a system CA bundle point Go's
// x509 at one.
var daemonForwardEnv = []string{
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
	"PILOT_PROXY", "PILOT_TRANSPORT",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// validateTransport accepts the two tunnel transports pilot-daemon knows.
func validateTransport(v string) error {
	switch v {
	case "udp", "compat":
		return nil
	}
	return fmt.Errorf("invalid transport %q: must be 'udp' or 'compat'", v)
}

// validateProxySetting accepts the -proxy contract: "auto" (use the
// environment's proxy in compat mode), "off", or an explicit
// http(s)://[user:pass@]host:port proxy URL.
func validateProxySetting(v string) error {
	switch v {
	case "auto", "off":
		return nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("invalid proxy %q: must be 'auto', 'off', or an http(s)://[user:pass@]host:port URL", redactProxyURL(v))
	}
	return nil
}

// proxyHasCredentials reports whether an explicit proxy URL carries userinfo.
func proxyHasCredentials(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.User != nil
}

// redactProxyURL hides proxy credentials for display: http://user:pass@h:p
// becomes http://***@h:p. Non-URL values ("auto", "off") pass through.
//
// TODO(netproxy): switch to common/netproxy's redaction helper once
// pilotctl bumps to a common release that ships it.
func redactProxyURL(v string) string {
	if u, err := url.Parse(v); err == nil && u.User != nil {
		return u.Scheme + "://***@" + u.Host + u.EscapedPath()
	}
	// Unparseable or scheme-less ("user:pass@host:port" parses as an opaque
	// URL with no userinfo): never echo anything before the last '@'.
	if i := strings.LastIndex(v, "@"); i >= 0 {
		prefix := ""
		if j := strings.Index(v, "://"); j >= 0 && j < i {
			prefix = v[:j+3]
		}
		return prefix + "***@" + v[i+1:]
	}
	return v
}

// resolveDaemonTransport picks the tunnel transport for `daemon start`:
// --transport, then $PILOT_TRANSPORT, then config.json "transport". "" means
// none was set and the daemon keeps its own default (udp).
//
// $PILOT_TRANSPORT is resolved here and handed to the daemon as an explicit
// -transport because pilot-daemon's -transport flag defaults to "udp", which
// masks the env var in every released daemon — exporting PILOT_TRANSPORT
// alone never switched a daemon started through pilotctl to compat.
func resolveDaemonTransport(flags map[string]string, cfg map[string]interface{}) (string, error) {
	v := strings.TrimSpace(flagString(flags, "transport", ""))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PILOT_TRANSPORT"))
	}
	if v == "" {
		if s, ok := cfg["transport"].(string); ok {
			v = strings.TrimSpace(s)
		}
	}
	if v == "" {
		return "", nil
	}
	if err := validateTransport(v); err != nil {
		return "", err
	}
	return v, nil
}

// resolveDaemonProxy picks the proxy policy for `daemon start`: --proxy, then
// config.json "proxy". "" means neither was set. $PILOT_PROXY is not read
// here: it reaches the daemon through the forwarded environment and the
// daemon resolves it itself.
func resolveDaemonProxy(flags map[string]string, cfg map[string]interface{}) (string, error) {
	v := strings.TrimSpace(flagString(flags, "proxy", ""))
	if v == "" {
		if s, ok := cfg["proxy"].(string); ok {
			v = strings.TrimSpace(s)
		}
	}
	if v == "" {
		return "", nil
	}
	if err := validateProxySetting(v); err != nil {
		return "", err
	}
	return v, nil
}

// compatSkipsDefault reports whether addr must be left off the daemon command
// line because it is the compiled-in raw-TCP production default and the
// daemon runs in compat mode. pilot-daemon only switches the registry to
// registry.pilotprotocol.network:443 (TLS) in compat mode when -registry was
// NOT given explicitly; `pilotctl init` writes the raw :9000 default into
// config.json, and forwarding that verbatim pinned compat daemons to a
// non-TLS port no HTTPS proxy will CONNECT to.
func compatSkipsDefault(transport, addr, def string) bool {
	return transport == "compat" && addr == def
}

// daemonChildEnv returns the environment for the pilot-daemon child: the
// full pilotctl environment (so every daemonForwardEnv variable reaches the
// daemon untouched) plus the launch-specific overrides.
//
//   - PILOT_ADMIN_TOKEN and a credential-bearing PILOT_PROXY are passed
//     here rather than on argv so they never show up in /proc/<pid>/cmdline
//     (PILOT-290).
//   - In compat mode a $PILOT_REGISTRY equal to the raw-TCP production
//     default is dropped: the daemon treats an env-provided registry as
//     explicit and would otherwise skip the compat TLS registry switch.
func daemonChildEnv(base []string, adminToken, proxyEnv, transport string) []string {
	set := map[string]string{}
	if adminToken != "" {
		set["PILOT_ADMIN_TOKEN"] = adminToken
	}
	if proxyEnv != "" {
		set["PILOT_PROXY"] = proxyEnv
	}
	env := make([]string, 0, len(base)+len(set))
	for _, kv := range base {
		k, v, _ := strings.Cut(kv, "=")
		if _, override := set[k]; override {
			continue
		}
		if k == "PILOT_REGISTRY" && compatSkipsDefault(transport, v, productionRegistryAddr) {
			continue
		}
		env = append(env, kv)
	}
	for _, k := range []string{"PILOT_ADMIN_TOKEN", "PILOT_PROXY"} {
		if v, ok := set[k]; ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// daemonFlagProbeTimeout bounds the `pilot-daemon -help` flag probe.
const daemonFlagProbeTimeout = 5 * time.Second

var (
	daemonFlagCacheMu sync.Mutex
	daemonFlagCache   = map[string]map[string]bool{}
)

// daemonFlags returns the set of flag names the pilot-daemon binary at bin
// defines, parsed from its Go flag-package `-help` usage ("  -name type").
// Returns nil when the binary could not be probed or printed nothing
// recognisable; callers treat nil as "unknown" and keep the flag.
func daemonFlags(bin string) map[string]bool {
	daemonFlagCacheMu.Lock()
	defer daemonFlagCacheMu.Unlock()
	if set, ok := daemonFlagCache[bin]; ok {
		return set
	}
	ctx, cancel := context.WithTimeout(context.Background(), daemonFlagProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-help")
	// Minimal environment: -help prints each flag's default, and a daemon
	// with env-backed defaults would echo e.g. a credential-bearing
	// $PILOT_PROXY into the captured output.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	out, _ := cmd.CombinedOutput() // -help exits 0 (flag.ExitOnError) or 2 on older builds
	var set map[string]bool
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.HasPrefix(line, "  -") {
			continue
		}
		name := strings.TrimPrefix(line, "  -")
		if i := strings.IndexAny(name, " \t"); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			continue
		}
		if set == nil {
			set = map[string]bool{}
		}
		set[name] = true
	}
	daemonFlagCache[bin] = set
	return set
}

// skewSensitiveDaemonFlags are pilot-daemon flags newer than some daemons a
// current pilotctl may still be paired with (a sibling binary left behind by
// a partial upgrade, a PILOT_DAEMON_BIN override, an npm-installed pair).
// Go's flag package aborts on an unknown flag, so forwarding one of these to
// an older daemon would turn `daemon start` into a crash loop.
var skewSensitiveDaemonFlags = []string{"transport", "proxy"}

// dropUnsupportedDaemonFlags removes skew-sensitive flags the daemon at bin
// does not define, warning once per dropped flag. Only probes the binary
// when one of those flags is actually present in args.
func dropUnsupportedDaemonFlags(bin string, args []string) []string {
	present := false
	for _, a := range args {
		for _, f := range skewSensitiveDaemonFlags {
			if a == "--"+f {
				present = true
			}
		}
	}
	if !present {
		return args
	}
	supported := daemonFlags(bin)
	if supported == nil {
		return args
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		name := strings.TrimPrefix(args[i], "--")
		skew := false
		for _, f := range skewSensitiveDaemonFlags {
			if args[i] == "--"+f && !supported[f] {
				skew = true
			}
		}
		if !skew {
			out = append(out, args[i])
			continue
		}
		value := ""
		if i+1 < len(args) {
			value = args[i+1]
			i++
		}
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "warning: %s does not support -%s (older pilot-daemon); not passing -%s %s — upgrade pilot-daemon to use it\n",
				bin, name, name, redactProxyURL(value))
		}
	}
	return out
}

// envProxyURL returns the proxy an HTTPS request from this process would
// use per the environment ($HTTPS_PROXY, then $ALL_PROXY, either case), or ""
// when none is set.
func envProxyURL() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// registryDialHint is the hint for a failed direct registry dial from
// pilotctl. Behind an egress proxy the dial fails by design — say so,
// instead of suggesting the registry is down.
func registryDialHint(addr string) string {
	if p := envProxyURL(); p != "" {
		return fmt.Sprintf("pilotctl dials the registry (%s) directly over TCP and does not use the proxy %s yet; daemon-backed commands (info, peers, trust, ping, send-message) reach the network through the daemon instead",
			addr, redactProxyURL(p))
	}
	return fmt.Sprintf("check that the registry is running at %s, or set PILOT_REGISTRY", addr)
}
