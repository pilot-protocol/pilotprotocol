// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// Compiled-in production endpoints. These are the same defaults cmd/daemon
// compiles in; `pilotctl init` and install.sh write them into config.json.
// Both are raw-TCP/UDP endpoints — compat mode (-transport=compat) must not
// be pinned to them, see compatSkipsDefault. compatRegistryAddr is the TLS
// registry compat mode (and any proxied connection) uses instead.
const (
	productionRegistryAddr = "34.71.57.205:9000"
	productionBeaconAddr   = "34.71.57.205:9001"
	compatRegistryAddr     = "registry.pilotprotocol.network:443"
)

// daemonForwardEnv is the environment `pilotctl daemon start` guarantees to
// hand to pilot-daemon, on both the fork and the --foreground exec path. The
// proxy variables drive the daemon's -proxy=auto resolution (a CONNECT proxy
// is the only way out of sandboxes such as Meta Muse), the PILOT_* ones are
// the daemon's environment overrides (they beat config.json), and the
// SSL_CERT_* pair lets a sandbox without a system CA bundle point Go's
// x509 at one.
var daemonForwardEnv = []string{
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy",
	"NO_PROXY", "no_proxy",
	"PILOT_PROXY", "PILOT_PROXY_CMD", "PILOT_TRANSPORT",
	"PILOT_REGISTRY_TRUST", "PILOT_REGISTRY_FINGERPRINT",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// clearableConfigKeys are the config.json keys `config --set key=` removes
// instead of storing an empty string.
var clearableConfigKeys = map[string]bool{"transport": true, "proxy": true, "proxy_cmd": true}

// fitTransportToDaemon keeps config.json usable by the pilot-daemon at bin
// after a downgrade (`pilotctl update --pin <older tag>`): a daemon that
// predates -transport=auto refuses to start with "transport":"auto" in
// config.json, and the pilotctl installed with it never overrides the
// value. Such a config gets transport=udp, the older daemon's default. It
// returns a note for the user, "" when nothing changed.
func fitTransportToDaemon(bin string) string {
	cfg := loadConfig()
	if t, _ := cfg["transport"].(string); !strings.EqualFold(strings.TrimSpace(t), "auto") {
		return ""
	}
	if ok, known := daemonSupportsAutoTransport(bin); ok || !known {
		return ""
	}
	cfg["transport"] = "udp"
	if err := saveConfig(cfg); err != nil {
		return fmt.Sprintf("the installed pilot-daemon does not support transport=auto (config.json); set it with: pilotctl config --set transport=udp (%v)", err)
	}
	return "the installed pilot-daemon predates transport=auto: config.json transport set to udp (after upgrading: pilotctl config --set transport=)"
}

// normalizeTransport lower-cases and validates a transport: udp, compat or
// auto ("" stays "").
func normalizeTransport(v string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "", "udp", "compat", "auto":
		return s, nil
	}
	return "", fmt.Errorf("invalid transport %q: must be 'udp', 'compat' or 'auto'", v)
}

// validateTransport accepts the tunnel transports pilot-daemon knows.
func validateTransport(v string) error {
	s, err := normalizeTransport(v)
	if err == nil && s == "" {
		err = fmt.Errorf("invalid transport %q: must be 'udp', 'compat' or 'auto'", v)
	}
	return err
}

// validateProxySetting accepts the -proxy contract: "auto" (use the
// environment's proxy in compat mode), "off" (or none/no/false/direct), or
// an explicit http(s)://[user:pass@]host:port proxy URL. See
// internal/proxyconf, which pilot-daemon uses too.
func validateProxySetting(v string) error {
	_, err := proxyconf.Normalize(v)
	return err
}

// proxyHasCredentials reports whether an explicit proxy URL carries
// userinfo. Any '@' counts, whatever url.Parse would make of the value, so
// a password with an unescaped '#', '/' or '?' still travels in the
// environment, never on argv.
func proxyHasCredentials(v string) bool {
	return proxyconf.HasCredentials(v)
}

// redactProxyURL hides proxy credentials for display: http://user:pass@h:p
// becomes http://***@h:p. "auto" and "off" pass through.
func redactProxyURL(v string) string {
	return proxyconf.Redact(v)
}

// resolveDaemonTransport picks the tunnel transport for `daemon start`:
// --transport, then $PILOT_TRANSPORT, then config.json "transport". "" means
// none was set: cmdDaemonStart then asks a daemon that supports it for
// auto, and otherwise leaves the daemon on its default (udp).
//
// The chosen value is handed to the daemon as an explicit -transport: a
// released pilot-daemon's -transport flag defaults to "udp", which masks
// the env var, so exporting PILOT_TRANSPORT alone never switched a daemon
// started through pilotctl.
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
	return normalizeTransport(v)
}

// resolveDaemonProxy picks the proxy for `daemon start`: --proxy, then
// $PILOT_PROXY, then config.json "proxy" — the same precedence pilot-daemon
// applies, so an explicitly passed flag or environment value always beats
// a persistent config default. "" means none was set (the daemon default,
// auto). The value is normalized ("none" becomes "off").
func resolveDaemonProxy(flags map[string]string, cfg map[string]interface{}) (string, error) {
	v := strings.TrimSpace(flagString(flags, "proxy", ""))
	if v == "" {
		v = strings.TrimSpace(os.Getenv("PILOT_PROXY"))
	}
	if v == "" {
		if s, ok := cfg["proxy"].(string); ok {
			v = strings.TrimSpace(s)
		}
	}
	if v == "" {
		return "", nil
	}
	return proxyconf.Normalize(v)
}

// compatSkipsDefault reports whether addr must be left off the daemon command
// line because it is the compiled-in raw-TCP production default and the
// daemon runs in compat mode. An older pilot-daemon only switches the
// registry to registry.pilotprotocol.network:443 (TLS) in compat mode when
// -registry was NOT given explicitly; `pilotctl init` writes the raw :9000
// default into config.json, and forwarding that verbatim pinned compat
// daemons to a non-TLS port no HTTPS proxy will CONNECT to.
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
//     default is dropped: an older daemon treats an env-provided registry as
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

// setEnv returns env with key set to value, replacing every existing entry
// for key (a child reads the first of duplicate entries on some paths and
// the last on others).
func setEnv(env []string, key, value string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if k, _, _ := strings.Cut(kv, "="); k == key {
			continue
		}
		out = append(out, kv)
	}
	return append(out, key+"="+value)
}

// sandboxProxyCmd is the proxy_cmd for hosted agent sandboxes: a fresh bash
// sees the sandbox's current proxy URL, whose credentials rotate (Meta Muse:
// every few minutes). install.sh saves the same command.
const sandboxProxyCmd = `bash -c 'printf %s "${https_proxy:-$HTTPS_PROXY}"'`

// Test seams for sandboxProxyCmdFor.
var (
	hostGOOS       = runtime.GOOS
	systemdRunning = func() bool {
		_, err := os.Stat("/run/systemd/system")
		return err == nil
	}
	bashAvailable = func() bool {
		_, err := exec.LookPath("bash")
		return err == nil
	}
)

// sandboxProxyCmdFor returns the $PILOT_PROXY_CMD `daemon start` hands the
// daemon when nothing configures one, "" when none applies. Without it a
// daemon keeps the proxy credentials it was started with, and once a
// sandbox rotates them every new connection fails with 407 ("node online,
// all apps broken"). It applies only when all of these hold:
//
//   - Linux without systemd (a container or VM such as a hosted agent
//     sandbox, where pilotctl rather than a service manager starts the
//     daemon);
//   - $HTTPS_PROXY or $https_proxy carries credentials;
//   - the proxy setting is auto (an explicit --proxy / $PILOT_PROXY URL is
//     left alone: the command would replace it);
//   - no proxy_cmd is configured: $PILOT_PROXY_CMD, and "proxy_cmd" in the
//     config file the daemon reads (--config, else ~/.pilot/config.json) and
//     in pilotctl's own config;
//   - bash is installed and the daemon at bin supports -proxy-cmd.
//
// It does not depend on the installer having saved proxy_cmd, so a node
// installed by an older installer gets it too.
func sandboxProxyCmdFor(bin string, plan daemonLaunchPlan, flags map[string]string) string {
	if sandboxRefreshCmd() == "" {
		return ""
	}
	if plan.Proxy != "" && plan.Proxy != proxyconf.Auto {
		return ""
	}
	if plan.ProxyCmd != "" || strings.TrimSpace(os.Getenv(proxyconf.EnvRefreshCommand)) != "" {
		return ""
	}
	if configuredProxyCmd(loadConfig()) != "" || configuredProxyCmd(daemonConfigFile(flags)) != "" {
		return ""
	}
	if f := daemonFlags(bin); !f["proxy-cmd"] {
		return ""
	}
	return sandboxProxyCmd
}

// sandboxRefreshCmd is sandboxProxyCmd on a host that looks like a hosted
// agent sandbox — Linux without systemd, $HTTPS_PROXY or $https_proxy
// carrying credentials, bash installed — and "" anywhere else.
func sandboxRefreshCmd() string {
	if hostGOOS != "linux" || systemdRunning() {
		return ""
	}
	if !proxyHasCredentials(os.Getenv("HTTPS_PROXY")) && !proxyHasCredentials(os.Getenv("https_proxy")) {
		return ""
	}
	if !bashAvailable() {
		return ""
	}
	return sandboxProxyCmd
}

func configuredProxyCmd(cfg map[string]interface{}) string {
	s, _ := cfg["proxy_cmd"].(string)
	return strings.TrimSpace(s)
}

// daemonConfigFile reads the config file pilot-daemon loads: --config, else
// $HOME/.pilot/config.json. Empty when it cannot be read.
func daemonConfigFile(flags map[string]string) map[string]interface{} {
	path := flagString(flags, "config", "")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil
		}
		path = filepath.Join(home, ".pilot", "config.json")
	}
	b, err := os.ReadFile(path) // #nosec G304 -- the operator's own config path
	if err != nil {
		return nil
	}
	var cfg map[string]interface{}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	return cfg
}

// daemonFlagProbeTimeout bounds the `pilot-daemon -help` flag probe.
const daemonFlagProbeTimeout = 5 * time.Second

var (
	daemonFlagCacheMu sync.Mutex
	daemonFlagCache   = map[string]map[string]string{}
)

// daemonFlagUsage returns the flags the pilot-daemon binary at bin defines,
// mapped to their usage text, parsed from its Go flag-package `-help`
// output ("  -name type" followed by indented usage lines). The binary is
// probed once per process. Returns nil when it could not be probed or
// printed nothing recognisable; callers treat nil as "unknown" and keep
// the flag.
func daemonFlagUsage(bin string) map[string]string {
	daemonFlagCacheMu.Lock()
	defer daemonFlagCacheMu.Unlock()
	if set, ok := daemonFlagCache[bin]; ok {
		return set
	}
	ctx, cancel := context.WithTimeout(context.Background(), daemonFlagProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-help")
	// Minimal environment: -help prints each flag's default, and an older
	// daemon with env-backed defaults would echo e.g. a credential-bearing
	// $PILOT_PROXY into the captured output.
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	out, _ := cmd.CombinedOutput() // -help exits 0 (flag.ExitOnError) or 2 on older builds
	var set map[string]string
	current := ""
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "  -") {
			name := strings.TrimPrefix(line, "  -")
			if i := strings.IndexAny(name, " \t"); i >= 0 {
				name = name[:i]
			}
			current = name
			if name == "" {
				continue
			}
			if set == nil {
				set = map[string]string{}
			}
			set[name] = ""
			continue
		}
		if current != "" && (strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")) {
			set[current] += strings.TrimSpace(line) + " "
		}
	}
	daemonFlagCache[bin] = set
	return set
}

// daemonFlags returns the set of flag names the pilot-daemon binary at bin
// defines (see daemonFlagUsage), nil when unknown.
func daemonFlags(bin string) map[string]bool {
	usage := daemonFlagUsage(bin)
	if usage == nil {
		return nil
	}
	set := make(map[string]bool, len(usage))
	for name := range usage {
		set[name] = true
	}
	return set
}

// autoTransportRe matches the -transport usage of a daemon that accepts
// -transport=auto.
var autoTransportRe = regexp.MustCompile(`'auto'`)

// daemonSupportsAutoTransport reports whether the daemon at bin accepts
// -transport=auto, and whether that is known at all.
func daemonSupportsAutoTransport(bin string) (supported, known bool) {
	usage := daemonFlagUsage(bin)
	if usage == nil {
		return false, false
	}
	u, ok := usage["transport"]
	return ok && autoTransportRe.MatchString(u), true
}

// adaptDaemonArgs fits a launch plan to the pilot-daemon binary at bin
// (probed once): a flag or value the daemon does not know would abort it
// on startup, and a new pilotctl is still paired with older daemons (a
// sibling binary left behind by a partial upgrade, a PILOT_DAEMON_BIN
// override, an npm-installed pair).
//
//   - No transport configured: a daemon that supports -transport=auto gets
//     it (udp when UDP works, compat when only TCP 443 does); an older one
//     keeps its default, udp, silently.
//   - -transport=auto on a daemon without it becomes -transport=udp (an
//     older daemon would also read "auto" from config.json and fail), with
//     a warning.
//   - -transport / -proxy on a daemon without the flag are dropped with a
//     warning, and so is a proxy handed over as $PILOT_PROXY.
//
// It returns the argv and the $PILOT_PROXY value to use, and the transport
// actually requested ("" = the daemon's default).
func adaptDaemonArgs(bin string, plan daemonLaunchPlan) (args []string, proxyEnv, transport string) {
	args = append([]string(nil), plan.Args...)
	proxyEnv = plan.ProxyEnv
	transport = plan.Transport
	flags := daemonFlags(bin)
	warn := func(format string, a ...interface{}) {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "warning: "+format+"\n", a...)
		}
	}

	switch {
	case transport == "":
		if ok, _ := daemonSupportsAutoTransport(bin); ok {
			args = append(args, "--transport", "auto")
			transport = "auto"
		}
	case transport == "auto":
		if ok, known := daemonSupportsAutoTransport(bin); known && !ok {
			if flags["transport"] {
				warn("%s does not support -transport=auto (older pilot-daemon); starting it with -transport=udp — upgrade pilot-daemon to use auto", bin)
				args = replaceFlagValue(args, "--transport", "udp")
				transport = "udp"
			} else {
				warn("%s does not support -transport (older pilot-daemon); not passing -transport auto — upgrade pilot-daemon to use it", bin)
				args = removeFlag(args, "--transport")
				transport = ""
			}
		}
	default:
		if flags != nil && !flags["transport"] {
			warn("%s does not support -transport (older pilot-daemon); not passing -transport %s — upgrade pilot-daemon to use it", bin, transport)
			args = removeFlag(args, "--transport")
			transport = ""
		}
	}

	if flags != nil && !flags["proxy"] {
		if hasFlag(args, "--proxy") {
			warn("%s does not support -proxy (older pilot-daemon); not passing -proxy %s — upgrade pilot-daemon to use it", bin, redactProxyURL(flagValue(args, "--proxy")))
			args = removeFlag(args, "--proxy")
		}
		if proxyEnv != "" {
			warn("%s does not support -proxy (older pilot-daemon); proxy %s will not be used — upgrade pilot-daemon to use it", bin, redactProxyURL(proxyEnv))
			proxyEnv = ""
		}
	}
	return args, proxyEnv, transport
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

// removeFlag drops every "name value" pair from args.
func removeFlag(args []string, name string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			i++ // skip the value
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// replaceFlagValue sets the value of every "name value" pair in args.
func replaceFlagValue(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i := 0; i+1 < len(out); i++ {
		if out[i] == name {
			out[i+1] = value
		}
	}
	return out
}

// daemonLogTransportRe finds the transport pilot-daemon reports on its
// "outbound network" startup line, in text or JSON log format.
var daemonLogTransportRe = regexp.MustCompile(`outbound network"?[ ,]+"?transport"?[=:]"?(udp|compat)`)

// transportFromDaemonLog returns the transport the daemon logged at
// startup ("" if unknown) — the only place the outcome of -transport=auto
// is visible to pilotctl.
func transportFromDaemonLog(path string) string {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- the per-PID daemon log daemon start itself created under the config dir
	if err != nil {
		return ""
	}
	m := daemonLogTransportRe.FindAllSubmatch(b, -1)
	if len(m) == 0 {
		return ""
	}
	return string(m[len(m)-1][1])
}

// effectiveTransport is what `daemon start` reports: the transport the
// daemon logged at startup, else the one requested ("" when neither is
// known), and whether -transport=auto chose it.
func effectiveTransport(requested, logPath string) (transport string, auto bool) {
	auto = requested == "auto"
	if logged := transportFromDaemonLog(logPath); logged != "" {
		return logged, auto
	}
	if auto {
		return "", true
	}
	return requested, false
}
