// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withTransportEnvCleared isolates HOME like withTempHomeFull and also blanks
// every variable planDaemonLaunch / daemonChildEnv read, so a developer shell
// exporting HTTPS_PROXY or PILOT_TRANSPORT cannot leak into assertions.
func withTransportEnvCleared(t *testing.T) string {
	t.Helper()
	tmp := withTempHomeFull(t)
	t.Setenv("PILOT_BEACON", "")
	for _, k := range daemonForwardEnv {
		t.Setenv(k, "")
	}
	return tmp
}

func argsHasPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func argsHasKey(args []string, key string) bool {
	for _, a := range args {
		if a == key {
			return true
		}
	}
	return false
}

func TestResolveDaemonTransportPrecedence(t *testing.T) {
	withTransportEnvCleared(t)
	cfg := map[string]interface{}{"transport": "udp"}

	if got, err := resolveDaemonTransport(map[string]string{}, map[string]interface{}{}); err != nil || got != "" {
		t.Fatalf("unset: got %q, %v; want \"\", nil", got, err)
	}
	if got, _ := resolveDaemonTransport(map[string]string{}, cfg); got != "udp" {
		t.Errorf("config: got %q, want udp", got)
	}
	t.Setenv("PILOT_TRANSPORT", "compat")
	if got, _ := resolveDaemonTransport(map[string]string{}, cfg); got != "compat" {
		t.Errorf("env should beat config: got %q", got)
	}
	if got, _ := resolveDaemonTransport(map[string]string{"transport": "udp"}, cfg); got != "udp" {
		t.Errorf("flag should beat env: got %q", got)
	}
	if _, err := resolveDaemonTransport(map[string]string{"transport": "quic"}, cfg); err == nil {
		t.Error("invalid transport must error")
	}
	t.Setenv("PILOT_TRANSPORT", "")
	if _, err := resolveDaemonTransport(map[string]string{}, map[string]interface{}{"transport": "compact"}); err == nil {
		t.Error("invalid config transport must error")
	}
}

func TestResolveDaemonProxyPrecedenceAndValidation(t *testing.T) {
	withTransportEnvCleared(t)
	// $PILOT_PROXY is the daemon's to resolve, never pilotctl's.
	t.Setenv("PILOT_PROXY", "off")
	if got, err := resolveDaemonProxy(map[string]string{}, map[string]interface{}{}); err != nil || got != "" {
		t.Fatalf("unset: got %q, %v", got, err)
	}
	cfg := map[string]interface{}{"proxy": "auto"}
	if got, _ := resolveDaemonProxy(map[string]string{}, cfg); got != "auto" {
		t.Errorf("config: got %q", got)
	}
	if got, _ := resolveDaemonProxy(map[string]string{"proxy": "http://p.example:3128"}, cfg); got != "http://p.example:3128" {
		t.Errorf("flag should beat config: got %q", got)
	}
	for _, ok := range []string{"auto", "off", "http://p:3128", "https://u:pw@p.example:443", "http://u@p"} {
		if err := validateProxySetting(ok); err != nil {
			t.Errorf("validateProxySetting(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"true", "socks5://p:1080", "p.example:3128", "http://", "u:pw@p:3128", "AUTO"} {
		err := validateProxySetting(bad)
		if err == nil {
			t.Errorf("validateProxySetting(%q) = nil, want error", bad)
			continue
		}
		if strings.Contains(err.Error(), "pw") {
			t.Errorf("error for %q leaks credentials: %v", bad, err)
		}
	}
}

func TestRedactProxyURL(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"auto":                            "auto",
		"off":                             "off",
		"http://proxy:3128":               "http://proxy:3128",
		"http://user:s3cret@proxy:3128":   "http://***@proxy:3128",
		"https://user@proxy.example:8443": "https://***@proxy.example:8443",
		"http://u:p%40ss@proxy:3128/":     "http://***@proxy:3128/",
		"user:s3cret@proxy:3128":          "***@proxy:3128",
		"http://us er:s3cret@proxy:3128":  "http://***@proxy:3128",
	}
	for in, want := range cases {
		got := redactProxyURL(in)
		if got != want {
			t.Errorf("redactProxyURL(%q) = %q, want %q", in, got, want)
		}
		if strings.Contains(got, "s3cret") {
			t.Errorf("redactProxyURL(%q) leaked the password: %q", in, got)
		}
	}
}

// TestBuildDaemonArgsUDPUnchanged pins backward compatibility: with no
// transport/proxy configured, the daemon command line is exactly what older
// pilotctl produced — the default registry/beacon are forwarded and neither
// --transport nor --proxy appears, so an older pilot-daemon still starts.
func TestBuildDaemonArgsUDPUnchanged(t *testing.T) {
	withTransportEnvCleared(t)
	if err := saveConfig(map[string]interface{}{
		"registry": productionRegistryAddr,
		"beacon":   productionBeaconAddr,
	}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	args, _, _ := buildDaemonArgs(nil)
	if !argsHasPair(args, "--registry", productionRegistryAddr) || !argsHasPair(args, "--beacon", productionBeaconAddr) {
		t.Errorf("udp mode must forward registry/beacon: %v", args)
	}
	for _, k := range []string{"--transport", "--proxy", "--endpoint", "--compat-beacon"} {
		if argsHasKey(args, k) {
			t.Errorf("unexpected %s in default args %v", k, args)
		}
	}
}

// TestBuildDaemonArgsCompatFromConfig is the Meta Muse shape: config.json from
// `pilotctl init` carries the raw-TCP registry default plus transport=compat
// and proxy=auto (install.sh --transport compat). The registry/beacon defaults
// must stay off argv so the daemon's compat 443/TLS defaults apply.
func TestBuildDaemonArgsCompatFromConfig(t *testing.T) {
	withTransportEnvCleared(t)
	if err := saveConfig(map[string]interface{}{
		"registry":  productionRegistryAddr,
		"beacon":    productionBeaconAddr,
		"transport": "compat",
		"proxy":     "auto",
	}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	plan := planDaemonLaunch(nil)
	if !argsHasPair(plan.Args, "--transport", "compat") {
		t.Errorf("expected --transport compat: %v", plan.Args)
	}
	if !argsHasPair(plan.Args, "--proxy", "auto") {
		t.Errorf("expected --proxy auto: %v", plan.Args)
	}
	if argsHasKey(plan.Args, "--registry") || argsHasKey(plan.Args, "--beacon") {
		t.Errorf("compat mode must not pin the raw-TCP defaults: %v", plan.Args)
	}
	if plan.Transport != "compat" || plan.Proxy != "auto" || plan.ProxyEnv != "" {
		t.Errorf("plan = %+v", plan)
	}
}

// TestBuildDaemonArgsCompatKeepsCustomRegistry: only the compiled-in default
// is dropped; an operator-chosen registry is forwarded even in compat mode.
func TestBuildDaemonArgsCompatKeepsCustomRegistry(t *testing.T) {
	withTransportEnvCleared(t)
	args, _, _ := buildDaemonArgs([]string{
		"--transport", "compat",
		"--registry", "registry.example:443",
		"--beacon", productionBeaconAddr,
	})
	if !argsHasPair(args, "--registry", "registry.example:443") {
		t.Errorf("custom registry must be forwarded: %v", args)
	}
	if argsHasKey(args, "--beacon") {
		t.Errorf("default beacon must be dropped in compat mode: %v", args)
	}
	// An explicit --registry equal to the default is still "not explicit".
	args, _, _ = buildDaemonArgs([]string{"--transport", "compat", "--registry", productionRegistryAddr})
	if argsHasKey(args, "--registry") {
		t.Errorf("default registry must be dropped in compat mode: %v", args)
	}
}

// TestBuildDaemonArgsTransportFromEnv: $PILOT_TRANSPORT becomes an explicit
// -transport (the daemon's own -transport default masks the env var).
func TestBuildDaemonArgsTransportFromEnv(t *testing.T) {
	withTransportEnvCleared(t)
	t.Setenv("PILOT_TRANSPORT", "compat")
	args, _, _ := buildDaemonArgs(nil)
	if !argsHasPair(args, "--transport", "compat") {
		t.Errorf("expected --transport compat from env: %v", args)
	}
	if argsHasKey(args, "--registry") {
		t.Errorf("compat from env must drop the default registry: %v", args)
	}
	if argsHasKey(args, "--proxy") {
		t.Errorf("--proxy must not be passed when unset: %v", args)
	}
}

// TestBuildDaemonArgsProxyCredentialsViaEnv: a proxy URL with userinfo never
// lands on argv (PILOT-290); it is carried in plan.ProxyEnv instead.
func TestBuildDaemonArgsProxyCredentialsViaEnv(t *testing.T) {
	withTransportEnvCleared(t)
	plan := planDaemonLaunch([]string{"--proxy", "http://user:s3cret@proxy.example:3128"})
	if strings.Contains(strings.Join(plan.Args, " "), "s3cret") || argsHasKey(plan.Args, "--proxy") {
		t.Errorf("credentialed proxy leaked onto argv: %v", plan.Args)
	}
	if plan.ProxyEnv != "http://user:s3cret@proxy.example:3128" {
		t.Errorf("ProxyEnv = %q", plan.ProxyEnv)
	}
	plan = planDaemonLaunch([]string{"--proxy", "http://proxy.example:3128"})
	if !argsHasPair(plan.Args, "--proxy", "http://proxy.example:3128") || plan.ProxyEnv != "" {
		t.Errorf("credential-free proxy should go on argv: %+v", plan)
	}
}

func TestBuildDaemonArgsForwardsOptionalDaemonFlags(t *testing.T) {
	withTransportEnvCleared(t)
	args, _, _ := buildDaemonArgs([]string{
		"--endpoint", "203.0.113.7:4000",
		"--compat-beacon", "wss://beacon.example/v1/compat",
		"--registry-trust", "pinned",
		"--registry-fingerprint", "abcd",
		"--tls-trust", "system",
		"--motd-feed-url", "",
		"--motd-interval", "30m",
	})
	for k, v := range map[string]string{
		"--endpoint":             "203.0.113.7:4000",
		"--compat-beacon":        "wss://beacon.example/v1/compat",
		"--registry-trust":       "pinned",
		"--registry-fingerprint": "abcd",
		"--tls-trust":            "system",
		"--motd-feed-url":        "",
		"--motd-interval":        "30m",
	} {
		if !argsHasPair(args, k, v) {
			t.Errorf("expected %s %q in %v", k, v, args)
		}
	}
}

func TestDaemonChildEnvForwardsProxyVars(t *testing.T) {
	t.Parallel()
	base := []string{"PATH=/usr/bin", "HOME=/home/agent"}
	for _, k := range daemonForwardEnv {
		base = append(base, k+"=value-of-"+k)
	}
	env := daemonChildEnv(base, "", "", "")
	have := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		have[k] = v
	}
	for _, k := range append([]string{"PATH", "HOME"}, daemonForwardEnv...) {
		if _, ok := have[k]; !ok {
			t.Errorf("%s was not forwarded to the daemon", k)
		}
	}
	if have["HTTPS_PROXY"] != "value-of-HTTPS_PROXY" {
		t.Errorf("HTTPS_PROXY = %q", have["HTTPS_PROXY"])
	}
}

func TestDaemonChildEnvOverrides(t *testing.T) {
	t.Parallel()
	base := []string{
		"PILOT_ADMIN_TOKEN=stale",
		"PILOT_PROXY=off",
		"PILOT_REGISTRY=" + productionRegistryAddr,
		"HTTPS_PROXY=http://u:p@proxy:3128",
	}
	count := func(env []string, key string) (n int, last string) {
		for _, kv := range env {
			if k, v, _ := strings.Cut(kv, "="); k == key {
				n++
				last = v
			}
		}
		return
	}

	env := daemonChildEnv(base, "tok", "http://u:p@proxy2:3128", "compat")
	if n, v := count(env, "PILOT_ADMIN_TOKEN"); n != 1 || v != "tok" {
		t.Errorf("PILOT_ADMIN_TOKEN: n=%d v=%q", n, v)
	}
	if n, v := count(env, "PILOT_PROXY"); n != 1 || v != "http://u:p@proxy2:3128" {
		t.Errorf("PILOT_PROXY: n=%d v=%q", n, v)
	}
	if n, _ := count(env, "PILOT_REGISTRY"); n != 0 {
		t.Errorf("compat mode must drop the default PILOT_REGISTRY: %v", env)
	}
	if n, _ := count(env, "HTTPS_PROXY"); n != 1 {
		t.Errorf("HTTPS_PROXY must be forwarded: %v", env)
	}

	// udp mode: nothing overridden, PILOT_REGISTRY kept.
	env = daemonChildEnv(base, "", "", "udp")
	if n, v := count(env, "PILOT_REGISTRY"); n != 1 || v != productionRegistryAddr {
		t.Errorf("udp mode must keep PILOT_REGISTRY: %v", env)
	}
	if n, v := count(env, "PILOT_ADMIN_TOKEN"); n != 1 || v != "stale" {
		t.Errorf("no override: PILOT_ADMIN_TOKEN n=%d v=%q", n, v)
	}
}

// writeFakeDaemon writes an executable shell script standing in for
// pilot-daemon. Its -help lists exactly the given flags (Go flag-package
// format); any other invocation records argv and environment to out and, like
// Go's flag package, dies on a flag it does not define.
func writeFakeDaemon(t *testing.T, flags []string, out string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake daemon")
	}
	dir := t.TempDir()
	var help strings.Builder
	var known strings.Builder
	for _, f := range flags {
		help.WriteString("  -" + f + " string\n    \tdescription of " + f + "\n")
		known.WriteString(" -" + f + " --" + f)
	}
	script := `#!/bin/sh
if [ "$1" = "-help" ]; then
  echo "Usage of pilot-daemon:" >&2
  cat >&2 <<'HELP'
` + help.String() + `HELP
  exit 0
fi
: > "` + out + `.args"
for a in "$@"; do
  case "$a" in
    -*)
      name="${a%%=*}"
      case "` + known.String() + ` " in
        *" $name "*) ;;
        *) echo "flag provided but not defined: $name" >&2; exit 2 ;;
      esac ;;
  esac
  printf '%s\n' "$a" >> "` + out + `.args"
done
env > "` + out + `.env"
exit 0
`
	path := filepath.Join(dir, "pilot-daemon")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake daemon: %v", err)
	}
	return path
}

var baseDaemonFlags = []string{
	"registry", "beacon", "listen", "socket", "identity", "log-level", "log-format",
	"encrypt", "email", "hostname", "config", "public", "webhook", "networks",
	"trust-auto-approve", "enterprise-control", "endpoint", "compat-beacon",
	"registry-trust", "registry-fingerprint", "tls-trust", "motd-feed-url", "motd-interval",
}

func TestDaemonFlagsProbe(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "probe")
	bin := writeFakeDaemon(t, append([]string{"transport"}, baseDaemonFlags...), out)
	set := daemonFlags(bin)
	if !set["transport"] || !set["registry"] || set["proxy"] {
		t.Errorf("probe parsed %v", set)
	}
	if got := daemonFlags(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Errorf("missing binary should probe as unknown (nil), got %v", got)
	}
}

// TestDropUnsupportedDaemonFlags: an older daemon (no -proxy, or neither
// -proxy nor -transport) gets those flags stripped instead of crashing on
// them; a current daemon — or one that cannot be probed — keeps them.
func TestDropUnsupportedDaemonFlags(t *testing.T) {
	t.Parallel()
	args := []string{"--listen", ":0", "--transport", "compat", "--proxy", "auto", "--socket", "/tmp/x.sock"}
	dir := t.TempDir()

	v1139 := writeFakeDaemon(t, append([]string{"transport"}, baseDaemonFlags...), filepath.Join(dir, "a"))
	got := dropUnsupportedDaemonFlags(v1139, args)
	if argsHasKey(got, "--proxy") || argsHasKey(got, "auto") {
		t.Errorf("v1.13.9-style daemon must not get --proxy: %v", got)
	}
	if !argsHasPair(got, "--transport", "compat") || !argsHasPair(got, "--socket", "/tmp/x.sock") {
		t.Errorf("supported flags must survive: %v", got)
	}

	ancient := writeFakeDaemon(t, baseDaemonFlags, filepath.Join(dir, "b"))
	got = dropUnsupportedDaemonFlags(ancient, args)
	if argsHasKey(got, "--proxy") || argsHasKey(got, "--transport") {
		t.Errorf("pre-compat daemon must get neither flag: %v", got)
	}
	if !argsHasPair(got, "--listen", ":0") {
		t.Errorf("unrelated flags must survive: %v", got)
	}

	current := writeFakeDaemon(t, append([]string{"transport", "proxy"}, baseDaemonFlags...), filepath.Join(dir, "c"))
	got = dropUnsupportedDaemonFlags(current, args)
	if strings.Join(got, " ") != strings.Join(args, " ") {
		t.Errorf("current daemon must keep every flag: %v", got)
	}

	got = dropUnsupportedDaemonFlags(filepath.Join(dir, "missing"), args)
	if strings.Join(got, " ") != strings.Join(args, " ") {
		t.Errorf("unprobeable daemon must keep every flag: %v", got)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// cliEnvCleared blanks the variables that would otherwise leak from the
// developer shell into a runCLI child and skew daemon start.
func cliEnvCleared(extra map[string]string) map[string]string {
	env := map[string]string{
		"PILOT_HOME":        "",
		"PILOT_REGISTRY":    "",
		"PILOT_BEACON":      "",
		"PILOT_ADMIN_TOKEN": "",
	}
	for _, k := range daemonForwardEnv {
		env[k] = ""
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// TestCLIDaemonStartForegroundCompatProxy drives the real `daemon start
// --foreground` exec path against a fake current daemon and checks what the
// daemon actually receives: compat flags on argv, no raw-TCP registry
// default, the credentialed proxy in env (not argv), and every proxy/TLS
// variable forwarded.
func TestCLIDaemonStartForegroundCompatProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{"transport", "proxy"}, baseDaemonFlags...), out)
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(dir, "pilot.sock"),
		"PILOT_TRANSPORT":  "compat",
		"HTTPS_PROXY":      "http://agent:s3cret@egress.internal:3128",
		"https_proxy":      "http://agent:s3cret@egress.internal:3128",
		"NO_PROXY":         "localhost,127.0.0.1",
		"no_proxy":         "localhost,127.0.0.1",
		"ALL_PROXY":        "http://agent:s3cret@egress.internal:3128",
		"SSL_CERT_FILE":    "/etc/ssl/muse/ca.pem",
		"SSL_CERT_DIR":     "/etc/ssl/muse",
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground", "--proxy", "http://agent:s3cret@egress.internal:3128"}, env)
	if code != 0 {
		t.Fatalf("daemon start --foreground exit=%d stderr=%s", code, stderr)
	}
	args := readLines(t, out+".args")
	if !argsHasPair(args, "--transport", "compat") {
		t.Errorf("daemon argv missing --transport compat: %v", args)
	}
	if argsHasKey(args, "--registry") || argsHasKey(args, "--beacon") {
		t.Errorf("compat daemon argv must not pin the raw-TCP defaults: %v", args)
	}
	if strings.Contains(strings.Join(args, " "), "s3cret") {
		t.Errorf("proxy credentials leaked onto daemon argv: %v", args)
	}
	got := map[string]string{}
	for _, kv := range readLines(t, out+".env") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v
		}
	}
	if got["PILOT_PROXY"] != "http://agent:s3cret@egress.internal:3128" {
		t.Errorf("PILOT_PROXY = %q, want the credentialed --proxy", got["PILOT_PROXY"])
	}
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "PILOT_TRANSPORT"} {
		if got[k] == "" {
			t.Errorf("%s did not reach the daemon", k)
		}
	}
}

// TestCLIDaemonStartForegroundOlderDaemon: config.json asks for compat +
// proxy=auto but the paired pilot-daemon predates -proxy. The start must
// still succeed (flag dropped with a warning) instead of crash-looping.
func TestCLIDaemonStartForegroundOlderDaemon(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{"transport"}, baseDaemonFlags...), out)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := `{"registry":"` + productionRegistryAddr + `","transport":"compat","proxy":"auto"}`
	if err := os.WriteFile(filepath.Join(home, ".pilot", "config.json"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(dir, "pilot.sock"),
		"PILOT_HOME":       home,
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "does not support -proxy") {
		t.Errorf("expected a skew warning, stderr=%s", stderr)
	}
	args := readLines(t, out+".args")
	if argsHasKey(args, "--proxy") {
		t.Errorf("older daemon must not receive --proxy: %v", args)
	}
	if !argsHasPair(args, "--transport", "compat") || argsHasKey(args, "--registry") {
		t.Errorf("compat args wrong: %v", args)
	}
}

func TestCLIDaemonStartRejectsBadTransport(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--transport", "compact"}, cliEnvCleared(nil))
	if code == 0 || !strings.Contains(stderr, "invalid transport") {
		t.Errorf("exit=%d stderr=%s", code, stderr)
	}
	_, stderr, code = runCLI(t, []string{"daemon", "start", "--proxy", "socks5://u:s3cret@p:1080"}, cliEnvCleared(nil))
	if code == 0 || !strings.Contains(stderr, "invalid proxy") {
		t.Errorf("exit=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stderr, "s3cret") {
		t.Errorf("invalid-proxy error leaked credentials: %s", stderr)
	}
}

func TestCLIConfigSetProxyRedactsAndValidates(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	env := cliEnvCleared(map[string]string{"PILOT_HOME": home})
	stdout, stderr, code := runCLI(t, []string{"--json", "config", "--set", "proxy=http://agent:s3cret@egress:3128"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if strings.Contains(stdout, "s3cret") || !strings.Contains(stdout, "***@egress:3128") {
		t.Errorf("config --set must echo the redacted proxy: %s", stdout)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".pilot", "config.json"))
	if err != nil || !strings.Contains(string(raw), "agent:s3cret@egress:3128") {
		t.Errorf("config.json must keep the real value: %s %v", raw, err)
	}
	stdout, _, code = runCLI(t, []string{"--json", "config"}, env)
	if code != 0 || strings.Contains(stdout, "s3cret") {
		t.Errorf("config show leaked the proxy password (exit=%d): %s", code, stdout)
	}
	_, stderr, code = runCLI(t, []string{"config", "--set", "transport=compact"}, env)
	if code == 0 || !strings.Contains(stderr, "invalid transport") {
		t.Errorf("config --set transport=compact: exit=%d stderr=%s", code, stderr)
	}
	_, _, code = runCLI(t, []string{"config", "--set", "transport=compat"}, env)
	if code != 0 {
		t.Errorf("config --set transport=compat: exit=%d", code)
	}
}

func TestRegistryDialHintMentionsProxy(t *testing.T) {
	withTransportEnvCleared(t)
	if h := registryDialHint("r:9000"); !strings.Contains(h, "PILOT_REGISTRY") {
		t.Errorf("no-proxy hint = %q", h)
	}
	t.Setenv("HTTPS_PROXY", "http://agent:s3cret@egress:3128")
	h := registryDialHint("r:9000")
	if !strings.Contains(h, "does not use the proxy") || strings.Contains(h, "s3cret") {
		t.Errorf("proxy hint = %q", h)
	}
}
