// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const autoUsage = "transport=tunnel transport: 'udp' (the default), 'compat' (...) or 'auto' (...)"

// v1.13.9's -transport usage: no 'auto'.
const v1139TransportUsage = "transport=tunnel transport: 'udp' (default) or 'compat' (WSS to beacon, opt-in, for UDP-blocked environments)"

func TestDaemonFlagUsageParsesUsage(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cur := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), filepath.Join(dir, "a"))
	if ok, known := daemonSupportsAutoTransport(cur); !ok || !known {
		t.Errorf("current daemon: auto=(%v, %v), want supported", ok, known)
	}
	old := writeFakeDaemon(t, append([]string{v1139TransportUsage}, baseDaemonFlags...), filepath.Join(dir, "b"))
	if ok, known := daemonSupportsAutoTransport(old); ok || !known {
		t.Errorf("v1.13.9 daemon: auto=(%v, %v), want known unsupported", ok, known)
	}
	if ok, known := daemonSupportsAutoTransport(filepath.Join(dir, "missing")); ok || known {
		t.Errorf("missing daemon: auto=(%v, %v), want unknown", ok, known)
	}
}

// adaptDaemonArgs: new pilotctl × old/new daemon. Nothing a daemon does not
// know ever reaches its argv, and an unconfigured transport becomes auto
// only where auto exists.
func TestAdaptDaemonArgs(t *testing.T) {
	withTransportEnvCleared(t)
	dir := t.TempDir()
	current := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), filepath.Join(dir, "cur"))
	v1139 := writeFakeDaemon(t, append([]string{v1139TransportUsage}, baseDaemonFlags...), filepath.Join(dir, "v1139"))
	ancient := writeFakeDaemon(t, baseDaemonFlags, filepath.Join(dir, "ancient"))
	base := []string{"--registry", productionRegistryAddr, "--listen", ":0"}

	for _, tc := range []struct {
		name          string
		bin           string
		plan          daemonLaunchPlan
		wantTransport string // value of --transport on argv, "" = absent
		wantProxyArg  string
		wantProxyEnv  string
	}{
		{"unset + current → auto", current, daemonLaunchPlan{Args: base}, "auto", "", ""},
		{"unset + v1.13.9 → daemon default", v1139, daemonLaunchPlan{Args: base}, "", "", ""},
		{"unset + ancient → daemon default", ancient, daemonLaunchPlan{Args: base}, "", "", ""},
		{"unset + unprobeable → daemon default", filepath.Join(dir, "missing"), daemonLaunchPlan{Args: base}, "", "", ""},
		{"auto + v1.13.9 → udp", v1139, daemonLaunchPlan{Args: append(base, "--transport", "auto"), Transport: "auto"}, "udp", "", ""},
		{"auto + ancient → dropped", ancient, daemonLaunchPlan{Args: append(base, "--transport", "auto"), Transport: "auto"}, "", "", ""},
		{"compat + v1.13.9 kept", v1139, daemonLaunchPlan{Args: append(base, "--transport", "compat"), Transport: "compat"}, "compat", "", ""},
		{"compat + ancient dropped", ancient, daemonLaunchPlan{Args: append(base, "--transport", "compat"), Transport: "compat"}, "", "", ""},
		{"proxy + v1.13.9 dropped", v1139,
			daemonLaunchPlan{Args: append(base, "--transport", "compat", "--proxy", "off"), Transport: "compat", Proxy: "off"}, "compat", "", ""},
		{"cred proxy env + v1.13.9 dropped", v1139,
			daemonLaunchPlan{Args: base, Transport: "", Proxy: "http://u:p@x:1", ProxyEnv: "http://u:p@x:1"}, "", "", ""},
		{"current keeps everything", current,
			daemonLaunchPlan{Args: append(base, "--transport", "compat", "--proxy", "off"), Transport: "compat", Proxy: "off"}, "compat", "off", ""},
		{"current keeps the env proxy", current,
			daemonLaunchPlan{Args: base, Proxy: "http://u:p@x:1", ProxyEnv: "http://u:p@x:1"}, "auto", "", "http://u:p@x:1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, proxyEnv, _ := adaptDaemonArgs(tc.bin, tc.plan)
			if got := flagValue(args, "--transport"); got != tc.wantTransport || (tc.wantTransport == "" && hasFlag(args, "--transport")) {
				t.Errorf("--transport = %q (args %v), want %q", got, args, tc.wantTransport)
			}
			if got := flagValue(args, "--proxy"); got != tc.wantProxyArg || (tc.wantProxyArg == "" && hasFlag(args, "--proxy")) {
				t.Errorf("--proxy = %q (args %v), want %q", got, args, tc.wantProxyArg)
			}
			if proxyEnv != tc.wantProxyEnv {
				t.Errorf("proxy env = %q, want %q", proxyEnv, tc.wantProxyEnv)
			}
			if !argsHasPair(args, "--registry", productionRegistryAddr) || !argsHasPair(args, "--listen", ":0") {
				t.Errorf("unrelated args lost: %v", args)
			}
		})
	}
}

// The real `daemon start --foreground` path against a current daemon with
// no transport configured anywhere: the daemon is asked for auto.
func TestCLIDaemonStartImplicitAuto(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), out)
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(dir, "pilot.sock"),
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	args := readLines(t, out+".args")
	if !argsHasPair(args, "--transport", "auto") {
		t.Errorf("daemon argv lacks --transport auto: %v", args)
	}
	if !argsHasPair(args, "--registry", productionRegistryAddr) {
		t.Errorf("auto must keep the registry on argv (an old daemon given udp needs it): %v", args)
	}
}

// config.json "proxy":"auto" must not override a credential-bearing
// --proxy: the URL travels as $PILOT_PROXY (which pilot-daemon ranks above
// config.json) and nothing on argv contradicts it.
func TestCLIDaemonStartCredProxyBeatsConfigAuto(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), out)
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".pilot", "config.json"), []byte(`{"transport":"compat","proxy":"auto"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(dir, "pilot.sock"),
		"PILOT_HOME":       home,
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground", "--proxy", "http://u:s3cret@corp:3128"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	args := readLines(t, out+".args")
	if hasFlag(args, "--proxy") {
		t.Errorf("argv carries a --proxy that would outrank the credentialed one: %v", args)
	}
	got := map[string]string{}
	for _, kv := range readLines(t, out+".env") {
		if k, v, ok := strings.Cut(kv, "="); ok {
			got[k] = v
		}
	}
	if got["PILOT_PROXY"] != "http://u:s3cret@corp:3128" {
		t.Errorf("PILOT_PROXY = %q", got["PILOT_PROXY"])
	}

	// Same with the URL exported as $PILOT_PROXY instead of --proxy.
	env["PILOT_PROXY"] = "http://u:s3cret@corp:3128"
	if _, stderr, code = runCLI(t, []string{"daemon", "start", "--foreground"}, env); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if args := readLines(t, out+".args"); hasFlag(args, "--proxy") {
		t.Errorf("$PILOT_PROXY lost to config.json's auto on argv: %v", args)
	}
}

// routeSpec renders a route for comparison: "addr[/tls][/pin][ via proxy]".
func routeSpec(r registryRoute) string {
	s := r.Addr
	if r.TLS {
		s += "/tls"
	}
	if r.Fingerprint != "" {
		s += "/pin"
	}
	if p := r.proxyFor(r.Addr); p != "" {
		s += " via proxy"
	}
	return s
}

func TestPlanRegistryRoutes(t *testing.T) {
	const fp = "c1f958f6bcff667cf6a08d5066cc031a9086115a7667835877ca62a3019b3da9"
	const (
		raw      = productionRegistryAddr
		tlsReg   = compatRegistryAddr + "/tls"
		tlsProxy = compatRegistryAddr + "/tls via proxy"
	)
	for _, tc := range []struct {
		name   string
		addr   string
		env    map[string]string
		cfg    map[string]interface{}
		daemon string // transport the running daemon reports
		want   []string
	}{
		{name: "plain host: raw default, then the TLS registry", addr: raw,
			want: []string{raw, tlsReg}},
		{name: "HTTPS_PROXY, transport unknown: direct first, proxied TLS fallback", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			want: []string{raw, tlsProxy}},
		{name: "HTTPS_PROXY + config compat: proxied TLS, then direct TLS", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			cfg:  map[string]interface{}{"transport": "compat"},
			want: []string{tlsProxy, tlsReg}},
		{name: "HTTPS_PROXY + running compat daemon (Muse)", addr: raw,
			env:    map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			cfg:    map[string]interface{}{"transport": "auto"},
			daemon: "compat",
			want:   []string{tlsProxy, tlsReg}},
		{name: "HTTPS_PROXY + running udp daemon: direct like the daemon", addr: raw,
			env:    map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			daemon: "udp",
			want:   []string{raw, tlsReg}},
		{name: "running daemon beats config", addr: raw,
			env:    map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			cfg:    map[string]interface{}{"transport": "compat"},
			daemon: "udp",
			want:   []string{raw, tlsReg}},
		// pilotctl-auto-proxy-regardless-of-transport: a private raw-TCP
		// registry on a udp (or unknown) host is dialed directly, as the
		// daemon does, even with HTTPS_PROXY exported.
		{name: "private registry + HTTPS_PROXY, transport unknown: direct", addr: "10.0.5.120:39000",
			env:  map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			want: []string{"10.0.5.120:39000"}},
		{name: "private registry + HTTPS_PROXY + udp: direct", addr: "10.0.5.120:39000",
			env:  map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128", "PILOT_TRANSPORT": "udp"},
			want: []string{"10.0.5.120:39000"}},
		{name: "private registry + compat: proxied, then direct", addr: "registry.corp.test:9000",
			env:  map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128", "PILOT_TRANSPORT": "compat"},
			want: []string{"registry.corp.test:9000 via proxy", "registry.corp.test:9000"}},
		{name: "config transport=compat, no proxy: TLS direct", addr: raw,
			cfg:  map[string]interface{}{"transport": "compat"},
			want: []string{tlsReg}},
		{name: "explicit PILOT_PROXY URL: proxied TLS in any transport", addr: raw,
			env:  map[string]string{"PILOT_PROXY": "http://u:p@corp.test:3128", "PILOT_TRANSPORT": "udp"},
			want: []string{tlsProxy}},
		{name: "explicit config proxy URL + private registry: proxied", addr: "registry.corp.test:9000",
			cfg:  map[string]interface{}{"proxy": "http://corp.test:3128"},
			want: []string{"registry.corp.test:9000 via proxy"}},
		{name: "PILOT_PROXY=off beats HTTPS_PROXY", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://egress.test:3128", "PILOT_PROXY": "off", "PILOT_TRANSPORT": "compat"},
			want: []string{tlsReg}},
		{name: "config proxy=none", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://egress.test:3128"},
			cfg:  map[string]interface{}{"proxy": "none"},
			want: []string{raw, tlsReg}},
		{name: "NO_PROXY exempts the TLS registry name (compat)", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://egress.test:3128", "NO_PROXY": ".pilotprotocol.network", "PILOT_TRANSPORT": "compat"},
			want: []string{tlsReg}},
		{name: "loopback registry never proxied", addr: "127.0.0.1:9000",
			env:  map[string]string{"HTTPS_PROXY": "http://egress.test:3128", "PILOT_TRANSPORT": "compat"},
			want: []string{"127.0.0.1:9000"}},
		{name: "fingerprint from env pins", addr: raw,
			env:  map[string]string{"HTTPS_PROXY": "http://egress.test:3128", "PILOT_REGISTRY_FINGERPRINT": fp, "PILOT_TRANSPORT": "compat"},
			want: []string{compatRegistryAddr + "/tls/pin via proxy", compatRegistryAddr + "/tls/pin"}},
		{name: "fingerprint from config, trust=system wins", addr: compatRegistryAddr,
			cfg:  map[string]interface{}{"registry_fingerprint": fp, "registry_trust": "system"},
			want: []string{tlsReg}},
		{name: "fingerprint from config pins", addr: compatRegistryAddr,
			cfg:  map[string]interface{}{"registry_fingerprint": fp},
			want: []string{compatRegistryAddr + "/tls/pin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTransportEnvCleared(t)
			stubDaemonTransport(t, tc.daemon)
			for _, k := range []string{"HTTPS_PROXY", "NO_PROXY", "PILOT_PROXY", "PILOT_REGISTRY_FINGERPRINT", "PILOT_REGISTRY_TRUST", "PILOT_TRANSPORT"} {
				t.Setenv(k, tc.env[k])
			}
			if tc.cfg != nil {
				if err := saveConfig(tc.cfg); err != nil {
					t.Fatal(err)
				}
			}
			routes, err := planRegistryRoutes(tc.addr)
			if err != nil {
				t.Fatalf("planRegistryRoutes: %v", err)
			}
			var got []string
			for _, r := range routes {
				got = append(got, routeSpec(r))
			}
			if strings.Join(got, " | ") != strings.Join(tc.want, " | ") {
				t.Errorf("routes = %q, want %q", got, tc.want)
			}
		})
	}
	t.Run("invalid proxy setting", func(t *testing.T) {
		withTransportEnvCleared(t)
		t.Setenv("PILOT_PROXY", "proxy.test:3128")
		if _, err := planRegistryRoutes(productionRegistryAddr); err == nil {
			t.Error("bare host:port proxy accepted")
		}
	})
	t.Run("malformed HTTPS_PROXY does not matter on udp", func(t *testing.T) {
		withTransportEnvCleared(t)
		t.Setenv("HTTPS_PROXY", "ftp://u:p@egress.test")
		t.Setenv("PILOT_TRANSPORT", "udp")
		if _, err := planRegistryRoutes("10.0.5.120:39000"); err != nil {
			t.Errorf("udp + malformed HTTPS_PROXY: %v", err)
		}
	})
}

// pilotctl-auto-proxy-regardless-of-transport, end to end: a LAN registry
// that worked directly on v1.13.9 still works with HTTPS_PROXY exported on a
// udp host, and the proxy sees nothing.
func TestPrivateRegistryDialedDirectlyWithProxyExported(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{"node_id": float64(1), "address": "0:0000.0000.0001", "public": true})
	proxyURL, targets := connectProxyToLoopback(t, "muse", "s3cret")
	env := cliEnvCleared(map[string]string{
		"PILOT_REGISTRY": r.addr(),
		"HTTPS_PROXY":    proxyURL,
		"PILOT_SOCKET":   filepath.Join(t.TempDir(), "none.sock"),
	})
	stdout, stderr, code := runCLI(t, []string{"--json", "lookup", "1"}, env)
	if code != 0 || !strings.Contains(stdout, "0:0000.0000.0001") {
		t.Fatalf("pilotctl lookup: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if got := targets(); len(got) != 0 {
		t.Fatalf("the proxy was used for a direct-reachable private registry: %q", got)
	}
}

// connectProxyToLoopback is an authenticating CONNECT proxy that routes
// *.pilot.invalid to loopback and records the CONNECT targets.
func connectProxyToLoopback(t *testing.T, user, pass string) (string, func() []string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	want := req.Header.Get("Authorization")
	var mu sync.Mutex
	var targets []string
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				r, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				mu.Lock()
				targets = append(targets, r.Method+" "+r.RequestURI)
				mu.Unlock()
				host, port, _ := net.SplitHostPort(r.RequestURI)
				if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != want || !strings.HasSuffix(host, ".pilot.invalid") {
					fmt.Fprint(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					return
				}
				up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
				if err != nil {
					fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
					return
				}
				defer up.Close()
				fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
				go func() { io.Copy(up, br); up.Close() }()
				io.Copy(c, up)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return fmt.Sprintf("http://%s:%s@%s", user, pass, ln.Addr()), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), targets...)
	}
}

// pilotctl's own registry commands go through the egress proxy (CONNECT by
// host name, with credentials) — the auto-handshake visibility check and
// `lookup` no longer trip a sandbox's direct-egress guard.
func TestRegistryCommandsUseTheProxy(t *testing.T) {
	r := newFakeRegistry(t)
	r.onOK("lookup", map[string]interface{}{"node_id": float64(99), "address": "0:0000.0000.0063", "public": true})
	proxyURL, targets := connectProxyToLoopback(t, "muse", "s3cret")
	_, port, _ := net.SplitHostPort(r.addr())
	regAddr := net.JoinHostPort("registry.pilot.invalid", port)

	withTransportEnvCleared(t)
	t.Setenv("HTTPS_PROXY", proxyURL)
	stubDaemonTransport(t, "compat") // a compat daemon runs: the proxy applies
	rc, route, err := dialRegistry(regAddr)
	if err != nil {
		t.Fatalf("dialRegistry through the proxy: %v", err)
	}
	defer rc.Close()
	if !route.proxied() {
		t.Error("route not proxied")
	}
	if _, err := rc.Lookup(99); err != nil {
		t.Fatalf("Lookup through the proxy: %v", err)
	}
	if got := targets(); len(got) != 1 || got[0] != "CONNECT "+regAddr {
		t.Fatalf("proxy requests = %q, want one CONNECT %s", got, regAddr)
	}

	// The CLI path too: `pilotctl lookup` in a child process.
	stdout, stderr, code := runCLI(t, []string{"--json", "lookup", "99"}, cliEnvCleared(map[string]string{
		"PILOT_REGISTRY":  regAddr,
		"HTTPS_PROXY":     proxyURL,
		"PILOT_TRANSPORT": "compat",
		"PILOT_SOCKET":    filepath.Join(t.TempDir(), "none.sock"),
	}))
	if code != 0 || !strings.Contains(stdout, "0:0000.0000.0063") {
		t.Fatalf("pilotctl lookup via proxy: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	if got := targets(); len(got) != 2 {
		t.Fatalf("CLI lookup did not go through the proxy: %q", got)
	}
}

func TestConfigSetTransportSwitchBackRestoresRegistry(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	env := cliEnvCleared(map[string]string{"PILOT_HOME": home})
	if _, stderr, code := runCLI(t, []string{"config", "--set", "registry=" + compatRegistryAddr}, env); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	stdout, stderr, code := runCLI(t, []string{"--json", "config", "--set", "transport=udp"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, productionRegistryAddr) {
		t.Errorf("switch back to udp did not report the restored registry: %s", stdout)
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".pilot", "config.json"))
	if !strings.Contains(string(raw), productionRegistryAddr) || strings.Contains(string(raw), compatRegistryAddr) {
		t.Errorf("config.json registry not restored: %s", raw)
	}
	// auto and none normalize.
	if stdout, _, code := runCLI(t, []string{"--json", "config", "--set", "transport=AUTO"}, env); code != 0 || !strings.Contains(stdout, `"auto"`) {
		t.Errorf("transport=AUTO: exit=%d %s", code, stdout)
	}
	if stdout, _, code := runCLI(t, []string{"--json", "config", "--set", "proxy=none"}, env); code != 0 || !strings.Contains(stdout, `"off"`) {
		t.Errorf("proxy=none: exit=%d %s", code, stdout)
	}
}

func TestTransportFromDaemonLog(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	text := filepath.Join(dir, "text.log")
	os.WriteFile(text, []byte(`time=x level=INFO msg="transport auto-selected" transport=compat reason="..."
time=x level=INFO msg="outbound network" transport=compat proxy="auto: http://***@p:3128" transport_from=default
`), 0o600)
	if got, auto := effectiveTransport("auto", text); got != "compat" || !auto {
		t.Errorf("text log: (%q, %v)", got, auto)
	}
	js := filepath.Join(dir, "json.log")
	os.WriteFile(js, []byte(`{"time":"x","level":"INFO","msg":"outbound network","transport":"udp","proxy":"none"}`+"\n"), 0o600)
	if got, _ := effectiveTransport("", js); got != "udp" {
		t.Errorf("json log: %q", got)
	}
	if got, auto := effectiveTransport("compat", filepath.Join(dir, "missing")); got != "compat" || auto {
		t.Errorf("no log: (%q, %v)", got, auto)
	}
}

// version-skew-config-transport-auto-bricks-older-daemon: after
// `pilotctl update --pin <older tag>`, a config.json "transport":"auto"
// that the installed (older) daemon would refuse is rewritten to udp; a
// daemon that knows auto, or any other value, is left alone.
func TestFitTransportToDaemon(t *testing.T) {
	withTransportEnvCleared(t)
	dir := t.TempDir()
	v1139 := writeFakeDaemon(t, append([]string{v1139TransportUsage}, baseDaemonFlags...), filepath.Join(dir, "v1139"))
	current := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), filepath.Join(dir, "cur"))

	if err := saveConfig(map[string]interface{}{"transport": "auto", "email": "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if note := fitTransportToDaemon(current); note != "" {
		t.Errorf("current daemon: note %q, want none", note)
	}
	if got := loadConfig()["transport"]; got != "auto" {
		t.Errorf("current daemon: transport = %v, want auto kept", got)
	}
	if note := fitTransportToDaemon(v1139); !strings.Contains(note, "transport set to udp") {
		t.Errorf("v1.13.9 daemon: note %q", note)
	}
	cfg := loadConfig()
	if cfg["transport"] != "udp" || cfg["email"] != "a@b.c" {
		t.Errorf("v1.13.9 daemon: config = %v, want transport=udp and the rest kept", cfg)
	}
	if err := saveConfig(map[string]interface{}{"transport": "compat"}); err != nil {
		t.Fatal(err)
	}
	if note := fitTransportToDaemon(v1139); note != "" || loadConfig()["transport"] != "compat" {
		t.Errorf("compat config changed for v1.13.9: note %q", note)
	}
}

// `config --set transport=` removes the key (the default, auto from
// pilotctl, applies again) instead of storing "" for a daemon to read.
func TestConfigSetEmptyClearsTransportKeys(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	env := cliEnvCleared(map[string]string{"PILOT_HOME": home})
	for _, kv := range []string{"transport=compat", "proxy=off", "proxy_cmd=cat /run/proxy-url", "transport=", "proxy=", "proxy_cmd="} {
		if _, stderr, code := runCLI(t, []string{"config", "--set", kv}, env); code != 0 {
			t.Fatalf("config --set %s: exit=%d stderr=%s", kv, code, stderr)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(home, ".pilot", "config.json"))
	for _, key := range []string{`"transport"`, `"proxy"`, `"proxy_cmd"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("config.json still has %s: %s", key, raw)
		}
	}
}
