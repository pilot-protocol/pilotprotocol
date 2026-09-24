// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// rotatingProxy is an in-process CONNECT proxy whose Basic-auth password
// rotates, the way Meta Muse's egress proxy rotates the credentials in
// HTTPS_PROXY: it accepts the current password only, answers anything else
// with 407, and tunnels accepted CONNECTs per routes.
type rotatingProxy struct {
	addr   string
	routes map[string]string

	mu   sync.Mutex
	pass string
	oks  map[string]int // password -> accepted CONNECTs
	n407 int
	seen []string
}

func newRotatingProxy(t *testing.T, pass string, routes map[string]string) *rotatingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &rotatingProxy{addr: ln.Addr().String(), routes: routes, pass: pass, oks: map[string]int{}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return p
}

func (p *rotatingProxy) url(pass string) string { return "http://muse:" + pass + "@" + p.addr }

func (p *rotatingProxy) rotate(pass string) {
	p.mu.Lock()
	p.pass = pass
	p.mu.Unlock()
}

func (p *rotatingProxy) stats() (oks map[string]int, n407 int, seen []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := map[string]int{}
	for k, v := range p.oks {
		m[k] = v
	}
	return m, p.n407, append([]string(nil), p.seen...)
}

func (p *rotatingProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", req.Header.Get("Proxy-Authorization"))
	user, pass, ok := req.BasicAuth()
	p.mu.Lock()
	p.seen = append(p.seen, req.Method+" "+req.RequestURI)
	good := ok && user == "muse" && pass == p.pass
	if good {
		p.oks[pass]++
	} else {
		p.n407++
	}
	to := p.routes[req.RequestURI]
	p.mu.Unlock()
	switch {
	case !good:
		fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"muse\"\r\nContent-Length: 0\r\n\r\n")
		return
	case req.Method != http.MethodConnect || to == "":
		fmt.Fprint(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.DialTimeout("tcp", to, 5*time.Second)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	go func() { _, _ = io.Copy(up, br); up.Close() }()
	_, _ = io.Copy(c, up)
}

// pilotctl's own registry commands behind a proxy that rotates its
// credentials: with a proxy command ($PILOT_PROXY_CMD, config proxy_cmd,
// or the sandbox default) the dial takes the command's current URL rather
// than a stale $HTTPS_PROXY, and a 407 mid-way re-runs the command and
// retries once (netproxy). Without one, the 407 is reported as such.
func TestRegistryDialFollowsRotatedProxyCredentials(t *testing.T) {
	reg, fp := newTLSFakeRegistry(t)
	reg.onOK("lookup", map[string]interface{}{"node_id": float64(5), "address": "0:0000.0000.0005", "public": true})
	proxy := newRotatingProxy(t, "pw-2", map[string]string{compatRegistryAddr: reg.addr()})
	urlFile := filepath.Join(t.TempDir(), "proxy-url")
	setURL := func(pass string) {
		t.Helper()
		if err := os.WriteFile(urlFile, []byte(proxy.url(pass)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setup := func(t *testing.T, withCmd bool) {
		withTransportEnvCleared(t)
		t.Setenv("HTTPS_PROXY", proxy.url("pw-1")) // pilotctl's launch environment: stale
		// Transport unknown (no daemon, nothing configured): the fallback
		// is the probed raw route, which the stub below keeps off the
		// network; compat's fallback would dial the real TLS registry.
		t.Setenv("PILOT_REGISTRY_FINGERPRINT", fp)
		if withCmd {
			t.Setenv("PILOT_PROXY_CMD", "cat '"+urlFile+"'")
		}
		stubRawDirectDial(t, "127.0.0.1:1") // direct raw dials stay local (refused)
	}

	t.Run("stale environment, no command: the 407 is reported", func(t *testing.T) {
		setup(t, false)
		rc, route, err := dialRegistry(productionRegistryAddr)
		if err == nil {
			rc.Close()
			t.Fatal("dial with stale credentials succeeded")
		}
		if !route.proxied() || !strings.Contains(err.Error(), "407 Proxy Authentication Required") {
			t.Fatalf("route %+v err %v, want the proxied route's 407", route, err)
		}
		if strings.Contains(err.Error(), "pw-1") {
			t.Fatalf("error leaks the password: %v", err)
		}
		if hint := registryDialHint(route); !strings.Contains(hint, "credentials") {
			t.Errorf("hint %q does not mention the credentials", hint)
		}
	})

	t.Run("command supplies the current credentials", func(t *testing.T) {
		setup(t, true)
		setURL("pw-2")
		_, before, _ := proxy.stats()
		rc, route, err := dialRegistry(productionRegistryAddr)
		if err != nil {
			t.Fatalf("dialRegistry: %v", err)
		}
		defer rc.Close()
		if _, err := rc.Lookup(5); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		oks, after, _ := proxy.stats()
		if !route.proxied() || oks["pw-2"] == 0 || after != before {
			t.Fatalf("route %+v, accepted %v, new 407s %d: want the command's pw-2 and no 407", route, oks, after-before)
		}
	})

	t.Run("rotation between resolve and dial: 407, refresh, retry", func(t *testing.T) {
		setup(t, true)
		setURL("pw-2")
		proxy.rotate("pw-2")
		routes, err := planRegistryRoutes(productionRegistryAddr)
		if err != nil || len(routes) == 0 || !routes[0].proxied() {
			t.Fatalf("routes = %+v, %v", routes, err)
		}
		// The proxy rotates after pilotctl read the URL.
		proxy.rotate("pw-3")
		setURL("pw-3")
		_, before, _ := proxy.stats()
		rc, err := routes[0].dial()
		if err != nil {
			t.Fatalf("dial after the rotation: %v", err)
		}
		defer rc.Close()
		if _, err := rc.Lookup(5); err != nil {
			t.Fatalf("Lookup after the rotation: %v", err)
		}
		oks, after, _ := proxy.stats()
		if after-before != 1 || oks["pw-3"] == 0 {
			t.Fatalf("407s %d, accepted %v: want one 407, then the refreshed pw-3", after-before, oks)
		}
	})
}

// "pilotctl must not try the raw registry directly first when a proxy is
// configured": for every configuration in which the proxy applies to the
// production registry, the first route is the TLS registry through it.
func TestRegistryRoutesProxyFirstWhenProxyConfigured(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    map[string]string
		cfg    map[string]interface{}
		daemon string
	}{
		{name: "HTTPS_PROXY, no daemon, nothing configured",
			env: map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"}},
		{name: "HTTPS_PROXY, config transport=auto, no daemon",
			env: map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			cfg: map[string]interface{}{"transport": "auto"}},
		{name: "HTTPS_PROXY, compat daemon",
			env:    map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			daemon: "compat"},
		{name: "HTTPS_PROXY, config compat",
			env: map[string]string{"HTTPS_PROXY": "http://u:p@egress.test:3128"},
			cfg: map[string]interface{}{"transport": "compat"}},
		{name: "explicit PILOT_PROXY, udp",
			env: map[string]string{"PILOT_PROXY": "http://u:p@corp.test:3128", "PILOT_TRANSPORT": "udp"}},
		{name: "explicit config proxy, udp daemon",
			cfg:    map[string]interface{}{"proxy": "http://corp.test:3128"},
			daemon: "udp"},
		{name: "ALL_PROXY only, no daemon",
			env: map[string]string{"ALL_PROXY": "http://u:p@egress.test:3128"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withTransportEnvCleared(t)
			stubDaemonTransport(t, tc.daemon)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if tc.cfg != nil {
				if err := saveConfig(tc.cfg); err != nil {
					t.Fatal(err)
				}
			}
			routes, err := planRegistryRoutes(productionRegistryAddr)
			if err != nil || len(routes) == 0 {
				t.Fatalf("planRegistryRoutes = %v, %v", routes, err)
			}
			if first := routes[0]; !first.proxied() || first.Addr != compatRegistryAddr || !first.TLS {
				t.Fatalf("first route = %s, want the TLS registry through the proxy", routeSpec(first))
			}
			for _, r := range routes[1:] {
				if !r.proxied() && !r.TLS && !r.Probe {
					t.Errorf("unprobed direct raw fallback %s behind a configured proxy", routeSpec(r))
				}
			}
		})
	}
}

func TestExtractProxyErrorFromDaemonLog(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{`time=2026-09-24T00:00:00Z level=WARN msg="registry dial failed, retrying" attempt=1 max=10 backoff=500ms error="dial registry TLS pinned: proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"`,
			"proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"},
		{`{"time":"x","level":"WARN","msg":"registry dial failed, retrying","error":"dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: 403 Forbidden"}`,
			"proxy CONNECT registry.pilotprotocol.network:443: 403 Forbidden"},
		{`time=x level=INFO msg="appstore: catalogue refresh failed (fetch catalogue from https://raw.githubusercontent.com/c.json: Get \"https://raw.githubusercontent.com/c.json\": proxy CONNECT raw.githubusercontent.com:443: 407 Proxy Authentication Required) and no cache; catalogue apps fail closed"`,
			"proxy CONNECT raw.githubusercontent.com:443: 407 Proxy Authentication Required"},
		{`time=x level=WARN msg="transport auto-selected" transport=compat reason="no UDP answer from beacon b, and the proxy http://***@p:3128 refused the compat beacon check (proxy CONNECT beacon.pilotprotocol.network:443: 407 Proxy Authentication Required); staying on compat"`,
			"proxy CONNECT beacon.pilotprotocol.network:443: 407 Proxy Authentication Required"},
		{`time=x level=ERROR msg="daemon start: registry dial (after 10 attempts): dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required; the proxy rejected its credentials (407)"`,
			"proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"},
		{`time=x level=WARN msg="registry dial failed, retrying" error="dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: dial proxy http://***@10.0.0.1:3128: dial tcp 10.0.0.1:3128: connect: connection refused"`,
			"proxy CONNECT registry.pilotprotocol.network:443: dial proxy http://***@10.0.0.1:3128: dial tcp 10.0.0.1:3128: connect: connection refused"},
		{`time=x level=INFO msg="daemon registered" node_id=5`, ""},
	} {
		if got := extractProxyError(tc.line); got != tc.want {
			t.Errorf("extractProxyError(%s)\n got %q\nwant %q", tc.line, got, tc.want)
		}
	}

	log := filepath.Join(t.TempDir(), "pilot.log")
	writeTestFile(t, log, strings.Join([]string{
		`time=x level=WARN msg="registry dial failed, retrying" error="dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"`,
		`time=x level=INFO msg="appstore: catalogue refresh failed (Get \"https://raw.githubusercontent.com/c\": proxy CONNECT raw.githubusercontent.com:443: 403 Forbidden) and no cache"`,
		`time=x level=ERROR msg="daemon start: registry dial (after 10 attempts): boom; hint"`,
		``,
	}, "\n"))
	if got := lastProxyErrorFromLog(log); got != "proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required" {
		t.Errorf("lastProxyErrorFromLog = %q, want the WARN line's 407 over the later INFO line", got)
	}
	if got := lastErrorFromLog(log); got != "daemon start: registry dial (after 10 attempts): boom; hint" {
		t.Errorf("lastErrorFromLog = %q", got)
	}
	if got := lastProxyErrorFromLog(filepath.Join(t.TempDir(), "missing.log")); got != "" {
		t.Errorf("missing log = %q", got)
	}
}

// writeStartFailDaemon writes a fake pilot-daemon for the forking `daemon
// start` path: -help lists a current daemon's flags, and a start writes
// logLines to stdout (pilotctl's per-PID log), then either exits with
// exitCode or, with exitCode < 0, stays up without ever serving its socket.
func writeStartFailDaemon(t *testing.T, logLines []string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script fake daemon")
	}
	var help strings.Builder
	for _, f := range append([]string{autoUsage, "proxy", "proxy-cmd"}, baseDaemonFlags...) {
		name, usage, ok := strings.Cut(f, "=")
		if !ok {
			usage = "description of " + name
		}
		help.WriteString("  -" + name + " string\n    \t" + usage + "\n")
	}
	var body strings.Builder
	for _, l := range logLines {
		body.WriteString("printf '%s\\n' " + shellQuote(l) + "\n")
	}
	tail := "exec sleep 60\n"
	if exitCode >= 0 {
		tail = "exit " + strconv.Itoa(exitCode) + "\n"
	}
	script := "#!/bin/sh\nif [ \"$1\" = \"-help\" ]; then\n  cat >&2 <<'HELP'\nUsage of pilot-daemon:\n" + help.String() + "HELP\n  exit 0\nfi\n" + body.String() + tail
	path := filepath.Join(t.TempDir(), "pilot-daemon")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// killPIDFile stops a fake daemon `daemon start` left running.
func killPIDFile(t *testing.T, home string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(home, ".pilot", "pilot.pid"))
	if err != nil {
		return
	}
	if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 0 {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

// E2E product gap: `pilotctl daemon start` behind a proxy that rejects the
// credentials used to say only "did not become ready within 30s". It must
// name the daemon's last proxy error (and say what to do about it), and
// it must notice a daemon that exited instead of waiting out the deadline.
func TestCLIDaemonStartReportsDaemonProxyError(t *testing.T) {
	const regErr = `time=2026-09-24T00:00:01Z level=WARN msg="registry dial failed, retrying" attempt=1 max=10 backoff=500ms error="dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"`
	const want = "proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required"

	t.Run("not ready in time", func(t *testing.T) {
		home := t.TempDir()
		t.Cleanup(func() { killPIDFile(t, home) })
		bin := writeStartFailDaemon(t, []string{
			`time=2026-09-24T00:00:00Z level=WARN msg="transport auto-selected" transport=compat reason="no UDP answer from beacon b, and the proxy http://***@p:3128 refused the compat beacon check (proxy CONNECT beacon.pilotprotocol.network:443: 407 Proxy Authentication Required); staying on compat"`,
			regErr,
		}, -1)
		env := cliEnvCleared(map[string]string{
			"PILOT_DAEMON_BIN": bin,
			"PILOT_SOCKET":     filepath.Join(t.TempDir(), "pilot.sock"),
			"PILOT_HOME":       home,
		})
		_, stderr, code := runCLI(t, []string{"daemon", "start", "--wait", "2s"}, env)
		if code == 0 {
			t.Fatalf("daemon start succeeded against a daemon that never became ready")
		}
		if !strings.Contains(stderr, "did not become ready within 2s; last proxy error: "+want) {
			t.Errorf("stderr lacks the daemon's proxy error:\n%s", stderr)
		}
		if !strings.Contains(stderr, "proxy_cmd") || !strings.Contains(stderr, "full log:") {
			t.Errorf("hint does not say what to do:\n%s", stderr)
		}
	})

	t.Run("daemon exits", func(t *testing.T) {
		home := t.TempDir()
		bin := writeStartFailDaemon(t, []string{
			regErr,
			`time=2026-09-24T00:00:48Z level=ERROR msg="daemon start: registry dial (after 10 attempts): dial registry TLS: proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required; the proxy rejected its credentials (407)"`,
		}, 1)
		env := cliEnvCleared(map[string]string{
			"PILOT_DAEMON_BIN": bin,
			"PILOT_SOCKET":     filepath.Join(t.TempDir(), "pilot.sock"),
			"PILOT_HOME":       home,
		})
		start := time.Now()
		_, stderr, code := runCLI(t, []string{"--json", "daemon", "start", "--wait", "20s"}, env)
		if code == 0 {
			t.Fatal("daemon start succeeded against a daemon that exited")
		}
		if elapsed := time.Since(start); elapsed > 10*time.Second {
			t.Errorf("daemon start took %s to notice the exit; want well under the 20s wait", elapsed)
		}
		var res struct{ Code, Message, Hint string }
		if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &res); err != nil {
			t.Fatalf("stderr is not one JSON error: %v\n%s", err, stderr)
		}
		if res.Code != "connection_failed" || !strings.Contains(res.Message, "exited during startup (exit status 1)") ||
			!strings.Contains(res.Message, "daemon start: registry dial (after 10 attempts)") || !strings.Contains(res.Message, want) {
			t.Errorf("error = %+v", res)
		}
		if _, err := os.Stat(filepath.Join(home, ".pilot", "pilot.pid")); err == nil {
			t.Error("PID file of the exited daemon left behind")
		}
	})
}

// buildRealDaemon compiles ./cmd/daemon for end-to-end tests.
func buildRealDaemon(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "pilot-daemon")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/pilot-protocol/pilotprotocol/cmd/daemon")
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build pilot-daemon: %v\n%s", err, out)
	}
	return bin
}

// End to end, the E2E product gap as a user hits it: plain `pilotctl
// daemon start` (transport auto) with the real pilot-daemon, UDP silently
// dropped, and an egress proxy that rejects the credentials. The daemon
// must stay on the proxy (compat; no CONNECT for the raw registry, no
// direct dial) and pilotctl must report the proxy's 407 with a hint, not
// only "did not become ready". Nothing leaves the machine: the in-process
// proxy answers every request with 407.
func TestE2EDaemonStartBehindRejectingProxy(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the real pilot-daemon")
	}
	if runtime.GOOS == "windows" {
		t.Skip("unix daemon")
	}
	bin := buildRealDaemon(t)
	proxy := newRotatingProxy(t, "right-pass", nil)
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	home := t.TempDir()
	t.Cleanup(func() { killPIDFile(t, home) })
	sockDir, err := os.MkdirTemp("", "pe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN":     bin,
		"PILOT_SOCKET":         filepath.Join(sockDir, "s"),
		"PILOT_HOME":           home,
		"HTTPS_PROXY":          proxy.url("wrong-pass"),
		"PILOT_NO_SKILLINJECT": "1",
		"PILOT_APPSTORE_ROOT":  filepath.Join(home, "apps"),
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--wait", "10s",
		"--beacon", udp.LocalAddr().String(),
		"--compat-beacon", "wss://beacon.pilotprotocol.network/v1/compat",
		"--motd-feed-url", ""}, env)
	t.Logf("pilotctl daemon start (exit %d):\n%s", code, stderr)
	if code == 0 {
		t.Fatal("daemon start succeeded behind a proxy that rejects the credentials")
	}
	if !strings.Contains(stderr, "last proxy error: proxy CONNECT ") || !strings.Contains(stderr, "407 Proxy Authentication Required") {
		t.Errorf("stderr does not name the proxy's 407:\n%s", stderr)
	}
	if !strings.Contains(stderr, "proxy_cmd") {
		t.Errorf("no hint about rotating credentials:\n%s", stderr)
	}
	if strings.Contains(stderr, "wrong-pass") {
		t.Errorf("stderr leaks the proxy password:\n%s", stderr)
	}
	_, n407, seen := proxy.stats()
	if n407 == 0 || !strings.Contains(strings.Join(seen, "\n"), "CONNECT registry.pilotprotocol.network:443") {
		t.Errorf("the daemon did not dial the registry through the proxy: %q", seen)
	}
	for _, s := range seen {
		if strings.Contains(s, "34.71.57.205") {
			t.Errorf("proxy asked for the raw registry: %q", s)
		}
	}
	logs, _ := os.ReadFile(filepath.Join(home, ".pilot", "pilot.log"))
	if strings.Contains(string(logs), "34.71.57.205:9000") {
		t.Errorf("the daemon dialed the raw registry directly:\n%s", logs)
	}
	if !strings.Contains(string(logs), `msg="transport auto-selected" transport=compat`) {
		t.Errorf("auto did not stay on compat:\n%s", logs)
	}
}

// A new pilotctl starting a daemon that predates -proxy (v1.13.9) from a
// shell whose only way out is $HTTPS_PROXY warns at start instead of
// leaving a bare "did not become ready" to explain it (phase-2 E2E
// scenario 3).
func TestCLIDaemonStartWarnsOldDaemonIgnoresProxy(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{v1139TransportUsage}, baseDaemonFlags...), out)
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(dir, "pilot.sock"),
		"HTTPS_PROXY":      "http://muse:s3cret@egress.test:3128",
	})
	_, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground"}, env)
	if code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "predates HTTPS-proxy support") || !strings.Contains(stderr, "$HTTPS_PROXY") {
		t.Errorf("no warning that the daemon ignores the proxy:\n%s", stderr)
	}
	if strings.Contains(stderr, "s3cret") {
		t.Errorf("warning leaks the proxy password:\n%s", stderr)
	}
	// --proxy off: the operator asked for no proxy; nothing to warn about.
	_, stderr, _ = runCLI(t, []string{"daemon", "start", "--foreground", "--proxy", "off"}, env)
	if strings.Contains(stderr, "predates HTTPS-proxy support") {
		t.Errorf("warned although --proxy off:\n%s", stderr)
	}
}
