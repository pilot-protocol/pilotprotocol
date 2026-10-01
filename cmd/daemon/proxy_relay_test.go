// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// fakeAppSource is an app-store app that does what the cloud-backed apps
// (plainweb, orthogonal, ...) do: HTTPS requests through the proxy in its
// environment (net/http's ProxyFromEnvironment, read once). It fetches
// $FAKE_APP_TARGET on a new connection every 200ms and appends one line
// per attempt to $FAKE_APP_OUT: "<unixnano> proxy=<user>@<host> ok|err ...".
const fakeAppSource = `package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func main() {
	proxy := "none"
	if u, err := url.Parse(os.Getenv("HTTPS_PROXY")); err == nil && u.Host != "" {
		proxy = u.User.Username() + "@" + u.Host
	}
	client := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}}
	out, err := os.OpenFile(os.Getenv("FAKE_APP_OUT"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(3)
	}
	parent := os.Getppid()
	for {
		if os.Getppid() != parent {
			os.Exit(0) // the daemon is gone: do not outlive the test
		}
		line := "ok"
		resp, err := client.Get(os.Getenv("FAKE_APP_TARGET"))
		if err != nil {
			line = "err " + strings.ReplaceAll(err.Error(), "\n", " ")
		} else {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			line = "ok " + string(b)
		}
		fmt.Fprintf(out, "%d proxy=%s %s\n", time.Now().UnixNano(), proxy, line)
		time.Sleep(200 * time.Millisecond)
	}
}
`

// buildFakeApp compiles fakeAppSource (standard library only) to path.
func buildFakeApp(t *testing.T, path string) {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
		if _, err := os.Stat(goBin); err != nil {
			t.Skip("no go toolchain to build the fake app")
		}
	}
	src := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(src, []byte(fakeAppSource), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(goBin, "build", "-o", path, src)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
	cmd.Dir = filepath.Dir(src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake app: %v\n%s", err, out)
	}
}

// sideloadApp installs binary as a sideloaded app-store app under root
// (the daemon's PILOT_APPSTORE_ROOT), which the daemon's supervisor
// spawns at startup with the daemon's environment.
func sideloadApp(t *testing.T, root, id, binary string) {
	t.Helper()
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bin", "app"), b, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	manifest := fmt.Sprintf(`{
	"id": %q,
	"manifest_version": 1,
	"app_version": "0.1.0",
	"protection": "shareable",
	"binary": {"runtime": "go", "path": "bin/app", "sha256": %q},
	"exposes": ["relaytest.ping"],
	"grants": [{"cap": "audit.log", "target": "*"}],
	"store": {"publisher": "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "signature": "sig:unsigned"}
}`, id, hex.EncodeToString(sum[:]))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".sideloaded"), nil, 0o400); err != nil {
		t.Fatal(err)
	}
}

// fakeAppLine is one line of the fake app's log.
type fakeAppLine struct {
	at    time.Time
	proxy string
	ok    bool
	text  string
}

func readFakeApp(t *testing.T, path string) []fakeAppLine {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []fakeAppLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ns int64
		var proxy, rest string
		fields := strings.SplitN(sc.Text(), " ", 3)
		if len(fields) < 3 {
			continue
		}
		fmt.Sscan(fields[0], &ns)
		proxy = strings.TrimPrefix(fields[1], "proxy=")
		rest = fields[2]
		lines = append(lines, fakeAppLine{at: time.Unix(0, ns), proxy: proxy, ok: strings.HasPrefix(rest, "ok "), text: rest})
	}
	return lines
}

// web4-470-apps-inherit-stale-proxy-creds, end to end with the real daemon
// and the real app-store supervisor. The egress proxy rotates its
// credentials and answers the stale ones the way Meta Muse's does (an
// unparseable status line). The daemon has a refresh command; the app it
// spawns only has the environment it inherits. Before the fix the app kept
// the launch-time HTTPS_PROXY and every request after the rotation failed
// ("node online, all apps broken"), also after a respawn. Now the app's
// HTTPS_PROXY is the daemon's loopback relay, and its requests keep
// working across rotations without ever holding the proxy's credentials.
func TestAppsFollowProxyRotationThroughTheRelay(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "hello") }))
	defer srv.Close()
	proxy := newRefusingProxy(t, "muse", "pw-1")
	proxy.rotate("muse", "pw-1") // anything else is rejected ...
	proxy.garbleRejections()     // ... with Muse's garbled status line
	proxy.forward("app.relay.test:443", srv.Listener.Addr().String())

	scratch := t.TempDir()
	urlFile := filepath.Join(scratch, "proxy-url")
	setURL := func(pass string) {
		t.Helper()
		if err := os.WriteFile(urlFile, []byte(fmt.Sprintf("http://muse:%s@%s\n", pass, proxy.ln.Addr())), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setURL("pw-1")
	appBin := filepath.Join(scratch, "fakeapp")
	buildFakeApp(t, appBin)
	appOut := filepath.Join(scratch, "fetches.log")

	d := startDaemon(t, daemonRun{
		env: []string{
			"PILOT_TRANSPORT=compat",
			"HTTPS_PROXY=" + fmt.Sprintf("http://muse:pw-1@%s", proxy.ln.Addr()),
			"PILOT_PROXY_CMD=cat '" + urlFile + "'",
			"FAKE_APP_TARGET=https://app.relay.test/",
			"FAKE_APP_OUT=" + appOut,
		},
		setup: func(home string) { sideloadApp(t, filepath.Join(home, "apps"), "io.sideload.relaytest", appBin) },
	})
	waitApp := func(what string, since time.Time, cond func(ok, failed []fakeAppLine) bool) []fakeAppLine {
		t.Helper()
		deadline := time.Now().Add(45 * time.Second)
		for {
			var ok, failed []fakeAppLine
			for _, l := range readFakeApp(t, appOut) {
				if l.at.Before(since) {
					continue
				}
				if l.ok {
					ok = append(ok, l)
				} else {
					failed = append(failed, l)
				}
			}
			if cond(ok, failed) {
				return failed
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s; app since %s: %d ok, failures %v\ndaemon output:\n%s", what, since.Format(time.RFC3339Nano), len(ok), failed, d.out.String())
			}
			time.Sleep(100 * time.Millisecond)
		}
	}

	start := time.Now().Add(-time.Minute)
	waitApp("the app never fetched through the proxy", start, func(ok, _ []fakeAppLine) bool { return len(ok) >= 2 })
	for _, l := range readFakeApp(t, appOut) {
		if !strings.HasPrefix(l.proxy, proxyconf.RelayUser+"@127.0.0.1:") {
			t.Fatalf("the app's HTTPS_PROXY is %q, want the daemon's relay (%s@127.0.0.1:port)", l.proxy, proxyconf.RelayUser)
		}
	}

	for _, pass := range []string{"pw-2", "pw-3"} {
		setURL(pass)
		proxy.rotate("muse", pass)
		rotated := time.Now()
		failed := waitApp("the app never fetched again after the rotation to "+pass, rotated, func(ok, _ []fakeAppLine) bool { return len(ok) >= 3 })
		if len(failed) > 0 {
			t.Errorf("after the rotation to %s the app saw failures: %v", pass, failed)
		}
		if proxy.accepted("muse", pass) == 0 {
			t.Fatalf("the proxy never saw the rotated credentials %s", pass)
		}
	}
	d.stop()
	logs := d.out.String()
	if !strings.Contains(logs, `msg="proxy relay listening"`) || !strings.Contains(logs, "the apps this daemon starts get HTTPS_PROXY") {
		t.Errorf("relay start not logged:\n%s", logs)
	}
	for _, secret := range []string{"pw-1", "pw-2", "pw-3"} {
		if strings.Contains(logs, secret) {
			t.Errorf("daemon output leaks %q", secret)
		}
	}
	if targets, _ := proxy.snapshot(); !contains(targets, "CONNECT app.relay.test:443") {
		t.Errorf("the app's CONNECTs never reached the egress proxy: %q", targets)
	}
}

// Without a refresh command the relay only serves the daemon's own
// http.DefaultTransport: the environment the apps inherit is exactly the
// daemon's own, and stays as valid as the daemon's, so it is left alone.
// Without a proxy there is no relay at all.
func TestRelayExportedOnlyWithProxyCommand(t *testing.T) {
	for _, k := range append(append([]string(nil), proxyEnvVars...), "PILOT_PROXY") {
		t.Setenv(k, "")
	}
	t.Cleanup(func() { activeProxyRelay.Store(nil) })
	t.Setenv("HTTPS_PROXY", "http://muse:s3cret@egress.test:3128")
	r, err := resolveProxy("auto", "", "compat")
	if err != nil {
		t.Fatal(err)
	}
	rl := startProxyRelay(r, "")
	if rl == nil {
		t.Fatal("no relay for a proxying daemon")
	}
	rl.Close()
	if got := os.Getenv("HTTPS_PROXY"); got != "http://muse:s3cret@egress.test:3128" {
		t.Fatalf("HTTPS_PROXY changed to %q without a proxy command", proxyconf.Redact(got))
	}
	if rl := startProxyRelay(nil, "cat /dev/null"); rl != nil {
		rl.Close()
		t.Fatal("relay started without a proxy")
	}
	off, _ := resolveProxy("off", "", "compat")
	if rl := startProxyRelay(off, ""); rl != nil {
		rl.Close()
		t.Fatal("relay started with -proxy=off")
	}
	if proxyCommandFor("off", "cmd", "compat", false) != "" || proxyCommandFor("auto", "cmd", "udp", false) != "" ||
		proxyCommandFor("auto", " cmd ", "compat", false) != "cmd" || proxyCommandFor("http://p.test:1", "cmd", "udp", false) != "cmd" {
		t.Error("proxyCommandFor")
	}
}

// With a refresh command the daemon starts the relay and exports it to
// the apps it spawns; its own refresh command keeps running in the launch
// environment, and a refresh that would make the relay the daemon's own
// proxy is refused.
func TestAppRelayEnvironment(t *testing.T) {
	for _, k := range append(append([]string(nil), proxyEnvVars...), "PILOT_PROXY", "PROBE_PROXY") {
		t.Setenv(k, "")
	}
	proxy := newRefusingProxy(t, "muse", "s3cret")
	launch := fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())
	t.Setenv("HTTPS_PROXY", launch)
	t.Setenv("https_proxy", launch)
	t.Setenv("HTTP_PROXY", launch)
	t.Setenv("PILOT_PROXY", launch)
	saved := launchEnvironment
	launchEnvironment = os.Environ()
	t.Cleanup(func() { launchEnvironment = saved; activeProxyRelay.Store(nil) })

	const command = `printf %s "$HTTPS_PROXY"`
	r, err := resolveProxy("auto", command, "compat")
	if err != nil {
		t.Fatal(err)
	}
	if got := describeProxy("auto", "compat", r); !strings.Contains(got, "(credentials refreshed by command)") || strings.Contains(got, "s3cret") {
		t.Fatalf("describeProxy = %q", got)
	}
	relay := startProxyRelay(r, command)
	if relay == nil {
		t.Fatal("no relay with a proxy command")
	}
	defer relay.Close()
	want := relay.URL().String()
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "PILOT_PROXY"} {
		if got := os.Getenv(k); got != want {
			t.Errorf("%s = %q, want the relay URL", k, proxyconf.Redact(got))
		}
	}
	if got := os.Getenv("HTTP_PROXY"); got != launch {
		t.Errorf("HTTP_PROXY = %q, want it left alone (the relay only tunnels)", proxyconf.Redact(got))
	}

	// The daemon's own refresh still sees the launch environment ...
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh after the relay started: %v", err)
	}
	if got := proxyconf.ProxyFor(r, "registry.pilotprotocol.network:443"); got != proxyconf.Redact(launch) {
		t.Fatalf("the daemon's proxy is now %q, want the egress proxy %q", got, proxyconf.Redact(launch))
	}
	// ... and a command that prints the relay (a launch environment that
	// already named it, say) is refused: the last good URL stays.
	launchEnvironment = os.Environ()
	loopy, err := resolveProxy(launch, command, "compat")
	if err != nil {
		t.Fatal(err)
	}
	if err := loopy.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "own proxy relay") {
		t.Fatalf("refresh printing the relay = %v, want refused", err)
	}
	if got := proxyconf.ProxyFor(loopy, "registry.pilotprotocol.network:443"); got != proxyconf.Redact(launch) {
		t.Fatalf("the daemon's proxy is %q after a refresh printed its relay, want %q", got, proxyconf.Redact(launch))
	}

	// PILOT_PROXY is only replaced when it names a proxy URL.
	for _, v := range []string{"auto", "off", ""} {
		t.Setenv("PILOT_PROXY", v)
		exportAppProxy(want)
		if got := os.Getenv("PILOT_PROXY"); got != v {
			t.Errorf("PILOT_PROXY=%q became %q", v, proxyconf.Redact(got))
		}
	}
}

// web4-470-muse-rejection-diagnostics-misdirect: the hint for a proxy that
// could not be parsed names the credentials and -proxy-cmd, and no hint
// sends a proxy-only host around the proxy unconditionally.
func TestProxyErrorHintGarbledRejection(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "right")
	proxy.rotate("muse", "right")
	proxy.garbleRejections()
	r, err := resolveProxy(fmt.Sprintf("http://muse:wrong@%s", proxy.ln.Addr()), "", "compat")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, dialErr := proxyconf.DialContext(r, nil)(ctx, "tcp", "registry.pilotprotocol.network:443")
	if dialErr == nil {
		t.Fatal("dial with the wrong password succeeded")
	}
	hint := proxyErrorHint(dialErr)
	if !strings.Contains(hint, "could not be parsed") || !strings.Contains(hint, "-proxy-cmd") || strings.Contains(hint, "udp") {
		t.Errorf("garbled rejection hint = %q", hint)
	}
	unreachable := proxyErrorHint(errors.New("proxy CONNECT registry.pilotprotocol.network:443: dial proxy http://***@127.0.0.1:1: connection refused"))
	if !strings.Contains(unreachable, "only if this host can reach the internet without the proxy") {
		t.Errorf("unreachable-proxy hint = %q", unreachable)
	}
	var ce *netproxy.ConnectError
	if errors.As(dialErr, &ce) {
		t.Fatalf("garbled answer surfaced as a ConnectError: %v", dialErr)
	}
}

// End to end with the real daemon: a wrong password under -transport=auto,
// answered the Muse way. The WARN hint and the registry dial errors name
// the credentials, not -transport=udp.
func TestAutoTransportGarbledRefusalHintsCredentials(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "right-pass")
	proxy.rotate("muse", "right-pass")
	proxy.garbleRejections()
	_, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", silentUDP(t),
			"-compat-beacon", defaultCompatBeacon,
			"-transport=auto",
			"-registry-fingerprint=" + strings.Repeat("00", 32),
		},
		env:   []string{"HTTPS_PROXY=" + fmt.Sprintf("http://muse:wrong-pass@%s", proxy.ln.Addr())},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	if !strings.Contains(logs, `level=WARN msg="transport auto-selected" transport=compat`) {
		t.Fatalf("auto did not stay on compat with a WARN:\n%s", logs)
	}
	for _, line := range strings.Split(logs, "\n") {
		if !strings.Contains(line, "transport auto-selected") {
			continue
		}
		if !strings.Contains(line, "could not be parsed") || !strings.Contains(line, "proxy-cmd") {
			t.Errorf("auto-selected WARN lacks the credential hint: %s", line)
		}
		if strings.Contains(line, "-transport=udp") {
			t.Errorf("auto-selected WARN suggests -transport=udp: %s", line)
		}
	}
	if strings.Contains(logs, "4O7") || strings.Contains(logs, "wrong-pass") {
		t.Errorf("daemon output quotes the proxy's answer or the password:\n%s", logs)
	}
}
