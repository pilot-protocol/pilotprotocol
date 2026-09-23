// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

// runMainEnv makes the test binary run the daemon's main() instead of the
// tests, so a test can start the real daemon with real flags and
// environment in a child process.
const runMainEnv = "PILOT_DAEMON_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var proxyEnvVars = []string{
	"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
	"HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD",
}

func TestResolveProxyPolicy(t *testing.T) {
	for _, k := range proxyEnvVars {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", "http://muse:s3cret@egress.test:3128")

	p, err := resolveProxyPolicy("auto", "", "udp")
	if err != nil || p != nil {
		t.Fatalf("auto/udp = (%v, %v), want (nil, nil)", p, err)
	}
	if got := describeProxy("auto", "udp", p); got != "none (-proxy=auto applies to -transport=compat only)" {
		t.Errorf("describeProxy(auto/udp) = %q", got)
	}

	p, err = resolveProxyPolicy("auto", "", "compat")
	if err != nil || p == nil || p.Mode() != netproxy.ModeAuto || !p.Enabled() {
		t.Fatalf("auto/compat = (%v, %v), want an enabled auto policy", p, err)
	}
	if got := describeProxy("auto", "compat", p); got != "auto: http://***@egress.test:3128" {
		t.Errorf("describeProxy(auto/compat) = %q", got)
	}

	p, err = resolveProxyPolicy("http://ops:hunter2@flag.test:8080", "", "udp")
	if err != nil || p == nil || p.Mode() != netproxy.ModeExplicit {
		t.Fatalf("explicit/udp = (%v, %v), want an explicit policy", p, err)
	}
	if got := describeProxy("http://ops:hunter2@flag.test:8080", "udp", p); got != "http://***@flag.test:8080" {
		t.Errorf("describeProxy(explicit) = %q", got)
	}

	p, err = resolveProxyPolicy("off", "", "compat")
	if err != nil || p == nil || p.Mode() != netproxy.ModeOff {
		t.Fatalf("off/compat = (%v, %v), want an off policy", p, err)
	}

	// A malformed -proxy URL is fatal (operator typo) ...
	if _, err := resolveProxyPolicy("ftp://ops:hunter2@flag.test", "", "compat"); err == nil {
		t.Fatal("malformed -proxy URL accepted")
	} else if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	// ... but a malformed environment under auto only costs the proxy.
	t.Setenv("HTTPS_PROXY", "ftp://muse:s3cret@egress.test")
	p, err = resolveProxyPolicy("auto", "", "compat")
	if err != nil || p != nil {
		t.Fatalf("auto/compat with malformed env = (%v, %v), want (nil, nil)", p, err)
	}
	if got := describeProxy("auto", "compat", p); got != "none" {
		t.Errorf("describeProxy(auto/compat, malformed env) = %q, want none", got)
	}
}

// refusingProxy records every request it gets and refuses all of them, so
// nothing a daemon under test sends ever leaves the machine.
type refusingProxy struct {
	ln net.Listener

	mu        sync.Mutex
	wantAuth  string
	targets   []string
	badAuths  int
	goodAuths map[string]int    // Proxy-Authorization value -> accepted requests
	forwards  map[string]string // CONNECT target -> local address tunnelled to
	reply407  bool              // answer bad credentials with 407 (rotation)
}

// forward makes the proxy tunnel CONNECT target to the local address to.
func (p *refusingProxy) forward(target, to string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.forwards == nil {
		p.forwards = map[string]string{}
	}
	p.forwards[target] = to
}

// rotate makes the proxy accept only user:pass from now on, answering
// anything else with 407 Proxy Authentication Required — the way a
// sandbox egress proxy rotates its credentials.
func (p *refusingProxy) rotate(user, pass string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.wantAuth = basicAuth(user, pass)
	p.reply407 = true
}

// accepted reports how many requests carried user:pass and were accepted.
func (p *refusingProxy) accepted(user, pass string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.goodAuths[basicAuth(user, pass)]
}

func basicAuth(user, pass string) string {
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	return req.Header.Get("Authorization")
}

func newRefusingProxy(t *testing.T, user, pass string) *refusingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p := &refusingProxy{ln: ln, wantAuth: basicAuth(user, pass), goodAuths: map[string]int{}}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				r, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				p.mu.Lock()
				p.targets = append(p.targets, r.Method+" "+r.RequestURI)
				auth := r.Header.Get("Proxy-Authorization")
				authOK := auth == p.wantAuth
				if authOK {
					p.goodAuths[auth]++
				} else {
					p.badAuths++
				}
				reply407 := !authOK && p.reply407
				connect := authOK && r.Method == http.MethodConnect
				to := ""
				if connect {
					to = p.forwards[r.RequestURI]
				}
				p.mu.Unlock()
				switch {
				case reply407:
					fmt.Fprint(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"muse\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				case to != "":
					up, err := net.Dial("tcp", to)
					if err != nil {
						fmt.Fprint(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
						return
					}
					defer up.Close()
					conn.SetDeadline(time.Time{})
					fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
					done := make(chan struct{}, 2)
					go func() { _, _ = io.Copy(up, conn); done <- struct{}{} }()
					go func() { _, _ = io.Copy(conn, up); done <- struct{}{} }()
					<-done
				default:
					fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
				}
			}()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
	return p
}

func (p *refusingProxy) snapshot() ([]string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...), p.badAuths
}

// syncBuffer is a bytes.Buffer safe for the exec copier goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestDaemonCompatThroughProxyEndToEnd runs the real daemon binary the way
// Meta Muse does: `pilotctl daemon start` arguments (the compiled-in raw
// TCP registry passed explicitly), transport from PILOT_TRANSPORT, and the
// egress proxy only in the environment. The compat registry must be
// CONNECTed by host name on :443, with credentials, and plugin HTTP clients
// (the catalogue pin fetch) must use the same proxy — also for ALL_PROXY
// and PILOT_PROXY, which net/http alone would not follow. The proxy refuses
// every request and the registry pin is bogus, so nothing reaches the
// network.
func TestDaemonCompatThroughProxyEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name, envVar, wantPrefix string
	}{
		{"HTTPS_PROXY", "HTTPS_PROXY", "auto: "},
		{"ALL_PROXY", "ALL_PROXY", "auto: "},
		{"PILOT_PROXY", "PILOT_PROXY", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			proxy := newRefusingProxy(t, "muse", "s3cret")
			targets, logs := runDaemonBehindProxy(t, tc.envVar+"="+fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr()), proxy)
			t.Logf("proxy requests: %q", targets)

			if _, badAuths := proxy.snapshot(); badAuths != 0 {
				t.Errorf("%d proxy request(s) lacked the proxy credentials", badAuths)
			}
			for _, target := range targets {
				if !strings.HasPrefix(target, "CONNECT ") {
					t.Errorf("non-CONNECT proxy request %q", target)
				}
				if strings.Contains(target, "34.71.57.205") {
					t.Errorf("proxy was asked for the raw-TCP registry/beacon: %q", target)
				}
			}
			if !contains(targets, "CONNECT raw.githubusercontent.com:443") {
				t.Errorf("catalogue fetch did not use the proxy; targets %q", targets)
			}
			if strings.Contains(logs, "s3cret") {
				t.Errorf("daemon output leaks the proxy password:\n%s", logs)
			}
			value := fmt.Sprintf("%shttp://***@%s", tc.wantPrefix, proxy.ln.Addr())
			if strings.Contains(value, " ") {
				value = strconv.Quote(value) // slog's text handler quotes only when needed
			}
			wantLog := `msg="outbound network" transport=compat proxy=` + value
			if !strings.Contains(logs, wantLog) {
				t.Errorf("daemon output lacks %s\n%s", wantLog, logs)
			}
		})
	}
}

// runDaemonBehindProxy starts main() in a child process with proxyEnv and
// returns the proxy's request targets once the registry CONNECT arrived,
// plus the daemon's output.
func runDaemonBehindProxy(t *testing.T, proxyEnv string, proxy *refusingProxy) ([]string, string) {
	t.Helper()
	return runDaemon(t, proxy, daemonRun{
		env:   []string{"PILOT_TRANSPORT=compat", proxyEnv},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
}

// daemonRun describes one child daemon: args replaces the default
// pilotctl-style network flags (registry, beacon, pinned bogus registry
// trust), env is added to a minimal environment, config (when set) is
// written to $HOME/.pilot/config.json, and await is the proxy request the
// run waits for.
type daemonRun struct {
	args   []string
	env    []string
	config string
	await  string
}

// runDaemon starts main() in a child process and returns the proxy's
// request targets once run.await arrived, plus the daemon's output. The
// proxy refuses everything it is not told to allow, so nothing reaches the
// network.
func runDaemon(t *testing.T, proxy *refusingProxy, run daemonRun) ([]string, string) {
	t.Helper()
	d := startDaemon(t, run)
	defer d.stop()
	d.waitFor(t, proxy, 45*time.Second, "proxy never saw "+strconv.Quote(run.await), func(targets []string) bool {
		return contains(targets, run.await)
	})
	d.stop()
	targets, _ := proxy.snapshot()
	return targets, d.out.String()
}

// runningDaemon is a child process running main().
type runningDaemon struct {
	cmd    *exec.Cmd
	cancel context.CancelFunc
	out    *syncBuffer
	once   sync.Once
}

func (d *runningDaemon) stop() {
	d.once.Do(func() {
		d.cancel()
		_ = d.cmd.Wait()
	})
}

// waitFor polls cond with the proxy's targets until it holds, failing the
// test with what after timeout.
func (d *runningDaemon) waitFor(t *testing.T, proxy *refusingProxy, timeout time.Duration, what string, cond func(targets []string) bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		targets, _ := proxy.snapshot()
		if cond(targets) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s; proxy saw %q\ndaemon output:\n%s", what, targets, d.out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startDaemon starts main() in a child process (see daemonRun).
func startDaemon(t *testing.T, run daemonRun) *runningDaemon {
	t.Helper()
	home := t.TempDir()
	sockDir, err := os.MkdirTemp("", "pdm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	if run.config != "" {
		if err := os.MkdirAll(filepath.Join(home, ".pilot"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".pilot", "config.json"), []byte(run.config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := run.args
	if args == nil {
		args = []string{
			"--registry", defaultRegistryAddr,
			"--beacon", defaultBeaconAddr,
			"-registry-trust=pinned",
			"-registry-fingerprint=" + strings.Repeat("00", 32),
		}
	}
	args = append(append([]string(nil), args...),
		"--listen", ":0",
		"--socket", filepath.Join(sockDir, "s"),
		"--identity", filepath.Join(home, "identity.json"),
		"--log-level", "info",
		"--log-format", "text",
		"-no-skillinject",
		"-motd-feed-url=",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{
		runMainEnv + "=1",
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + os.TempDir(),
		"PILOT_NO_SKILLINJECT=1",
		"PILOT_APPSTORE_ROOT=" + filepath.Join(home, "apps"),
	}, run.env...)
	out := &syncBuffer{}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("start daemon: %v", err)
	}
	d := &runningDaemon{cmd: cmd, cancel: cancel, out: out}
	t.Cleanup(d.stop)
	return d
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
