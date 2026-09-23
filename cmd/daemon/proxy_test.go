// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
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

	p, err := resolveProxyPolicy("auto", "udp")
	if err != nil || p != nil {
		t.Fatalf("auto/udp = (%v, %v), want (nil, nil)", p, err)
	}
	if got := describeProxy("auto", "udp", p); got != "none (-proxy=auto applies to -transport=compat only)" {
		t.Errorf("describeProxy(auto/udp) = %q", got)
	}

	p, err = resolveProxyPolicy("auto", "compat")
	if err != nil || p == nil || p.Mode() != netproxy.ModeAuto || !p.Enabled() {
		t.Fatalf("auto/compat = (%v, %v), want an enabled auto policy", p, err)
	}
	if got := describeProxy("auto", "compat", p); got != "auto: http://***@egress.test:3128" {
		t.Errorf("describeProxy(auto/compat) = %q", got)
	}

	p, err = resolveProxyPolicy("http://ops:hunter2@flag.test:8080", "udp")
	if err != nil || p == nil || p.Mode() != netproxy.ModeExplicit {
		t.Fatalf("explicit/udp = (%v, %v), want an explicit policy", p, err)
	}
	if got := describeProxy("http://ops:hunter2@flag.test:8080", "udp", p); got != "http://***@flag.test:8080" {
		t.Errorf("describeProxy(explicit) = %q", got)
	}

	p, err = resolveProxyPolicy("off", "compat")
	if err != nil || p == nil || p.Mode() != netproxy.ModeOff {
		t.Fatalf("off/compat = (%v, %v), want an off policy", p, err)
	}

	// A malformed -proxy URL is fatal (operator typo) ...
	if _, err := resolveProxyPolicy("ftp://ops:hunter2@flag.test", "compat"); err == nil {
		t.Fatal("malformed -proxy URL accepted")
	} else if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	// ... but a malformed environment under auto only costs the proxy.
	t.Setenv("HTTPS_PROXY", "ftp://muse:s3cret@egress.test")
	p, err = resolveProxyPolicy("auto", "compat")
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
	ln       net.Listener
	wantAuth string

	mu       sync.Mutex
	targets  []string
	badAuths int
	allowed  map[string]bool // CONNECT targets answered 200 (then closed)
}

// allow makes the proxy accept CONNECT target (answer 200, then close the
// tunnel): enough for a reachability check, useless for anything else.
func (p *refusingProxy) allow(target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.allowed == nil {
		p.allowed = map[string]bool{}
	}
	p.allowed[target] = true
}

func newRefusingProxy(t *testing.T, user, pass string) *refusingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	p := &refusingProxy{ln: ln, wantAuth: req.Header.Get("Authorization")}
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
				authOK := r.Header.Get("Proxy-Authorization") == p.wantAuth
				if !authOK {
					p.badAuths++
				}
				ok := authOK && r.Method == http.MethodConnect && p.allowed[r.RequestURI]
				p.mu.Unlock()
				if ok {
					fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
					return
				}
				fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = append([]string{
		runMainEnv + "=1",
		"HOME=" + home,
		"PATH=" + os.Getenv("PATH"),
		"TMPDIR=" + os.TempDir(),
		"PILOT_NO_SKILLINJECT=1",
		"PILOT_APPSTORE_ROOT=" + filepath.Join(home, "apps"),
	}, run.env...)
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
	}()

	deadline := time.Now().Add(45 * time.Second)
	for {
		targets, _ := proxy.snapshot()
		if contains(targets, run.await) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy never saw %q; saw %q\ndaemon output:\n%s", run.await, targets, out.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	_ = cmd.Wait()
	targets, _ := proxy.snapshot()
	return targets, out.String()
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
