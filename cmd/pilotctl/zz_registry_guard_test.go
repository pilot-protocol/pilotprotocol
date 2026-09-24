// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// guardPolicyReply is what a sandbox network guard answers a direct
// connection with (Meta Muse: a policy message, then close).
const guardPolicyReply = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nDirect egress is blocked by sandbox policy; use HTTPS_PROXY.\n"

// fakeGuard accepts TCP connections, writes guardPolicyReply (unless quiet)
// and closes them. It counts the connections it saw.
func fakeGuard(t *testing.T, quiet bool) (addr string, conns *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			if !quiet {
				_, _ = io.WriteString(c, guardPolicyReply)
			}
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), conns
}

func TestProbedDirectDial(t *testing.T) {
	ctx := context.Background()

	t.Run("guard that talks first", func(t *testing.T) {
		addr, _ := fakeGuard(t, false)
		_, err := probedDirectDial(ctx, "tcp", addr)
		if !errors.Is(err, errNotRegistry) || !strings.Contains(err.Error(), "sent data before any request") {
			t.Fatalf("err = %v, want errNotRegistry (sent data)", err)
		}
	})
	t.Run("guard that closes at once", func(t *testing.T) {
		addr, _ := fakeGuard(t, true)
		_, err := probedDirectDial(ctx, "tcp", addr)
		if !errors.Is(err, errNotRegistry) || !strings.Contains(err.Error(), "closed the connection") {
			t.Fatalf("err = %v, want errNotRegistry (closed)", err)
		}
	})
	t.Run("registry stays silent: connection usable", func(t *testing.T) {
		r := newFakeRegistry(t)
		start := time.Now()
		c, err := probedDirectDial(ctx, "tcp", r.addr())
		if err != nil {
			t.Fatalf("probedDirectDial: %v", err)
		}
		defer c.Close()
		if d := time.Since(start); d < guardProbeWait {
			t.Errorf("probe returned after %v, before guardProbeWait", d)
		}
		// The read deadline is cleared: a request/response still works.
		if err := writeFrame(c, `{"type":"lookup","node_id":1}`); err != nil {
			t.Fatal(err)
		}
		if _, err := readFrame(c); err != nil {
			t.Fatalf("read after probe: %v", err)
		}
	})
	t.Run("dial error passes through", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		ln.Close()
		if _, err := probedDirectDial(ctx, "tcp", addr); err == nil || errors.Is(err, errNotRegistry) {
			t.Fatalf("err = %v, want the dial error", err)
		}
	})
}

func writeFrame(w io.Writer, body string) error {
	n := len(body)
	_, err := w.Write(append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, body...))
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

// newTLSFakeRegistry is newFakeRegistry behind TLS with a self-signed
// certificate; it returns the registry and the certificate's SHA-256
// fingerprint (for PILOT_REGISTRY_FINGERPRINT).
func newTLSFakeRegistry(t *testing.T) (*fakeRegistry, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: compatRegistryHost},
		DNSNames:     []string{compatRegistryHost},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := tls.NewListener(ln, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	r := &fakeRegistry{t: t, ln: tl, handlers: map[string]func(map[string]interface{}) map[string]interface{}{}}
	go r.accept()
	t.Cleanup(func() { tl.Close() })
	return r, hex.EncodeToString(sum[:])
}

const compatRegistryHost = "registry.pilotprotocol.network"

// mapProxy is an authenticating CONNECT proxy that sends each allowed
// target to a local address and records every CONNECT target. refuse makes
// it answer 403 to everything, like a proxy whose policy denies the host.
type mapProxy struct {
	url    string
	mu     sync.Mutex
	routes map[string]string
	seen   []string
	refuse atomic.Bool
}

func newMapProxy(t *testing.T, routes map[string]string) *mapProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &mapProxy{url: "http://muse:s3cret@" + ln.Addr().String(), routes: routes}
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

func (p *mapProxy) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.seen = append(p.seen, req.Method+" "+req.RequestURI)
	to, ok := p.routes[req.RequestURI]
	p.mu.Unlock()
	if req.Method != http.MethodConnect || !ok || p.refuse.Load() {
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

func (p *mapProxy) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

// stubRawDirectDial sends direct dials of the production raw registry to
// to (never the real 34.71.57.205) and counts them; any other direct dial
// fails the test.
func stubRawDirectDial(t *testing.T, to string) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	prev := rawDirectDial
	rawDirectDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != productionRegistryAddr {
			t.Errorf("unexpected direct dial of %s", addr)
			return nil, errors.New("unexpected direct dial")
		}
		calls.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, to)
	}
	t.Cleanup(func() { rawDirectDial = prev })
	return calls
}

// pilotctl-raw-route-defeated-by-muse-guard: no daemon running and no
// transport configured, HTTPS_PROXY exported, and a network guard that
// accepts direct TCP to the raw registry. pilotctl must reach the registry
// through the proxy, and must not hand back the guard's connection.
func TestUnknownTransportRegistryDialPrefersProxyOverGuard(t *testing.T) {
	reg, fp := newTLSFakeRegistry(t)
	reg.onOK("lookup", map[string]interface{}{"node_id": float64(5), "address": "0:0000.0000.0005", "public": true})
	proxy := newMapProxy(t, map[string]string{compatRegistryAddr: reg.addr()})
	guardAddr, guardConns := fakeGuard(t, false)

	setup := func(t *testing.T, rawTo string) *atomic.Int32 {
		withTransportEnvCleared(t) // also: no running daemon answers
		t.Setenv("HTTPS_PROXY", proxy.url)
		t.Setenv("PILOT_REGISTRY_FINGERPRINT", fp)
		return stubRawDirectDial(t, rawTo)
	}

	t.Run("proxy allows the registry: proxied TLS, guard untouched", func(t *testing.T) {
		rawCalls := setup(t, guardAddr)
		rc, route, err := dialRegistry(productionRegistryAddr)
		if err != nil {
			t.Fatalf("dialRegistry: %v", err)
		}
		defer rc.Close()
		if route.Addr != compatRegistryAddr || !route.proxied() || !route.TLS {
			t.Errorf("route = %+v, want the proxied TLS registry", route)
		}
		if _, err := rc.Lookup(5); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if n := rawCalls.Load(); n != 0 {
			t.Errorf("direct raw dials = %d, want 0 (the proxied route comes first)", n)
		}
		if n := guardConns.Load(); n != 0 {
			t.Errorf("guard saw %d connections, want 0", n)
		}
	})

	t.Run("proxy refuses: the guard is detected, the proxy error is reported", func(t *testing.T) {
		rawCalls := setup(t, guardAddr)
		proxy.refuse.Store(true)
		defer proxy.refuse.Store(false)
		before := guardConns.Load()
		rc, route, err := dialRegistry(productionRegistryAddr)
		if err == nil {
			rc.Close()
			t.Fatal("dialRegistry succeeded against a guard")
		}
		if !route.proxied() || !strings.Contains(err.Error(), "403") {
			t.Errorf("reported route %+v err %v, want the proxied route's 403", route, err)
		}
		if rawCalls.Load() != 1 || guardConns.Load() == before {
			t.Errorf("direct fallback not tried: raw dials=%d guard conns=%d", rawCalls.Load(), guardConns.Load()-before)
		}
	})

	t.Run("proxy refuses, registry reachable directly: raw fallback works", func(t *testing.T) {
		plain := newFakeRegistry(t)
		plain.onOK("lookup", map[string]interface{}{"node_id": float64(5), "address": "0:0000.0000.0005", "public": true})
		rawCalls := setup(t, plain.addr())
		proxy.refuse.Store(true)
		defer proxy.refuse.Store(false)
		rc, route, err := dialRegistry(productionRegistryAddr)
		if err != nil {
			t.Fatalf("dialRegistry: %v", err)
		}
		defer rc.Close()
		if route.Addr != productionRegistryAddr || route.proxied() || route.TLS {
			t.Errorf("route = %+v, want the direct raw registry", route)
		}
		if _, err := rc.Lookup(5); err != nil {
			t.Fatalf("Lookup over the raw fallback: %v", err)
		}
		if rawCalls.Load() != 1 {
			t.Errorf("raw dials = %d, want 1", rawCalls.Load())
		}
	})
}

func TestSandboxProxyCmdFor(t *testing.T) {
	dir := t.TempDir()
	withCmd := writeFakeDaemon(t, append([]string{autoUsage, "proxy", "proxy-cmd"}, baseDaemonFlags...), filepath.Join(dir, "new"))
	withoutCmd := writeFakeDaemon(t, append([]string{autoUsage, "proxy"}, baseDaemonFlags...), filepath.Join(dir, "old"))
	const creds = "http://muse:s3cret@egress.test:3128"

	for _, tc := range []struct {
		name    string
		goos    string
		systemd bool
		noBash  bool
		bin     string
		env     map[string]string
		cfg     string // ~/.pilot/config.json
		flags   map[string]string
		proxy   string // plan.Proxy
		want    bool
	}{
		{name: "Muse-like sandbox", env: map[string]string{"HTTPS_PROXY": creds}, want: true},
		{name: "lower-case https_proxy only", env: map[string]string{"https_proxy": creds}, want: true},
		{name: "plan proxy auto", env: map[string]string{"HTTPS_PROXY": creds}, proxy: "auto", want: true},
		{name: "config without proxy_cmd", env: map[string]string{"HTTPS_PROXY": creds}, cfg: `{"transport":"compat"}`, want: true},
		{name: "macOS", goos: "darwin", env: map[string]string{"HTTPS_PROXY": creds}},
		{name: "systemd host", systemd: true, env: map[string]string{"HTTPS_PROXY": creds}},
		{name: "proxy without credentials", env: map[string]string{"HTTPS_PROXY": "http://egress.test:3128"}},
		{name: "ALL_PROXY only", env: map[string]string{"ALL_PROXY": creds}},
		{name: "no proxy", env: map[string]string{}},
		{name: "PILOT_PROXY_CMD set", env: map[string]string{"HTTPS_PROXY": creds, "PILOT_PROXY_CMD": "cat /run/p"}},
		{name: "config proxy_cmd", env: map[string]string{"HTTPS_PROXY": creds}, cfg: `{"proxy_cmd":"cat /run/p"}`},
		{name: "--config file proxy_cmd", env: map[string]string{"HTTPS_PROXY": creds}, flags: map[string]string{"config": "CFGFILE"}},
		{name: "explicit proxy URL", env: map[string]string{"HTTPS_PROXY": creds}, proxy: "http://u:p@corp.test:3128"},
		{name: "proxy off", env: map[string]string{"HTTPS_PROXY": creds}, proxy: "off"},
		{name: "no bash", noBash: true, env: map[string]string{"HTTPS_PROXY": creds}},
		{name: "daemon without -proxy-cmd", bin: withoutCmd, env: map[string]string{"HTTPS_PROXY": creds}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := withTransportEnvCleared(t)
			t.Setenv("HOME", home)
			for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "PILOT_PROXY_CMD"} {
				t.Setenv(k, tc.env[k])
			}
			goos := tc.goos
			if goos == "" {
				goos = "linux"
			}
			stubSandboxHost(t, goos, tc.systemd, !tc.noBash)
			if tc.cfg != "" {
				writeTestFile(t, filepath.Join(home, ".pilot", "config.json"), tc.cfg)
			}
			flags := map[string]string{}
			for k, v := range tc.flags {
				if v == "CFGFILE" {
					v = filepath.Join(t.TempDir(), "custom.json")
					writeTestFile(t, v, `{"proxy_cmd":"cat /run/p"}`)
				}
				flags[k] = v
			}
			bin := tc.bin
			if bin == "" {
				bin = withCmd
			}
			got := sandboxProxyCmdFor(bin, daemonLaunchPlan{Proxy: tc.proxy}, flags)
			if (got != "") != tc.want {
				t.Fatalf("sandboxProxyCmdFor = %q, want set=%v", got, tc.want)
			}
			if tc.want && got != sandboxProxyCmd {
				t.Errorf("command = %q, want %q", got, sandboxProxyCmd)
			}
		})
	}
}

// stubSandboxHost sets the host seams sandboxProxyCmdFor reads.
func stubSandboxHost(t *testing.T, goos string, systemd, bash bool) {
	t.Helper()
	prevGOOS, prevSystemd, prevBash := hostGOOS, systemdRunning, bashAvailable
	hostGOOS = goos
	systemdRunning = func() bool { return systemd }
	bashAvailable = func() bool { return bash }
	t.Cleanup(func() { hostGOOS, systemdRunning, bashAvailable = prevGOOS, prevSystemd, prevBash })
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// web4-install-sh-edits-not-in-canonical-installer, the binary half: `daemon
// start` in a sandbox hands the daemon PILOT_PROXY_CMD by itself, so rotating
// credentials are re-read even when the installer that set the node up never
// saved proxy_cmd. A configured proxy_cmd is never overridden.
func TestCLIDaemonStartSandboxProxyCmd(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	out := filepath.Join(dir, "daemon")
	bin := writeFakeDaemon(t, append([]string{autoUsage, "proxy", "proxy-cmd"}, baseDaemonFlags...), out)
	home := t.TempDir()
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN":      bin,
		"PILOT_SOCKET":          filepath.Join(dir, "pilot.sock"),
		"PILOT_HOME":            home,
		"HTTPS_PROXY":           "http://muse:s3cret@egress.test:3128",
		"PILOTCTL_TEST_SANDBOX": "1", // Linux, no systemd, bash present
	})
	daemonEnv := func() []string {
		var got []string
		for _, kv := range readLines(t, out+".env") {
			if strings.HasPrefix(kv, "PILOT_PROXY_CMD=") {
				got = append(got, kv)
			}
		}
		return got
	}

	if _, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground"}, env); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	if got := daemonEnv(); len(got) != 1 || got[0] != "PILOT_PROXY_CMD="+sandboxProxyCmd {
		t.Errorf("daemon PILOT_PROXY_CMD = %q, want exactly %q", got, sandboxProxyCmd)
	}

	// A proxy_cmd in config.json wins: the daemon reads it itself.
	writeTestFile(t, filepath.Join(home, ".pilot", "config.json"), `{"proxy_cmd":"cat /run/proxy-url"}`)
	if _, stderr, code := runCLI(t, []string{"daemon", "start", "--foreground"}, env); code != 0 {
		t.Fatalf("exit=%d stderr=%s", code, stderr)
	}
	for _, kv := range daemonEnv() {
		if kv != "PILOT_PROXY_CMD=" {
			t.Errorf("configured proxy_cmd overridden by %q", kv)
		}
	}
}
