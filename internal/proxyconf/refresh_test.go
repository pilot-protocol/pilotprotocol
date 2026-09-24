// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

// rotatingProxy is a CONNECT proxy that accepts one password at a time
// (407 for any other), like an egress proxy that rotates its credentials,
// and tunnels every accepted CONNECT to upstream.
type rotatingProxy struct {
	ln       net.Listener
	upstream string

	mu   sync.Mutex
	pass string
	oks  map[string]int // password -> accepted CONNECTs
	n407 int
	// garble answers rejected credentials with a status line net/http
	// cannot parse, the way Meta Muse's proxy does ("malformed HTTP
	// status code"), instead of a clean 407.
	garble bool
	// refuse answers every CONNECT with this status (0: none).
	refuse int
}

func newRotatingProxy(t *testing.T, pass, upstream string) *rotatingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &rotatingProxy{ln: ln, upstream: upstream, pass: pass, oks: map[string]int{}}
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

func (p *rotatingProxy) url(pass string) string {
	return fmt.Sprintf("http://muse:%s@%s", pass, p.ln.Addr())
}

func (p *rotatingProxy) rotate(pass string) {
	p.mu.Lock()
	p.pass = pass
	p.mu.Unlock()
}

func (p *rotatingProxy) stats() (oks map[string]int, n407 int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := map[string]int{}
	for k, v := range p.oks {
		m[k] = v
	}
	return m, p.n407
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
	good := ok && user == "muse" && pass == p.pass
	if good {
		p.oks[pass]++
	} else {
		p.n407++
	}
	garble, refuse := p.garble, p.refuse
	p.mu.Unlock()
	if req.Method != http.MethodConnect || !good {
		if garble {
			fmt.Fprint(c, "HTTP/1.1 4O7 Proxy Authentication Required\r\n\r\n")
			return
		}
		fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if refuse != 0 {
		fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", refuse, http.StatusText(refuse))
		return
	}
	up, err := net.Dial("tcp", p.upstream)
	if err != nil {
		fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	fmt.Fprint(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

// urlFile stands in for the sandbox's rotating HTTPS_PROXY: the refresh
// command prints the file.
type urlFile struct {
	t    *testing.T
	path string
	p    *rotatingProxy
}

func newURLFile(t *testing.T, p *rotatingProxy, pass string) *urlFile {
	f := &urlFile{t: t, path: filepath.Join(t.TempDir(), "proxy-url"), p: p}
	f.set(pass)
	return f
}

func (f *urlFile) set(pass string) {
	f.t.Helper()
	if err := os.WriteFile(f.path, []byte(f.p.url(pass)+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// rotate changes the proxy's password and what the command prints.
func (f *urlFile) rotate(pass string) {
	f.set(pass)
	f.p.rotate(pass)
}

func (f *urlFile) command() string { return "cat '" + f.path + "'" }

func clearEnv(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(k, "")
	}
}

func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// Resolve wires netproxy's refresh command in: auto takes the command's URL
// (NO_PROXY still applies), an explicit URL is replaced by it, off ignores
// it, and nothing it prints shows up in String.
func TestResolveWithRefreshCommand(t *testing.T) {
	clearEnv(t)
	t.Setenv("NO_PROXY", ".corp.example")
	cmd := netproxy.WithRefreshCommand("echo http://muse:cmdpw9@cmd.test:3128")
	for _, spec := range []string{"auto", "http://muse:flagpw@flag.test:8080"} {
		r, err := Resolve(spec, cmd)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", spec, err)
		}
		if got := ProxyFor(r, "registry.pilotprotocol.network:443"); got != "http://***@cmd.test:3128" {
			t.Errorf("%s: ProxyFor(registry) = %q, want the command's proxy", spec, got)
		}
		if s := r.String(); strings.Contains(s, "cmdpw9") || !strings.Contains(s, "credentials refreshed by command") {
			t.Errorf("%s: String = %q", spec, s)
		}
		if Proxies(r, "127.0.0.1:9000") || Proxies(r, "localhost:80") {
			t.Errorf("%s: loopback proxied", spec)
		}
	}
	auto, _ := Resolve("auto", cmd)
	if Proxies(auto, "git.corp.example:443") {
		t.Error("auto: NO_PROXY ignored with a refresh command")
	}
	off, err := Resolve("none", cmd)
	if err != nil || off.Mode() != netproxy.ModeOff || off.Enabled() {
		t.Fatalf("Resolve(none, cmd) = (%v, %v), want off", off, err)
	}
	if ProxyFor(nil, "x.test:443") != "" || Proxies(nil, "x.test:443") {
		t.Error("nil resolver proxies")
	}
}

// The heart of muse-proxy-cred-rotation-unhandled on the raw-dial path
// (registry, WSS beacon): a dial whose CONNECT gets 407 after a rotation
// re-runs the command and is retried once; credentials that stay wrong
// return the 407 after exactly one retry-less refresh.
func TestDialContextRetriesAfterRotation(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "one", echoServer(t))
	urls := newURLFile(t, proxy, "one")
	r, err := Resolve("auto", netproxy.WithRefreshCommand(urls.command()), netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	dial := DialContext(r, nil)
	ping := func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := dial(ctx, "tcp", "registry.pilot.invalid:443")
		if err != nil {
			return err
		}
		defer c.Close()
		if _, err := c.Write([]byte("ping")); err != nil {
			return err
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			return fmt.Errorf("echo = (%q, %v)", buf, err)
		}
		return nil
	}
	if err := ping(); err != nil {
		t.Fatalf("dial before the rotation: %v", err)
	}
	urls.rotate("two")
	if err := ping(); err != nil {
		t.Fatalf("dial after the rotation: %v", err)
	}
	oks, n407 := proxy.stats()
	if n407 != 1 || oks["two"] != 1 {
		t.Fatalf("proxy: 407s %d, accepted %v; want one 407, then the refreshed credentials", n407, oks)
	}

	// Credentials that are really wrong: the proxy moves on, the command
	// does not. One refresh, no retry (same URL), and the 407 comes back.
	proxy.rotate("three")
	err = ping()
	if !AuthRejected(err) {
		t.Fatalf("dial with unrefreshable credentials = %v, want the 407", err)
	}
	if strings.Contains(err.Error(), "two") {
		t.Fatalf("error leaks the password: %v", err)
	}
	if _, n407 := proxy.stats(); n407 != 2 {
		t.Fatalf("407s = %d, want 2 (no retry with the same URL)", n407)
	}
}

// HTTP clients built with RoundTripper retry a request whose CONNECT got
// 407 once the command has new credentials (replaying a body when it can),
// and keep loopback off the proxy.
func TestRoundTripperRetriesAfterRotation(t *testing.T) {
	clearEnv(t)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s", r.Method, body)
	}))
	defer srv.Close()
	proxy := newRotatingProxy(t, "one", srv.Listener.Addr().String())
	urls := newURLFile(t, proxy, "one")
	r, err := Resolve("auto", netproxy.WithRefreshCommand(urls.command()), netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	// base as the daemon has it: http.DefaultTransport-like, configured in
	// place by ConfigureTransport — RoundTripper must not let that hook
	// swallow the 407 before RefreshingTransport sees it.
	base := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test server
	ConfigureTransport(base, r, nil)
	rt := RoundTripper(r, base)
	client := &http.Client{Transport: rt, Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	do := func(method, target string, body io.Reader) (string, error) {
		req, err := http.NewRequest(method, target, body)
		if err != nil {
			return "", err
		}
		req.Close = true // a new CONNECT per request
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	const target = "https://app.pilot.invalid/api"
	if got, err := do(http.MethodGet, target, nil); err != nil || got != "GET " {
		t.Fatalf("GET before the rotation = (%q, %v)", got, err)
	}
	urls.rotate("two")
	if got, err := do(http.MethodPost, target, bytes.NewReader([]byte("payload"))); err != nil || got != "POST payload" {
		t.Fatalf("POST after the rotation = (%q, %v)", got, err)
	}
	if oks, n407 := proxy.stats(); n407 != 1 || oks["two"] != 1 {
		t.Fatalf("proxy: 407s %d, accepted %v", n407, oks)
	}

	// A body that cannot be replayed is not retried after a refused
	// CONNECT ... (net/http never sent it, but without GetBody it cannot
	// be rebuilt) ...
	urls.rotate("three")
	if _, err := do(http.MethodPost, target, io.NopCloser(strings.NewReader("once"))); !AuthRejected(err) {
		t.Fatalf("unreplayable POST after a rotation = %v, want the 407", err)
	}
	// ... but the refresh happened: the next request goes through.
	if got, err := do(http.MethodGet, target, nil); err != nil || got != "GET " {
		t.Fatalf("GET after the refresh = (%q, %v)", got, err)
	}

	// Loopback never goes to the proxy.
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "local") }))
	defer local.Close()
	before, _ := proxy.stats()
	if got, err := do(http.MethodGet, local.URL, nil); err != nil || got != "local" {
		t.Fatalf("GET loopback = (%q, %v)", got, err)
	}
	if after, _ := proxy.stats(); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("loopback request reached the proxy: %v -> %v", before, after)
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("server hits = %d, want 3", n)
	}
	if RoundTripper(nil, nil) != http.DefaultTransport || RoundTripper(nil, base) != base {
		t.Error("RoundTripper(nil) wraps the transport")
	}
}

// ConfigureTransport (http.DefaultTransport, which plugins use or clone):
// connections follow the resolver's current credentials, and a 407
// refreshes them before the request fails, so the next one succeeds; the
// error never quotes the proxy.
func TestConfigureTransportRefreshesOn407(t *testing.T) {
	clearEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	proxy := newRotatingProxy(t, "one", srv.Listener.Addr().String())
	urls := newURLFile(t, proxy, "one")
	r, err := Resolve("auto", netproxy.WithRefreshCommand(urls.command()), netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test server
	ConfigureTransport(tr, r, nil)
	clone := tr.Clone() // a plugin that cloned DefaultTransport
	for name, rt := range map[string]*http.Transport{"configured": tr, "clone": clone} {
		client := &http.Client{Transport: rt, Timeout: 10 * time.Second}
		get := func() error {
			req, _ := http.NewRequest(http.MethodGet, "https://plugin.pilot.invalid/x", nil)
			req.Close = true
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			resp.Body.Close()
			return nil
		}
		if err := get(); err != nil {
			t.Fatalf("%s: GET = %v", name, err)
		}
		pass := "p-" + name
		urls.rotate(pass)
		err := get()
		var ce *netproxy.ConnectError
		if !errors.As(err, &ce) || ce.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%s: GET after the rotation = %v, want the 407 as a ConnectError", name, err)
		}
		if err := get(); err != nil {
			t.Fatalf("%s: GET after the refresh = %v", name, err)
		}
		if oks, _ := proxy.stats(); oks[pass] != 1 {
			t.Fatalf("%s: accepted %v, want the refreshed %s once", name, oks, pass)
		}
	}
	ConfigureTransport(nil, r, nil)
	plain := &http.Transport{}
	ConfigureTransport(plain, nil, nil)
	if plain.Proxy != nil || plain.OnProxyConnectResponse != nil {
		t.Error("ConfigureTransport(nil resolver) changed the transport")
	}
}
