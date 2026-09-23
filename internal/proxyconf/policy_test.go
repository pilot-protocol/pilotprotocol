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
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

// rotatingProxy is a CONNECT proxy that accepts one password at a time
// (407 for any other) and tunnels every accepted CONNECT to upstream.
type rotatingProxy struct {
	ln       net.Listener
	upstream string

	mu    sync.Mutex
	pass  string
	oks   map[string]int // password -> accepted CONNECTs
	n407  int
	sawNo int // CONNECTs without credentials
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
	switch {
	case !ok:
		p.sawNo++
	case good:
		p.oks[pass]++
	default:
		p.n407++
	}
	p.mu.Unlock()
	if req.Method != http.MethodConnect || !good {
		fmt.Fprint(c, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"t\"\r\nContent-Length: 0\r\n\r\n")
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

// fakeSource is a proxy command stand-in: it prints *url, counting runs.
type fakeSource struct {
	mu   sync.Mutex
	url  string
	err  error
	runs int
}

func (f *fakeSource) set(u string, err error) {
	f.mu.Lock()
	f.url, f.err = u, err
	f.mu.Unlock()
}

func (f *fakeSource) run(context.Context, string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs++
	return f.url, f.err
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
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

func clearEnv(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
}

func TestStaticAndNilPolicy(t *testing.T) {
	var nilPolicy *Policy
	if Static(nil) != nil {
		t.Fatal("Static(nil) is not nil")
	}
	if nilPolicy.Enabled() || nilPolicy.Refreshable() || nilPolicy.Resolver() != nil || nilPolicy.RequestProxy() != nil {
		t.Fatal("nil policy is not inert")
	}
	if nilPolicy.String() != "none" || nilPolicy.Proxies("registry.pilot.invalid:443") {
		t.Fatal("nil policy describes itself as proxying")
	}
	if changed, err := nilPolicy.Refresh(context.Background()); changed || err != nil {
		t.Fatal("nil policy refreshed")
	}
	nilPolicy.Run(context.Background(), time.Millisecond) // returns at once
	tr := &http.Transport{}
	nilPolicy.ConfigureTransport(tr)
	if tr.Proxy != nil {
		t.Fatal("nil policy configured a transport")
	}

	r, _ := netproxy.Explicit("http://u:secret@proxy.test:3128")
	p := Static(r)
	if !p.Enabled() || p.Refreshable() || p.Mode() != netproxy.ModeExplicit {
		t.Fatalf("static policy = enabled %v refreshable %v mode %s", p.Enabled(), p.Refreshable(), p.Mode())
	}
	if strings.Contains(p.String(), "secret") {
		t.Fatalf("String leaks the password: %s", p.String())
	}
	if !p.Proxies("registry.pilot.invalid:443") || p.Proxies("127.0.0.1:9000") || p.Proxies("localhost:1") {
		t.Fatal("Proxies ignores the loopback exemption")
	}
	if rt := p.RoundTripper(http.DefaultTransport); rt != http.DefaultTransport {
		t.Fatal("a static policy wraps the round tripper")
	}
}

func TestCommandPolicyRefresh(t *testing.T) {
	clearEnv(t)
	src := &fakeSource{url: "http://muse:one@proxy.test:3128"}
	p, err := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Refreshable() || !p.Enabled() || p.Mode() != netproxy.ModeExplicit {
		t.Fatalf("command policy: refreshable %v enabled %v mode %s", p.Refreshable(), p.Enabled(), p.Mode())
	}
	if s := p.String(); strings.Contains(s, "one") || !strings.Contains(s, "refreshed from the proxy command") {
		t.Fatalf("String = %q", s)
	}
	if changed, err := p.Refresh(context.Background()); changed || err != nil {
		t.Fatalf("unchanged refresh = (%v, %v)", changed, err)
	}
	src.set("http://muse:two@proxy.test:3128", nil)
	if changed, err := p.Refresh(context.Background()); !changed || err != nil {
		t.Fatalf("rotated refresh = (%v, %v)", changed, err)
	}
	u, _ := p.Resolver().ProxyForAddr("registry.pilot.invalid:443")
	if pw, _ := u.User.Password(); pw != "two" {
		t.Fatalf("password after refresh = %q, want two", pw)
	}
	// A failing command keeps the current proxy.
	src.set("", errors.New("exit status 1"))
	if changed, err := p.Refresh(context.Background()); changed || err == nil {
		t.Fatalf("failing refresh = (%v, %v)", changed, err)
	}
	u, _ = p.Resolver().ProxyForAddr("registry.pilot.invalid:443")
	if pw, _ := u.User.Password(); pw != "two" {
		t.Fatalf("password after a failed refresh = %q, want two", pw)
	}
	if _, err := newCommandPolicy(context.Background(), "  ", nil, true, src.run); err == nil {
		t.Fatal("empty command accepted")
	}
}

// A failing first run serves the fallback until the command succeeds.
func TestCommandPolicyFallback(t *testing.T) {
	clearEnv(t)
	src := &fakeSource{err: errors.New("exit status 127")}
	fallback, _ := netproxy.Explicit("http://muse:launch@proxy.test:3128")
	p, err := newCommandPolicy(context.Background(), "cmd", fallback, true, src.run)
	if err == nil || p == nil {
		t.Fatalf("first run failure = (%v, %v), want a usable policy and the error", p, err)
	}
	if p.Resolver() != fallback {
		t.Fatal("fallback not in use")
	}
	p2, _ := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	if !p2.Enabled() || !p2.Proxies("registry.pilot.invalid:443") || p2.String() != "none yet (refreshed from the proxy command)" {
		t.Fatalf("no-fallback policy: enabled %v, %q", p2.Enabled(), p2.String())
	}
	src.set("http://muse:fresh@proxy.test:3128", nil)
	if changed, err := p.Refresh(context.Background()); !changed || err != nil {
		t.Fatalf("refresh = (%v, %v)", changed, err)
	}
}

// The heart of muse-proxy-cred-rotation-unhandled: a dial whose CONNECT
// the proxy rejects with 407 re-runs the command and retries once.
func TestCommandPolicyDialRetriesOn407(t *testing.T) {
	clearEnv(t)
	echo := echoServer(t)
	proxy := newRotatingProxy(t, "one", echo)
	src := &fakeSource{url: proxy.url("one")}
	p, err := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	if err != nil {
		t.Fatal(err)
	}
	dial := p.DialContext(nil)
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

	proxy.rotate("two")
	src.set(proxy.url("two"), nil)
	runs := src.count()
	if err := ping(); err != nil {
		t.Fatalf("dial after the rotation: %v", err)
	}
	oks, n407 := proxy.stats()
	if n407 != 1 || oks["two"] != 1 {
		t.Fatalf("proxy: 407s %d, accepted %v; want one 407, then the refreshed credentials", n407, oks)
	}
	if src.count() != runs+1 {
		t.Fatalf("command runs = %d, want one refresh", src.count()-runs)
	}

	// Credentials that are really wrong: one refresh, no retry (same URL),
	// and the 407 error comes back.
	proxy.rotate("three")
	if err := ping(); err == nil || !IsProxyAuthError(err) {
		t.Fatalf("dial with unrefreshable credentials = %v, want the 407", err)
	}
	if _, n407 := proxy.stats(); n407 != 2 {
		t.Fatalf("407s = %d, want 2 (no retry with the same URL)", n407)
	}
}

// NO_PROXY applies to a command policy with -proxy=auto semantics only;
// loopback always goes direct.
func TestCommandPolicyNoProxy(t *testing.T) {
	clearEnv(t)
	t.Setenv("NO_PROXY", "*.corp.example,10.0.0.0/8")
	src := &fakeSource{url: "http://muse:x@proxy.test:3128"}
	auto, _ := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	explicit, _ := newCommandPolicy(context.Background(), "cmd", nil, false, src.run)
	for addr, want := range map[string]bool{
		"registry.pilotprotocol.network:443": true,
		"git.corp.example:443":               false,
		"10.1.2.3:9000":                      false,
		"127.0.0.1:9000":                     false,
	} {
		if got := auto.Proxies(addr); got != want {
			t.Errorf("auto: Proxies(%s) = %v, want %v", addr, got, want)
		}
	}
	if !explicit.Proxies("git.corp.example:443") || explicit.Proxies("localhost:80") {
		t.Error("explicit command policy: NO_PROXY applied or loopback proxied")
	}
	pf := auto.RequestProxy()
	for raw, want := range map[string]bool{
		"https://raw.githubusercontent.com/x": true,
		"https://git.corp.example/x":          false,
		"http://127.0.0.1:8080/hook":          false,
		"ws://10.0.0.7/x":                     false,
	} {
		u, _ := url.Parse(raw)
		got, err := pf(&http.Request{URL: u})
		if err != nil || (got != nil) != want {
			t.Errorf("RequestProxy(%s) = (%v, %v), want proxied=%v", raw, got, err, want)
		}
	}
}

// HTTP clients: the transport follows the refreshed URL, a 407 on CONNECT
// refreshes at once, and RoundTripper retries the request (replaying a
// body when it can).
func TestCommandPolicyHTTPRetriesOn407(t *testing.T) {
	clearEnv(t)
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "%s %s", r.Method, body)
	}))
	defer srv.Close()
	proxy := newRotatingProxy(t, "one", srv.Listener.Addr().String())
	src := &fakeSource{url: proxy.url("one")}
	p, err := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // test server
	p.ConfigureTransport(tr)
	client := &http.Client{Transport: p.RoundTripper(tr), Timeout: 10 * time.Second}
	defer tr.CloseIdleConnections()

	get := func(method string, body io.Reader) (string, error) {
		req, err := http.NewRequest(method, "https://app.pilot.invalid/api", body)
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
	if got, err := get(http.MethodGet, nil); err != nil || got != "GET " {
		t.Fatalf("GET before the rotation = (%q, %v)", got, err)
	}
	proxy.rotate("two")
	src.set(proxy.url("two"), nil)
	if got, err := get(http.MethodPost, bytes.NewReader([]byte("payload"))); err != nil || got != "POST payload" {
		t.Fatalf("POST after the rotation = (%q, %v)", got, err)
	}
	oks, n407 := proxy.stats()
	if n407 != 1 || oks["two"] != 1 {
		t.Fatalf("proxy: 407s %d, accepted %v", n407, oks)
	}

	// A body that cannot be replayed is not retried.
	proxy.rotate("three")
	src.set(proxy.url("three"), nil)
	if _, err := get(http.MethodPost, io.NopCloser(strings.NewReader("once"))); err == nil || !IsProxyAuthError(err) {
		t.Fatalf("unreplayable POST after a rotation = %v, want the 407", err)
	}
	// ... but the refresh happened: the next request goes through.
	if got, err := get(http.MethodGet, nil); err != nil || got != "GET " {
		t.Fatalf("GET after the refresh = (%q, %v)", got, err)
	}
	if n := hits.Load(); n != 3 {
		t.Fatalf("server hits = %d, want 3", n)
	}
}

func TestCommandPolicyRun(t *testing.T) {
	clearEnv(t)
	src := &fakeSource{url: "http://muse:one@proxy.test:3128"}
	p, _ := newCommandPolicy(context.Background(), "cmd", nil, true, src.run)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx, 10*time.Millisecond); close(done) }()
	src.set("http://muse:two@proxy.test:3128", nil)
	deadline := time.Now().Add(3 * time.Second)
	for {
		u, _ := p.Resolver().ProxyForAddr("x.test:443")
		if pw, _ := u.User.Password(); pw == "two" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run never refreshed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
}

func TestIsProxyAuthError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{&netproxy.ConnectError{Target: "x:443", StatusCode: 407}, true},
		{fmt.Errorf("dial: %w", &netproxy.ConnectError{Target: "x:443", StatusCode: 407}), true},
		{&netproxy.ConnectError{Target: "x:443", StatusCode: 403}, false},
		{fmt.Errorf("Get x: %w", ErrProxyAuth), true},
		{errors.New("Proxy Authentication Required"), true},
		{errors.New(`read CONNECT response: malformed HTTP status code "Proxy"`), true},
		{errors.New("connection refused"), false},
	} {
		if got := IsProxyAuthError(tc.err); got != tc.want {
			t.Errorf("IsProxyAuthError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// The real command runner: /bin/sh -c, first line of stdout, validated;
// nothing it prints ever shows up in an error.
func TestRunProxyCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	t.Setenv("PILOT_ADMIN_TOKEN", "admin-secret")
	ctx := context.Background()
	got, err := runProxyCommand(ctx, `printf 'http://muse:%s@proxy.test:3128\nsecond line\n' "${PILOT_ADMIN_TOKEN:-hidden}"; echo noise >&2`)
	if err != nil || got != "http://muse:hidden@proxy.test:3128" {
		t.Fatalf("runProxyCommand = (%q, %v), want the first line, without the admin token", got, err)
	}
	for cmd, want := range map[string]string{
		"exit 3":                           "exit status 3",
		"true":                             "printed nothing",
		"echo auto":                        "want an http:// or https:// proxy URL",
		"echo muse:s3cret@proxy.test:3128": "invalid proxy",
		"echo socks5://u:s3cret@p:1080":    "scheme must be http or https",
		"echo s3cret; exit 1":              "exit status 1",
	} {
		_, err := runProxyCommand(ctx, cmd)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("runProxyCommand(%q) = %v, want an error containing %q", cmd, err, want)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("runProxyCommand(%q) error leaks output: %v", cmd, err)
		}
	}
}
