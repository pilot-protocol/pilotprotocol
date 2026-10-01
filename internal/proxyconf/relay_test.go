// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

func (p *rotatingProxy) setGarble(on bool) {
	p.mu.Lock()
	p.garble = on
	p.mu.Unlock()
}

func (p *rotatingProxy) setRefuse(status int) {
	p.mu.Lock()
	p.refuse = status
	p.mu.Unlock()
}

// countingCommand is a refresh command that prints the rotating URL file
// and counts its runs.
func countingCommand(t *testing.T, urls *urlFile) (command string, runs func() int) {
	t.Helper()
	counter := filepath.Join(t.TempDir(), "runs")
	command = fmt.Sprintf("echo x >> '%s'; cat '%s'", counter, urls.path)
	return command, func() int {
		b, _ := os.ReadFile(counter)
		return strings.Count(string(b), "x")
	}
}

// startTestRelay starts a Relay for r and stops it with the test.
func startTestRelay(t *testing.T, r *netproxy.Resolver) *Relay {
	t.Helper()
	rl, err := StartRelay(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rl.Close() })
	return rl
}

// appClient is an app the daemon started: a plain net/http client whose
// proxy comes from its environment, here the Relay's URL.
func appClient(proxyURL *url.URL) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, // #nosec G402 -- test server
			DisableKeepAlives: true,                                  // a new CONNECT per request
		},
	}
}

func getBody(c *http.Client, target string) (string, error) {
	resp, err := c.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// web4-470-apps-inherit-stale-proxy-creds: an app keeps whatever proxy URL
// it inherited. Pointed at the Relay, it never holds the proxy's
// credentials: after the proxy rotates them — and answers the stale ones
// the way Meta Muse does, with a status line that cannot be parsed — the
// app's next request still succeeds, because the Relay refreshes and
// retries the CONNECT upstream.
func TestRelayFollowsRotationForApps(t *testing.T) {
	clearEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "hello ", r.Host) }))
	defer srv.Close()
	proxy := newRotatingProxy(t, "one", srv.Listener.Addr().String())
	proxy.setGarble(true)
	urls := newURLFile(t, proxy, "one")
	command, runs := countingCommand(t, urls)
	r, err := Resolve("auto", netproxy.WithRefreshFunc(CommandSource(command, nil)), netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	relay := startTestRelay(t, r)
	app := appClient(relay.URL())

	const target = "https://app.pilot.invalid/x"
	if got, err := getBody(app, target); err != nil || got != "hello app.pilot.invalid" {
		t.Fatalf("GET before the rotation = (%q, %v)", got, err)
	}
	before := runs()
	for i, pass := range []string{"two", "three", "four"} {
		urls.rotate(pass)
		if got, err := getBody(app, target); err != nil || got != "hello app.pilot.invalid" {
			t.Fatalf("GET after rotation %d = (%q, %v)", i+1, got, err)
		}
		if oks, _ := proxy.stats(); oks[pass] != 1 {
			t.Fatalf("rotation %d: proxy accepted %v, want the refreshed %q once", i+1, oks, pass)
		}
	}
	if n := runs() - before; n != 3 {
		t.Errorf("refresh command ran %d times for 3 rotations, want 3", n)
	}
	if _, n407 := proxy.stats(); n407 != 3 {
		t.Errorf("proxy rejected %d CONNECTs, want 3 (one per rotation, then the retry)", n407)
	}

	// Credentials the command cannot fix: the app gets a 502 that names
	// the problem without any credentials or proxy-supplied text.
	proxy.rotate("unknown")
	_, err = getBody(app, target)
	if err == nil {
		t.Fatal("GET with unrefreshable credentials succeeded")
	}
	msg := err.Error()
	for _, want := range []string{"Bad Gateway", "pilot-daemon proxy relay", "malformed HTTP status code", "response text withheld"} {
		if !strings.Contains(msg, want) {
			t.Errorf("app error %q lacks %q", msg, want)
		}
	}
	for _, secret := range []string{"four", "unknown", "4O7", "muse:"} {
		if strings.Contains(msg, secret) {
			t.Errorf("app error %q leaks %q", msg, secret)
		}
	}
}

// Only CONNECT is relayed, only with the Relay's own credentials, and a
// refused request never reaches the egress proxy.
func TestRelayRequiresItsCredentials(t *testing.T) {
	clearEnv(t)
	echo := echoServer(t)
	proxy := newRotatingProxy(t, "one", echo)
	r, err := Resolve(proxy.url("one"))
	if err != nil {
		t.Fatal(err)
	}
	relay := startTestRelay(t, r)
	if u := relay.URL(); u.User.Username() != RelayUser || !IsLoopbackHost(u.Hostname()) {
		t.Fatalf("relay URL %s: want %s@loopback", Redact(u.String()), RelayUser)
	}
	token, _ := relay.URL().User.Password()
	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}
	for _, tc := range []struct {
		name, request string
		want          int
	}{
		{"no credentials", "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\n\r\n", 407},
		{"wrong token", "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\nProxy-Authorization: " + basic(RelayUser, "nope") + "\r\n\r\n", 407},
		{"the proxy's credentials", "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\nProxy-Authorization: " + basic("muse", "one") + "\r\n\r\n", 407},
		{"not CONNECT", "GET http://svc.pilot.invalid/ HTTP/1.1\r\nHost: svc.pilot.invalid\r\nProxy-Authorization: " + basic(RelayUser, token) + "\r\n\r\n", 405},
		{"no port", "CONNECT svc.pilot.invalid HTTP/1.1\r\nHost: svc.pilot.invalid\r\nProxy-Authorization: " + basic(RelayUser, token) + "\r\n\r\n", 400},
		{"garbage", "hello\r\n\r\n", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := rawRelayRequest(t, relay, tc.request)
			if status != tc.want {
				t.Fatalf("status %d, want %d", status, tc.want)
			}
		})
	}
	if oks, n407 := proxy.stats(); len(oks) != 0 || n407 != 0 {
		t.Fatalf("refused requests reached the proxy: accepted %v, 407s %d", oks, n407)
	}

	// With the token: tunnelled through the proxy, bytes both ways.
	status, conn := rawRelayRequest(t, relay, "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\nProxy-Authorization: "+basic(RelayUser, token)+"\r\n\r\n")
	if status != 200 {
		t.Fatalf("authorized CONNECT: status %d", status)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the relay = (%q, %v)", buf, err)
	}
	if oks, _ := proxy.stats(); oks["one"] != 1 {
		t.Fatalf("proxy accepted %v, want one CONNECT with the proxy's credentials", oks)
	}
}

// rawRelayRequest sends request to the Relay and returns the response
// status and the connection (closed with the test).
func rawRelayRequest(t *testing.T, relay *Relay, request string) (int, net.Conn) {
	t.Helper()
	c, err := net.Dial("tcp", relay.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read relay response: %v", err)
	}
	c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		t.Fatalf("relay sent %d bytes after its response", br.Buffered())
	}
	return resp.StatusCode, c
}

// A proxy that refuses the target is passed on as 403; a proxy that
// cannot be reached as 502; neither with credentials in it.
func TestRelayRefusals(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "s3cret", echoServer(t))
	proxy.setRefuse(http.StatusForbidden)
	r, err := Resolve(proxy.url("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	app := appClient(startTestRelay(t, r).URL())
	_, err = getBody(app, "https://blocked.pilot.invalid/")
	if err == nil || !strings.Contains(err.Error(), "Forbidden") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("GET via a refusing proxy = %v, want Forbidden without credentials", err)
	}

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := "http://muse:s3cret@" + closed.Addr().String()
	closed.Close()
	r, err = Resolve(dead)
	if err != nil {
		t.Fatal(err)
	}
	app = appClient(startTestRelay(t, r).URL())
	_, err = getBody(app, "https://any.pilot.invalid/")
	if err == nil || !strings.Contains(err.Error(), "Bad Gateway") || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("GET via an unreachable proxy = %v, want Bad Gateway without credentials", err)
	}

	if _, err := StartRelay(nil, nil); err == nil {
		t.Error("StartRelay(nil resolver) started")
	}
	if _, err := StartRelay(netproxy.Off(), nil); err == nil {
		t.Error("StartRelay(off) started")
	}
}

// Serves recognises the Relay in a proxy URL (the daemon's guard against a
// refresh command that prints it), and a CONNECT whose proxy would be the
// Relay itself is refused instead of looping.
func TestRelayServesAndLoopGuard(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "one", echoServer(t))
	r, err := Resolve(proxy.url("one"))
	if err != nil {
		t.Fatal(err)
	}
	relay := startTestRelay(t, r)
	_, port, _ := net.SplitHostPort(relay.Addr())
	for in, want := range map[string]bool{
		relay.URL().String():                  true,
		"http://x:y@127.0.0.1:" + port:        true,
		"http://localhost:" + port + "/":      true,
		"  http://127.0.0.1:" + port + "\n":   true,
		proxy.url("one"):                      false,
		"http://proxy.example:" + port:        false,
		"not a url":                           false,
		"":                                    false,
		"http://a:b/c@127.0.0.1:" + port + "": true,
	} {
		if got := relay.Serves(in); got != want {
			t.Errorf("Serves(%q) = %v, want %v", in, got, want)
		}
	}
	var none *Relay
	if none.Serves(relay.URL().String()) || none.Close() != nil {
		t.Error("nil Relay")
	}

	// A relay whose resolver names the relay itself.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	selfResolver, err := Resolve("http://muse:one@" + ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	self, err := startRelayOn(ln, selfResolver, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	selfToken, _ := self.URL().User.Password()
	status, _ := rawRelayRequest(t, self, "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\nProxy-Authorization: Basic "+
		base64.StdEncoding.EncodeToString([]byte(RelayUser+":"+selfToken))+"\r\n\r\n")
	if status != http.StatusLoopDetected {
		t.Fatalf("CONNECT through a relay that proxies to itself: status %d, want 508", status)
	}
}

// Close ends open tunnels and returns once their goroutines are done.
func TestRelayCloseEndsTunnels(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "one", echoServer(t))
	r, err := Resolve(proxy.url("one"))
	if err != nil {
		t.Fatal(err)
	}
	relay, err := StartRelay(r, nil)
	if err != nil {
		t.Fatal(err)
	}
	token, _ := relay.URL().User.Password()
	status, conn := rawRelayRequest(t, relay, "CONNECT svc.pilot.invalid:443 HTTP/1.1\r\nHost: svc.pilot.invalid:443\r\nProxy-Authorization: Basic "+
		base64.StdEncoding.EncodeToString([]byte(RelayUser+":"+token))+"\r\n\r\n")
	if status != 200 {
		t.Fatalf("CONNECT: status %d", status)
	}
	done := make(chan error, 1)
	go func() { done <- relay.Close() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return with a tunnel open")
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("tunnel still open after Close")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("tunnel not closed by Close")
	}
	if _, err := net.DialTimeout("tcp", relay.Addr(), time.Second); err == nil {
		t.Error("relay still accepting after Close")
	}
	if err := relay.Close(); err != nil {
		t.Errorf("second Close = %v", err)
	}
}

// web4-470-configuretransport-ignores-garbled-rejection: plugin clients on
// http.DefaultTransport (configured in place, or cloned from it) behind a
// proxy that answers stale credentials with an unparseable status line.
// With the daemon's Relay, the first request after a rotation already
// succeeds (one refresh, the Relay's retry) and no proxy bytes reach an
// error; plain http:// requests and loopback keep their old routes.
func TestConfigureTransportViaRelayHandlesGarbledRejection(t *testing.T) {
	clearEnv(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	proxy := newRotatingProxy(t, "one", srv.Listener.Addr().String())
	proxy.setGarble(true)
	urls := newURLFile(t, proxy, "one")
	command, runs := countingCommand(t, urls)
	r, err := Resolve("auto", netproxy.WithRefreshFunc(CommandSource(command, nil)), netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	relay := startTestRelay(t, r)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} // #nosec G402 -- test server
	ConfigureTransport(tr, r, relay.URL())
	clone := tr.Clone() // a plugin that cloned DefaultTransport
	// A fixed order: the credentials restored below are the last ones
	// rotated in here (map order would make that random).
	for _, c := range []struct {
		name string
		rt   *http.Transport
	}{{"configured", tr}, {"clone", clone}} {
		name, rt := c.name, c.rt
		client := &http.Client{Transport: rt, Timeout: 20 * time.Second}
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
		before := runs()
		urls.rotate(pass)
		if err := get(); err != nil {
			t.Fatalf("%s: first GET after the rotation = %v, want success (refresh + retry in the relay)", name, err)
		}
		if n := runs() - before; n != 1 {
			t.Errorf("%s: refresh command ran %d times, want 1", name, n)
		}
		if oks, _ := proxy.stats(); oks[pass] != 1 {
			t.Fatalf("%s: accepted %v, want the refreshed %s once", name, oks, pass)
		}
	}

	// Credentials nothing can fix: the error is the relay's account of
	// what happened upstream, in netproxy's words, never the proxy's.
	proxy.rotate("unknown")
	req, _ := http.NewRequest(http.MethodGet, "https://plugin.pilot.invalid/x", nil)
	req.Close = true
	_, err = (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Do(req)
	var ce *netproxy.ConnectError
	if err == nil || !UnreadableConnectReply(err) || !errors.As(err, &ce) || ce.StatusCode != http.StatusBadGateway {
		t.Fatalf("GET with unrefreshable credentials = %v, want the relay's 502 carrying netproxy's report", err)
	}
	if strings.Contains(err.Error(), "4O7") || strings.Contains(err.Error(), "unknown") || strings.Contains(err.Error(), "pilot-relay") {
		t.Fatalf("error leaks proxy text or credentials: %v", err)
	}
	if CredentialHint(err) == "" {
		t.Errorf("no credential hint for %v", err)
	}
	proxy.rotate("p-clone")
	proxy.setRefuse(http.StatusForbidden)
	_, err = (&http.Client{Transport: tr, Timeout: 20 * time.Second}).Get("https://blocked.pilot.invalid/")
	if !errors.As(err, &ce) || ce.StatusCode != http.StatusForbidden || !strings.Contains(err.Error(), "proxy CONNECT blocked.pilot.invalid:443: 403 Forbidden") {
		t.Fatalf("GET of a target the proxy refuses = %v, want its 403", err)
	}
	proxy.setRefuse(0)

	// The routes: https through the relay, http:// straight to the proxy
	// (a relay only tunnels), loopback direct.
	for target, want := range map[string]string{
		"https://plugin.pilot.invalid/": relay.Addr(),
		"wss://plugin.pilot.invalid/":   relay.Addr(),
		"http://plugin.pilot.invalid/":  proxy.ln.Addr().String(),
		"https://127.0.0.1:9/":          "",
		"http://localhost/":             "",
	} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		u, err := tr.Proxy(req)
		got := ""
		if u != nil {
			got = u.Host
		}
		if err != nil || got != want {
			t.Errorf("Proxy(%s) = (%v, %v), want host %q", target, u, err, want)
		}
	}
}

// Without a Relay, a garbled rejection is net/http's own error — which is
// why the daemon passes its Relay whenever it proxies. This documents the
// limit ConfigureTransport's comment describes.
func TestConfigureTransportWithoutRelayGarbled(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "one", echoServer(t))
	proxy.setGarble(true)
	r, err := Resolve(proxy.url("stale"))
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{}
	ConfigureTransport(tr, r, nil)
	_, err = (&http.Client{Transport: tr, Timeout: 10 * time.Second}).Get("https://plugin.pilot.invalid/")
	if err == nil || !strings.Contains(err.Error(), "malformed HTTP status code") {
		t.Fatalf("GET = %v, want net/http's malformed status error", err)
	}
}

// The credential hints: a 407, and netproxy's report of a CONNECT answer
// it could not parse (Meta Muse's form), each get one that names
// -proxy-cmd; anything else gets none.
func TestCredentialHint(t *testing.T) {
	clearEnv(t)
	proxy := newRotatingProxy(t, "right", echoServer(t))
	dialErr := func(garble bool) error {
		proxy.setGarble(garble)
		r, err := Resolve(proxy.url("wrong"))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := DialContext(r, nil)(ctx, "tcp", "registry.pilot.invalid:443")
		if err == nil {
			c.Close()
			t.Fatal("dial with wrong credentials succeeded")
		}
		return err
	}
	garbled := dialErr(true)
	if !UnreadableConnectReply(garbled) || AuthRejected(garbled) {
		t.Fatalf("garbled rejection %v: UnreadableConnectReply %v, AuthRejected %v", garbled, UnreadableConnectReply(garbled), AuthRejected(garbled))
	}
	hint := CredentialHint(garbled)
	if !strings.Contains(hint, "could not be parsed") || !strings.Contains(hint, "-proxy-cmd") || strings.Contains(hint, "udp") {
		t.Errorf("garbled hint = %q", hint)
	}
	if strings.Contains(garbled.Error(), "4O7") || strings.Contains(garbled.Error(), "wrong") {
		t.Errorf("error quotes the proxy or the password: %v", garbled)
	}
	rejected := dialErr(false)
	if !AuthRejected(rejected) || UnreadableConnectReply(rejected) || !strings.Contains(CredentialHint(rejected), "(407)") {
		t.Errorf("407: %v, hint %q", rejected, CredentialHint(rejected))
	}
	wrapped := fmt.Errorf("registry dial (after 10 attempts): %w", garbled)
	if CredentialHint(wrapped) == "" {
		t.Error("no hint for a wrapped garbled rejection")
	}
	for _, err := range []error{nil, errors.New("dial tcp: connection refused"), errors.New("read CONNECT response: EOF")} {
		if h := CredentialHint(err); h != "" {
			t.Errorf("CredentialHint(%v) = %q, want none", err, h)
		}
	}
}
