// SPDX-License-Identifier: AGPL-3.0-or-later

package wss_test

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/transport/wss"
)

// The compat beacon behind an authenticating HTTP CONNECT proxy — the only
// egress in a Meta Muse-style sandbox. The beacon is served only as
// beacon.pilot.invalid, a reserved name that never resolves locally, and
// only the proxy knows where it lives. A working transport therefore proves
// the proxy was asked to CONNECT by host name and that TLS ran end-to-end
// with the beacon (the certificate covers only that name).

const proxiedBeaconHost = "beacon.pilot.invalid"

// connectProxy is a minimal authenticating CONNECT proxy. It routes
// *.pilot.invalid to loopback, answers 407 without the expected Basic
// credentials, refuses every other method and host, and records each
// request target.
type connectProxy struct {
	ln       net.Listener
	wantAuth string

	mu      sync.Mutex
	targets []string
	denied  []int
	live    []net.Conn
	wg      sync.WaitGroup
}

func newConnectProxy(t *testing.T, user, pass string) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	p := &connectProxy{ln: ln, wantAuth: req.Header.Get("Authorization")}
	p.wg.Add(1)
	go p.accept()
	t.Cleanup(func() {
		ln.Close()
		p.mu.Lock()
		for _, c := range p.live {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p
}

func (p *connectProxy) url(user, pass string) string {
	return fmt.Sprintf("http://%s:%s@%s", user, pass, p.ln.Addr())
}

func (p *connectProxy) connects() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

func (p *connectProxy) deniedStatuses() []int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]int(nil), p.denied...)
}

func (p *connectProxy) track(c net.Conn) {
	p.mu.Lock()
	p.live = append(p.live, c)
	p.mu.Unlock()
}

func (p *connectProxy) accept() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.track(conn)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.serve(conn)
		}()
	}
}

func (p *connectProxy) deny(conn net.Conn, code int) {
	p.mu.Lock()
	p.denied = append(p.denied, code)
	p.mu.Unlock()
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
}

func (p *connectProxy) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.RequestURI)
	p.mu.Unlock()
	if req.Method != http.MethodConnect {
		p.deny(conn, http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Proxy-Authorization") != p.wantAuth {
		p.deny(conn, http.StatusProxyAuthRequired)
		return
	}
	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil || !strings.HasSuffix(host, ".pilot.invalid") {
		p.deny(conn, http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		p.deny(conn, http.StatusBadGateway)
		return
	}
	p.track(up)
	defer up.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, br); up.Close(); done <- struct{}{} }()
	go func() { io.Copy(conn, up); conn.Close(); done <- struct{}{} }()
	<-done
	<-done
}

// newProxiedFakeBeacon serves the fake beacon protocol over TLS with a
// certificate for proxiedBeaconHost only, and records the SNI of every
// handshake.
func newProxiedFakeBeacon(t *testing.T, nodeID uint32) (*fakeBeacon, *x509.CertPool, func() []string) {
	t.Helper()
	cert, pool := proxiedCert(t, proxiedBeaconHost)
	fb := &fakeBeacon{expectedID: nodeID, t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/", fb.handle)
	fb.srv = httptest.NewUnstartedServer(mux)
	var mu sync.Mutex
	var snis []string
	fb.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			snis = append(snis, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	fb.srv.StartTLS()
	t.Cleanup(fb.srv.Close)
	return fb, pool, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), snis...)
	}
}

// proxiedURL is the beacon URL a daemon is given: the unresolvable name
// plus the real listener's port.
func proxiedURL(fb *fakeBeacon) string {
	_, port, _ := net.SplitHostPort(fb.srv.Listener.Addr().String())
	return "wss://" + net.JoinHostPort(proxiedBeaconHost, port) + "/v1/compat"
}

func proxiedTarget(fb *fakeBeacon) string {
	_, port, _ := net.SplitHostPort(fb.srv.Listener.Addr().String())
	return net.JoinHostPort(proxiedBeaconHost, port)
}

func proxiedCert(t *testing.T, host string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func assertOnlyConnects(t *testing.T, p *connectProxy, target string, min int) {
	t.Helper()
	got := p.connects()
	if len(got) < min {
		t.Fatalf("proxy saw %d CONNECTs %q, want at least %d", len(got), got, min)
	}
	for _, g := range got {
		if g != target {
			t.Fatalf("proxy saw request target %q, want only %q (a host name, never an IP)", g, target)
		}
	}
}

func TestDial_ThroughAuthenticatingConnectProxy(t *testing.T) {
	t.Parallel()
	const nodeID uint32 = 7001
	fb, pool, snis := newProxiedFakeBeacon(t, nodeID)
	proxy := newConnectProxy(t, "muse", "s3cret")
	res, err := netproxy.Explicit(proxy.url("muse", "s3cret"))
	if err != nil {
		t.Fatalf("netproxy.Explicit: %v", err)
	}

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:         proxiedURL(fb),
		TLSConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		Proxy:       res.ProxyForRequest,
		Identity:    mustID(t),
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial through proxy: %v", err)
	}
	defer tr.Close()

	if _, err := tr.Send([]byte("via-proxy"), nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	frame, _, err := tr.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if string(frame) != "echo:via-proxy" {
		t.Fatalf("Recv = %q, want %q", frame, "echo:via-proxy")
	}
	assertOnlyConnects(t, proxy, proxiedTarget(fb), 1)
	if got := snis(); len(got) != 1 || got[0] != proxiedBeaconHost {
		t.Fatalf("beacon saw SNI %q, want [%q]", got, proxiedBeaconHost)
	}
}

// The reconnect path uses the same proxy: after the beacon drops the
// connection, the supervisor's redial is CONNECTed by name again.
func TestReconnect_ThroughConnectProxy(t *testing.T) {
	t.Parallel()
	const nodeID uint32 = 7002
	fb, pool, _ := newProxiedFakeBeacon(t, nodeID)
	fb.killAfterFrame = 1
	proxy := newConnectProxy(t, "muse", "s3cret")
	res, err := netproxy.Explicit(proxy.url("muse", "s3cret"))
	if err != nil {
		t.Fatalf("netproxy.Explicit: %v", err)
	}

	tr, err := wss.Dial(context.Background(), wss.Config{
		URL:         proxiedURL(fb),
		TLSConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		Proxy:       res.ProxyForRequest,
		Identity:    mustID(t),
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Dial through proxy: %v", err)
	}
	defer tr.Close()

	if _, err := tr.Send([]byte("kill"), nil); err != nil {
		t.Fatalf("Send (kill): %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for fb.authCount.Load() < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("transport never re-authenticated through the proxy (auths=%d, connects=%q)", fb.authCount.Load(), proxy.connects())
		}
		time.Sleep(50 * time.Millisecond)
	}
	assertOnlyConnects(t, proxy, proxiedTarget(fb), 2)
}

// With the proxy taken from the environment, NO_PROXY is honoured: an
// exempted beacon is dialed directly — which, for a name that only the
// proxy can reach, fails without the proxy ever being asked.
func TestDial_ProxyFromEnvironmentHonoursNoProxy(t *testing.T) {
	const nodeID uint32 = 7003
	fb, pool, _ := newProxiedFakeBeacon(t, nodeID)
	proxy := newConnectProxy(t, "muse", "s3cret")
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", proxy.url("muse", "s3cret"))

	dial := func() error {
		res, err := netproxy.FromEnvironment()
		if err != nil {
			t.Fatalf("netproxy.FromEnvironment: %v", err)
		}
		tr, err := wss.Dial(context.Background(), wss.Config{
			URL:         proxiedURL(fb),
			TLSConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			Proxy:       res.ProxyForRequest,
			Identity:    mustID(t),
			NodeID:      nodeID,
			DialTimeout: 5 * time.Second,
		})
		if err == nil {
			tr.Close()
		}
		return err
	}

	if err := dial(); err != nil {
		t.Fatalf("Dial with HTTPS_PROXY: %v", err)
	}
	assertOnlyConnects(t, proxy, proxiedTarget(fb), 1)

	t.Setenv("NO_PROXY", ".pilot.invalid")
	if err := dial(); err == nil {
		t.Fatal("Dial of a NO_PROXY-exempt, locally unresolvable beacon succeeded; want a direct-dial failure")
	}
	if got := proxy.connects(); len(got) != 1 {
		t.Fatalf("proxy saw %d requests %q after NO_PROXY exemption, want still 1", len(got), got)
	}
}

// Wrong proxy credentials fail the dial with the proxy's 407, and the
// error never carries the credentials.
func TestDial_ProxyAuthFailureDoesNotLeakCredentials(t *testing.T) {
	t.Parallel()
	const nodeID uint32 = 7004
	fb, pool, _ := newProxiedFakeBeacon(t, nodeID)
	proxy := newConnectProxy(t, "muse", "s3cret")
	res, err := netproxy.Explicit(proxy.url("muse", "wr0ng-pa55"))
	if err != nil {
		t.Fatalf("netproxy.Explicit: %v", err)
	}

	_, err = wss.Dial(context.Background(), wss.Config{
		URL:         proxiedURL(fb),
		TLSConfig:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		Proxy:       res.ProxyForRequest,
		Identity:    mustID(t),
		NodeID:      nodeID,
		DialTimeout: 5 * time.Second,
	})
	if err == nil {
		t.Fatal("Dial with wrong proxy credentials succeeded")
	}
	if strings.Contains(err.Error(), "wr0ng-pa55") || strings.Contains(err.Error(), "muse") {
		t.Fatalf("dial error leaks proxy credentials: %v", err)
	}
	if got := proxy.deniedStatuses(); len(got) != 1 || got[0] != http.StatusProxyAuthRequired {
		t.Fatalf("proxy denials = %v, want [407]", got)
	}
	if fb.authCount.Load() != 0 {
		t.Fatal("beacon was reached despite the proxy refusing the CONNECT")
	}
}
