// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/netproxy"
	rendezvous "github.com/pilot-protocol/rendezvous"
)

// proxyEnvVars are every variable netproxy.FromEnvironment reads; tests
// clear them so the developer's or CI runner's own proxy never leaks in.
var proxyEnvVars = []string{
	"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy",
	"HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD",
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range proxyEnvVars {
		t.Setenv(k, "")
	}
}

// --- ResolveProxy: -proxy × transport × environment ------------------------

func TestResolveProxyMatrix(t *testing.T) {
	const envProxy = "http://muse:s3cret@egress.test:3128"
	const flagProxy = "http://ops:hunter2@flag-proxy.test:8080"
	type want struct {
		policy  bool   // non-nil policy
		mode    string // policy Mode()
		enabled bool
		// proxy chosen for a pilot host and for a NO_PROXY'd host; "" = direct
		pilot, exempt string
	}
	cases := []struct {
		name, spec, transport string
		env                   map[string]string
		want                  want
	}{
		{name: "auto udp ignores env", spec: "auto", transport: "udp",
			env:  map[string]string{"HTTPS_PROXY": envProxy},
			want: want{}},
		{name: "empty spec udp", spec: "", transport: "udp",
			env:  map[string]string{"HTTPS_PROXY": envProxy},
			want: want{}},
		{name: "auto default transport", spec: "auto", transport: "",
			env:  map[string]string{"HTTPS_PROXY": envProxy},
			want: want{}},
		{name: "auto compat HTTPS_PROXY", spec: "auto", transport: "compat",
			env:  map[string]string{"HTTPS_PROXY": envProxy, "NO_PROXY": ".internal.test"},
			want: want{policy: true, mode: netproxy.ModeAuto, enabled: true, pilot: "egress.test:3128"}},
		{name: "AUTO compat lower-case env", spec: " AUTO ", transport: "compat",
			env:  map[string]string{"https_proxy": envProxy, "no_proxy": "svc.internal.test"},
			want: want{policy: true, mode: netproxy.ModeAuto, enabled: true, pilot: "egress.test:3128"}},
		{name: "auto compat ALL_PROXY fallback", spec: "auto", transport: "compat",
			env:  map[string]string{"ALL_PROXY": "http://all.test:1080"},
			want: want{policy: true, mode: netproxy.ModeAuto, enabled: true, pilot: "all.test:1080", exempt: "all.test:1080"}},
		{name: "auto compat no env", spec: "auto", transport: "compat",
			want: want{policy: true, mode: netproxy.ModeAuto}},
		{name: "off udp", spec: "off", transport: "udp",
			env:  map[string]string{"HTTPS_PROXY": envProxy},
			want: want{policy: true, mode: netproxy.ModeOff}},
		{name: "off compat", spec: "OFF", transport: "compat",
			env:  map[string]string{"HTTPS_PROXY": envProxy},
			want: want{policy: true, mode: netproxy.ModeOff}},
		{name: "url udp", spec: flagProxy, transport: "udp",
			env:  map[string]string{"HTTPS_PROXY": envProxy, "NO_PROXY": ".internal.test"},
			want: want{policy: true, mode: netproxy.ModeExplicit, enabled: true, pilot: "flag-proxy.test:8080", exempt: "flag-proxy.test:8080"}},
		{name: "url compat", spec: flagProxy, transport: "compat",
			env:  map[string]string{"NO_PROXY": ".internal.test"},
			want: want{policy: true, mode: netproxy.ModeExplicit, enabled: true, pilot: "flag-proxy.test:8080", exempt: "flag-proxy.test:8080"}},
		{name: "https url default port", spec: "https://tls-proxy.test", transport: "udp",
			want: want{policy: true, mode: netproxy.ModeExplicit, enabled: true, pilot: "tls-proxy.test", exempt: "tls-proxy.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearProxyEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			policy, err := ResolveProxy(tc.spec, tc.transport)
			if err != nil {
				t.Fatalf("ResolveProxy(%q, %q): %v", tc.spec, tc.transport, err)
			}
			if (policy != nil) != tc.want.policy {
				t.Fatalf("policy = %v, want non-nil=%v", policy, tc.want.policy)
			}
			if policy == nil {
				return
			}
			if got := policy.Mode(); got != tc.want.mode {
				t.Errorf("Mode = %q, want %q", got, tc.want.mode)
			}
			if got := policy.Enabled(); got != tc.want.enabled {
				t.Errorf("Enabled = %v, want %v", got, tc.want.enabled)
			}
			check := func(target, want string) {
				t.Helper()
				u, err := policy.ProxyForAddr(target)
				if err != nil {
					t.Fatalf("ProxyForAddr(%s): %v", target, err)
				}
				got := ""
				if u != nil {
					got = u.Host
				}
				if got != want {
					t.Errorf("proxy for %s = %q, want %q", target, got, want)
				}
				req := &http.Request{URL: &url.URL{Scheme: "https", Host: target}}
				ru, err := policy.ProxyForRequest(req)
				if err != nil {
					t.Fatalf("ProxyForRequest(%s): %v", target, err)
				}
				if (ru == nil) != (u == nil) || (ru != nil && ru.Host != u.Host) {
					t.Errorf("ProxyForRequest(%s) = %v, ProxyForAddr = %v; the registry and HTTP paths must agree", target, ru, u)
				}
			}
			check("registry.pilotprotocol.network:443", tc.want.pilot)
			check("svc.internal.test:443", tc.want.exempt)
			if s := policy.String(); strings.Contains(s, "s3cret") || strings.Contains(s, "hunter2") || strings.Contains(s, "muse") || strings.Contains(s, "ops:") {
				t.Errorf("String() leaks credentials: %q", s)
			}
		})
	}
}

func TestResolveProxyRejectsMalformedSettings(t *testing.T) {
	clearProxyEnv(t)
	if _, err := ResolveProxy("socks5://user:pw@proxy.test:1080", "udp"); err == nil {
		t.Fatal("unsupported proxy scheme accepted")
	}
	t.Setenv("HTTPS_PROXY", "ftp://muse:s3cret@proxy.test:21")
	_, err := ResolveProxy("auto", "compat")
	if err == nil {
		t.Fatal("malformed HTTPS_PROXY accepted in compat mode")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error leaks credentials: %v", err)
	}
	// udp + auto never reads the environment, so a bad value is harmless.
	if p, err := ResolveProxy("auto", "udp"); err != nil || p != nil {
		t.Fatalf("ResolveProxy(auto, udp) with bad env = (%v, %v), want (nil, nil)", p, err)
	}
}

// --- a Muse-style egress: authenticating CONNECT-only proxy -----------------

// proxyTestConnect is an authenticating CONNECT proxy that routes
// *.pilot.invalid (names that never resolve locally) to loopback and
// records every request target.
type proxyTestConnect struct {
	ln net.Listener

	mu       sync.Mutex
	wantAuth string
	targets  []string
	denied   map[int]int // status -> count of refused requests
	live     []net.Conn
	wg       sync.WaitGroup
}

// setAuth makes the proxy accept only user:pass from now on (a credential
// rotation); anything else gets 407.
func (p *proxyTestConnect) setAuth(user, pass string) {
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	p.mu.Lock()
	p.wantAuth = req.Header.Get("Authorization")
	p.mu.Unlock()
}

// deniedWith returns how many requests the proxy refused with status.
func (p *proxyTestConnect) deniedWith(status int) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.denied[status]
}

func newProxyTestConnect(t *testing.T, user, pass string) *proxyTestConnect {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	p := &proxyTestConnect{ln: ln, wantAuth: req.Header.Get("Authorization")}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := ln.Accept()
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
	}()
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

func (p *proxyTestConnect) url(user, pass string) string {
	return fmt.Sprintf("http://%s:%s@%s", user, pass, p.ln.Addr())
}

func (p *proxyTestConnect) track(c net.Conn) {
	p.mu.Lock()
	p.live = append(p.live, c)
	p.mu.Unlock()
}

// counts returns how many requests named each target.
func (p *proxyTestConnect) counts() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	m := map[string]int{}
	for _, target := range p.targets {
		m[target]++
	}
	return m
}

func (p *proxyTestConnect) serve(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	p.mu.Lock()
	p.targets = append(p.targets, req.RequestURI)
	wantAuth := p.wantAuth
	p.mu.Unlock()
	deny := func(code int) {
		p.mu.Lock()
		if p.denied == nil {
			p.denied = map[int]int{}
		}
		p.denied[code]++
		p.mu.Unlock()
		fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", code, http.StatusText(code))
	}
	if req.Method != http.MethodConnect {
		deny(http.StatusMethodNotAllowed)
		return
	}
	if req.Header.Get("Proxy-Authorization") != wantAuth {
		deny(http.StatusProxyAuthRequired)
		return
	}
	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil || !strings.HasSuffix(host, ".pilot.invalid") {
		deny(http.StatusForbidden)
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		deny(http.StatusBadGateway)
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

// proxyTestCert issues a self-signed certificate for one host name only
// (no IP SANs) and adds it to pool.
func proxyTestCert(t *testing.T, host string, pool *x509.CertPool) (tls.Certificate, []byte, *ecdsa.PrivateKey) {
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
	if pool != nil {
		pool.AddCert(leaf)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, der, key
}

// startProxiedRegistry runs a real rendezvous registry over TLS with a
// certificate for registry.pilot.invalid, and returns the address a daemon
// must use (the unresolvable name plus the real port) and the leaf's pin.
func startProxiedRegistry(t *testing.T, pool *x509.CertPool) (*rendezvous.Server, string, string) {
	t.Helper()
	_, der, key := proxyTestCert(t, "registry.pilot.invalid", pool)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	reg := rendezvous.New("")
	if err := reg.SetTLS(certFile, keyFile); err != nil {
		t.Fatalf("registry SetTLS: %v", err)
	}
	go func() { _ = reg.ListenAndServe("127.0.0.1:0") }()
	select {
	case <-reg.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("registry failed to start")
	}
	t.Cleanup(func() { reg.Close() })
	_, port, _ := net.SplitHostPort(reg.Addr().String())
	sum := sha256.Sum256(der)
	return reg, net.JoinHostPort("registry.pilot.invalid", port), hex.EncodeToString(sum[:])
}

// proxiedBeacon is a compat WSS beacon stand-in served over TLS as
// beacon.pilot.invalid. It completes the Ed25519 auth challenge only for a
// node whose key matches the registry's record, then drains frames.
type proxiedBeacon struct {
	srv    *httptest.Server
	authed atomic.Uint32 // node ID of the last authenticated daemon
	snis   chan string

	mu    sync.Mutex
	conns []*websocket.Conn
}

// dropAll closes every authenticated WSS connection (a beacon restart).
func (b *proxiedBeacon) dropAll() {
	b.mu.Lock()
	conns := b.conns
	b.conns = nil
	b.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseNow()
	}
}

func startProxiedBeacon(t *testing.T, pool *x509.CertPool, lookup func(uint32) ([]byte, bool)) (*proxiedBeacon, string) {
	t.Helper()
	cert, _, _ := proxyTestCert(t, "beacon.pilot.invalid", pool)
	b := &proxiedBeacon{snis: make(chan string, 16)}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.handle(w, r, lookup)
	}))
	b.srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			select {
			case b.snis <- hello.ServerName:
			default:
			}
			return nil, nil
		},
	}
	b.srv.StartTLS()
	t.Cleanup(b.srv.Close)
	_, port, _ := net.SplitHostPort(b.srv.Listener.Addr().String())
	return b, net.JoinHostPort("beacon.pilot.invalid", port)
}

func (b *proxiedBeacon) handle(w http.ResponseWriter, r *http.Request, lookup func(uint32) ([]byte, bool)) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"pilot.v1"}})
	if err != nil {
		return
	}
	defer conn.CloseNow()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	const nonce, ts = "0123456789abcdef0123456789abcdef", int64(1700000000)
	challenge, _ := json.Marshal(map[string]interface{}{"type": "auth_challenge", "nonce": nonce, "ts": ts})
	if err := conn.Write(ctx, websocket.MessageText, challenge); err != nil {
		return
	}
	_, body, err := conn.Read(ctx)
	if err != nil {
		return
	}
	var reply struct {
		NodeID    uint32 `json:"node_id"`
		PublicKey string `json:"public_key"`
		Sig       string `json:"sig"`
	}
	if json.Unmarshal(body, &reply) != nil {
		return
	}
	registered, ok := lookup(reply.NodeID)
	sig, _ := base64.StdEncoding.DecodeString(reply.Sig)
	msg := fmt.Sprintf("compat_auth:%d:%d:%s", reply.NodeID, ts, nonce)
	if !ok || !ed25519.Verify(ed25519.PublicKey(registered), []byte(msg), sig) {
		conn.Close(websocket.StatusPolicyViolation, "auth_fail")
		return
	}
	ok2, _ := json.Marshal(map[string]string{"type": "auth_ok"})
	if err := conn.Write(ctx, websocket.MessageText, ok2); err != nil {
		return
	}
	b.authed.Store(reply.NodeID)
	b.mu.Lock()
	b.conns = append(b.conns, conn)
	b.mu.Unlock()
	for {
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
	}
}

// TestStartCompatModeThroughConnectProxy is the Meta Muse sandbox in
// miniature: no route to the registry or the beacon except an
// authenticating CONNECT proxy taken from HTTPS_PROXY, and both services
// reachable only by host names that do not resolve locally. A compat daemon
// with -proxy=auto must register over TLS (system trust, full pool), bring
// the WSS tunnel up, and reconnect the registry — all through the proxy.
func TestStartCompatModeThroughConnectProxy(t *testing.T) {
	clearProxyEnv(t)
	proxy := newProxyTestConnect(t, "muse", "s3cret")

	// The policy snapshots the environment. Clear it again before the
	// fixtures start: the in-process registry's own HTTP client (its
	// GitHub release poller) would otherwise follow HTTPS_PROXY too, and
	// net/http caches that environment for the whole test binary.
	t.Setenv("HTTPS_PROXY", proxy.url("muse", "s3cret"))
	policy, err := ResolveProxy("auto", "compat")
	if err != nil {
		t.Fatalf("ResolveProxy: %v", err)
	}
	if !policy.Enabled() {
		t.Fatalf("policy %s is not enabled", policy)
	}
	t.Setenv("HTTPS_PROXY", "")

	roots := x509.NewCertPool()
	reg, regAddr, _ := startProxiedRegistry(t, roots)
	beacon, beaconHost := startProxiedBeacon(t, roots, reg.LookupPublicKey)

	sockDir, err := os.MkdirTemp("", "pdx")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	d := New(Config{
		RegistryAddr:        regAddr,
		RegistryTLS:         true,
		RegistryTrust:       "system",
		TransportMode:       "compat",
		CompatBeaconURL:     "wss://" + beaconHost + "/v1/compat",
		CompatTLSTrust:      "system",
		Proxy:               policy,
		SocketPath:          sockDir + "/s",
		IdentityPath:        t.TempDir() + "/id.json",
		Email:               "proxy-compat@example.test",
		Encrypt:             true,
		DisablePolicyRunner: true,
		systemRoots:         roots,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("Start behind the proxy: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })

	if d.NodeID() == 0 {
		t.Fatal("daemon has no node ID after Start")
	}
	if got := beacon.authed.Load(); got != d.NodeID() {
		t.Fatalf("beacon authenticated node %d, want %d", got, d.NodeID())
	}
	select {
	case sni := <-beacon.snis:
		if sni != "beacon.pilot.invalid" {
			t.Fatalf("beacon SNI = %q, want beacon.pilot.invalid", sni)
		}
	default:
		t.Fatal("beacon saw no TLS handshake")
	}

	counts := proxy.counts()
	if counts[regAddr] < 4 {
		t.Errorf("registry CONNECTs = %d, want >= 4 (primary + pool)", counts[regAddr])
	}
	if counts[beaconHost] != 1 {
		t.Errorf("beacon CONNECTs = %d, want 1", counts[beaconHost])
	}
	for target := range counts {
		if target != regAddr && target != beaconHost {
			t.Errorf("unexpected proxy request target %q (all: %v)", target, counts)
		}
	}

	// The reconnect path (rx-watchdog soft recovery, half-open registry)
	// builds a fresh client through the same proxy.
	before := counts[regAddr]
	if err := d.forceReconnectRegistry(); err != nil {
		t.Fatalf("forceReconnectRegistry: %v", err)
	}
	if _, err := d.reg().Lookup(d.NodeID()); err != nil {
		t.Fatalf("Lookup on the reconnected registry client: %v", err)
	}
	if after := proxy.counts()[regAddr]; after < before+4 {
		t.Fatalf("registry CONNECTs after reconnect = %d, want >= %d", after, before+4)
	}
}

// Pinned registry trust (the fallback for sandboxes without a CA bundle)
// works through an explicit -proxy URL, in UDP mode too.
func TestDialRegistryClientPinnedThroughExplicitProxy(t *testing.T) {
	t.Parallel()
	proxy := newProxyTestConnect(t, "muse", "s3cret")
	_, regAddr, pin := startProxiedRegistry(t, nil)
	policy, err := ResolveProxy(proxy.url("muse", "s3cret"), "udp")
	if err != nil {
		t.Fatalf("ResolveProxy: %v", err)
	}
	d := New(Config{
		RegistryAddr:        regAddr,
		RegistryTLS:         true,
		RegistryTrust:       "pinned",
		RegistryFingerprint: pin,
		Proxy:               policy,
	})
	rc, err := d.dialRegistryClient()
	if err != nil {
		t.Fatalf("dialRegistryClient: %v", err)
	}
	defer rc.Close()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	resp, err := rc.RegisterWithKey("127.0.0.1:4000", crypto.EncodePublicKey(id.PublicKey), "proxy-pinned@example.test", nil)
	if err != nil {
		t.Fatalf("register through the proxy: %v", err)
	}
	if id, _ := resp["node_id"].(float64); id == 0 {
		t.Fatalf("register response has no node_id: %v", resp)
	}
	counts := proxy.counts()
	if len(counts) != 1 || counts[regAddr] == 0 {
		t.Fatalf("proxy request targets = %v, want only %q", counts, regAddr)
	}
}

// Without a proxy resolver nothing changes: no dialer option and the MOTD
// client stays on http.DefaultTransport (net/http's own proxy environment
// handling).
func TestNoProxyPolicyKeepsHistoricalDialing(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://env-proxy.test:3128")
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	d := New(Config{})
	if opts := d.registryDialOptions(); opts != nil {
		t.Fatalf("registryDialOptions without a proxy = %d options, want none", len(opts))
	}
	if c := d.newHTTPClient(time.Second); c.Transport != nil {
		t.Fatalf("HTTP client transport = %T, want nil (http.DefaultTransport)", c.Transport)
	}

	// -proxy=off: no registry dialer, and daemon HTTP fetches stop
	// following the proxy environment.
	var sawProxy atomic.Bool
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProxy.Store(true) // an HTTP request here means it went via the "proxy"
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(front.Close)
	t.Setenv("HTTP_PROXY", front.URL)
	t.Setenv("http_proxy", front.URL)
	off := New(Config{Proxy: netproxy.Off()})
	if opts := off.registryDialOptions(); opts != nil {
		t.Fatal("-proxy=off still installs a registry dialer")
	}
	c := off.newHTTPClient(2 * time.Second)
	if c.Transport == nil {
		t.Fatal("-proxy=off HTTP client uses http.DefaultTransport, which follows the proxy environment")
	}
	resp, err := c.Get("http://unreachable.pilot.invalid/")
	if err == nil {
		resp.Body.Close()
	}
	if sawProxy.Load() {
		t.Fatal("-proxy=off HTTP client went through the environment's proxy")
	}
}
