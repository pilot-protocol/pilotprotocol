// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

// rotatingURLFile is the stand-in for Meta Muse's rotating HTTPS_PROXY: a
// file holding the current proxy URL, read by a refresh command, as a
// fresh `bash -c 'printf %s "$https_proxy"'` reads the rotated value.
type rotatingURLFile struct {
	t     *testing.T
	path  string
	proxy *proxyTestConnect
}

func newRotatingURLFile(t *testing.T, proxy *proxyTestConnect, pass string) *rotatingURLFile {
	f := &rotatingURLFile{t: t, path: filepath.Join(t.TempDir(), "proxy-url"), proxy: proxy}
	f.set(pass)
	return f
}

func (f *rotatingURLFile) set(pass string) {
	f.t.Helper()
	if err := os.WriteFile(f.path, []byte(f.proxy.url("muse", pass)+"\n"), 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// rotate makes the proxy accept only pass (407 for the old credentials)
// and the refresh command print it.
func (f *rotatingURLFile) rotate(pass string) {
	f.set(pass)
	f.proxy.setAuth("muse", pass)
}

func (f *rotatingURLFile) command() string { return "cat '" + f.path + "'" }

// muse-proxy-cred-rotation-unhandled, in miniature: a compat daemon behind
// an authenticating CONNECT proxy whose credentials rotate while it runs.
// With a resolver built with netproxy.WithRefreshCommand (the daemon's
// -proxy-cmd) the registry reconnect and the WSS beacon reconnect after the
// rotation get 407 once, re-read the proxy URL and succeed — no restart.
func TestProxyRefreshCommandFollowsCredentialRotation(t *testing.T) {
	clearProxyEnv(t)
	proxy := newProxyTestConnect(t, "muse", "old-pass")
	urls := newRotatingURLFile(t, proxy, "old-pass")
	resolver, err := ResolveProxy("auto", TransportCompat,
		netproxy.WithRefreshCommand(urls.command()),
		netproxy.WithRefreshInterval(-1)) // only the 407 path refreshes here
	if err != nil {
		t.Fatalf("ResolveProxy: %v", err)
	}
	if !strings.Contains(resolver.String(), "credentials refreshed by command") || strings.Contains(resolver.String(), "old-pass") {
		t.Fatalf("resolver = %q", resolver.String())
	}

	roots := x509.NewCertPool()
	reg, regAddr, _ := startProxiedRegistry(t, roots)
	beacon, beaconHost := startProxiedBeacon(t, roots, reg.LookupPublicKey)
	sockDir, err := os.MkdirTemp("", "pdr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	d := New(Config{
		RegistryAddr:        regAddr,
		RegistryTLS:         true,
		RegistryTrust:       "system",
		TransportMode:       "compat",
		CompatBeaconURL:     "wss://" + beaconHost + "/v1/compat",
		CompatTLSTrust:      "system",
		Proxy:               resolver,
		SocketPath:          sockDir + "/s",
		IdentityPath:        t.TempDir() + "/id.json",
		Email:               "proxy-rotation@example.test",
		Encrypt:             true,
		DisablePolicyRunner: true,
		systemRoots:         roots,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("Start behind the proxy: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	for len(beacon.snis) > 0 {
		<-beacon.snis
	}

	// Rotate: the proxy now rejects old-pass with 407.
	urls.rotate("new-pass")

	if err := d.forceReconnectRegistry(); err != nil {
		t.Fatalf("registry reconnect after the rotation: %v", err)
	}
	if _, err := d.reg().Lookup(d.NodeID()); err != nil {
		t.Fatalf("Lookup after the rotation: %v", err)
	}
	if n := proxy.deniedWith(http.StatusProxyAuthRequired); n < 1 {
		t.Fatalf("proxy 407s = %d, want the stale credentials rejected at least once", n)
	}

	// The WSS beacon drops; its reconnect carries the new credentials.
	beacon.dropAll()
	select {
	case sni := <-beacon.snis:
		if sni != "beacon.pilot.invalid" {
			t.Fatalf("beacon SNI = %q", sni)
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the WSS beacon never reconnected through the rotated proxy (proxy: %v)", proxy.counts())
	}
	if !proxyURLHasPassword(resolver, "new-pass") {
		t.Fatal("resolver does not carry the rotated credentials")
	}
}

// The timed refresh: a lookup after the refresh interval re-runs the
// command, so connections made after a rotation carry the new credentials
// from the start (no 407).
func TestProxyRefreshCommandPeriodicRefresh(t *testing.T) {
	clearProxyEnv(t)
	proxy := newProxyTestConnect(t, "muse", "old-pass")
	_, regAddr, pin := startProxiedRegistry(t, nil)
	urls := newRotatingURLFile(t, proxy, "old-pass")
	resolver, err := ResolveProxy("auto", TransportCompat,
		netproxy.WithRefreshCommand(urls.command()),
		netproxy.WithRefreshInterval(50*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		RegistryAddr:        regAddr,
		RegistryTLS:         true,
		RegistryTrust:       "pinned",
		RegistryFingerprint: pin,
		Proxy:               resolver,
	})

	urls.rotate("new-pass")
	deadline := time.Now().Add(5 * time.Second)
	for !proxyURLHasPassword(resolver, "new-pass") { // each lookup may start the timed refresh
		if time.Now().After(deadline) {
			t.Fatal("the timed refresh never picked up the rotated URL")
		}
		time.Sleep(20 * time.Millisecond)
	}
	rc, err := d.dialRegistryClient()
	if err != nil {
		t.Fatalf("dialRegistryClient after the refresh: %v", err)
	}
	rc.Close()
	if n := proxy.deniedWith(http.StatusProxyAuthRequired); n != 0 {
		t.Errorf("proxy 407s = %d, want 0: the refresh ran before the dial", n)
	}
}

// Daemon-owned HTTP clients (newHTTPClient: the MOTD fetch) sit on a
// netproxy.RefreshingTransport: a request whose CONNECT the proxy rejects
// after a rotation is retried once with the refreshed credentials, and
// loopback targets never go to the proxy.
func TestNewHTTPClientRetriesAfterRotation(t *testing.T) {
	clearProxyEnv(t)
	var hits atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, "motd")
	}))
	roots := x509.NewCertPool()
	cert, _, _ := proxyTestCert(t, "motd.pilot.invalid", roots)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	proxy := newProxyTestConnect(t, "muse", "one")
	urls := newRotatingURLFile(t, proxy, "one")
	resolver, err := ResolveProxy("auto", TransportCompat,
		netproxy.WithRefreshCommand(urls.command()),
		netproxy.WithRefreshInterval(-1))
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Proxy: resolver, systemRoots: roots})
	client := d.newHTTPClient(10 * time.Second)
	get := func(url string) (string, error) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
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
	target := "https://motd.pilot.invalid:" + port + "/today"
	if got, err := get(target); err != nil || got != "motd" {
		t.Fatalf("GET before the rotation = (%q, %v)", got, err)
	}
	urls.rotate("two")
	if got, err := get(target); err != nil || got != "motd" {
		t.Fatalf("GET after the rotation = (%q, %v), want the 407 retried with the new credentials", got, err)
	}
	if n := proxy.deniedWith(http.StatusProxyAuthRequired); n != 1 {
		t.Errorf("proxy 407s = %d, want exactly one (then the retry)", n)
	}

	// Loopback goes direct, whatever the proxy says.
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "local") }))
	t.Cleanup(local.Close)
	before := len(proxy.counts())
	if got, err := get(local.URL); err != nil || got != "local" {
		t.Fatalf("GET loopback = (%q, %v)", got, err)
	}
	if len(proxy.counts()) != before {
		t.Fatalf("loopback request reached the proxy: %v", proxy.counts())
	}
	if n := hits.Load(); n != 2 {
		t.Errorf("server hits = %d, want 2", n)
	}
}

func proxyURLHasPassword(r *netproxy.Resolver, pass string) bool {
	u, err := r.ProxyForAddr("registry.pilot.invalid:443")
	if err != nil || u == nil {
		return false
	}
	got, _ := u.User.Password()
	return got == pass
}

// pilotctl asks the running daemon which transport it resolved (its
// registry route mirrors the daemon's): info reports udp or compat.
func TestInfoReportsTransport(t *testing.T) {
	t.Parallel()
	for mode, want := range map[string]string{"": "udp", "udp": "udp", "compat": "compat"} {
		if got := New(Config{TransportMode: mode}).Info().Transport; got != want {
			t.Errorf("TransportMode %q: Info().Transport = %q, want %q", mode, got, want)
		}
	}
}
