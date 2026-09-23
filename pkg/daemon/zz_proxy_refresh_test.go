// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"crypto/x509"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// muse-proxy-cred-rotation-unhandled, in miniature: a compat daemon behind
// an authenticating CONNECT proxy whose credentials rotate while it runs.
// With a command-backed ProxyPolicy the registry reconnect and the WSS
// beacon reconnect after the rotation get 407 once, re-read the proxy URL
// and succeed — no restart.
func TestCommandProxyPolicyFollowsCredentialRotation(t *testing.T) {
	clearProxyEnv(t)
	proxy := newProxyTestConnect(t, "muse", "old-pass")
	urlFile := filepath.Join(t.TempDir(), "proxy-url")
	setURL := func(pass string) {
		t.Helper()
		if err := os.WriteFile(urlFile, []byte(proxy.url("muse", pass)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	setURL("old-pass")
	policy, err := NewCommandProxyPolicy(context.Background(), "cat '"+urlFile+"'", nil, true)
	if err != nil {
		t.Fatalf("NewCommandProxyPolicy: %v", err)
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
		RegistryAddr:         regAddr,
		RegistryTLS:          true,
		RegistryTrust:        "system",
		TransportMode:        "compat",
		CompatBeaconURL:      "wss://" + beaconHost + "/v1/compat",
		CompatTLSTrust:       "system",
		ProxyPolicy:          policy,
		ProxyRefreshInterval: time.Hour, // only the 407 path refreshes here
		SocketPath:           sockDir + "/s",
		IdentityPath:         t.TempDir() + "/id.json",
		Email:                "proxy-rotation@example.test",
		Encrypt:              true,
		DisablePolicyRunner:  true,
		systemRoots:          roots,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("Start behind the proxy: %v", err)
	}
	t.Cleanup(func() { _ = d.Stop() })
	for len(beacon.snis) > 0 {
		<-beacon.snis
	}

	// Rotate: the proxy now rejects old-pass with 407.
	setURL("new-pass")
	proxy.setAuth("muse", "new-pass")

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
}

// Run refreshes a command-backed policy periodically, so connections made
// after a rotation carry the new credentials from the start (no 407).
func TestCommandProxyPolicyPeriodicRefresh(t *testing.T) {
	clearProxyEnv(t)
	proxy := newProxyTestConnect(t, "muse", "old-pass")
	_, regAddr, pin := startProxiedRegistry(t, nil)
	urlFile := filepath.Join(t.TempDir(), "proxy-url")
	if err := os.WriteFile(urlFile, []byte(proxy.url("muse", "old-pass")), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := NewCommandProxyPolicy(context.Background(), "cat '"+urlFile+"'", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{
		RegistryAddr:         regAddr,
		RegistryTLS:          true,
		RegistryTrust:        "pinned",
		RegistryFingerprint:  pin,
		ProxyPolicy:          policy,
		ProxyRefreshInterval: 50 * time.Millisecond,
	})
	d.startProxyRefresh()
	t.Cleanup(d.cancelCtx) // ends the refresh loop (the daemon never started)

	if err := os.WriteFile(urlFile, []byte(proxy.url("muse", "new-pass")), 0o600); err != nil {
		t.Fatal(err)
	}
	proxy.setAuth("muse", "new-pass")
	deadline := time.Now().Add(5 * time.Second)
	for !proxyURLHasPassword(policy, "new-pass") {
		if time.Now().After(deadline) {
			t.Fatal("periodic refresh never picked up the rotated URL")
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

func proxyURLHasPassword(p *ProxyPolicy, pass string) bool {
	u, err := p.Resolver().ProxyForAddr("registry.pilot.invalid:443")
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
