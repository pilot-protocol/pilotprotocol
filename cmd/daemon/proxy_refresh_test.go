// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// muse-proxy-cred-rotation-unhandled: the egress proxy rotates its
// credentials while the daemon runs. With -proxy-cmd ($PILOT_PROXY_CMD)
// the daemon re-reads the proxy URL when the proxy answers 407, retries
// with the new credentials, and keeps using them — without a restart.
func TestProxyCmdFollowsCredentialRotation(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "old-pass")
	urlFile := filepath.Join(t.TempDir(), "proxy-url")
	write := func(pass string) {
		t.Helper()
		if err := os.WriteFile(urlFile, []byte(fmt.Sprintf("http://muse:%s@%s\n", pass, proxy.ln.Addr())), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("old-pass")
	d := startDaemon(t, daemonRun{
		env: []string{
			"PILOT_TRANSPORT=compat",
			// The launch environment's proxy, stale after the rotation.
			"HTTPS_PROXY=" + fmt.Sprintf("http://muse:old-pass@%s", proxy.ln.Addr()),
			"PILOT_PROXY_CMD=cat '" + urlFile + "'",
		},
	})
	d.waitFor(t, proxy, 30*time.Second, "no registry CONNECT with the launch credentials", func([]string) bool {
		return proxy.accepted("muse", "old-pass") > 0
	})

	// Rotate: the proxy now wants new-pass and answers old-pass with 407.
	write("new-pass")
	proxy.rotate("muse", "new-pass")
	d.waitFor(t, proxy, 30*time.Second, "the daemon never retried with the rotated credentials", func([]string) bool {
		return proxy.accepted("muse", "new-pass") >= 2 // the 407 retry, then the next redial
	})
	d.stop()
	logs := d.out.String()
	for _, secret := range []string{"old-pass", "new-pass"} {
		if strings.Contains(logs, secret) {
			t.Errorf("daemon output leaks %q:\n%s", secret, logs)
		}
	}
	if !strings.Contains(logs, "credentials refreshed by command") {
		t.Errorf("startup line does not mention the proxy command:\n%s", logs)
	}
}

// A failing -proxy-cmd at startup costs nothing: the launch environment's
// proxy serves until the command succeeds.
func TestProxyCmdFailureFallsBackToEnvironment(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	_, logs := runDaemon(t, proxy, daemonRun{
		env: []string{
			"PILOT_TRANSPORT=compat",
			"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr()),
			"PILOT_PROXY_CMD=exit 3",
		},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	if proxy.accepted("muse", "s3cret") == 0 {
		t.Error("launch-environment proxy not used after the proxy command failed")
	}
	if !strings.Contains(logs, "-proxy-cmd failed; keeping the last good proxy URL") {
		t.Errorf("proxy command failure not logged:\n%s", logs)
	}
}

// daemon-proxied-udp-registry-stays-raw-9000: an explicit proxy in udp mode
// sends the registry dial through the proxy, so the compiled-in raw-TCP
// registry moves to registry.pilotprotocol.network:443 over TLS — the
// rule pilotctl's registry route applies — instead of asking a
// CONNECT-443-only proxy for 34.71.57.205:9000.
func TestProxiedUDPRegistryUsesTLS443(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	targets, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", silentUDP(t),
			"-transport=udp",
			"-proxy", fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr()),
		},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	for _, target := range targets {
		if strings.Contains(target, "34.71.57.205") {
			t.Errorf("proxy was asked for the raw-TCP registry: %q", target)
		}
	}
	if !strings.Contains(logs, "registry_trust=system") {
		t.Errorf("TLS registry trust not defaulted to system:\n%s", logs)
	}
}

// compat-explicit-registry-tls-now-pinned-fatal: -transport=compat with an
// explicit -registry-tls but no -registry-trust defaults trust to system
// (as before -proxy existed) instead of exiting on the flag default
// "pinned" without a fingerprint.
func TestCompatExplicitRegistryTLSDefaultsTrust(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	_, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", "reg.pilot.invalid:9443",
			"--beacon", defaultBeaconAddr,
			"-transport=compat",
			"-registry-tls",
		},
		env:   []string{"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())},
		await: "CONNECT reg.pilot.invalid:9443",
	})
	if strings.Contains(logs, "requires RegistryFingerprint") {
		t.Errorf("daemon fell to pinned trust without a fingerprint:\n%s", logs)
	}
}

// Service units set PILOT_TRANSPORT_DEFAULT=auto: it applies only when
// nothing else chooses a transport, so config.json still wins.
func TestTransportDefaultEnv(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	proxy.forward("beacon.pilotprotocol.network:443", fakeCompatBeacon(t))
	env := []string{
		"PILOT_TRANSPORT_DEFAULT=auto",
		"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr()),
	}
	_, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", silentUDP(t),
			"-compat-beacon", defaultCompatBeacon,
			"-registry-fingerprint=" + strings.Repeat("00", 32),
		},
		env:   env,
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	if !strings.Contains(logs, `msg="transport auto-selected" transport=compat`) || !strings.Contains(logs, "transport_from=PILOT_TRANSPORT_DEFAULT") {
		t.Errorf("PILOT_TRANSPORT_DEFAULT=auto not applied:\n%s", logs)
	}

	proxy2 := newRefusingProxy(t, "muse", "s3cret")
	_, logs = runDaemon(t, proxy2, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", silentUDP(t),
			"-registry-fingerprint=" + strings.Repeat("00", 32),
		},
		config: `{"transport":"compat"}`,
		env:    []string{"PILOT_TRANSPORT_DEFAULT=udp", "HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy2.ln.Addr())},
		await:  "CONNECT registry.pilotprotocol.network:443",
	})
	if !strings.Contains(logs, "transport_from=config") {
		t.Errorf("config.json transport lost to PILOT_TRANSPORT_DEFAULT:\n%s", logs)
	}
}
