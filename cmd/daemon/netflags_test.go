// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

func TestFlagSourcesEnvOverConfig(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.String("proxy", "", "")
	fs.String("transport", "", "")
	fs.String("registry-trust", "pinned", "")
	fs.String("registry-fingerprint", "", "")
	if err := fs.Parse([]string{"-transport", "udp"}); err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{"proxy": "auto", "transport": "compat", "registry_trust": "system", "registry-fingerprint": 7.0}
	src := newFlagSources(fs, cfg)
	if !src.cmdline["transport"] || src.config["transport"] {
		t.Fatalf("transport: cmdline=%v config=%v, want cmdline only", src.cmdline["transport"], src.config["transport"])
	}
	for _, name := range []string{"proxy", "registry-trust", "registry-fingerprint"} {
		if !src.config[name] || !src.explicit(name) {
			t.Errorf("%s not recognised as set by config.json", name)
		}
	}

	env := map[string]string{}
	getenv = func(k string) string { return env[k] }
	t.Cleanup(func() { getenv = os.Getenv })

	// flag > env > config > default
	env["PILOT_TRANSPORT"] = "auto"
	if v, from := src.envOverConfig("transport", "udp", "PILOT_TRANSPORT"); v != "udp" || from != srcFlag {
		t.Errorf("transport = (%q, %s), want the flag", v, from)
	}
	env["PILOT_PROXY"] = "http://muse:s3cret@egress.test:3128"
	if v, from := src.envOverConfig("proxy", "auto", "PILOT_PROXY"); v != env["PILOT_PROXY"] || from != srcEnv {
		t.Errorf("proxy = (%q, %s), want $PILOT_PROXY over config.json's auto", v, from)
	}
	delete(env, "PILOT_PROXY")
	if v, from := src.envOverConfig("proxy", "auto", "PILOT_PROXY"); v != "auto" || from != srcConfig {
		t.Errorf("proxy = (%q, %s), want config.json", v, from)
	}
	src2 := newFlagSources(fs, nil)
	if v, from := src2.envOverConfig("registry-trust", "pinned", "PILOT_REGISTRY_TRUST"); v != "pinned" || from != srcDefault {
		t.Errorf("registry-trust = (%q, %s), want the default", v, from)
	}
}

func TestCompatKeepsRegistry(t *testing.T) {
	for _, tc := range []struct {
		name string
		r    registrySettings
		want bool
	}{
		{"default, not chosen", registrySettings{Addr: defaultRegistryAddr}, false},
		{"default passed by pilotctl", registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true}, false},
		{"default with spaces", registrySettings{Addr: " " + defaultRegistryAddr + " ", AddrExplicit: true}, false},
		{"custom", registrySettings{Addr: "10.0.0.5:9000", AddrExplicit: true}, true},
		{"custom TLS host", registrySettings{Addr: "registry.corp.example:443", AddrExplicit: true}, true},
		{"custom from default only", registrySettings{Addr: "10.0.0.5:9000"}, false},
		// The TCP/9000 fallback: -registry-tls=false asks for the raw registry.
		{"default + explicit -registry-tls=false", registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, TLSExplicit: true}, true},
		{"default + explicit -registry-tls=true", registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, TLS: true, TLSExplicit: true}, false},
	} {
		if got := compatKeepsRegistry(tc.r); got != tc.want {
			t.Errorf("%s: compatKeepsRegistry = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestApplyRegistryDefaults(t *testing.T) {
	const fp = "c1f958f6bcff667cf6a08d5066cc031a9086115a7667835877ca62a3019b3da9"
	pilotctl := registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, Trust: "pinned"}
	for _, tc := range []struct {
		name      string
		transport string
		in, want  registrySettings
	}{
		{"udp unchanged", daemon.TransportUDP, pilotctl, pilotctl},
		{"compat moves the default registry to TLS/443, system trust", daemon.TransportCompat, pilotctl,
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, TLS: true, Trust: "system"}},
		{"compat with a fingerprint (config/env) pins", daemon.TransportCompat,
			registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, Trust: "pinned", Fingerprint: fp},
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, TLS: true, Trust: "pinned", Fingerprint: fp}},
		{"compat keeps an explicit system trust even with a fingerprint", daemon.TransportCompat,
			registrySettings{Addr: defaultRegistryAddr, Trust: "system", TrustExplicit: true, Fingerprint: fp},
			registrySettings{Addr: compatRegistryAddr, TLS: true, Trust: "system", TrustExplicit: true, Fingerprint: fp}},
		{"compat keeps explicit pinned trust (config registry_trust)", daemon.TransportCompat,
			registrySettings{Addr: defaultRegistryAddr, Trust: "pinned", TrustExplicit: true, Fingerprint: fp},
			registrySettings{Addr: compatRegistryAddr, TLS: true, Trust: "pinned", TrustExplicit: true, Fingerprint: fp}},
		{"compat + explicit -registry-tls=false keeps the raw registry (TCP/9000 fallback)", daemon.TransportCompat,
			registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, TLSExplicit: true, Trust: "pinned"},
			registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true, TLSExplicit: true, Trust: "pinned"}},
		{"compat keeps a custom registry, TLS on", daemon.TransportCompat,
			registrySettings{Addr: "10.0.0.5:9443", AddrExplicit: true, Trust: "pinned"},
			registrySettings{Addr: "10.0.0.5:9443", AddrExplicit: true, TLS: true, Trust: "system"}},
		{"udp with the compat registry address turns TLS on (switch back from compat)", daemon.TransportUDP,
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, Trust: "pinned"},
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, TLS: true, Trust: "system"}},
		{"udp with the compat registry and explicit -registry-tls=false is left alone", daemon.TransportUDP,
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, TLSExplicit: true, Trust: "pinned"},
			registrySettings{Addr: compatRegistryAddr, AddrExplicit: true, TLSExplicit: true, Trust: "pinned"}},
	} {
		if got := applyRegistryDefaults(tc.transport, tc.in); got != tc.want {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}

func TestAutoCompatBlocker(t *testing.T) {
	std := registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true}
	if why := autoCompatBlocker(std, defaultBeaconAddr, true, false); why != "" {
		t.Errorf("production defaults blocked: %s", why)
	}
	if why := autoCompatBlocker(registrySettings{Addr: compatRegistryAddr, AddrExplicit: true}, defaultBeaconAddr, true, false); why != "" {
		t.Errorf("compat registry blocked: %s", why)
	}
	if why := autoCompatBlocker(registrySettings{Addr: "10.0.0.5:9000", AddrExplicit: true}, defaultBeaconAddr, true, false); why == "" {
		t.Error("private raw registry not blocked")
	}
	if why := autoCompatBlocker(registrySettings{Addr: "reg.corp:443", AddrExplicit: true, TLS: true, TLSExplicit: true}, defaultBeaconAddr, true, false); why != "" {
		t.Errorf("private TLS registry blocked: %s", why)
	}
	if why := autoCompatBlocker(std, "10.0.0.6:9001", true, false); why == "" {
		t.Error("private beacon with the public compat beacon not blocked")
	}
	if why := autoCompatBlocker(std, "10.0.0.6:9001", true, true); why != "" {
		t.Errorf("private beacon with its own compat beacon blocked: %s", why)
	}
}

// resolveAutoTransport runs the compat check through the proxy compat mode
// would use, and never probes a configuration auto must not move.
func TestResolveAutoTransport(t *testing.T) {
	for _, k := range proxyEnvVars {
		t.Setenv(k, "")
	}
	var got []daemon.AutoTransportProbe
	autoProbe = func(ctx context.Context, p daemon.AutoTransportProbe) (string, string) {
		got = append(got, p)
		return daemon.TransportCompat, "stub"
	}
	t.Cleanup(func() { autoProbe = daemon.SelectTransport })
	std := registrySettings{Addr: defaultRegistryAddr, AddrExplicit: true}

	mode, _, err := resolveAutoTransport(std, defaultBeaconAddr, true, defaultCompatBeacon, false, "auto")
	if err != nil || mode != daemon.TransportCompat || len(got) != 1 {
		t.Fatalf("auto = (%q, %v), probes %d", mode, err, len(got))
	}
	if got[0].Dial != nil || got[0].BeaconAddr != defaultBeaconAddr || got[0].CompatBeaconURL != defaultCompatBeacon {
		t.Errorf("probe without a proxy = %+v, want a direct check of the production beacons", got[0])
	}

	t.Setenv("HTTPS_PROXY", "http://muse:s3cret@egress.test:3128")
	if _, _, err := resolveAutoTransport(std, defaultBeaconAddr, true, defaultCompatBeacon, false, "auto"); err != nil || got[1].Dial == nil {
		t.Errorf("with HTTPS_PROXY the compat check does not use the proxy (err %v)", err)
	}
	if _, _, err := resolveAutoTransport(std, defaultBeaconAddr, true, defaultCompatBeacon, false, "off"); err != nil || got[2].Dial != nil {
		t.Errorf("-proxy=off still proxies the compat check (err %v)", err)
	}
	if _, _, err := resolveAutoTransport(std, defaultBeaconAddr, true, defaultCompatBeacon, false, "ftp://x"); err == nil {
		t.Error("malformed -proxy accepted")
	}

	mode, reason, err := resolveAutoTransport(registrySettings{Addr: "10.0.0.5:9000", AddrExplicit: true}, defaultBeaconAddr, true, defaultCompatBeacon, false, "auto")
	if err != nil || mode != daemon.TransportUDP || len(got) != 3 {
		t.Errorf("private registry: (%q, %q, %v), probes %d — want udp without probing", mode, reason, err, len(got))
	}
}

// -help and flag errors print every flag's default. $PILOT_PROXY (which
// pilotctl uses for credential-bearing proxy URLs) must never show up.
func TestHelpNeverPrintsProxyCredentials(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"--help"}, {"-no-such-flag"}} {
		cmd := exec.Command(os.Args[0], args...)
		cmd.Env = []string{
			runMainEnv + "=1",
			"HOME=" + t.TempDir(),
			"PATH=" + os.Getenv("PATH"),
			"PILOT_PROXY=http://muse:s3cret@egress.test:3128",
			"PILOT_REGISTRY_FINGERPRINT=" + strings.Repeat("ab", 32),
		}
		out, _ := cmd.CombinedOutput()
		if strings.Contains(string(out), "s3cret") || strings.Contains(string(out), "muse") {
			t.Errorf("pilot-daemon %v prints the proxy credentials:\n%s", args, out)
		}
		if !strings.Contains(string(out), "-proxy") || !strings.Contains(string(out), "'auto'") {
			t.Errorf("pilot-daemon %v usage lacks -proxy / auto:\n%s", args, out)
		}
	}
}

// silentUDP returns a UDP address that receives but never answers: a
// beacon behind a UDP-blocking firewall.
func silentUDP(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn.LocalAddr().String()
}

// An old pilotctl (v1.13.9) passes the raw-TCP registry and beacon on
// every start and knows nothing of -transport or -proxy; config.json
// carries transport=compat. The new daemon must still come up in compat
// through the environment's proxy.
func TestOldPilotctlArgsWithCompatConfig(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	targets, logs := runDaemon(t, proxy, daemonRun{
		args: []string{ // v1.13.9 buildDaemonArgs, minus the per-test paths
			"--registry", defaultRegistryAddr,
			"--beacon", defaultBeaconAddr,
		},
		config: `{"registry":"` + defaultRegistryAddr + `","beacon":"` + defaultBeaconAddr + `","transport":"compat",` +
			`"registry_trust":"pinned","registry_fingerprint":"` + strings.Repeat("00", 32) + `"}`,
		env:   []string{"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	for _, target := range targets {
		if strings.Contains(target, "34.71.57.205") {
			t.Errorf("proxy was asked for the raw-TCP registry: %q", target)
		}
	}
	if !strings.Contains(logs, "transport_from=config") {
		t.Errorf("transport not taken from config.json:\n%s", logs)
	}
	// config.json's pinned trust survives compat mode.
	if strings.Contains(logs, "registry_trust=system") {
		t.Errorf("config.json registry_trust=pinned was overridden:\n%s", logs)
	}
}

// A credential-bearing proxy handed over as $PILOT_PROXY (pilotctl's
// --proxy with credentials) beats config.json's "proxy":"auto", and an
// explicit URL proxies the registry in udp mode too.
func TestPilotProxyEnvBeatsConfigAuto(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	_, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", "registry.pilot.invalid:9000",
			"--beacon", silentUDP(t),
		},
		config: `{"proxy":"auto","transport":"udp"}`,
		env:    []string{"PILOT_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())},
		await:  "CONNECT registry.pilot.invalid:9000",
	})
	if _, bad := proxy.snapshot(); bad != 0 {
		t.Errorf("%d proxy request(s) without the credentials", bad)
	}
	if strings.Contains(logs, "s3cret") {
		t.Errorf("daemon output leaks the proxy password:\n%s", logs)
	}
}

// -transport=compat with an explicit -registry-tls=false keeps the raw
// TCP registry (the TCP/9000 fallback) instead of sending plaintext to the
// TLS registry on :443.
func TestCompatRegistryTLSFalseKeepsRawRegistry(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	targets, _ := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", defaultBeaconAddr,
			"-transport=compat",
			"-registry-tls=false",
		},
		env:   []string{"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())},
		await: "CONNECT " + defaultRegistryAddr,
	})
	for _, target := range targets {
		if strings.Contains(target, "registry.pilotprotocol.network") {
			t.Errorf("compat + -registry-tls=false switched to the TLS registry: %q", target)
		}
	}
}

// -transport=auto on a UDP-blocked host whose only way out is the proxy:
// the UDP probe gets no answer, the compat beacon is reachable through the
// proxy, so the daemon runs compat and registers through the proxy.
func TestAutoTransportFallsBackToCompatThroughProxy(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	proxy.allow("beacon.pilotprotocol.network:443")
	start := time.Now()
	targets, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", defaultRegistryAddr,
			"--beacon", silentUDP(t),
			"-compat-beacon", defaultCompatBeacon,
			"-transport=auto",
			"-registry-fingerprint=" + strings.Repeat("00", 32),
		},
		env:   []string{"HTTPS_PROXY=" + fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr())},
		await: "CONNECT registry.pilotprotocol.network:443",
	})
	if !strings.Contains(logs, `msg="transport auto-selected" transport=compat`) {
		t.Errorf("no auto-selection log line:\n%s", logs)
	}
	if n := strings.Count(logs, "transport auto-selected"); n != 1 {
		t.Errorf("auto decision logged %d times, want once", n)
	}
	if !contains(targets, "CONNECT beacon.pilotprotocol.network:443") {
		t.Errorf("compat check did not go through the proxy: %q", targets)
	}
	for _, target := range targets {
		if strings.Contains(target, "34.71.57.205") {
			t.Errorf("proxy was asked for the raw-TCP registry: %q", target)
		}
	}
	t.Logf("auto → compat → registry CONNECT in %s", time.Since(start))
}

// auto never moves a private deployment onto the public compat beacon.
func TestAutoTransportKeepsPrivateRegistryOnUDP(t *testing.T) {
	proxy := newRefusingProxy(t, "muse", "s3cret")
	_, logs := runDaemon(t, proxy, daemonRun{
		args: []string{
			"--registry", "registry.pilot.invalid:9000",
			"--beacon", silentUDP(t),
			"-transport=auto",
			"-proxy", fmt.Sprintf("http://muse:s3cret@%s", proxy.ln.Addr()),
		},
		await: "CONNECT registry.pilot.invalid:9000",
	})
	if !strings.Contains(logs, `msg="transport auto-selected" transport=udp`) {
		t.Errorf("private registry did not stay on udp:\n%s", logs)
	}
}
