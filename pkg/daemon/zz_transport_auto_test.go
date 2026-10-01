// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// udpBeacon answers BeaconMsgDiscover like a real beacon when answer is
// true, and silently drops everything otherwise (a UDP-blocked path).
func udpBeacon(t *testing.T, answer bool) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if !answer || n < 5 || buf[0] != protocol.BeaconMsgDiscover {
				continue
			}
			reply := []byte{protocol.BeaconMsgDiscoverReply, 4}
			reply = append(reply, from.IP.To4()...)
			reply = binary.BigEndian.AppendUint16(reply, uint16(from.Port))
			_, _ = conn.WriteToUDP(reply, from)
		}
	}()
	return conn.LocalAddr().String()
}

func tcpListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().String()
}

// compatBeaconStub is a TLS server that answers a plain GET of the compat
// path with status — 426 Upgrade Required is what a live WebSocket beacon
// sends; a front whose beacon is down answers 502.
func compatBeaconStub(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/compat" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// When UDP works, auto is udp — the transport the daemon always used —
// found in one round trip, and the compat side is never touched.
func TestSelectTransportUDPWorks(t *testing.T) {
	t.Parallel()
	beacon := udpBeacon(t, true)
	dialed := false
	start := time.Now()
	mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://beacon.pilot.invalid/v1/compat",
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("must not be called")
		},
	})
	if mode != TransportUDP {
		t.Fatalf("mode = %q (%s), want udp", mode, reason)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("UDP-reachable probe took %s; want about one round trip", elapsed)
	}
	if dialed {
		t.Error("compat check ran although UDP answered")
	}
}

// UDP blocked, compat beacon answering (426 to a plain GET): compat,
// within the probe bound plus the local check.
func TestSelectTransportUDPBlockedFallsBackToCompat(t *testing.T) {
	t.Parallel()
	beacon := udpBeacon(t, false)
	compat := compatBeaconStub(t, http.StatusUpgradeRequired)
	start := time.Now()
	mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://" + compat + "/v1/compat",
		UDPTimeout:      300 * time.Millisecond,
	})
	if mode != TransportCompat {
		t.Fatalf("mode = %q (%s), want compat", mode, reason)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("fallback took %s, want the bounded probe (~300ms) plus a local connect", elapsed)
	}
	if !strings.Contains(reason, "no UDP answer") {
		t.Errorf("reason %q does not say why", reason)
	}
}

// Nothing reachable (no network yet, beacon outage): stay on udp, as a
// daemon always did — a compat daemon could not start either.
func TestSelectTransportNothingReachableStaysUDP(t *testing.T) {
	t.Parallel()
	beacon := udpBeacon(t, false)
	// Take a port and close it so connects are refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := ln.Addr().String()
	ln.Close()
	mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://" + refused + "/v1/compat",
		UDPTimeout:      200 * time.Millisecond,
		TCPTimeout:      time.Second,
	})
	if mode != TransportUDP {
		t.Fatalf("mode = %q (%s), want udp", mode, reason)
	}
	for _, tc := range []struct{ beacon, compat string }{
		{"", "wss://beacon.pilot.invalid/v1/compat"},
		{beacon, ""},
		{beacon, "ftp://beacon.pilot.invalid"},
	} {
		if mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
			BeaconAddr: tc.beacon, CompatBeaconURL: tc.compat, UDPTimeout: 100 * time.Millisecond,
		}); mode != TransportUDP {
			t.Errorf("SelectTransport(%q, %q) = %q (%s), want udp", tc.beacon, tc.compat, mode, reason)
		}
	}
}

// auto-compat-check-tcp-only-fatal-on-beacon-outage: a front that accepts
// TCP (or TLS) while the beacon behind it is down is not a working compat
// path. auto stays on udp, which starts degraded and registers, instead of
// picking compat and exiting on the failed WSS connect.
func TestSelectTransportFrontUpBeaconDownStaysUDP(t *testing.T) {
	t.Parallel()
	beacon := udpBeacon(t, false)
	for name, compat := range map[string]string{
		"TCP accept-and-close": tcpListener(t),
		"TLS front, 502":       compatBeaconStub(t, http.StatusBadGateway),
		"TLS front, 503":       compatBeaconStub(t, http.StatusServiceUnavailable),
	} {
		mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
			BeaconAddr:      beacon,
			CompatBeaconURL: "wss://" + compat + "/v1/compat",
			UDPTimeout:      100 * time.Millisecond,
			TCPTimeout:      2 * time.Second,
		})
		if mode != TransportUDP {
			t.Errorf("%s: mode = %q (%s), want udp", name, mode, reason)
		}
	}
}

// Behind an egress proxy the compat check goes through the proxy, by host
// name — the Muse case: UDP silently dropped, direct TCP killed.
func TestSelectTransportCompatCheckUsesProxy(t *testing.T) {
	clearProxyEnv(t)
	beacon := udpBeacon(t, false)
	proxy := newProxyTestConnect(t, "muse", "s3cret")
	target := compatBeaconStub(t, http.StatusUpgradeRequired)
	_, port, _ := net.SplitHostPort(target)
	policy, err := ResolveProxy(proxy.url("muse", "s3cret"), TransportCompat)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Proxy: policy})
	mode, reason, _ := SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://beacon.pilot.invalid:" + port + "/v1/compat",
		Dial:            d.proxyDialer(),
		UDPTimeout:      200 * time.Millisecond,
	})
	if mode != TransportCompat {
		t.Fatalf("mode = %q (%s), want compat", mode, reason)
	}
	if got := proxy.counts()["beacon.pilot.invalid:"+port]; got != 1 {
		t.Fatalf("proxy CONNECTs = %v, want one for beacon.pilot.invalid:%s", proxy.counts(), port)
	}
}

// E2E product gap (Muse, wrong or stale proxy password): UDP gets no
// answer and the proxy refuses the compat check. auto must not settle on
// udp — a udp daemon dials the raw registry directly, past the proxy,
// which a proxy-only sandbox kills — but stay on compat, report the proxy
// error, and let the registry dial (with refreshed credentials) fail or
// recover through the proxy.
func TestSelectTransportProxyRefusalStaysCompat(t *testing.T) {
	clearProxyEnv(t)
	beacon := udpBeacon(t, false)
	target := compatBeaconStub(t, http.StatusUpgradeRequired)
	_, port, _ := net.SplitHostPort(target)
	compatURL := "wss://beacon.pilot.invalid:" + port + "/v1/compat"

	proxy := newProxyTestConnect(t, "muse", "right")
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadProxy := "http://muse:s3cret@" + closed.Addr().String()
	closed.Close()

	for _, tc := range []struct {
		name, proxyURL, compatURL string
		wantStatus                int // 0: not a ConnectError
	}{
		{"407 wrong password", proxy.url("muse", "s3cret"), compatURL, http.StatusProxyAuthRequired},
		{"403 forbidden target", proxy.url("muse", "right"), "wss://beacon.example.test:" + port + "/v1/compat", http.StatusForbidden},
		{"proxy unreachable", deadProxy, compatURL, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := ResolveProxy(tc.proxyURL, TransportCompat)
			if err != nil {
				t.Fatal(err)
			}
			d := New(Config{Proxy: r})
			mode, reason, proxyErr := SelectTransport(context.Background(), AutoTransportProbe{
				BeaconAddr:      beacon,
				CompatBeaconURL: tc.compatURL,
				Dial:            d.proxyDialer(),
				ProxyFor:        func(addr string) string { return proxyconf.ProxyFor(r, addr) },
				UDPTimeout:      200 * time.Millisecond,
				TCPTimeout:      3 * time.Second,
			})
			if mode != TransportCompat || proxyErr == nil {
				t.Fatalf("SelectTransport = (%q, %q, %v), want compat with the proxy error", mode, reason, proxyErr)
			}
			if strings.Contains(reason, "s3cret") || strings.Contains(proxyErr.Error(), "s3cret") {
				t.Fatalf("reason or error leaks the proxy password: %q / %v", reason, proxyErr)
			}
			if !strings.Contains(reason, "***@") {
				t.Errorf("reason %q does not name the (redacted) proxy", reason)
			}
			var ce *netproxy.ConnectError
			if tc.wantStatus != 0 {
				if !errors.As(proxyErr, &ce) || ce.StatusCode != tc.wantStatus {
					t.Fatalf("proxyErr = %v, want a %d ConnectError", proxyErr, tc.wantStatus)
				}
				if hint := ProxyRefusalHint(proxyErr); hint == "" {
					t.Errorf("no hint for %v", proxyErr)
				}
			}
		})
	}

	// Without a proxy the same failure (nothing reachable) stays on udp,
	// as before.
	mode, reason, proxyErr := SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://" + closed.Addr().String() + "/v1/compat",
		UDPTimeout:      100 * time.Millisecond,
		TCPTimeout:      time.Second,
	})
	if mode != TransportUDP || proxyErr != nil {
		t.Fatalf("direct, nothing reachable = (%q, %q, %v), want udp", mode, reason, proxyErr)
	}

	// A proxy that tunnels fine to a front whose beacon is down is not a
	// proxy error: udp, as before.
	front := compatBeaconStub(t, http.StatusBadGateway)
	_, frontPort, _ := net.SplitHostPort(front)
	r, _ := ResolveProxy(proxy.url("muse", "right"), TransportCompat)
	d := New(Config{Proxy: r})
	mode, reason, proxyErr = SelectTransport(context.Background(), AutoTransportProbe{
		BeaconAddr:      beacon,
		CompatBeaconURL: "wss://beacon.pilot.invalid:" + frontPort + "/v1/compat",
		Dial:            d.proxyDialer(),
		ProxyFor:        func(addr string) string { return proxyconf.ProxyFor(r, addr) },
		UDPTimeout:      100 * time.Millisecond,
		TCPTimeout:      3 * time.Second,
	})
	if mode != TransportUDP || proxyErr != nil {
		t.Fatalf("proxied, beacon down = (%q, %q, %v), want udp", mode, reason, proxyErr)
	}
}

func TestNormalizeTransport(t *testing.T) {
	for in, want := range map[string]string{"": "", "udp": "udp", " COMPAT ": "compat", "Auto": "auto"} {
		if got, err := NormalizeTransport(in); err != nil || got != want {
			t.Errorf("NormalizeTransport(%q) = (%q, %v), want %q", in, got, err, want)
		}
	}
	if _, err := NormalizeTransport("wss"); err == nil {
		t.Error("NormalizeTransport accepted wss")
	}
}

// -proxy=none and the other "off" spellings disable the proxy; any other
// bare word is an error instead of a proxy host name.
func TestResolveProxyWords(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "http://env.test:3128")
	for _, off := range []string{"none", "NONE", "no", "false", "direct", "off"} {
		p, err := ResolveProxy(off, TransportCompat)
		if err != nil || p == nil || p.Mode() != netproxy.ModeOff {
			t.Errorf("ResolveProxy(%q) = (%v, %v), want off", off, p, err)
		}
	}
	for _, bad := range []string{"proxy", "true", "yes", "env.test:3128", "u:s3cret@env.test:3128"} {
		_, err := ResolveProxy(bad, TransportCompat)
		if err == nil {
			t.Errorf("ResolveProxy(%q) accepted", bad)
		} else if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("ResolveProxy(%q) error leaks the password: %v", bad, err)
		}
	}
	// A bad HTTP_PROXY no longer throws away a good HTTPS_PROXY (common
	// v0.5.14): compat still proxies TLS targets.
	t.Setenv("HTTP_PROXY", "socks5://127.0.0.1:1080")
	p, err := ResolveProxy("auto", TransportCompat)
	if err != nil || !p.Enabled() {
		t.Fatalf("auto/compat with a bad HTTP_PROXY = (%v, %v), want the HTTPS_PROXY policy", p, err)
	}
	if u, _ := p.ProxyForAddr("registry.pilotprotocol.network:443"); u == nil || u.Host != "env.test:3128" {
		t.Fatalf("registry proxy = %v, want env.test:3128", u)
	}
}

// An explicit -proxy URL takes every outbound target except this machine:
// loopback webhooks, sidecars and a local registry go direct.
func TestExplicitProxyNeverTakesLoopback(t *testing.T) {
	t.Parallel()
	proxy := newProxyTestConnect(t, "muse", "s3cret")
	policy, err := ResolveProxy(proxy.url("muse", "s3cret"), TransportUDP)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Proxy: policy})
	pf := proxyconf.RequestProxy(d.config.Proxy)
	for _, target := range []string{"http://127.0.0.1:8080/hook", "http://localhost:5002/analyze"} {
		u, err := pf(&http.Request{URL: mustURL(t, target)})
		if err != nil || u != nil {
			t.Errorf("HTTP proxy for %s = (%v, %v), want direct", target, u, err)
		}
	}
	if u, _ := pf(&http.Request{URL: mustURL(t, "https://raw.githubusercontent.com/x")}); u == nil {
		t.Error("remote HTTP target not proxied")
	}

	local := tcpListener(t)
	conn, err := d.proxyDialer()(context.Background(), "tcp", local)
	if err != nil {
		t.Fatalf("dial loopback %s: %v", local, err)
	}
	conn.Close()
	if n := len(proxy.counts()); n != 0 {
		t.Fatalf("loopback dial reached the proxy: %v", proxy.counts())
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
