// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/netproxy"
)

func TestNormalize(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", Auto},
		{" auto ", Auto},
		{"AUTO", Auto},
		{"off", Off},
		{"OFF", Off},
		{"none", Off},
		{" None ", Off},
		{"no", Off},
		{"false", Off},
		{"direct", Off},
		{"http://proxy.test:3128", "http://proxy.test:3128"},
		{"https://proxy.test", "https://proxy.test"},
		{" http://u:p@proxy.test:3128 ", "http://u:p@proxy.test:3128"},
		// netproxy splits the userinfo at the last '@', so an unescaped
		// '/', '#' or '?' in the password is fine.
		{"http://agent:12#34/x@egress.test:3128", "http://agent:12#34/x@egress.test:3128"},
	} {
		got, err := Normalize(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("Normalize(%q) = (%q, %v), want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestNormalizeRejectsWordsAndOtherSchemes(t *testing.T) {
	for _, in := range []string{
		"proxy",
		"yes",
		"true",
		"proxy.test:3128",                 // no scheme: never guess
		"muse:s3cret@proxy.test:3128",     // no scheme, with credentials
		"socks5://muse:s3cret@proxy:1080", // unsupported scheme
		"ftp://proxy.test",
		"http://",
		"http://muse:s3cret@",
	} {
		_, err := Normalize(in)
		if err == nil {
			t.Errorf("Normalize(%q) accepted", in)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") {
			t.Errorf("Normalize(%q) error leaks the password: %v", in, err)
		}
	}
}

func TestResolve(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(k, "")
	}
	t.Setenv("HTTPS_PROXY", "http://env.test:3128")
	r, err := Resolve("auto")
	if err != nil || r.Mode() != netproxy.ModeAuto || !r.Enabled() {
		t.Fatalf("Resolve(auto) = (%v, %v)", r, err)
	}
	for _, off := range []string{"off", "none", "direct"} {
		r, err = Resolve(off)
		if err != nil || r.Mode() != netproxy.ModeOff || r.Enabled() {
			t.Fatalf("Resolve(%s) = (%v, %v), want off", off, r, err)
		}
	}
	r, err = Resolve("http://flag.test:8080")
	if err != nil || r.Mode() != netproxy.ModeExplicit {
		t.Fatalf("Resolve(url) = (%v, %v)", r, err)
	}
	if _, err := Resolve("none.example"); err == nil {
		t.Fatal("Resolve accepted a bare host name")
	}
}

func TestHasCredentialsAndRedact(t *testing.T) {
	for _, tc := range []struct {
		in    string
		creds bool
		shown string
	}{
		{"auto", false, "auto"},
		{"off", false, "off"},
		{"http://proxy.test:3128", false, "http://proxy.test:3128"},
		{"http://muse:s3cret@proxy.test:3128", true, "http://***@proxy.test:3128"},
		{"http://agent:1234#Xyz9@egress.test:3128", true, "http://***@egress.test:3128"},
		{"http://agent:12/34?x@egress.test:3128", true, "http://***@egress.test:3128"},
		{"muse:s3cret@proxy.test:3128", true, "***@proxy.test:3128"},
		{"socks5://muse:s3cret@proxy:1080", true, "socks5://***@proxy:1080"},
	} {
		if got := HasCredentials(tc.in); got != tc.creds {
			t.Errorf("HasCredentials(%q) = %v, want %v", tc.in, got, tc.creds)
		}
		if got := Redact(tc.in); got != tc.shown {
			t.Errorf("Redact(%q) = %q, want %q", tc.in, got, tc.shown)
		}
	}
}

func TestIsLoopbackHost(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost":              true,
		"LOCALHOST.":             true,
		"api.localhost":          true,
		"127.0.0.1":              true,
		"127.3.2.1":              true,
		"::1":                    true,
		"[::1]":                  true,
		"example.com":            false,
		"10.0.0.1":               false,
		"registry.pilot.invalid": false,
		"":                       false,
		"localhost.example.com":  false,
	} {
		if got := IsLoopbackHost(host); got != want {
			t.Errorf("IsLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

// An explicit proxy normally takes every target; loopback is the exception
// on both the HTTP and the raw-dial path.
func TestLoopbackNeverProxied(t *testing.T) {
	r, err := netproxy.Explicit("http://proxy.test:3128")
	if err != nil {
		t.Fatal(err)
	}
	pf := RequestProxy(r)
	for _, target := range []string{"http://127.0.0.1:8080/hook", "http://localhost:5002/analyze", "https://[::1]:9443/"} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		if u, err := pf(req); err != nil || u != nil {
			t.Errorf("proxy for %s = (%v, %v), want direct", target, u, err)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, "https://raw.githubusercontent.com/x", nil)
	if u, err := pf(req); err != nil || u == nil || u.Host != "proxy.test:3128" {
		t.Errorf("proxy for a remote target = (%v, %v), want proxy.test:3128", u, err)
	}
	if RequestProxy(nil) != nil {
		t.Error("RequestProxy(nil) is not nil")
	}
}

// DialContext sends a loopback target straight to it, and a remote target
// through the proxy with CONNECT by name.
func TestDialContextLoopbackDirectRemoteViaProxy(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()

	var mu sync.Mutex
	var connects []string
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()
	go func() {
		for {
			c, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				mu.Lock()
				connects = append(connects, req.Method+" "+req.RequestURI)
				mu.Unlock()
				up, err := net.Dial("tcp", echo.Addr().String())
				if err != nil {
					return
				}
				defer up.Close()
				fmt.Fprint(c, "HTTP/1.1 200 OK\r\n\r\n")
				go io.Copy(up, br)
				io.Copy(c, up)
			}()
		}
	}()

	r, err := netproxy.Explicit("http://" + proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dial := DialContext(r, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	roundTrip := func(addr string) {
		t.Helper()
		c, err := dial(ctx, "tcp", addr)
		if err != nil {
			t.Fatalf("dial %s: %v", addr, err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
			t.Fatalf("echo via %s = (%q, %v)", addr, buf, err)
		}
	}

	roundTrip(echo.Addr().String())
	mu.Lock()
	if len(connects) != 0 {
		t.Fatalf("loopback dial went to the proxy: %q", connects)
	}
	mu.Unlock()

	roundTrip("registry.pilot.invalid:443")
	mu.Lock()
	defer mu.Unlock()
	if len(connects) != 1 || connects[0] != "CONNECT registry.pilot.invalid:443" {
		t.Fatalf("proxy requests = %q, want one CONNECT registry.pilot.invalid:443", connects)
	}
}
