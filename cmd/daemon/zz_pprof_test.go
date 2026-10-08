// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPprofListenAddrLoopbackOnly(t *testing.T) {
	ok := map[string]string{
		"127.0.0.1:6060": "127.0.0.1:6060",
		"127.0.0.1:0":    "127.0.0.1:0",
		"[::1]:6060":     "[::1]:6060",
		"localhost:6060": "127.0.0.1:6060",
		"LOCALHOST:7":    "127.0.0.1:7",
		"127.1.2.3:6060": "127.1.2.3:6060",
	}
	for in, want := range ok {
		got, err := pprofListenAddr(in)
		if err != nil || got != want {
			t.Errorf("pprofListenAddr(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "10.0.0.1:6060", "34.71.57.205:6060", "example.com:6060"} {
		if _, err := pprofListenAddr(in); !errors.Is(err, errPprofNotLoopback) {
			t.Errorf("pprofListenAddr(%q) err = %v; want errPprofNotLoopback", in, err)
		}
	}
	for _, in := range []string{"", "6060", "127.0.0.1"} {
		if _, err := pprofListenAddr(in); err == nil {
			t.Errorf("pprofListenAddr(%q) accepted a value with no port", in)
		}
	}
}

func TestPprofServesProfilesButNotCmdline(t *testing.T) {
	addr, err := startPprof("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	get := func(path string) (int, string) {
		t.Helper()
		resp, err := client.Get("http://" + addr.String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get("/debug/pprof/heap?debug=1"); code != http.StatusOK || !strings.Contains(body, "heap profile") {
		t.Fatalf("heap profile: status %d, body starts %.80q", code, body)
	}
	if code, body := get("/debug/pprof/goroutine?debug=1"); code != http.StatusOK || !strings.Contains(body, "goroutine profile") {
		t.Fatalf("goroutine profile: status %d, body starts %.80q", code, body)
	}
	// The index would otherwise serve cmdline through its generic handler;
	// it must not, because the command line can carry -admin-token.
	if code, _ := get("/debug/pprof/cmdline"); code == http.StatusOK {
		t.Fatalf("/debug/pprof/cmdline served (status %d); it must not be", code)
	}
}

func TestStartPprofRejectsRoutableAddress(t *testing.T) {
	if _, err := startPprof("0.0.0.0:0"); !errors.Is(err, errPprofNotLoopback) {
		t.Fatalf("startPprof(0.0.0.0:0) err = %v; want errPprofNotLoopback", err)
	}
}
