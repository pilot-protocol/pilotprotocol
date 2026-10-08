// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
	"time"
)

// errPprofNotLoopback rejects a -pprof address that is not on a loopback
// interface. Profiles show where the daemon spends memory and CPU, and its
// goroutine stacks; they are for the operator of this host, so the listener
// never binds a routable address.
var errPprofNotLoopback = errors.New("-pprof must be a loopback address (127.0.0.1:<port>, [::1]:<port> or localhost:<port>)")

// pprofListenAddr checks a -pprof value and returns the address to bind:
// "localhost" becomes 127.0.0.1 so a resolver cannot send it elsewhere.
func pprofListenAddr(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("-pprof %q: %w", addr, err)
	}
	if strings.EqualFold(host, "localhost") {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return "", errPprofNotLoopback
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// pprofMux serves Go's runtime profiles under /debug/pprof/: heap, allocs,
// goroutine, threadcreate, block, mutex (through the index), plus a CPU
// profile, an execution trace and symbol lookup. /debug/pprof/cmdline is
// left out: the command line can carry -admin-token.
func pprofMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return mux
}

// startPprof serves runtime profiles on addr (see pprofListenAddr) for the
// life of the process and returns the bound address. Off unless -pprof is
// set. Any local user can connect to a loopback TCP port, unlike the IPC
// socket, so leave it off where other users share the host.
func startPprof(addr string) (net.Addr, error) {
	bind, err := pprofListenAddr(addr)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("-pprof listen %s: %w", bind, err)
	}
	srv := &http.Server{
		Handler:           pprofMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("pprof listener stopped", "addr", ln.Addr().String(), "error", err)
		}
	}()
	return ln.Addr(), nil
}
