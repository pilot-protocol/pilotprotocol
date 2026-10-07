// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/json"
	"net"
	"sync"
	"testing"

	"github.com/pilot-protocol/common/ipcutil"
	registry "github.com/pilot-protocol/common/registry/client"
)

// startFakeRegistry stands up an in-process TCP listener that speaks the
// registry's JSON-over-framed-IPC protocol. The respond callback receives
// each request map and returns the response map. The returned client is
// dialed through the standard registry.Dial path so it exercises the same
// connection lifecycle as a real daemon.
//
// This helper was originally defined alongside the cycle/fetchmembers
// tests; those tests were removed when their referenced symbols moved to
// plugins/handshake (T3.3) and plugins/policy (T2.3). The helper itself
// is still consumed by handshake_dispatch_test.go and a few daemon-side
// info/wire tests, so we keep it here in a dedicated _test.go.
func startFakeRegistry(t *testing.T, respond func(req map[string]interface{}) map[string]interface{}) (*registry.Client, func()) {
	t.Helper()
	addr, stop := serveFakeRegistry(t, respond)
	client, err := registry.Dial(addr)
	if err != nil {
		stop()
		t.Fatalf("dial fake registry: %v", err)
	}

	// Configure a no-op test signer. After PILOT-128 the registry client
	// refuses to send any signed request when no signer is set. The fake
	// registry doesn't verify signatures, so any non-empty string suffices.
	// Tests that need the no-signer error path should call client.SetSigner(nil).
	client.SetSigner(func(challenge string) string {
		return "test-sig:" + challenge
	})

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			client.Close()
			stop()
		})
	}
	return client, cleanup
}

// serveFakeRegistry is the server half of startFakeRegistry, for tests that
// need the address itself (a daemon that dials its own registry connections,
// such as forceReconnectRegistry). It accepts any number of connections.
// The returned stop closes the listener and waits for every connection
// handler to return.
func serveFakeRegistry(t *testing.T, respond func(req map[string]interface{}) map[string]interface{}) (string, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		closed bool
		conns  []net.Conn
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			// Server-side conns are closed by stop, so a client the test
			// never closes cannot keep a handler (and stop) waiting.
			mu.Lock()
			if closed {
				mu.Unlock()
				conn.Close()
				return
			}
			conns = append(conns, conn)
			mu.Unlock()
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				for {
					raw, err := ipcutil.Read(c)
					if err != nil {
						return
					}
					var req map[string]interface{}
					if err := json.Unmarshal(raw, &req); err != nil {
						return
					}
					resp := respond(req)
					if resp == nil {
						resp = map[string]interface{}{}
					}
					// common@v0.4.7 (PILOT-132) rejects any non-empty
					// registry response that lacks a "type" envelope
					// field. The fake-registry callbacks predate that
					// requirement and rarely set "type" explicitly;
					// inject a default so we don't have to update every
					// single test. Tests that exercise a specific type
					// (e.g. error envelopes) still win — we only fill
					// the field when the callback didn't.
					if len(resp) > 0 {
						if _, hasType := resp["type"]; !hasType {
							resp["type"] = "response"
						}
					}
					out, _ := json.Marshal(resp)
					if err := ipcutil.Write(c, out); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	stop := func() {
		mu.Lock()
		if closed {
			mu.Unlock()
			return
		}
		closed = true
		lis.Close()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
	return lis.Addr().String(), stop
}
