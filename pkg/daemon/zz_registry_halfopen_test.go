// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	registryclient "github.com/pilot-protocol/common/registry/client"
)

func newHalfOpenListener(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln
}

func TestWithRegistryDeadlineTimesOutOnHalfOpenConn(t *testing.T) {
	t.Parallel()
	ln := newHalfOpenListener(t)
	defer ln.Close()

	rc, err := registryclient.Dial(ln.Addr().String())
	if err != nil {
		t.Fatalf("dial half-open listener: %v", err)
	}

	const deadline = 200 * time.Millisecond
	start := time.Now()
	_, err = withRegistryDeadline(deadline, func() (map[string]interface{}, error) {
		return rc.Lookup(1)
	})
	elapsed := time.Since(start)

	if !errors.Is(err, errRegistryCallTimedOut) {
		t.Fatalf("err = %v, want errRegistryCallTimedOut", err)
	}
	if elapsed > 2*deadline {
		t.Fatalf("withRegistryDeadline took %v, want close to the %v deadline", elapsed, deadline)
	}
}

func TestForceReconnectRegistryRecoversFromHalfOpenConn(t *testing.T) {
	t.Parallel()
	reg, liveRC := startTestRegistry(t)
	defer reg.Close()
	defer liveRC.Close()

	deadLn := newHalfOpenListener(t)
	defer deadLn.Close()

	deadRC, err := registryclient.Dial(deadLn.Addr().String())
	if err != nil {
		t.Fatalf("dial half-open listener: %v", err)
	}

	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}

	d := New(Config{RegistryAddr: reg.Addr().String()})
	d.identity = id
	d.regConn.Store(deadRC)

	deadlineHit := make(chan error, 1)
	go func() {
		_, err := withRegistryDeadline(300*time.Millisecond, func() (map[string]interface{}, error) {
			return deadRC.Lookup(1)
		})
		deadlineHit <- err
	}()
	select {
	case err := <-deadlineHit:
		if !errors.Is(err, errRegistryCallTimedOut) {
			t.Fatalf("lookup on half-open conn err = %v, want errRegistryCallTimedOut", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lookup on half-open conn never returned")
	}

	start := time.Now()
	if err := d.forceReconnectRegistry(); err != nil {
		t.Fatalf("forceReconnectRegistry: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("forceReconnectRegistry took %v, want a fresh dial to complete quickly", elapsed)
	}

	newRC := d.reg()
	if newRC == deadRC {
		t.Fatal("regConn was not replaced by forceReconnectRegistry")
	}

	resp, err := newRC.RegisterWithKeyOpts(registryclient.RegisterOpts{
		ListenAddr: "127.0.0.1:5500",
		PublicKey:  crypto.EncodePublicKey(id.PublicKey),
	})
	if err != nil {
		t.Fatalf("post-reconnect register failed: %v", err)
	}
	if _, ok := resp["node_id"]; !ok {
		t.Fatalf("register response missing node_id: %v", resp)
	}
}

// A reconnect requested after Stop began (the heartbeat and rx-watchdog
// call forceReconnectRegistry without coordinating with Stop) must not
// install a fresh registry pool that nothing will ever close.
func TestForceReconnectRegistryAfterStopDoesNotReplaceConn(t *testing.T) {
	t.Parallel()
	reg, liveRC := startTestRegistry(t)
	defer reg.Close()
	defer liveRC.Close()

	d := New(Config{RegistryAddr: reg.Addr().String()})
	d.regConn.Store(liveRC)
	close(d.stopCh)

	if err := d.forceReconnectRegistry(); !errors.Is(err, errDaemonStopping) {
		t.Fatalf("forceReconnectRegistry after stop: err = %v, want errDaemonStopping", err)
	}
	if got := d.reg(); got != liveRC {
		t.Fatal("forceReconnectRegistry replaced the registry conn after Stop began")
	}
}
