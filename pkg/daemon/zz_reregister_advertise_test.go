// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"os"
	"testing"

	registry "github.com/pilot-protocol/common/registry/client"
)

// TestReRegisterKeepsAdvertiseEndpoint verifies that a re-registration
// (registry reconnect, rx-watchdog soft recovery) sends the operator's
// -advertise-endpoint again, like Start does, instead of replacing the
// registered endpoint with the tunnel socket's local address.
func TestReRegisterKeepsAdvertiseEndpoint(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	rc.Close()

	sockDir, err := os.MkdirTemp("", "pds")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	const advertised = "203.0.113.9:4000"
	d := New(Config{
		ListenAddr:          "127.0.0.1:0",
		RegistryAddr:        reg.Addr().String(),
		SocketPath:          sockDir + "/s",
		IdentityPath:        t.TempDir() + "/i",
		Email:               "advertise@example.test",
		AdvertiseEndpoint:   advertised,
		Public:              true, // lookup returns real_addr for public nodes
		DisablePolicyRunner: true,
	})
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Stop()

	lookup, err := registry.Dial(reg.Addr().String())
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer lookup.Close()
	registered := func() string {
		t.Helper()
		resp, err := lookup.Lookup(d.NodeID())
		if err != nil {
			t.Fatalf("lookup: %v", err)
		}
		addr, _ := resp["real_addr"].(string)
		return addr
	}

	if got := registered(); got != advertised {
		t.Fatalf("after Start: registered endpoint = %q, want %q", got, advertised)
	}
	d.reRegister()
	if got := registered(); got != advertised {
		t.Fatalf("after reRegister: registered endpoint = %q, want %q", got, advertised)
	}
}
