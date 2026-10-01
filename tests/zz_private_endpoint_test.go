// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"net"
	"testing"
	"time"

	registryclient "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// privateInterfaceIP returns a private (RFC 1918) IPv4 address of this host
// on which the given TCP port is reachable, or "" when there is none.
func privateInterfaceIP(port string) string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipNet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP.To4()
		if ip == nil || !ip.IsPrivate() {
			continue
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), time.Second)
		if err != nil {
			continue
		}
		c.Close()
		return ip.String()
	}
	return ""
}

// TestPrivateNetworkEndpointReported covers a node whose beacon and registry
// are both on its own private network (a container on a Docker bridge, a lab
// LAN). STUN then reflects a private address, which the daemon discards, and
// the address it sends to the registry is the loopback form of its wildcard
// tunnel socket. The registry replaces that host with the one it observed, so
// peers resolve a reachable private address with the real tunnel port — and
// the daemon must report that same endpoint rather than loopback.
func TestPrivateNetworkEndpointReported(t *testing.T) {
	requireRealNetwork(t)
	t.Parallel()
	env := NewTestEnv(t)

	_, regPort, _ := net.SplitHostPort(env.RegistryAddr)
	_, beaconPort, _ := net.SplitHostPort(env.BeaconAddr)
	lanIP := privateInterfaceIP(regPort)
	if lanIP == "" {
		t.Skip("no private IPv4 interface address on this host")
	}

	a := env.AddDaemon(func(c *daemon.Config) {
		c.RegistryAddr = net.JoinHostPort(lanIP, regPort)
		c.BeaconAddr = net.JoinHostPort(lanIP, beaconPort)
	})
	b := env.AddDaemon()

	rc, err := registryclient.Dial(env.RegistryAddr)
	if err != nil {
		t.Fatalf("dial registry: %v", err)
	}
	defer rc.Close()
	setClientSigner(rc, b.Daemon.Identity())
	resp, err := rc.Resolve(a.Daemon.NodeID(), b.Daemon.NodeID())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	realAddr, _ := resp["real_addr"].(string)
	host, _, err := net.SplitHostPort(realAddr)
	if err != nil {
		t.Fatalf("real_addr %q: %v", realAddr, err)
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
		t.Fatalf("registry hands peers an unusable endpoint %q", realAddr)
	}
	if host != lanIP {
		t.Errorf("registry endpoint host = %s, want %s", host, lanIP)
	}

	if got := a.Daemon.Info().Endpoint; got != realAddr {
		t.Errorf("daemon reports endpoint %q, but peers resolve %q", got, realAddr)
	}
}
