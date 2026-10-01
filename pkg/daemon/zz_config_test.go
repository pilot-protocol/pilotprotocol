// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Config zero-value vs explicit-value round-trip ---

func TestConfigKeepaliveIntervalZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.keepaliveInterval(); got != DefaultKeepaliveInterval {
		t.Fatalf("keepaliveInterval() = %v, want %v", got, DefaultKeepaliveInterval)
	}
}

func TestConfigKeepaliveIntervalExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{KeepaliveInterval: 45 * time.Second}
	if got := c.keepaliveInterval(); got != 45*time.Second {
		t.Fatalf("keepaliveInterval() = %v, want 45s", got)
	}
}

func TestConfigIdleTimeoutZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.idleTimeout(); got != DefaultIdleTimeout {
		t.Fatalf("idleTimeout() = %v, want %v", got, DefaultIdleTimeout)
	}
}

func TestConfigIdleTimeoutExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{IdleTimeout: 200 * time.Second}
	if got := c.idleTimeout(); got != 200*time.Second {
		t.Fatalf("idleTimeout() = %v, want 200s", got)
	}
}

func TestConfigSYNRateLimitZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.synRateLimit(); got != DefaultSYNRateLimit {
		t.Fatalf("synRateLimit() = %d, want %d", got, DefaultSYNRateLimit)
	}
}

func TestConfigSYNRateLimitExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{SYNRateLimit: 250}
	if got := c.synRateLimit(); got != 250 {
		t.Fatalf("synRateLimit() = %d, want 250", got)
	}
}

func TestConfigMaxConnectionsPerPortZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.maxConnectionsPerPort(); got != DefaultMaxConnectionsPerPort {
		t.Fatalf("maxConnectionsPerPort() = %d, want %d", got, DefaultMaxConnectionsPerPort)
	}
}

func TestConfigMaxConnectionsPerPortExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{MaxConnectionsPerPort: 2048}
	if got := c.maxConnectionsPerPort(); got != 2048 {
		t.Fatalf("maxConnectionsPerPort() = %d, want 2048", got)
	}
}

func TestConfigMaxTotalConnectionsZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.maxTotalConnections(); got != DefaultMaxTotalConnections {
		t.Fatalf("maxTotalConnections() = %d, want %d", got, DefaultMaxTotalConnections)
	}
}

func TestConfigMaxTotalConnectionsExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{MaxTotalConnections: 131072}
	if got := c.maxTotalConnections(); got != 131072 {
		t.Fatalf("maxTotalConnections() = %d, want 131072", got)
	}
}

func TestConfigTimeWaitDurationZeroFallsBackToDefault(t *testing.T) {
	t.Parallel()
	c := &Config{}
	if got := c.timeWaitDuration(); got != DefaultTimeWaitDuration {
		t.Fatalf("timeWaitDuration() = %v, want %v", got, DefaultTimeWaitDuration)
	}
}

func TestConfigTimeWaitDurationExplicitValueWins(t *testing.T) {
	t.Parallel()
	c := &Config{TimeWaitDuration: 30 * time.Second}
	if got := c.timeWaitDuration(); got != 30*time.Second {
		t.Fatalf("timeWaitDuration() = %v, want 30s", got)
	}
}

// --- isPrivateAddr ---

func TestIsPrivateAddrLoopback(t *testing.T) {
	t.Parallel()
	if !isPrivateAddr("127.0.0.1:4000") {
		t.Fatalf("127.0.0.1:4000 should be private (loopback)")
	}
}

func TestIsPrivateAddrRFC1918(t *testing.T) {
	t.Parallel()
	cases := []string{"10.0.0.1:1", "192.168.4.1:22", "172.16.5.3:80"}
	for _, c := range cases {
		if !isPrivateAddr(c) {
			t.Fatalf("%s should be private", c)
		}
	}
}

func TestIsPrivateAddrLinkLocal(t *testing.T) {
	t.Parallel()
	if !isPrivateAddr("169.254.1.1:4000") {
		t.Fatalf("169.254.x.x is link-local, should be private")
	}
}

func TestIsPrivateAddrPublicIPv4IsNotPrivate(t *testing.T) {
	t.Parallel()
	if isPrivateAddr("8.8.8.8:53") {
		t.Fatalf("8.8.8.8 is public, should NOT be private")
	}
	if isPrivateAddr("34.71.57.205:9000") {
		t.Fatalf("34.71.57.205 is public (GCP), should NOT be private")
	}
}

func TestIsPrivateAddrMalformedReturnsFalse(t *testing.T) {
	t.Parallel()
	if isPrivateAddr("not-a-host-port") {
		t.Fatalf("malformed host:port should return false")
	}
	if isPrivateAddr("") {
		t.Fatalf("empty string should return false")
	}
}

func TestIsPrivateAddrUnparseableIPReturnsFalse(t *testing.T) {
	t.Parallel()
	// Valid host:port format but host is unparseable as IP — isPrivate requires ip != nil
	if isPrivateAddr("not.an.ip.address:4000") {
		t.Fatalf("non-IP host should return false")
	}
}

// --- matchLANSubnet ---

func TestMatchLANSubnetSameSlash24Matches(t *testing.T) {
	t.Parallel()
	ours := []string{"192.168.1.10:4000"}
	theirs := []interface{}{"192.168.1.20:4000"}
	if got := matchLANSubnet(ours, theirs); got != "192.168.1.20:4000" {
		t.Fatalf("matchLANSubnet = %q, want 192.168.1.20:4000", got)
	}
}

func TestMatchLANSubnetDifferentSlash24NoMatch(t *testing.T) {
	t.Parallel()
	ours := []string{"192.168.1.10:4000"}
	theirs := []interface{}{"192.168.2.20:4000"}
	if got := matchLANSubnet(ours, theirs); got != "" {
		t.Fatalf("matchLANSubnet = %q, want empty", got)
	}
}

func TestMatchLANSubnetNonStringPeerIsSkipped(t *testing.T) {
	t.Parallel()
	ours := []string{"10.0.0.1:4000"}
	theirs := []interface{}{42, "10.0.0.2:4000"}
	if got := matchLANSubnet(ours, theirs); got != "10.0.0.2:4000" {
		t.Fatalf("matchLANSubnet = %q, want 10.0.0.2:4000 (int peer skipped)", got)
	}
}

func TestMatchLANSubnetMalformedPeerIsSkipped(t *testing.T) {
	t.Parallel()
	ours := []string{"10.0.0.1:4000"}
	theirs := []interface{}{"bad-addr", "10.0.0.2:4000"}
	if got := matchLANSubnet(ours, theirs); got != "10.0.0.2:4000" {
		t.Fatalf("matchLANSubnet should skip malformed 'bad-addr' and match 10.0.0.2:4000; got %q", got)
	}
}

func TestMatchLANSubnetMalformedOursIsSkipped(t *testing.T) {
	t.Parallel()
	ours := []string{"bad-addr", "10.0.0.1:4000"}
	theirs := []interface{}{"10.0.0.2:4000"}
	if got := matchLANSubnet(ours, theirs); got != "10.0.0.2:4000" {
		t.Fatalf("matchLANSubnet should skip malformed ours; got %q", got)
	}
}

func TestMatchLANSubnetIPv6PeerIsSkipped(t *testing.T) {
	t.Parallel()
	ours := []string{"192.168.1.10:4000"}
	theirs := []interface{}{"[fe80::1]:4000", "192.168.1.11:4000"}
	if got := matchLANSubnet(ours, theirs); got != "192.168.1.11:4000" {
		t.Fatalf("matchLANSubnet should skip IPv6 peer; got %q", got)
	}
}

func TestMatchLANSubnetEmptyInputsReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := matchLANSubnet(nil, nil); got != "" {
		t.Fatalf("matchLANSubnet(nil,nil) = %q, want empty", got)
	}
	if got := matchLANSubnet([]string{"10.0.0.1:1"}, nil); got != "" {
		t.Fatalf("matchLANSubnet(ours,nil) should be empty")
	}
	if got := matchLANSubnet(nil, []interface{}{"10.0.0.1:1"}); got != "" {
		t.Fatalf("matchLANSubnet(nil,theirs) should be empty")
	}
}

// --- addrFamilyMismatch ---

func TestAddrFamilyMismatchNilLocalReturnsFalse(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// No tunnels.Listen → LocalAddr() == nil
	if d.addrFamilyMismatch("1.2.3.4:80") {
		t.Fatalf("nil local addr should NOT report mismatch")
	}
}

func TestAddrFamilyMismatchSameIPv4ReturnsFalse(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// Use a concrete IPv4 local bind
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer d.tunnels.Close()
	if d.addrFamilyMismatch("8.8.8.8:53") {
		t.Fatalf("IPv4 local + IPv4 remote should not mismatch")
	}
}

func TestAddrFamilyMismatchIPv4LocalIPv6RemoteReturnsTrue(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer d.tunnels.Close()
	if !d.addrFamilyMismatch("[2001:db8::1]:443") {
		t.Fatalf("IPv4 local + IPv6 remote should mismatch")
	}
}

func TestAddrFamilyMismatchMalformedRemoteReturnsFalse(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer d.tunnels.Close()
	if d.addrFamilyMismatch("not-a-host-port") {
		t.Fatalf("malformed remote should return false")
	}
}

func TestAddrFamilyMismatchUnparseableRemoteIPReturnsFalse(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.tunnels.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer d.tunnels.Close()
	// valid host:port, but host is not an IP — net.ParseIP returns nil
	if d.addrFamilyMismatch("example.invalid:4000") {
		t.Fatalf("unparseable remote IP should return false (no mismatch signal)")
	}
}

// --- collectLANAddrs (loose contract: it should not panic and every returned
// entry must be host:port with the requested port and a private IPv4 host) ---

func TestCollectLANAddrsReturnsPortedPrivateIPv4Entries(t *testing.T) {
	t.Parallel()
	addrs := collectLANAddrs("4000")
	for _, a := range addrs {
		host, port, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatalf("%q is not host:port: %v", a, err)
		}
		if port != "4000" {
			t.Fatalf("addr %q: port = %q, want 4000", a, port)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("addr %q: host %q is not a valid IP", a, host)
		}
		if ip.To4() == nil {
			t.Fatalf("addr %q: expected IPv4, got %v", a, ip)
		}
		if !(ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
			t.Fatalf("addr %q: host %v is not private or link-local", a, ip)
		}
		if ip.IsLoopback() {
			t.Fatalf("addr %q: should not include loopback", a)
		}
	}
}

// --- New + Daemon basic wiring ---

func TestNewDaemonInitializesAllMaps(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.tunnels == nil {
		t.Fatalf("tunnels should be non-nil")
	}
	if d.ports == nil {
		t.Fatalf("ports should be non-nil")
	}
	if d.stopCh == nil {
		t.Fatalf("stopCh should be non-nil")
	}
	if d.perSrcSYN == nil {
		t.Fatalf("perSrcSYN should be non-nil")
	}
	if d.epCache == nil {
		t.Fatalf("epCache should be non-nil")
	}
	if d.resolveCache == nil {
		t.Fatalf("resolveCache should be non-nil")
	}
	if d.netPolicies == nil {
		t.Fatalf("netPolicies should be non-nil")
	}
	if d.managed == nil {
		t.Fatalf("managed should be non-nil")
	}
	// policyRunners moved to plugins/policy (T2.3) — daemon now holds
	// only a coreapi.PolicyManager interface, set by cmd/daemon.
	if d.memberTags == nil {
		t.Fatalf("memberTags should be non-nil")
	}
	if d.ipc == nil {
		t.Fatalf("ipc should be non-nil")
	}
	// d.handshakes is wired by RegisterHandshakeService after T3.3,
	// so it's expected to be nil immediately after New() (the
	// composition root attaches the plugin's HandshakeService later).
	if d.handshakes != nil {
		t.Fatalf("handshakes should be nil before RegisterHandshakeService")
	}
	// Config should be preserved
	if d.config.SocketPath != "" {
		t.Fatalf("socket path = %q, want empty", d.config.SocketPath)
	}
}

func TestNewDaemonSeedsSynTokensWithRateLimit(t *testing.T) {
	t.Parallel()
	d := New(Config{SYNRateLimit: 77})
	if d.synTokens != 77 {
		t.Fatalf("synTokens = %d, want 77", d.synTokens)
	}
}

func TestNewDaemonSeedsSynTokensWithDefaultWhenZero(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.synTokens != DefaultSYNRateLimit {
		t.Fatalf("synTokens = %d, want default %d", d.synTokens, DefaultSYNRateLimit)
	}
}

// --- allowSYN ---

func TestAllowSYNConsumesTokensUntilEmpty(t *testing.T) {
	t.Parallel()
	d := New(Config{SYNRateLimit: 3})
	// Prevent any refill during this test by setting lastFill to now.
	d.synMu.Lock()
	d.synLastFill = time.Now()
	d.synMu.Unlock()

	granted := 0
	for i := 0; i < 10; i++ {
		if d.allowSYN() {
			granted++
		} else {
			break
		}
	}
	// With zero elapsed time since NEW, refill=0, so we get exactly the initial tokens.
	if granted != 3 {
		t.Fatalf("granted = %d, want 3 (rate limit)", granted)
	}
	// Further calls should be denied.
	if d.allowSYN() {
		t.Fatalf("4th allowSYN should be denied after bucket drained")
	}
}

func TestAllowSYNRefillsAfterOneSecond(t *testing.T) {
	t.Parallel()
	d := New(Config{SYNRateLimit: 2})
	// Drain the bucket
	d.allowSYN()
	d.allowSYN()
	if d.allowSYN() {
		t.Fatalf("3rd allowSYN should be denied")
	}
	// Rewind lastFill by 1.1s to trigger a refill.
	d.synMu.Lock()
	d.synLastFill = time.Now().Add(-1100 * time.Millisecond)
	d.synMu.Unlock()
	if !d.allowSYN() {
		t.Fatalf("expected refill to permit the next SYN")
	}
}

// --- allowSYNFromSource ---

func TestAllowSYNFromSourceFirstCallSeedsBucket(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if !d.allowSYNFromSource(42) {
		t.Fatalf("first call for a new source should be allowed")
	}
	d.perSrcSYNMu.Lock()
	b, ok := d.perSrcSYN[42]
	d.perSrcSYNMu.Unlock()
	if !ok || b == nil {
		t.Fatalf("bucket should be created for source 42")
	}
	if b.tokens != perSourceSYNBurst-1 {
		t.Fatalf("new bucket tokens = %d, want %d", b.tokens, perSourceSYNBurst-1)
	}
}

func TestAllowSYNFromSourceDeniesAfterLimit(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	src := uint32(99)
	granted := 0
	for i := 0; i < perSourceSYNBurst+5; i++ {
		if d.allowSYNFromSource(src) {
			granted++
		}
	}
	if granted != perSourceSYNBurst {
		t.Fatalf("granted = %d, want %d", granted, perSourceSYNBurst)
	}
}

func TestAllowSYNFromSourceCapFullRejectsNewSource(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// Fill the map to capacity with distinct sources (each has tokens > 0).
	for i := 0; i < maxPerSrcSYNEntries; i++ {
		d.perSrcSYN[uint32(i)] = &srcSYNBucket{tokens: 1, lastFill: time.Now()}
	}
	// A brand-new source should be rejected because the map is full.
	if d.allowSYNFromSource(0xFFFFFFFF) {
		t.Fatalf("expected cap-full rejection for new source")
	}
	// But an existing source still has its tokens — should be allowed.
	if !d.allowSYNFromSource(0) {
		t.Fatalf("existing source should still be allowed when map is full")
	}
}

// --- reapPerSrcSYN ---

func TestReapPerSrcSYNRemovesStaleBucketsAndKeepsFresh(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	stale := time.Now().Add(-2 * SYNBucketAge)
	fresh := time.Now()
	d.perSrcSYN[1] = &srcSYNBucket{tokens: 5, lastFill: stale}
	d.perSrcSYN[2] = &srcSYNBucket{tokens: 5, lastFill: fresh}
	d.perSrcSYN[3] = &srcSYNBucket{tokens: 5, lastFill: stale}

	d.reapPerSrcSYN()

	d.perSrcSYNMu.Lock()
	_, has1 := d.perSrcSYN[1]
	_, has2 := d.perSrcSYN[2]
	_, has3 := d.perSrcSYN[3]
	d.perSrcSYNMu.Unlock()
	if has1 {
		t.Fatalf("stale bucket 1 should have been removed")
	}
	if !has2 {
		t.Fatalf("fresh bucket 2 should have been kept")
	}
	if has3 {
		t.Fatalf("stale bucket 3 should have been removed")
	}
}

// --- discoverWithTempSocket ---

func TestDiscoverWithTempSocketResolveErrorPropagates(t *testing.T) {
	t.Parallel()
	_, err := discoverWithTempSocket("ignored:0", "not-a-valid-addr")
	if err == nil {
		t.Fatalf("expected resolve error for bad listen addr")
	}
}

func TestDiscoverWithTempSocketListenErrorPropagates(t *testing.T) {
	t.Parallel()
	// Bind a socket on an ephemeral port, then try to bind the same port again.
	blocker, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("blocker listen: %v", err)
	}
	defer blocker.Close()
	addr := blocker.LocalAddr().String()
	_, err = discoverWithTempSocket("ignored:0", addr)
	if err == nil {
		t.Fatalf("expected bind error on duplicate port")
	}
	if !strings.Contains(err.Error(), "temp listen") {
		t.Fatalf("error = %v, want to contain \"temp listen\"", err)
	}
}

func TestDiscoverWithTempSocketDiscoverErrorPropagates(t *testing.T) {
	t.Parallel()
	// Silent beacon → DiscoverEndpoint will time out.
	silent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("silent listen: %v", err)
	}
	defer silent.Close()
	_, err = discoverWithTempSocket(silent.LocalAddr().String(), "127.0.0.1:0")
	if err == nil {
		t.Fatalf("expected timeout/discover error from silent beacon")
	}
}

// --- concurrency smoke on allowSYNFromSource ---

func TestAllowSYNFromSourceIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(src uint32) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = d.allowSYNFromSource(src)
			}
		}(uint32(i))
	}
	wg.Wait()
	// If the race detector is on, this test is real; otherwise it's a smoke check.
	if len(d.perSrcSYN) != 8 {
		t.Fatalf("expected 8 source buckets, got %d", len(d.perSrcSYN))
	}
}

// Keep %w-style errors usable even if future edits drop callers.
var _ = fmt.Errorf
