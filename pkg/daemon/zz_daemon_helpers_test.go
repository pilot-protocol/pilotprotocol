// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Config accessor defaults vs custom
// ---------------------------------------------------------------------------

func TestConfigKeepaliveIntervalDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.keepaliveInterval(); got != DefaultKeepaliveInterval {
		t.Errorf("got %v, want default %v", got, DefaultKeepaliveInterval)
	}
}

func TestConfigKeepaliveIntervalCustom(t *testing.T) {
	t.Parallel()
	c := Config{KeepaliveInterval: 7 * time.Second}
	if got := c.keepaliveInterval(); got != 7*time.Second {
		t.Errorf("got %v, want 7s", got)
	}
}

func TestConfigIdleTimeoutDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.idleTimeout(); got != DefaultIdleTimeout {
		t.Errorf("got %v, want default", got)
	}
}

func TestConfigIdleTimeoutCustom(t *testing.T) {
	t.Parallel()
	c := Config{IdleTimeout: 99 * time.Second}
	if got := c.idleTimeout(); got != 99*time.Second {
		t.Errorf("got %v", got)
	}
}

func TestConfigSYNRateLimitDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.synRateLimit(); got != DefaultSYNRateLimit {
		t.Errorf("got %d, want default", got)
	}
}

func TestConfigSYNRateLimitCustom(t *testing.T) {
	t.Parallel()
	c := Config{SYNRateLimit: 7}
	if got := c.synRateLimit(); got != 7 {
		t.Errorf("got %d", got)
	}
}

func TestConfigMaxConnectionsPerPortDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.maxConnectionsPerPort(); got != DefaultMaxConnectionsPerPort {
		t.Errorf("got %d", got)
	}
}

func TestConfigMaxConnectionsPerPortCustom(t *testing.T) {
	t.Parallel()
	c := Config{MaxConnectionsPerPort: 11}
	if got := c.maxConnectionsPerPort(); got != 11 {
		t.Errorf("got %d", got)
	}
}

func TestConfigMaxTotalConnectionsDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.maxTotalConnections(); got != DefaultMaxTotalConnections {
		t.Errorf("got %d", got)
	}
}

func TestConfigMaxTotalConnectionsCustom(t *testing.T) {
	t.Parallel()
	c := Config{MaxTotalConnections: 5}
	if got := c.maxTotalConnections(); got != 5 {
		t.Errorf("got %d", got)
	}
}

func TestConfigTimeWaitDurationDefault(t *testing.T) {
	t.Parallel()
	c := Config{}
	if got := c.timeWaitDuration(); got != DefaultTimeWaitDuration {
		t.Errorf("got %v", got)
	}
}

func TestConfigTimeWaitDurationCustom(t *testing.T) {
	t.Parallel()
	c := Config{TimeWaitDuration: 33 * time.Second}
	if got := c.timeWaitDuration(); got != 33*time.Second {
		t.Errorf("got %v", got)
	}
}

// ---------------------------------------------------------------------------
// New() constructor — initializes all maps + subsystems
// ---------------------------------------------------------------------------

func TestNewInitsAllFields(t *testing.T) {
	t.Parallel()
	cfg := Config{SYNRateLimit: 17}
	d := New(cfg)
	if d == nil {
		t.Fatal("New returned nil")
	}
	if d.tunnels == nil {
		t.Error("tunnels nil")
	}
	if d.ports == nil {
		t.Error("ports nil")
	}
	if d.stopCh == nil {
		t.Error("stopCh nil")
	}
	if d.synTokens != 17 {
		t.Errorf("synTokens=%d, want 17 (matches synRateLimit())", d.synTokens)
	}
	if d.perSrcSYN == nil || d.epCache == nil || d.resolveCache == nil ||
		d.netPolicies == nil || d.managed == nil || d.memberTags == nil {
		t.Error("a map field is nil after New()")
	}
	if d.ipc == nil {
		t.Error("ipc nil — NewIPCServer skipped")
	}
	// stopCh open initially
	select {
	case <-d.stopCh:
		t.Error("stopCh already closed at construction")
	default:
	}
}

// ---------------------------------------------------------------------------
// allowSYN / allowSYNFromSource / reapPerSrcSYN
// ---------------------------------------------------------------------------

func TestAllowSYNAcceptsUntilExhausted(t *testing.T) {
	t.Parallel()
	d := New(Config{SYNRateLimit: 3})
	// 3 should pass (initial bucket = limit)
	for i := 0; i < 3; i++ {
		if !d.allowSYN() {
			t.Errorf("call %d: expected accept", i)
		}
	}
	// Next should deny (no time has passed for refill)
	if d.allowSYN() {
		t.Error("expected deny after bucket exhausted")
	}
}

func TestAllowSYNRefillsAfterTime(t *testing.T) {
	t.Parallel()
	d := New(Config{SYNRateLimit: 100})
	// drain
	for i := 0; i < 100; i++ {
		d.allowSYN()
	}
	if d.allowSYN() {
		t.Fatal("bucket should be empty")
	}
	// Force refill by rewinding lastFill
	d.synMu.Lock()
	d.synLastFill = time.Now().Add(-1 * time.Second)
	d.synMu.Unlock()
	if !d.allowSYN() {
		t.Error("expected accept after refill")
	}
}

func TestAllowSYNFromSourceFirstAcceptedThenLimited(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// First N up to perSourceSYNBurst must accept (initial = limit-1, plus the one consumed by initial creation = limit total)
	accepts := 0
	for i := 0; i < perSourceSYNBurst; i++ {
		if d.allowSYNFromSource(42) {
			accepts++
		}
	}
	if accepts != perSourceSYNBurst {
		t.Errorf("got %d accepts in first %d calls, want %d", accepts, perSourceSYNBurst, perSourceSYNBurst)
	}
	// Next must deny
	if d.allowSYNFromSource(42) {
		t.Error("expected deny after per-source bucket exhausted")
	}
}

func TestAllowSYNFromSourceCapAtMaxEntries(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// Fill the map to maxPerSrcSYNEntries
	d.perSrcSYNMu.Lock()
	for i := uint32(1); i <= maxPerSrcSYNEntries; i++ {
		d.perSrcSYN[i] = &srcSYNBucket{tokens: 1, lastFill: time.Now()}
	}
	d.perSrcSYNMu.Unlock()
	// New source must be rejected
	if d.allowSYNFromSource(0xCAFEBABE) {
		t.Error("expected reject when per-src map is full")
	}
}

func TestReapPerSrcSYNRemovesStale(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// Insert a fresh one and a stale one
	d.perSrcSYNMu.Lock()
	d.perSrcSYN[1] = &srcSYNBucket{tokens: 5, lastFill: time.Now()}
	d.perSrcSYN[2] = &srcSYNBucket{tokens: 5, lastFill: time.Now().Add(-2 * SYNBucketAge)}
	d.perSrcSYNMu.Unlock()
	d.reapPerSrcSYN()
	d.perSrcSYNMu.Lock()
	defer d.perSrcSYNMu.Unlock()
	if _, ok := d.perSrcSYN[1]; !ok {
		t.Error("fresh entry was reaped")
	}
	if _, ok := d.perSrcSYN[2]; ok {
		t.Error("stale entry not reaped")
	}
}

// ---------------------------------------------------------------------------
// stopping flag
// ---------------------------------------------------------------------------

func TestStoppingFalseInitiallyTrueAfterClose(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.stopping() {
		t.Error("stopping() should be false before close")
	}
	close(d.stopCh)
	if !d.stopping() {
		t.Error("stopping() should be true after close")
	}
}

// ---------------------------------------------------------------------------
// SetMemberTags / GetMemberTags
// ---------------------------------------------------------------------------

func TestSetGetMemberTagsRoundTrip(t *testing.T) {
	t.Parallel()
	d := &Daemon{memberTags: map[uint16][]string{}}
	if got := d.GetMemberTags(7); got != nil {
		t.Errorf("missing should be nil, got %v", got)
	}
	d.SetMemberTags(7, []string{"alpha", "beta"})
	got := d.GetMemberTags(7)
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Errorf("got %v, want [alpha beta]", got)
	}
	// Overwrite
	d.SetMemberTags(7, []string{"x"})
	if got := d.GetMemberTags(7); len(got) != 1 || got[0] != "x" {
		t.Errorf("overwrite: got %v", got)
	}
}

// ---------------------------------------------------------------------------
// StopPolicyRunner / stopPolicyRunners — nil-manager no-ops (interface path)
// ---------------------------------------------------------------------------

func TestStopPolicyRunnerNilManagerIsNoop(t *testing.T) {
	t.Parallel()
	d := &Daemon{} // policyManager is nil — must not panic
	d.StopPolicyRunner(99)
}

func TestStopPolicyRunnersNilManagerIsNoop(t *testing.T) {
	t.Parallel()
	d := &Daemon{} // policyManager is nil — must not panic
	d.stopPolicyRunners()
}

// ---------------------------------------------------------------------------
// Simple accessors: Identity / TunnelAddr / Addr / NodeID
// ---------------------------------------------------------------------------

func TestIdentityNilWhenUnset(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	if d.Identity() != nil {
		t.Error("expected nil identity")
	}
}

func TestTunnelAddrUnsetReturnsNil(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // tunnels created but not bound
	if got := d.TunnelAddr(); got != nil {
		t.Errorf("expected nil for unbound tunnel, got %v", got)
	}
}

func TestAddrUnsetReturnsZero(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	got := d.Addr()
	if got.Network != 0 || got.Node != 0 {
		t.Errorf("unset Addr should be zero, got %+v", got)
	}
}

func TestAddTunnelPeerStoresInTunnels(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
	d.AddTunnelPeer(99, addr)
	if !d.tunnels.HasPeer(99) {
		t.Error("peer not stored after AddTunnelPeer")
	}
}

// ---------------------------------------------------------------------------
// SetWebhookURL — set + replace + clear (using New() so tunnels/handshakes wired)
// ---------------------------------------------------------------------------

func TestSetWebhookURLNilManagerIsNoop(t *testing.T) {
	t.Parallel()
	// webhookManager not registered (nil) — SetWebhookURL must not panic.
	d := New(Config{})
	d.SetWebhookURL("http://127.0.0.1:65000/wh")
	d.SetWebhookURL("")
}

// ---------------------------------------------------------------------------
// addrFamilyMismatch — nil-tunnel-localaddr branch
// ---------------------------------------------------------------------------

func TestAddrFamilyMismatchNilLocalAddr(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // tunnels exist but unbound — LocalAddr() returns nil
	if d.addrFamilyMismatch("1.2.3.4:5") {
		t.Error("nil local addr should return false (no mismatch)")
	}
}

// ---------------------------------------------------------------------------
// collectLANAddrs — must not panic; returns slice (env-dependent)
// ---------------------------------------------------------------------------

func TestCollectLANAddrsNoPanic(t *testing.T) {
	t.Parallel()
	got := collectLANAddrs("4000")
	// Each entry must be host:port (4000 suffix)
	for _, addr := range got {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			t.Errorf("entry %q is not host:port: %v", addr, err)
			continue
		}
		if port != "4000" {
			t.Errorf("entry %q port=%s, want 4000", addr, port)
		}
	}
}

// ---------------------------------------------------------------------------
// evaluatePortPolicy — fallback to isPortAllowed when no policy runner
// ---------------------------------------------------------------------------

func TestEvaluatePortPolicyFallsBackToAllowlist(t *testing.T) {
	t.Parallel()
	d := &Daemon{
		netPolicies: map[uint16][]uint16{1: {80}},
		memberTags:  map[uint16][]string{},
	}
	// Allowed by allowlist
	if !d.evaluatePortPolicy("connect", 1, 80, 0, 0, "") {
		t.Error("port 80 should be allowed")
	}
	// Denied
	if d.evaluatePortPolicy("connect", 1, 81, 0, 0, "") {
		t.Error("port 81 should be denied (not in allowlist)")
	}
	// Unknown network — empty policy → all allowed
	if !d.evaluatePortPolicy("connect", 999, 80, 0, 0, "") {
		t.Error("unknown net should fall through to allow")
	}
}

// ---------------------------------------------------------------------------
// isPrivateAddr coverage of error paths (the public host case)
// ---------------------------------------------------------------------------

func TestIsPrivateAddrPublic(t *testing.T) {
	t.Parallel()
	if isPrivateAddr("8.8.8.8:53") {
		t.Error("public IP should not be marked private")
	}
}

func TestIsPrivateAddrBadHostPort(t *testing.T) {
	t.Parallel()
	if isPrivateAddr("not-host-port") {
		t.Error("malformed addr should return false")
	}
}

func TestIsPrivateAddrInvalidIP(t *testing.T) {
	t.Parallel()
	if isPrivateAddr("not-an-ip:80") {
		t.Error("non-IP host should return false")
	}
}

// Use the atomic import (silences unused if reorganized later).
var _ = atomic.LoadUint64
