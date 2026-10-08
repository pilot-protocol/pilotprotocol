// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	registrywire "github.com/pilot-protocol/common/registry/wire"
)

// This file targets ~32% of pkg/daemon statements that were uncovered at
// the time of writing (baseline 68.2% under -short). It focuses on:
//   - Public/private accessors that delegate to internal state or sub-mgrs
//   - Validation/error paths that take inputs and return errors
//   - Pure helpers (beacon merge, cache reaping, simple state machines)
//   - IPC dispatch paths reachable without a real socket
//
// Goroutine-driven loops (idleSweepLoop, relayProbeLoop, networkSyncLoop,
// trustRepublishLoop, beaconRefreshLoop's happy path, pollRelayedHandshakes,
// loadPolicyRunners, RotateKey's happy path) need a live registry + tunnels;
// those are exercised by the `./tests/` integration suite (now nightly) and
// intentionally not duplicated here.

// ---------------------------------------------------------------------------
// Trivial accessors (Ports / Bus / Tunnels / AdminToken / IdentityPath / ...)
// ---------------------------------------------------------------------------

func TestPortsAccessorReturnsManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.Ports() == nil {
		t.Fatalf("Ports() returned nil; New() should wire a PortManager")
	}
	if d.Ports() != d.ports {
		t.Fatalf("Ports() should return the same instance as d.ports")
	}
}

func TestBusAccessorReturnsBus(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.Bus() == nil {
		t.Fatalf("Bus() returned nil; New() should wire an inProcessBus")
	}
	if d.Bus() != d.bus {
		t.Fatalf("Bus() should return the same instance as d.bus")
	}
}

func TestTunnelsAccessorReturnsManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.Tunnels() == nil {
		t.Fatalf("Tunnels() returned nil; New() should wire a TunnelManager")
	}
	if d.Tunnels() != d.tunnels {
		t.Fatalf("Tunnels() should return the same instance as d.tunnels")
	}
}

func TestAdminTokenReturnsConfigValue(t *testing.T) {
	t.Parallel()
	d := New(Config{AdminToken: "super-secret"})
	if got := d.AdminToken(); got != "super-secret" {
		t.Fatalf("AdminToken = %q, want super-secret", got)
	}
}

func TestAdminTokenEmptyByDefault(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if got := d.AdminToken(); got != "" {
		t.Fatalf("AdminToken default = %q, want empty", got)
	}
}

func TestIdentityPathReturnsConfigValue(t *testing.T) {
	t.Parallel()
	d := New(Config{IdentityPath: "/tmp/id.json"})
	if got := d.IdentityPath(); got != "/tmp/id.json" {
		t.Fatalf("IdentityPath = %q", got)
	}
}

func TestTrustAutoApproveReturnsFlag(t *testing.T) {
	t.Parallel()
	d := New(Config{TrustAutoApprove: true})
	if !d.TrustAutoApprove() {
		t.Fatal("TrustAutoApprove flag not surfaced")
	}
	d2 := New(Config{TrustAutoApprove: false})
	if d2.TrustAutoApprove() {
		t.Fatal("TrustAutoApprove should be false")
	}
}

func TestRegistryClientNilWhenUnset(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.RegistryClient() != nil {
		t.Fatal("RegistryClient should be nil for fresh daemon without regConn")
	}
}

// ---------------------------------------------------------------------------
// Plugin-handle wiring: TrustChecker / HandshakeService / PolicyManager /
// WebhookManager. Verify registers, accessor results, and the nil-safe
// guards around methods that delegate.
// ---------------------------------------------------------------------------

type covFakeTrustChecker struct {
	trusted map[uint32]string
}

func (f *covFakeTrustChecker) IsTrusted(nodeID uint32) (string, bool) {
	v, ok := f.trusted[nodeID]
	return v, ok
}

func TestGetTrustCheckerNilByDefault(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.GetTrustChecker() != nil {
		t.Fatal("GetTrustChecker should be nil before registration")
	}
}

func TestRegisterTrustCheckerStoresAndAccessorReturns(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	tc := &covFakeTrustChecker{trusted: map[uint32]string{7: "alice"}}
	d.RegisterTrustChecker(tc)
	got := d.GetTrustChecker()
	if got == nil {
		t.Fatal("trust checker not stored")
	}
	name, ok := got.IsTrusted(7)
	if !ok || name != "alice" {
		t.Fatalf("got (%q,%v), want (alice,true)", name, ok)
	}
}

func TestHandshakeServiceAccessor(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.HandshakeService() != nil {
		t.Fatal("HandshakeService should be nil before registration")
	}
	fs := &fakeHandshakeService{}
	d.RegisterHandshakeService(fs)
	if d.HandshakeService() != fs {
		t.Fatal("HandshakeService accessor should return registered svc")
	}
}

func TestTrustedPeersNilSafeWhenNoService(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if got := d.TrustedPeers(); got != nil {
		t.Fatalf("TrustedPeers with nil handshake = %v, want nil", got)
	}
}

func TestTrustedPeersDelegatesToService(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := &fakeHandshakeService{
		trustedRecs: []HandshakeTrustRecord{{NodeID: 1}, {NodeID: 2}},
	}
	d.RegisterHandshakeService(fs)
	got := d.TrustedPeers()
	if len(got) != 2 {
		t.Fatalf("TrustedPeers len = %d, want 2", len(got))
	}
}

func TestHandshakeRevokeTrustNilServiceReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.HandshakeRevokeTrust(1); err == nil {
		t.Fatal("expected error when handshake service not registered")
	}
}

func TestHandshakeRevokeTrustDelegates(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := &fakeHandshakeService{trustedRecs: []HandshakeTrustRecord{{NodeID: 5}}}
	d.RegisterHandshakeService(fs)
	if err := d.HandshakeRevokeTrust(5); err != nil {
		t.Fatalf("HandshakeRevokeTrust: %v", err)
	}
	if len(fs.TrustedPeers()) != 0 {
		t.Fatalf("expected fake to drop trusted entry; got %v", fs.TrustedPeers())
	}
}

func TestHandshakeSendRequestNilServiceReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.HandshakeSendRequest(1, "hi"); err == nil {
		t.Fatal("expected error when handshake service not registered")
	}
}

func TestHandshakeSendRequestDelegates(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	fs := &fakeHandshakeService{}
	d.RegisterHandshakeService(fs)
	if err := d.HandshakeSendRequest(42, "please"); err != nil {
		t.Fatalf("HandshakeSendRequest: %v", err)
	}
}

func TestHandshakePendingCountNilSafe(t *testing.T) {
	t.Parallel()
	if got := handshakePendingCount(nil); got != 0 {
		t.Fatalf("nil service pending count = %d, want 0", got)
	}
	fs := &fakeHandshakeService{
		pendingRecs: []HandshakePendingRecord{{NodeID: 1}, {NodeID: 2}},
	}
	if got := handshakePendingCount(fs); got != 2 {
		t.Fatalf("got %d pending, want 2", got)
	}
}

// ---------------------------------------------------------------------------
// PolicyManager wiring: RegisterPolicyManager + StartPolicyRunner without
// a manager, evaluatePortPolicy delegation paths.
// ---------------------------------------------------------------------------

type covFakePolicyRunner struct {
	netID     uint16
	members   map[uint32]bool
	allowPort uint16
}

func (f *covFakePolicyRunner) NetworkID() uint16       { return f.netID }
func (f *covFakePolicyRunner) HasMember(n uint32) bool { return f.members[n] }
func (f *covFakePolicyRunner) EvaluatePortGate(_ string, port uint16, _ uint32, _ int, _ string, _, _ []string) bool {
	return port == f.allowPort
}
func (f *covFakePolicyRunner) EvaluateActions(string, map[string]any) {}
func (f *covFakePolicyRunner) Status() map[string]any                 { return map[string]any{"id": f.netID} }
func (f *covFakePolicyRunner) PeerList() []map[string]interface{}     { return nil }
func (f *covFakePolicyRunner) ForceCycle() map[string]any             { return map[string]any{"ok": true} }
func (f *covFakePolicyRunner) ReconcileNow()                          {}
func (f *covFakePolicyRunner) PolicyJSON() ([]byte, error)            { return []byte(`{}`), nil }
func (f *covFakePolicyRunner) Stop()                                  {}

type covFakePolicyManager struct {
	runners map[uint16]PolicyRunner
}

func (f *covFakePolicyManager) Start(netID uint16, _ []byte) (PolicyRunner, error) {
	r := &covFakePolicyRunner{netID: netID, allowPort: 80}
	if f.runners == nil {
		f.runners = make(map[uint16]PolicyRunner)
	}
	f.runners[netID] = r
	return r, nil
}
func (f *covFakePolicyManager) Stop(netID uint16) { delete(f.runners, netID) }
func (f *covFakePolicyManager) Get(netID uint16) PolicyRunner {
	if r, ok := f.runners[netID]; ok {
		return r
	}
	return nil
}
func (f *covFakePolicyManager) All() []PolicyRunner {
	out := make([]PolicyRunner, 0, len(f.runners))
	for _, r := range f.runners {
		out = append(out, r)
	}
	return out
}
func (f *covFakePolicyManager) StopAll()             { f.runners = nil }
func (f *covFakePolicyManager) LoadPersisted() error { return nil }

func TestRegisterPolicyManagerWires(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if d.GetPolicyRunner(1) != nil {
		t.Fatal("expected nil runner before manager registered")
	}
	pm := &covFakePolicyManager{}
	d.RegisterPolicyManager(pm)
	if _, err := pm.Start(7, nil); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if d.GetPolicyRunner(7) == nil {
		t.Fatal("expected runner after register+seed")
	}
}

func TestStartPolicyRunnerNoManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if err := d.StartPolicyRunner(1, []byte(`{}`)); err == nil {
		t.Fatal("expected error when no manager registered")
	}
}

func TestStartPolicyRunnerDelegates(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	pm := &covFakePolicyManager{}
	d.RegisterPolicyManager(pm)
	if err := d.StartPolicyRunner(9, []byte(`{}`)); err != nil {
		t.Fatalf("StartPolicyRunner: %v", err)
	}
	if d.GetPolicyRunner(9) == nil {
		t.Fatal("expected runner after Start")
	}
}

func TestStopPolicyRunnerNoManagerNoPanic(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.StopPolicyRunner(1) // must not panic
}

func TestStopPolicyRunnerDelegates(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	pm := &covFakePolicyManager{}
	d.RegisterPolicyManager(pm)
	_, _ = pm.Start(3, nil)
	d.StopPolicyRunner(3)
	if d.GetPolicyRunner(3) != nil {
		t.Fatal("runner should be gone after Stop")
	}
}

func TestStopPolicyRunnersNoManagerNoPanic(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.stopPolicyRunners() // no manager — must no-op
}

func TestStopPolicyRunnersDelegatesToManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	pm := &covFakePolicyManager{}
	d.RegisterPolicyManager(pm)
	_, _ = pm.Start(1, nil)
	_, _ = pm.Start(2, nil)
	d.stopPolicyRunners()
	if len(pm.All()) != 0 {
		t.Fatalf("expected StopAll to clear runners; got %d", len(pm.All()))
	}
}

// evaluatePortPolicy through a policy manager: primary runner allows + cross.

func TestEvaluatePortPolicyPrimaryRunnerAllows(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	pm := &covFakePolicyManager{runners: map[uint16]PolicyRunner{
		1: &covFakePolicyRunner{netID: 1, allowPort: 80},
	}}
	d.RegisterPolicyManager(pm)
	if !d.evaluatePortPolicy("connect", 1, 80, 99, 0, "in") {
		t.Fatal("port 80 on net 1 should be allowed by primary runner")
	}
	if d.evaluatePortPolicy("connect", 1, 9999, 99, 0, "in") {
		t.Fatal("port 9999 on net 1 should be denied by primary runner")
	}
}

func TestEvaluatePortPolicyCrossNetworkRunnerConsulted(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	other := &covFakePolicyRunner{netID: 7, allowPort: 80, members: map[uint32]bool{42: true}}
	pm := &covFakePolicyManager{runners: map[uint16]PolicyRunner{7: other}}
	d.RegisterPolicyManager(pm)
	// Packet arrives on network 0 (no primary), but peer 42 is a member of net 7.
	// The cross-network runner is consulted and denies port 81.
	if d.evaluatePortPolicy("connect", 0, 81, 42, 0, "in") {
		t.Fatal("cross-network runner should deny port 81")
	}
	if !d.evaluatePortPolicy("connect", 0, 80, 42, 0, "in") {
		t.Fatal("cross-network runner should allow port 80")
	}
}

// ---------------------------------------------------------------------------
// nodeInfoTagsFor: tag extraction from resolveCache
// ---------------------------------------------------------------------------

func TestNodeInfoTagsForEmptyWhenNoCache(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if got := d.nodeInfoTagsFor(42); got != nil {
		t.Fatalf("nodeInfoTagsFor with no cache = %v, want nil", got)
	}
}

func TestNodeInfoTagsForExtractsStrings(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"svc", "prod"},
	})
	got := d.nodeInfoTagsFor(42)
	if !reflect.DeepEqual(got, []string{"svc", "prod"}) {
		t.Fatalf("got %v, want [svc prod]", got)
	}
}

func TestNodeInfoTagsForSkipsNonStrings(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheResolve(42, map[string]interface{}{
		"tags": []interface{}{"svc", 42, nil, "prod"},
	})
	got := d.nodeInfoTagsFor(42)
	if !reflect.DeepEqual(got, []string{"svc", "prod"}) {
		t.Fatalf("got %v, want [svc prod]", got)
	}
}

func TestNodeInfoTagsForNoTagsKey(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.cacheResolve(42, map[string]interface{}{"endpoint": "1.2.3.4:5"})
	if got := d.nodeInfoTagsFor(42); got != nil {
		t.Fatalf("got %v, want nil (no tags key)", got)
	}
}

// ---------------------------------------------------------------------------
// Beacon shim functions (mergeBeaconLists, isUnreachableBeaconHost,
// beaconCachePath, newBeaconSelectionState, computeRefreshDecision,
// initialJitter, save/loadBeaconCache).
// ---------------------------------------------------------------------------

func TestMergeBeaconListsCombinesAndDedups(t *testing.T) {
	t.Parallel()
	got := mergeBeaconLists([]string{"a:1", "b:2"}, []string{"b:2", "c:3"})
	if len(got) == 0 {
		t.Fatal("merge returned empty")
	}
	seen := map[string]bool{}
	for _, x := range got {
		seen[x] = true
	}
	for _, want := range []string{"a:1", "b:2", "c:3"} {
		if !seen[want] {
			t.Fatalf("merged list missing %q (got %v)", want, got)
		}
	}
}

func TestMergeBeaconListsNilBootstrapStillWorks(t *testing.T) {
	t.Parallel()
	got := mergeBeaconLists(nil, []string{"x:1"})
	if len(got) != 1 || got[0] != "x:1" {
		t.Fatalf("got %v, want [x:1]", got)
	}
}

func TestIsUnreachableBeaconHostPrivate(t *testing.T) {
	t.Parallel()
	if !isUnreachableBeaconHost("10.0.0.1") {
		t.Fatal("10.0.0.1 should be unreachable (private)")
	}
	if !isUnreachableBeaconHost("127.0.0.1") {
		t.Fatal("loopback should be unreachable")
	}
}

func TestIsUnreachableBeaconHostPublic(t *testing.T) {
	t.Parallel()
	if isUnreachableBeaconHost("8.8.8.8") {
		t.Fatal("8.8.8.8 should be reachable")
	}
	if isUnreachableBeaconHost("beacon.example.com") {
		t.Fatal("hostname should be treated as reachable")
	}
}

func TestBeaconCachePathEmptyIdentityReturnsEmpty(t *testing.T) {
	t.Parallel()
	if got := beaconCachePath(""); got != "" {
		t.Fatalf("beaconCachePath('') = %q, want empty", got)
	}
}

func TestBeaconCachePathWithIdentity(t *testing.T) {
	t.Parallel()
	got := beaconCachePath("/var/pilot/identity.json")
	if got == "" {
		t.Fatal("beaconCachePath with identity returned empty")
	}
	if filepath.Dir(got) != "/var/pilot" {
		t.Fatalf("beaconCachePath dir = %q, want /var/pilot", filepath.Dir(got))
	}
}

func TestNewBeaconSelectionStateNotNil(t *testing.T) {
	t.Parallel()
	s := newBeaconSelectionState([]string{"a:1", "b:2"})
	if s == nil {
		t.Fatal("newBeaconSelectionState returned nil")
	}
}

func TestInitialJitterBounded(t *testing.T) {
	t.Parallel()
	for i := 0; i < 20; i++ {
		j := initialJitter()
		if j < 0 {
			t.Fatalf("initialJitter = %v, must be non-negative", j)
		}
		if j > beaconRefreshJitter {
			t.Fatalf("initialJitter = %v, exceeds beaconRefreshJitter=%v", j, beaconRefreshJitter)
		}
	}
}

func TestSaveLoadBeaconCacheRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	want := []string{"a:1", "b:2"}
	if err := saveBeaconCache(idPath, want); err != nil {
		t.Fatalf("saveBeaconCache: %v", err)
	}
	got, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("loadBeaconCache: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip = %v, want %v", got, want)
	}
}

func TestLoadBeaconCacheMissingFileReturnsNoError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "no-such-identity.json")
	// routing.LoadBeaconCache returns (nil, nil) on missing file — daemon
	// callers treat that as "no cache, fine to skip", not as an error.
	got, err := loadBeaconCache(idPath)
	if err != nil {
		t.Fatalf("missing file should NOT error; got %v", err)
	}
	if got != nil {
		t.Fatalf("missing file should return nil slice; got %v", got)
	}
}

func TestComputeRefreshDecisionBootstrapOnly(t *testing.T) {
	t.Parallel()
	s := newBeaconSelectionState([]string{"a:1"})
	d := computeRefreshDecision(s, nil, []byte("key"))
	// With no discovered list and empty bootstrap merge, decision is
	// safe (we don't crash). NewPick may be empty or the bootstrap entry.
	_ = d
}

// ---------------------------------------------------------------------------
// probeBeaconsParallel: empty list returns empty map without panicking
// ---------------------------------------------------------------------------

func TestProbeBeaconsParallelEmptyList(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	got := d.probeBeaconsParallel(nil, 50*time.Millisecond)
	if len(got) != 0 {
		t.Fatalf("nil list -> %v, want empty map", got)
	}
}

// ---------------------------------------------------------------------------
// beaconRefreshTick: nil regConn early return — exercises the typed-nil
// guard documented in the comment.
// ---------------------------------------------------------------------------

func TestBeaconRefreshTickNilRegConnEarlyReturn(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// d.regConn is nil. First tick should log + return, not panic.
	d.beaconRefreshTick(true)
	d.beaconRefreshTick(false)
}

// beaconRefreshLoop: with no beaconSelection, regConn, or identity, the
// loop exits cleanly without ever scheduling work.
func TestBeaconRefreshLoopEarlyExitWithoutDeps(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	done := make(chan struct{})
	go func() {
		d.beaconRefreshLoop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("beaconRefreshLoop did not exit on missing deps")
	}
}

// ---------------------------------------------------------------------------
// Cache reaping: reapCaches evicts expired entries from epCache/resolveCache/
// hostnameCache.
// ---------------------------------------------------------------------------

func TestReapCachesEvictsExpiredEntries(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	now := time.Now()

	d.epCacheMu.Lock()
	d.epCache[1] = &endpointEntry{addr: "fresh", cachedAt: now}
	d.epCache[2] = &endpointEntry{addr: "stale", cachedAt: now.Add(-100 * time.Hour)}
	d.epCacheMu.Unlock()

	d.resolveCacheMu.Lock()
	d.resolveCache[1] = &resolveEntry{resp: map[string]interface{}{}, cachedAt: now}
	d.resolveCache[2] = &resolveEntry{resp: map[string]interface{}{}, cachedAt: now.Add(-100 * time.Hour)}
	d.resolveCacheMu.Unlock()

	d.hostnameCacheMu.Lock()
	d.hostnameCache["fresh"] = &hostnameCacheEntry{resp: map[string]interface{}{}, cachedAt: now}
	d.hostnameCache["stale"] = &hostnameCacheEntry{resp: map[string]interface{}{}, cachedAt: now.Add(-100 * time.Hour)}
	d.hostnameCacheMu.Unlock()

	d.reapCaches()

	d.epCacheMu.RLock()
	if _, ok := d.epCache[1]; !ok {
		t.Error("fresh epCache entry was evicted")
	}
	if _, ok := d.epCache[2]; ok {
		t.Error("stale epCache entry not evicted")
	}
	d.epCacheMu.RUnlock()

	d.resolveCacheMu.RLock()
	if _, ok := d.resolveCache[1]; !ok {
		t.Error("fresh resolveCache entry was evicted")
	}
	if _, ok := d.resolveCache[2]; ok {
		t.Error("stale resolveCache entry not evicted")
	}
	d.resolveCacheMu.RUnlock()

	d.hostnameCacheMu.RLock()
	if _, ok := d.hostnameCache["fresh"]; !ok {
		t.Error("fresh hostnameCache entry was evicted")
	}
	if _, ok := d.hostnameCache["stale"]; ok {
		t.Error("stale hostnameCache entry not evicted")
	}
	d.hostnameCacheMu.RUnlock()
}

// ---------------------------------------------------------------------------
// hostnameCache disk persistence: persistHostnameCache + loadHostnameCache
// round trip.
// ---------------------------------------------------------------------------

func TestPersistAndLoadHostnameCacheRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	d := New(Config{IdentityPath: idPath})
	now := time.Now()

	d.hostnameCacheMu.Lock()
	d.hostnameCache["alice"] = &hostnameCacheEntry{
		resp:     map[string]interface{}{"node_id": float64(1)},
		cachedAt: now,
	}
	d.hostnameCacheMu.Unlock()

	d.persistHostnameCache()

	path := filepath.Join(dir, "hostname_cache.json")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected hostname_cache.json on disk: %v", err)
	}

	d2 := New(Config{IdentityPath: idPath})
	d2.loadHostnameCache()
	d2.hostnameCacheMu.RLock()
	defer d2.hostnameCacheMu.RUnlock()
	e, ok := d2.hostnameCache["alice"]
	if !ok {
		t.Fatal("alice entry not restored")
	}
	if e.resp["node_id"] != float64(1) {
		t.Fatalf("node_id = %v, want 1", e.resp["node_id"])
	}
}

func TestPersistHostnameCacheNoIdentityNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // IdentityPath == ""
	d.persistHostnameCache()
	d.loadHostnameCache()
}

func TestLoadHostnameCacheMissingFileNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	d := New(Config{IdentityPath: idPath})
	d.loadHostnameCache()
	d.hostnameCacheMu.RLock()
	defer d.hostnameCacheMu.RUnlock()
	if len(d.hostnameCache) != 0 {
		t.Fatalf("expected empty cache; got %d entries", len(d.hostnameCache))
	}
}

func TestLoadHostnameCacheCorruptFileIgnored(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")
	d := New(Config{IdentityPath: idPath})
	path := filepath.Join(dir, "hostname_cache.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt file: %v", err)
	}
	d.loadHostnameCache() // must not panic
}

func TestLoadHostnameCacheDropsExpiredEntries(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	idPath := filepath.Join(dir, "identity.json")

	snap := hostnameCacheDisk{
		SavedAt: time.Now(),
		Hostnames: map[string]hostnameCacheDiskEntry{
			"fresh": {Resp: map[string]interface{}{}, CachedAt: time.Now()},
			"stale": {Resp: map[string]interface{}{}, CachedAt: time.Now().Add(-100 * time.Hour)},
		},
	}
	data, _ := json.Marshal(snap)
	if err := os.WriteFile(filepath.Join(dir, "hostname_cache.json"), data, 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	d := New(Config{IdentityPath: idPath})
	d.loadHostnameCache()
	d.hostnameCacheMu.RLock()
	defer d.hostnameCacheMu.RUnlock()
	if _, ok := d.hostnameCache["fresh"]; !ok {
		t.Error("fresh entry was not loaded")
	}
	if _, ok := d.hostnameCache["stale"]; ok {
		t.Error("stale entry should have been dropped at load time")
	}
}

func TestHostnameCachePathEmptyWithoutIdentity(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if got := d.hostnameCachePath(); got != "" {
		t.Fatalf("hostnameCachePath = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// unackedHasData: helper for FinWait state machine
// ---------------------------------------------------------------------------

func TestUnackedHasDataEmpty(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	conn := &Connection{}
	if d.unackedHasData(conn) {
		t.Fatal("empty Unacked should report no data")
	}
}

func TestUnackedHasDataOnlyFINReturnsFalse(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	conn := &Connection{}
	conn.Unacked = []*retxEntry{{seq: 1, isFIN: true}}
	if d.unackedHasData(conn) {
		t.Fatal("FIN-only Unacked should report no data")
	}
}

// SACKed data is not acknowledged: the receiver may hold it without
// delivering it, so FinWait keeps retransmitting until it is.
func TestUnackedHasDataOnlySackedReturnsTrue(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	conn := &Connection{}
	conn.Unacked = []*retxEntry{{seq: 1, sacked: true}, {seq: 2, sacked: true}}
	if !d.unackedHasData(conn) {
		t.Fatal("all-sacked Unacked still holds data that is not cumulatively acknowledged")
	}
}

func TestUnackedHasDataMixedReturnsTrue(t *testing.T) {
	t.Parallel()
	d := &Daemon{}
	conn := &Connection{}
	conn.Unacked = []*retxEntry{
		{seq: 1, sacked: true},
		{seq: 2}, // real data
		{seq: 3, isFIN: true},
	}
	if !d.unackedHasData(conn) {
		t.Fatal("mixed Unacked with real DATA should report true")
	}
}

// ---------------------------------------------------------------------------
// networkIDFromBusPayload: type coercion across uint16/int/int64/float64
// ---------------------------------------------------------------------------

func TestNetworkIDFromBusPayloadVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   any
		want uint16
		ok   bool
	}{
		{"uint16", uint16(7), 7, true},
		{"int", int(8), 8, true},
		{"int64", int64(9), 9, true},
		{"float64", float64(10), 10, true},
		{"string-rejected", "11", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := map[string]any{"network_id": tc.in}
			got, ok := networkIDFromBusPayload(p)
			if ok != tc.ok || got != tc.want {
				t.Fatalf("got (%d,%v), want (%d,%v)", got, ok, tc.want, tc.ok)
			}
		})
	}
}

func TestNetworkIDFromBusPayloadMissingKey(t *testing.T) {
	t.Parallel()
	got, ok := networkIDFromBusPayload(map[string]any{})
	if ok || got != 0 {
		t.Fatalf("missing key should return (0,false); got (%d,%v)", got, ok)
	}
}

func TestNetworkIDFromBusPayloadNilMap(t *testing.T) {
	t.Parallel()
	if got, ok := networkIDFromBusPayload(nil); ok || got != 0 {
		t.Fatalf("nil map should return (0,false), got (%d,%v)", got, ok)
	}
}

// ---------------------------------------------------------------------------
// handleNetworkJoinedInternal / handleNetworkLeftInternal
// ---------------------------------------------------------------------------

func TestHandleNetworkJoinedInternalSkipsWhenAlreadyRunning(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.managedMu.Lock()
	d.managed[42] = &ManagedEngine{netID: 42, peers: map[uint32]*managedPeer{}}
	d.managedMu.Unlock()

	d.handleNetworkJoinedInternal(map[string]any{
		"network_id": uint16(42),
		"rules":      map[string]any{"cycle": "10s"},
	})

	d.managedMu.Lock()
	defer d.managedMu.Unlock()
	if _, ok := d.managed[42]; !ok {
		t.Fatal("existing managed engine should not be removed")
	}
}

func TestHandleNetworkJoinedInternalMissingRulesIsNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.handleNetworkJoinedInternal(map[string]any{"network_id": uint16(1)})
	d.managedMu.Lock()
	defer d.managedMu.Unlock()
	if len(d.managed) != 0 {
		t.Fatalf("managed = %d, want 0", len(d.managed))
	}
}

func TestHandleNetworkJoinedInternalBadNetworkIDIsNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.handleNetworkJoinedInternal(map[string]any{
		"network_id": "not-an-id",
		"rules":      map[string]any{"cycle": "10s"},
	})
	d.managedMu.Lock()
	defer d.managedMu.Unlock()
	if len(d.managed) != 0 {
		t.Fatal("malformed network_id should not start an engine")
	}
}

func TestHandleNetworkLeftInternalNoEngineNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.handleNetworkLeftInternal(map[string]any{"network_id": uint16(99)})
}

func TestHandleNetworkLeftInternalBadPayloadIsNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.handleNetworkLeftInternal(map[string]any{})
}

// ---------------------------------------------------------------------------
// subscribeNetworkInternalToBus: idempotent + nil bus is no-op
// ---------------------------------------------------------------------------

func TestSubscribeNetworkInternalToBusNilBus(t *testing.T) {
	t.Parallel()
	d := &Daemon{} // bus is nil
	d.subscribeNetworkInternalToBus()
	if d.netSubStop != nil {
		t.Fatal("nil bus path should not install a subscription")
	}
}

func TestSubscribeNetworkInternalToBusIdempotent(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.subscribeNetworkInternalToBus()
	first := d.netSubStop
	if first == nil {
		t.Fatal("expected subscription after first call")
	}
	d.subscribeNetworkInternalToBus() // second call should replace
	if d.netSubStop == nil {
		t.Fatal("expected new subscription after second call")
	}
	d.netSubStop()
}

// ---------------------------------------------------------------------------
// publishEvent / PublishEvent / publishEventInternal: nil-safe + delivery
// ---------------------------------------------------------------------------

func TestPublishEventNilDaemonNoPanic(t *testing.T) {
	t.Parallel()
	var d *Daemon
	d.publishEvent("topic", map[string]any{"k": "v"})
}

func TestPublishEventDeliversToSubscriber(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	ch, cancel := d.bus.Subscribe("foo.*")
	defer cancel()
	d.PublishEvent("foo.bar", map[string]any{"k": "v"})
	select {
	case ev := <-ch:
		if ev.Topic != "foo.bar" {
			t.Fatalf("topic = %q, want foo.bar", ev.Topic)
		}
		if ev.Payload["k"] != "v" {
			t.Fatalf("payload = %v", ev.Payload)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("event not delivered")
	}
}

func TestPublishEventInternalReaches(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	ch, cancel := d.bus.Subscribe("*")
	defer cancel()
	d.publishEventInternal("internal.topic", map[string]any{})
	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("internal publish never reached subscriber")
	}
}

// ---------------------------------------------------------------------------
// WebhookManager wiring + nil-safe webhookStats
// ---------------------------------------------------------------------------

type covFakeWebhookManager struct {
	urls []string
	mu   sync.Mutex
	st   WebhookStats
}

func (f *covFakeWebhookManager) SetURL(u string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.urls = append(f.urls, u)
}
func (f *covFakeWebhookManager) Stats() WebhookStats { return f.st }

func TestSetWebhookURLNoManagerNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.SetWebhookURL("https://example.com") // must not panic
}

func TestSetWebhookURLDelegatesToManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	wm := &covFakeWebhookManager{}
	d.RegisterWebhookManager(wm)
	d.SetWebhookURL("https://example.com/hook")
	if len(wm.urls) != 1 || wm.urls[0] != "https://example.com/hook" {
		t.Fatalf("urls = %v", wm.urls)
	}
}

func TestWebhookStatsNoManagerReturnsZero(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if got := d.webhookStats(); got != (WebhookStats{}) {
		t.Fatalf("expected zero WebhookStats, got %+v", got)
	}
}

func TestWebhookStatsDelegatesToManager(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	wm := &covFakeWebhookManager{st: WebhookStats{Dropped: 7, CircuitSkips: 3}}
	d.RegisterWebhookManager(wm)
	got := d.webhookStats()
	if got.Dropped != 7 || got.CircuitSkips != 3 {
		t.Fatalf("got %+v, want {7,3}", got)
	}
}

// ---------------------------------------------------------------------------
// RotateKey error paths (no identity). Happy path needs a real registry and
// is exercised by `./tests/`.
// ---------------------------------------------------------------------------

func TestRotateKeyNoIdentityReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if _, err := d.RotateKey(); err == nil {
		t.Fatal("expected error when identity is nil")
	}
}

// ---------------------------------------------------------------------------
// buildCompatTLSConfig: trust value parsing
// ---------------------------------------------------------------------------

func TestBuildCompatTLSConfigDefaultPinned(t *testing.T) {
	t.Parallel()
	cfg, err := buildCompatTLSConfig("")
	if err != nil {
		// Production builds skip dev-* roots (compat.skipDevPems=true).
		// Until a production root cert is minted and embedded, the pool
		// is empty and PinnedRoots returns "no embedded Pilot Protocol
		// roots found". Skip rather than fail — matches the guard the
		// authoring PR adds to compat.TestPinnedRoots_LoadsEmbeddedRoots.
		if strings.Contains(err.Error(), "no embedded") {
			t.Skipf("no production roots embedded yet: %v", err)
		}
		t.Fatalf("buildCompatTLSConfig(''): %v", err)
	}
	if cfg == nil || cfg.RootCAs == nil {
		t.Fatal("expected pinned root pool")
	}
}

func TestBuildCompatTLSConfigPinnedExplicit(t *testing.T) {
	t.Parallel()
	cfg, err := buildCompatTLSConfig("pinned")
	if err != nil {
		// See TestBuildCompatTLSConfigDefaultPinned above for rationale.
		if strings.Contains(err.Error(), "no embedded") {
			t.Skipf("no production roots embedded yet: %v", err)
		}
		t.Fatalf("buildCompatTLSConfig('pinned'): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
}

func TestBuildCompatTLSConfigSystem(t *testing.T) {
	t.Parallel()
	cfg, err := buildCompatTLSConfig("system")
	if err != nil {
		t.Fatalf("buildCompatTLSConfig('system'): %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.RootCAs != nil {
		t.Fatal("system mode should not pin RootCAs")
	}
}

func TestBuildCompatTLSConfigInvalidRejected(t *testing.T) {
	t.Parallel()
	if _, err := buildCompatTLSConfig("nonsense"); err == nil {
		t.Fatal("expected error for invalid trust value")
	}
}

// ---------------------------------------------------------------------------
// NewConnReadWriter and connAdapter behavior
// ---------------------------------------------------------------------------

func TestNewConnReadWriterWrapsConnection(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	c := &Connection{
		ID:      1,
		RecvBuf: make(chan []byte, 4),
	}
	rw := d.NewConnReadWriter(c)
	if rw == nil {
		t.Fatal("NewConnReadWriter returned nil")
	}
	if _, ok := rw.(ConnReadWriter); !ok {
		t.Fatal("returned value does not satisfy ConnReadWriter")
	}
}

// ---------------------------------------------------------------------------
// Tunnel accessors: SetEventBus, DropCrypto on unknown peer (no panic),
// SetRelayPeerPinned, recordOutboundSend, replaySalvage nil guards.
// ---------------------------------------------------------------------------

func TestSetEventBusAssigns(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	bus := newInProcessBus(func() uint32 { return 1 })
	tm.SetEventBus(bus)
	if tm.bus != bus {
		t.Fatal("SetEventBus did not assign")
	}
	ch, cancel := bus.Subscribe("test.*")
	defer cancel()
	tm.publishEvent("test.x", map[string]any{})
	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("event not received via SetEventBus")
	}
}

func TestPublishEventNilBusNoPanic(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager() // tm.bus is nil
	tm.publishEvent("ignored", map[string]any{})
}

func TestDropCryptoUnknownPeerNoPanic(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.DropCrypto(99999) // no peer; must not panic
}

func TestSetRelayPeerPinnedAssigns(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.SetRelayPeerPinned(42, true)
	if !tm.routing.IsRelayPeer(42) {
		t.Fatal("SetRelayPeerPinned(true) did not set relay flag")
	}
}

func TestRecordOutboundSendStamps(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.recordOutboundSend(7)
	last, ok := tm.routing.LastOutboundSend(7)
	if !ok {
		t.Fatal("recordOutboundSend did not stamp")
	}
	if time.Since(last) > time.Second {
		t.Fatalf("stamp too old: %v", time.Since(last))
	}
}

func TestSendDirectProbeNoPeer(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SendDirectProbe(404, nil); err == nil {
		t.Fatal("expected error when peer endpoint not stored")
	}
}

// replaySalvage: nil guards must short-circuit safely.
func TestReplaySalvageNilGuards(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	tm.replaySalvage(nil, nil, 1, nil) // all-nil path
}

// isICMPUnreachable: a plain error should not match the syscall sentinels.
// The matching path is exercised exhaustively in routing/ tests.
func TestIsICMPUnreachableNilReturnsFalse(t *testing.T) {
	t.Parallel()
	if isICMPUnreachable(nil) {
		t.Fatal("nil err should not match")
	}
}

type covSimpleErr struct{ s string }

func (e *covSimpleErr) Error() string { return e.s }

func TestIsICMPUnreachableUnrelatedReturnsFalse(t *testing.T) {
	t.Parallel()
	if isICMPUnreachable(&covSimpleErr{"unrelated"}) {
		t.Fatal("unrelated error should not match")
	}
}

// ---------------------------------------------------------------------------
// PortManager.ConnectionList: empty + single-conn shape
// ---------------------------------------------------------------------------

func TestConnectionListEmpty(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	if got := pm.ConnectionList(); len(got) != 0 {
		t.Fatalf("got %d entries, want 0", len(got))
	}
}

func TestConnectionListReturnsOneEntry(t *testing.T) {
	t.Parallel()
	pm := NewPortManager()
	c := &Connection{
		ID:       42,
		State:    StateEstablished,
		WindowCh: make(chan struct{}, 1),
		RetxStop: make(chan struct{}),
		RecvBuf:  make(chan []byte, 1),
	}
	pm.mu.Lock()
	pm.connections[c.ID] = c
	pm.mu.Unlock()

	list := pm.ConnectionList()
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1", len(list))
	}
	if list[0].ID != 42 {
		t.Fatalf("ID = %d, want 42", list[0].ID)
	}
}

// ---------------------------------------------------------------------------
// IPC dispatch: unknown command, handleManaged unknown sub-command,
// handleManaged member-tags short payload, handleBroadcast short payload.
// ---------------------------------------------------------------------------

func TestDispatchUnknownCommandReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.dispatch(ic, 0xFF, 0, nil)
	})
	assertErrorReply(t, reply, "unknown command")
}

func TestHandleBroadcastMissingHeader(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleBroadcast(ic, 0, []byte{0x00}) // < 6 bytes
	})
	assertErrorReply(t, reply, "missing header")
}

func TestHandleBroadcastTruncatedToken(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	// Header: netID(2)=1, dstPort(2)=80, tokenLen(2)=10 — but no token bytes follow.
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint16(payload[2:4], 80)
	binary.BigEndian.PutUint16(payload[4:6], 10)
	reply := runHandler(t, client, func() {
		s.handleBroadcast(ic, 0, payload)
	})
	assertErrorReply(t, reply, "truncated token")
}

func TestHandleBroadcastNoAdminTokenRejected(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // no admin token
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := make([]byte, 6)
	binary.BigEndian.PutUint16(payload[0:2], 1)
	binary.BigEndian.PutUint16(payload[2:4], 80)
	binary.BigEndian.PutUint16(payload[4:6], 0) // no token
	reply := runHandler(t, client, func() {
		s.handleBroadcast(ic, 0, payload)
	})
	assertErrorReply(t, reply, "admin token")
}

func TestHandleManagedUnknownSubCommand(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, []byte{0xFE}) // unknown sub
	})
	assertErrorReply(t, reply, "unknown sub-command")
}

func TestHandleManagedCycleNoEngineSendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, []byte{SubManagedCycle})
	})
	assertErrorReply(t, reply, "no active managed networks")
}

func TestHandleManagedReconcileNoRunner(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedReconcile, 0x00, 0x05}
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, payload)
	})
	assertErrorReply(t, reply, "no active policy runner")
}

func TestHandleManagedMemberTagsShortPayload(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, []byte{SubManagedMemberTags, 0x00}) // <7 bytes of rest
	})
	assertErrorReply(t, reply, "missing action")
}

func TestHandleManagedPolicyUnknownAction(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedPolicy, 0x7F, 0x00, 0x01} // unknown action
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, payload)
	})
	assertErrorReply(t, reply, "unknown action")
}

func TestHandleManagedPolicyGetNoEngine(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	s := d.ipc
	ic, client := newIPCTestConn(t)
	payload := []byte{SubManagedPolicy, 0x00, 0x00, 0x01} // get, netID=1, no engine
	reply := runHandler(t, client, func() {
		s.handleManaged(ic, 0, payload)
	})
	// Should reply OK with engine="none" or similar — verify it's not an error.
	if reply[0] == CmdError {
		t.Fatalf("expected OK reply; got error: %q", reply[3:])
	}
}

func TestHandleRotateKeyNoIdentitySendsError(t *testing.T) {
	t.Parallel()
	d := New(Config{}) // no identity
	s := d.ipc
	ic, client := newIPCTestConn(t)
	reply := runHandler(t, client, func() {
		s.handleRotateKey(ic, 0)
	})
	if reply[0] != CmdError {
		t.Fatalf("expected error reply; got 0x%02X", reply[0])
	}
}

// ManagedEngine.Status: read-only, no I/O. Quick coverage win for the
// accessor without touching ForceCycle (which needs a real regConn).
func TestManagedEngineStatusReturnsRules(t *testing.T) {
	t.Parallel()
	me := &ManagedEngine{
		netID:    7,
		rules:    &registrywire.NetworkRules{Cycle: "10s", Links: 3},
		peers:    map[uint32]*managedPeer{1: {NodeID: 1}, 2: {NodeID: 2}},
		joinedAt: time.Now(),
	}
	st := me.Status()
	if st["network_id"] != uint16(7) {
		t.Fatalf("network_id = %v, want 7", st["network_id"])
	}
	if st["peers"] != 2 {
		t.Fatalf("peers = %v, want 2", st["peers"])
	}
	if st["max_links"] != 3 {
		t.Fatalf("max_links = %v, want 3", st["max_links"])
	}
}

// ---------------------------------------------------------------------------
// recoverLayer: panic capture + counter increment. recoverLayer MUST be
// directly the deferred function — calling recover() from inside a function
// called by another deferred function does NOT catch the panic.
// ---------------------------------------------------------------------------

func TestRecoverLayerNoPanicReturnsFalse(t *testing.T) {
	t.Parallel()
	before := RecoveredPanicCount()
	func() {
		defer recoverLayer("L0", "noop", nil, nil)
	}()
	if RecoveredPanicCount() != before {
		t.Fatal("counter should not increment on no-panic")
	}
}

func TestRecoverLayerCatchesAndIncrements(t *testing.T) {
	t.Parallel()
	// Recovery counter is process-global and other parallel tests touch
	// it via the panic-survival suite. Snapshot before, assert monotonic.
	before := RecoveredPanicCount()
	func() {
		defer recoverLayer("L1", "test", nil, nil)
		panic("boom")
	}()
	if RecoveredPanicCount() <= before {
		t.Fatalf("counter did not advance: before=%d after=%d",
			before, RecoveredPanicCount())
	}
}

func TestRecoverLayerCallsOnPanic(t *testing.T) {
	t.Parallel()
	called := false
	func() {
		defer recoverLayer("L2", "test", nil, func(any) { called = true })
		panic("inner")
	}()
	if !called {
		t.Fatal("onPanic callback was not invoked")
	}
}

func TestRecoverLayerOnPanicThatItselfPanicsSwallowed(t *testing.T) {
	t.Parallel()
	// recoverLayer wraps onPanic in its own recover() — an onPanic that
	// itself panics must not propagate out of recoverLayer.
	func() {
		defer recoverLayer("L3", "test", nil, func(any) { panic("inner-inner") })
		panic("outer")
	}()
	// No assertion needed: if recoverLayer leaked the inner panic, this
	// test would crash with an unrecovered panic.
}

func TestRecoverLayerPublishesBusEvent(t *testing.T) {
	t.Parallel()
	bus := newInProcessBus(func() uint32 { return 1 })
	ch, cancel := bus.Subscribe("L4.panic")
	defer cancel()
	func() {
		defer recoverLayer("L4", "op", bus, nil)
		panic("bus-event")
	}()
	select {
	case ev := <-ch:
		if ev.Topic != "L4.panic" {
			t.Fatalf("topic = %q", ev.Topic)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("L4.panic not received on bus")
	}
}

// ---------------------------------------------------------------------------
// inProcessBus / matchPattern coverage
// ---------------------------------------------------------------------------

func TestInProcessBusPublishNilBusNoOp(t *testing.T) {
	t.Parallel()
	var b *inProcessBus
	b.Publish("any", nil) // must not panic
}

func TestInProcessBusSubscribeNilReturnsClosedCh(t *testing.T) {
	t.Parallel()
	var b *inProcessBus
	ch, cancel := b.Subscribe("any")
	if cancel == nil {
		t.Fatal("cancel should not be nil")
	}
	if _, ok := <-ch; ok {
		t.Fatal("expected closed channel from nil-bus Subscribe")
	}
	cancel() // no-op
}

func TestInProcessBusSlowSubscriberDropped(t *testing.T) {
	t.Parallel()
	b := newInProcessBus(func() uint32 { return 1 })
	_, cancel := b.Subscribe("flood.*")
	defer cancel()
	// Don't drain — fill the buffer + force a drop. We just verify
	// Publish does not block.
	for i := 0; i < 2000; i++ {
		b.Publish("flood.x", map[string]any{"i": i})
	}
}

func TestInProcessBusMatchPatternVariants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pattern, topic string
		want           bool
	}{
		{"*", "anything", true},
		{"", "empty-pattern", true},
		{"foo.*", "foo.bar", true},
		{"foo.*", "foo.bar.baz", true},
		{"foo.*", "fooXbar", false},
		{"foo.bar", "foo.bar", true},
		{"foo.bar", "foo.baz", false},
	}
	for _, tc := range cases {
		if got := matchPattern(tc.pattern, tc.topic); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v", tc.pattern, tc.topic, got, tc.want)
		}
	}
}

func TestInProcessBusUnsubscribeRemovesSubscriber(t *testing.T) {
	t.Parallel()
	b := newInProcessBus(func() uint32 { return 1 })
	ch, cancel := b.Subscribe("x")
	cancel()
	if _, ok := <-ch; ok {
		t.Fatal("expected closed channel after cancel")
	}
	b.Publish("x", nil) // must still not panic
}

// ---------------------------------------------------------------------------
// connAdapter.Close + pilotAddr formatting
// ---------------------------------------------------------------------------

func TestConnAdapterCloseForwarding(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	c := &Connection{
		ID:       1,
		State:    StateEstablished,
		RecvBuf:  make(chan []byte, 1),
		RetxStop: make(chan struct{}),
	}
	d.ports.mu.Lock()
	d.ports.connections[c.ID] = c
	d.ports.mu.Unlock()
	rw := d.NewConnReadWriter(c)
	if err := rw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPilotAddrStringFormat(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	c := &Connection{ID: 1, LocalPort: 80, RemotePort: 81}
	rw := d.NewConnReadWriter(c).(*connAdapter)
	la := rw.LocalAddr()
	if la.Network() != "pilot" {
		t.Fatalf("Network() = %q, want pilot", la.Network())
	}
	if la.String() == "" {
		t.Fatal("String() returned empty")
	}
	ra := rw.RemoteAddr()
	if ra.Network() != "pilot" {
		t.Fatalf("RemoteAddr Network() = %q, want pilot", ra.Network())
	}
}

func TestConnAdapterDeadlineSettersNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	c := &Connection{ID: 1}
	rw := d.NewConnReadWriter(c).(*connAdapter)
	if err := rw.SetDeadline(time.Now()); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := rw.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if err := rw.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
}

// ---------------------------------------------------------------------------
// RegConnListNodes: nil regConn returns a typed error rather than panicking.
// ---------------------------------------------------------------------------

func TestRegConnListNodesNilRegConnReturnsError(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	if _, err := d.RegConnListNodes(1, ""); err == nil {
		t.Fatal("expected error when regConn is nil")
	}
}

// ---------------------------------------------------------------------------
// prewarmTrustedResolves: nil handshake service returns immediately.
// ---------------------------------------------------------------------------

func TestPrewarmTrustedResolvesNilHandshakeNoOp(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	// Pre-close stopCh so even if the function tried to sleep, it would
	// bail. With nil handshakes the function returns before sleeping.
	close(d.stopCh)
	d.prewarmTrustedResolves()
}

func TestPrewarmTrustedResolvesEmptyTrustedListReturns(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	d.RegisterHandshakeService(&fakeHandshakeService{}) // empty
	// Without pre-closing stopCh, the 2s sleep would run. Override here
	// so the test completes quickly: closed stopCh wakes the select.
	close(d.stopCh)
	d.prewarmTrustedResolves()
}
