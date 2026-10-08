// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
)

// registryLog counts the requests a fake registry received, by type.
type registryLog struct {
	mu    sync.Mutex
	count map[string]int
}

func (l *registryLog) add(typ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.count == nil {
		l.count = map[string]int{}
	}
	l.count[typ]++
}

func (l *registryLog) get(typ string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.count[typ]
}

func (l *registryLog) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.count = nil
}

// registerOK is a fake registry's reply to a register for node 7.
func registerOK(hostname string) map[string]interface{} {
	resp := map[string]interface{}{
		"type":    "register_ok",
		"node_id": float64(7),
		"address": protocol.Addr{Node: 7}.String(),
	}
	if hostname != "" {
		resp["hostname"] = hostname
	}
	return resp
}

// newRegistryTestDaemon is a daemon registered as node 7 with the fake
// registry at addr, which it can also dial again (forceReconnectRegistry).
func newRegistryTestDaemon(t *testing.T, addr string, cfg Config) *Daemon {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	cfg.RegistryAddr = addr
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:4000"
	}
	d := New(cfg)
	d.identity = id
	rc, err := registry.Dial(addr)
	if err != nil {
		t.Fatalf("dial fake registry: %v", err)
	}
	rc.SetSigner(func(challenge string) string { return "test-sig:" + challenge })
	d.regConn.Store(rc)
	t.Cleanup(func() {
		if c := d.reg(); c != nil {
			c.Close()
		}
	})
	d.setNodeID_testhelper(7)
	d.lastRegistryOKNano.Store(time.Now().UnixNano())
	return d
}

// An address change leaves the registry holding everything about this node
// except where it is. The re-registration must say only that: a node that
// trusts the service fleet would otherwise send a signed ReportTrust per
// trusted peer, plus SetVisibility and SetHostname, on every address change.
func TestReRegisterEndpointWritesOnlyTheEndpoint(t *testing.T) {
	t.Parallel()
	var log registryLog
	hostname := "edge-1"
	echo := hostname
	var echoMu sync.Mutex
	nodeID := float64(7)
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		log.add(typ)
		if typ != "register" {
			return map[string]interface{}{"type": typ + "_ok"}
		}
		echoMu.Lock()
		defer echoMu.Unlock()
		resp := registerOK(echo)
		resp["node_id"] = nodeID
		resp["address"] = protocol.Addr{Node: uint32(nodeID)}.String()
		return resp
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{Public: true, Hostname: hostname})
	fs := installFakeHandshake(d)
	fs.trustedRecs = []HandshakeTrustRecord{{NodeID: 41}, {NodeID: 42}, {NodeID: 43}}

	if err := d.reRegisterEndpoint(); err != nil {
		t.Fatalf("reRegisterEndpoint: %v", err)
	}
	if log.get("register") != 1 || log.get("report_trust") != 0 || log.get("set_visibility") != 0 || log.get("set_hostname") != 0 {
		t.Fatalf("endpoint-only re-registration sent %v, want one register and nothing else", log.count)
	}

	// The registry may have reaped the node while it could not reach us:
	// no answer for endpointOnlyRegistryFresh means the full restore.
	log.reset()
	d.lastRegistryOKNano.Store(time.Now().Add(-endpointOnlyRegistryFresh - time.Minute).UnixNano())
	if err := d.reRegisterEndpoint(); err != nil {
		t.Fatalf("reRegisterEndpoint after silence: %v", err)
	}
	if log.get("report_trust") != 3 || log.get("set_visibility") != 1 || log.get("set_hostname") != 1 {
		t.Fatalf("after a long silence sent %v, want the full restore", log.count)
	}

	// A reply without our hostname: the node came back without it, and
	// without its visibility. Trust pairs are keyed by node ID and survive.
	log.reset()
	echoMu.Lock()
	echo = ""
	echoMu.Unlock()
	if err := d.reRegisterEndpoint(); err != nil {
		t.Fatalf("reRegisterEndpoint: %v", err)
	}
	if log.get("set_visibility") != 1 || log.get("set_hostname") != 1 || log.get("report_trust") != 0 {
		t.Fatalf("hostname missing from the reply: sent %v, want visibility and hostname restored", log.count)
	}

	// A different node ID: the registry did not know this key any more.
	log.reset()
	echoMu.Lock()
	echo, nodeID = hostname, 8
	echoMu.Unlock()
	if err := d.reRegisterEndpoint(); err != nil {
		t.Fatalf("reRegisterEndpoint: %v", err)
	}
	if log.get("report_trust") != 3 {
		t.Fatalf("new node ID: sent %v, want the trust pairs re-synced", log.count)
	}
}

// The address-change recovery uses the endpoint-only re-registration; the
// resume handler keeps the full one, since a long suspend can outlast the
// registry's reap threshold.
func TestAddrChangeRecoveryRegistersEndpointOnly(t *testing.T) {
	t.Parallel()
	var log registryLog
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		log.add(typ)
		if typ == "register" {
			return registerOK("")
		}
		return map[string]interface{}{"type": typ + "_ok"}
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{Public: true})
	fs := installFakeHandshake(d)
	fs.trustedRecs = []HandshakeTrustRecord{{NodeID: 41}, {NodeID: 42}}

	if !d.recoverFromAddrChange(addrReasonLocal, "10.0.0.4", "10.0.0.77", false) {
		t.Fatal("recovery reported a registry failure")
	}
	if log.get("register") != 1 || log.get("report_trust") != 0 || log.get("set_visibility") != 0 {
		t.Fatalf("address-change recovery sent %v, want one register and nothing else", log.count)
	}

	log.reset()
	d.reestablishOKWall = 0 // not coalesced with the run above
	if !d.reestablishTransport("resume", reestablishOpts{freshConn: true}) {
		t.Fatal("resume re-establishment failed")
	}
	if log.get("report_trust") != 2 || log.get("set_visibility") != 1 {
		t.Fatalf("resume sent %v, want the full re-registration", log.count)
	}
}

// registry_ok must say what the registry answered. A heartbeat that lands
// while the re-registration fails moves lastRegistryOKNano too, and must not
// make the failure read as success.
func TestReestablishTransportReportsAFailedRegistration(t *testing.T) {
	t.Parallel()
	var d *Daemon
	var ready sync.WaitGroup
	ready.Add(1)
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] == "register" {
			ready.Wait()
			d.lastRegistryOKNano.Store(time.Now().UnixNano()) // a heartbeat, concurrently
			return map[string]interface{}{"type": "error", "error": "registry overloaded"}
		}
		return map[string]interface{}{"type": "ok"}
	})
	defer stop()
	d = newRegistryTestDaemon(t, addr, Config{})
	ready.Done()

	for _, o := range []reestablishOpts{{}, {freshConn: true, endpointOnly: true, always: true}} {
		if d.reestablishTransport("test", o) {
			t.Fatalf("reestablishTransport(%+v) reported success for a rejected re-registration", o)
		}
	}
}

// Two recoveries at once — the resume handler and the address watcher both
// fire when a laptop wakes on a new network — must not abort each other:
// each forceReconnectRegistry closes the connection the other may be in the
// middle of a request on. They run one after the other.
func TestReestablishTransportRunsOneAtATime(t *testing.T) {
	t.Parallel()
	var inFlight, overlapped atomic.Int32
	registering := make(chan struct{}, 4)
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] != "register" {
			return map[string]interface{}{"type": "ok"}
		}
		if inFlight.Add(1) > 1 {
			overlapped.Store(1)
		}
		registering <- struct{}{}
		time.Sleep(300 * time.Millisecond)
		inFlight.Add(-1)
		return registerOK("")
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{})

	results := make(chan bool, 2)
	go func() { results <- d.reestablishTransport("resume", reestablishOpts{freshConn: true}) }()
	<-registering // the first run is waiting on its register
	go func() {
		results <- d.reestablishTransport("addr-change", reestablishOpts{freshConn: true, endpointOnly: true, always: true})
	}()
	for i := 0; i < 2; i++ {
		select {
		case ok := <-results:
			if !ok {
				t.Fatal("a re-registration failed: the other run replaced the registry connection under it")
			}
		case <-time.After(30 * time.Second):
			t.Fatal("re-establishment did not finish")
		}
	}
	if overlapped.Load() != 0 {
		t.Fatal("two re-registrations were in flight at once")
	}
}

// A run the registry accepted moments ago did the work a resume or rx-silence
// recovery wants, so they skip theirs. The address watcher never skips: the
// run before may have registered the address we just left.
func TestReestablishTransportCoalescesRecentRuns(t *testing.T) {
	t.Parallel()
	var log registryLog
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		log.add(typ)
		if typ == "register" {
			return registerOK("")
		}
		return map[string]interface{}{"type": "ok"}
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{})

	run := func(cause string, o reestablishOpts) {
		t.Helper()
		if !d.reestablishTransport(cause, o) {
			t.Fatalf("%s: reported failure", cause)
		}
	}
	run("resume", reestablishOpts{freshConn: true})
	run("resume", reestablishOpts{freshConn: true})
	run("rx-silence", reestablishOpts{})
	if got := log.get("register"); got != 1 {
		t.Fatalf("registers = %d after three runs within %v, want 1", got, reestablishCoalesce)
	}
	run("addr-change", reestablishOpts{freshConn: true, endpointOnly: true, always: true})
	if got := log.get("register"); got != 2 {
		t.Fatalf("registers = %d, want the address change to run regardless", got)
	}
	// The address change re-registered the endpoint only. A resume wants the
	// full re-registration, so it does not count as done.
	run("resume", reestablishOpts{freshConn: true})
	if got := log.get("register"); got != 3 {
		t.Fatalf("registers = %d, want a full caller to run after an endpoint-only run", got)
	}
	run("rx-silence", reestablishOpts{})
	if got := log.get("register"); got != 3 {
		t.Fatalf("registers = %d, want rx-silence skipped right after a full run", got)
	}

	d.reestablishMu.Lock()
	d.reestablishOKWall = time.Now().Add(-2 * reestablishCoalesce).UnixNano()
	d.reestablishMu.Unlock()
	run("resume", reestablishOpts{freshConn: true})
	if got := log.get("register"); got != 4 {
		t.Fatalf("registers = %d, want a run once the last one is older than %v", got, reestablishCoalesce)
	}
}

// The heartbeat's own reconnect and re-registration (trustRepublishLoop)
// take reestablishMu too, so they cannot replace or use the registry
// connection under a recovery's requests either: while a recovery holds the
// mutex they wait for it.
func TestHeartbeatRegistryCallsWaitForARecovery(t *testing.T) {
	t.Parallel()
	var log registryLog
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		log.add(typ)
		if typ == "register" {
			return registerOK("")
		}
		return map[string]interface{}{"type": "ok"}
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{})

	reconnect := func() error {
		_, err := d.reconnectRegistrySerialised(d.reg())
		return err
	}
	for _, call := range []struct {
		name string
		fn   func() error
	}{
		{"reconnect", reconnect},
		{"re-register", d.reRegisterSerialised},
	} {
		before := d.reg()
		registers := log.get("register")
		d.reestablishMu.Lock() // a recovery in progress
		done := make(chan error, 1)
		go func() { done <- call.fn() }()
		select {
		case err := <-done:
			d.reestablishMu.Unlock()
			t.Fatalf("heartbeat %s ran while a recovery held the lock (err %v)", call.name, err)
		case <-time.After(200 * time.Millisecond):
		}
		if d.reg() != before || log.get("register") != registers {
			d.reestablishMu.Unlock()
			t.Fatalf("heartbeat %s touched the registry while a recovery held the lock", call.name)
		}
		d.reestablishMu.Unlock()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("heartbeat %s: %v", call.name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("heartbeat %s never ran once the recovery let go", call.name)
		}
	}
}

// The heartbeat does not repeat a recovery that has just run. Its call can
// time out on the connection a recovery replaced while the call waited (a
// resume whose own dial was slow). It then replaced the fresh connection
// again and re-registered in full a second time: two registers and two
// ReportTrust per trusted peer. Its own re-registration counts for a
// recovery right after it the same way.
func TestHeartbeatDoesNotRepeatARecovery(t *testing.T) {
	t.Parallel()
	var log registryLog
	addr, stop := serveFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		typ, _ := req["type"].(string)
		log.add(typ)
		if typ == "register" {
			return registerOK("")
		}
		return map[string]interface{}{"type": typ + "_ok"}
	})
	defer stop()
	d := newRegistryTestDaemon(t, addr, Config{})
	fs := installFakeHandshake(d)
	fs.trustedRecs = []HandshakeTrustRecord{{NodeID: 41}, {NodeID: 42}}

	stale := d.reg() // the heartbeat's call is waiting on this connection
	if !d.reestablishTransport("resume", reestablishOpts{freshConn: true}) {
		t.Fatal("resume recovery failed")
	}
	fresh := d.reg()

	// The call times out: the heartbeat reconnects, then re-registers.
	reconnected, err := d.reconnectRegistrySerialised(stale)
	if err != nil {
		t.Fatalf("heartbeat reconnect: %v", err)
	}
	if reconnected || d.reg() != fresh {
		t.Fatal("the heartbeat replaced the connection the recovery had just opened")
	}
	if err := d.reRegisterSerialised(); err != nil {
		t.Fatalf("heartbeat re-register: %v", err)
	}
	if log.get("register") != 1 || log.get("report_trust") != 2 {
		t.Fatalf("resume then heartbeat sent %v, want one register and one report_trust per trusted peer", log.count)
	}

	// The other way round: a resume right after the heartbeat's own
	// re-registration skips its registry half.
	d.reestablishMu.Lock()
	d.reestablishOKWall = time.Now().Add(-2 * reestablishCoalesce).UnixNano()
	d.reestablishMu.Unlock()
	log.reset()
	if err := d.reRegisterSerialised(); err != nil {
		t.Fatalf("heartbeat re-register: %v", err)
	}
	if !d.reestablishTransport("resume", reestablishOpts{freshConn: true}) {
		t.Fatal("resume recovery failed")
	}
	if log.get("register") != 1 || d.reg() != fresh {
		t.Fatalf("heartbeat then resume sent %v and replaced the connection: %v, want one register", log.count, d.reg() != fresh)
	}
}
