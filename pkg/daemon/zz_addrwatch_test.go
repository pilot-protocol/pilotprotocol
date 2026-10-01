// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/udpio"
)

// addrRecoverCall is one invocation of the stubbed recovery.
type addrRecoverCall struct {
	reason, previous, current string
	announce                  bool
}

// swapAddrRecoverForTest stubs the recovery hook. registryOK is what each
// stubbed recovery reports. Tests using it must NOT run in parallel with each
// other (global hook), mirroring swapPathResetForTest.
func swapAddrRecoverForTest(t *testing.T, registryOK *bool) *[]addrRecoverCall {
	t.Helper()
	var calls []addrRecoverCall
	prev := addrWatchRecover
	addrWatchRecover = func(_ *Daemon, reason, previous, current string, announce bool) bool {
		calls = append(calls, addrRecoverCall{reason, previous, current, announce})
		return *registryOK
	}
	t.Cleanup(func() { addrWatchRecover = prev })
	return &calls
}

// fakeAddrSource is the injectable address source: tests set ip/ok between
// ticks instead of touching real interfaces.
type fakeAddrSource struct {
	ip string
	ok bool
}

func (f *fakeAddrSource) fn() (string, bool) { return f.ip, f.ok }

func newAddrWatchTestDaemon() *Daemon {
	return &Daemon{
		tunnels:   NewTunnelManager(),
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

func TestAddrWatchNoChangeNeverFires(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	for i := 0; i < 600; i++ {
		if d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("tick %d fired with an unchanged address", i)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("recoveries = %d, want 0", len(*calls))
	}
}

func TestAddrWatchChangeFiresOnceOnTheFirstTick(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now) // baseline

	src.ip = "10.0.0.77"
	if !d.addrWatchTick(st, src.fn, now.Add(time.Second)) {
		t.Fatal("address change did not fire on the first tick that saw it")
	}
	for i := 2; i < 300; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 {
		t.Fatalf("recoveries = %d, want exactly 1 for one change", len(*calls))
	}
	got := (*calls)[0]
	want := addrRecoverCall{addrReasonLocal, "10.0.0.4", "10.0.0.77", true}
	if got != want {
		t.Fatalf("recovery = %+v, want %+v", got, want)
	}
}

// An interface that drops and comes back with the same address (cable
// re-plugged, Wi-Fi roaming on one network, `docker network disconnect` then
// `connect` with the same IP) changed nothing anyone else needs to hear about.
func TestAddrWatchOfflineThenSameAddressDoesNotFire(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)

	for i := 1; i <= 20; i++ {
		src.ip, src.ok = "", i%2 == 0 // no route on odd ticks
		if src.ok {
			src.ip = "10.0.0.4"
		}
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 0 {
		t.Fatalf("recoveries = %d, want 0 for an interface flapping on one address", len(*calls))
	}
}

// Going offline is not a change, and a new address after the outage fires
// only once the route is back.
func TestAddrWatchOfflineThenNewAddressFiresWhenBack(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)

	src.ip, src.ok = "", false
	for i := 1; i <= 5; i++ {
		if d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second)) {
			t.Fatal("fired while offline")
		}
	}
	src.ip, src.ok = "10.0.0.77", true
	if !d.addrWatchTick(st, src.fn, now.Add(6*time.Second)) {
		t.Fatal("did not fire when the route came back on a new address")
	}
	if len(*calls) != 1 || (*calls)[0].previous != "10.0.0.4" || (*calls)[0].current != "10.0.0.77" {
		t.Fatalf("calls = %+v", *calls)
	}
}

// A daemon that starts offline has nothing to compare against: the first
// address it sees is the baseline.
func TestAddrWatchFirstAddressAfterOfflineStartIsBaseline(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)
	src.ip, src.ok = "10.0.0.4", true
	d.addrWatchTick(st, src.fn, now.Add(time.Second))
	if len(*calls) != 0 {
		t.Fatalf("recoveries = %d, want 0", len(*calls))
	}
}

// A second change inside the cooldown is deferred, not dropped and not run
// early.
func TestAddrWatchChangeDuringCooldownIsDeferred(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)

	src.ip = "10.0.0.5"
	d.addrWatchTick(st, src.fn, now.Add(time.Second)) // recovery 1 at t=1s

	src.ip = "10.0.0.6"
	for i := 2; i < 11; i++ { // t=2s..10s: inside the 10s cooldown
		if d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second)) {
			t.Fatalf("fired at t=%ds, inside the cooldown", i)
		}
	}
	if !d.addrWatchTick(st, src.fn, now.Add(11*time.Second)) {
		t.Fatal("deferred change did not run when the cooldown ended")
	}
	if len(*calls) != 2 || (*calls)[1].previous != "10.0.0.5" || (*calls)[1].current != "10.0.0.6" {
		t.Fatalf("calls = %+v", *calls)
	}
}

// A→B→A where the second hop falls inside the cooldown of an earlier
// recovery: by the time the cooldown ends the address is the one already
// announced, so there is nothing to do.
func TestAddrWatchFlapBackToAnnouncedAddressIsCancelled(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)

	src.ip = "10.0.0.5"
	d.addrWatchTick(st, src.fn, now.Add(time.Second)) // announces .5

	src.ip = "10.0.0.6"
	d.addrWatchTick(st, src.fn, now.Add(2*time.Second))
	src.ip = "10.0.0.5"
	for i := 3; i < 120; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 {
		t.Fatalf("recoveries = %d, want 1 (the excursion to .6 was never announced)", len(*calls))
	}
}

// A flapping interface must not turn into a re-registration storm: the gap
// between recoveries doubles up to addrRecoverCooldownMax.
func TestAddrWatchFlappingIsRateLimited(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)

	var fired []int
	const seconds = 30 * 60
	for i := 1; i <= seconds; i++ {
		// A new address every second for half an hour.
		src.ip = net.IPv4(10, 0, byte(i>>8), byte(i)).String()
		if d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second)) {
			fired = append(fired, i)
		}
	}
	// 1s, +10s, +20s, +40s, +80s, then one per 2 minutes.
	wantHead := []int{1, 11, 31, 71, 151, 271, 391}
	if len(fired) < len(wantHead) {
		t.Fatalf("fired at %v, want it to start %v", fired, wantHead)
	}
	for i, w := range wantHead {
		if fired[i] != w {
			t.Fatalf("fired at %v, want it to start %v", fired, wantHead)
		}
	}
	if max := 5 + seconds/int(addrRecoverCooldownMax/time.Second); len(fired) > max {
		t.Fatalf("%d recoveries in %ds of flapping, want at most %d", len(fired), seconds, max)
	}
	if len(*calls) != len(fired) {
		t.Fatalf("recoveries = %d, fired ticks = %d", len(*calls), len(fired))
	}
}

func TestAddrWatchCooldownResetsAfterQuiet(t *testing.T) {
	st := &addrWatchState{}
	now := time.Now()
	st.noteLocal("10.0.0.1", true)
	for i, ip := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		st.noteLocal(ip, true)
		st.began(now.Add(time.Duration(i)*time.Minute), addrReasonLocal)
	}
	if got := st.cooldown(); got != 4*addrRecoverCooldown {
		t.Fatalf("cooldown after 3 recoveries = %v, want %v", got, 4*addrRecoverCooldown)
	}
	st.noteLocal("10.0.0.5", true)
	st.began(now.Add(2*time.Minute+addrRecoverQuiet), addrReasonLocal)
	if got := st.cooldown(); got != addrRecoverCooldown {
		t.Fatalf("cooldown after a quiet period = %v, want %v", got, addrRecoverCooldown)
	}
}

// The NAT case: the local address is unchanged but the beacon reports us at
// a different public IP.
func TestAddrWatchObservedEndpointChangeFires(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "192.168.1.20", ok: true}
	st := &addrWatchState{}
	now := time.Now()

	d.tunnels.observedEndpoint.Store(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40000})
	d.addrWatchTick(st, src.fn, now) // baseline for both inputs

	// Same IP, different port: a NAT renumbering ports is not a move.
	d.tunnels.observedEndpoint.Store(&net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40001})
	if d.addrWatchTick(st, src.fn, now.Add(time.Second)) {
		t.Fatal("fired on a port-only change of the observed endpoint")
	}

	d.tunnels.observedEndpoint.Store(&net.UDPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 40001})
	if !d.addrWatchTick(st, src.fn, now.Add(2*time.Second)) {
		t.Fatal("did not fire when the beacon reported a new public IP")
	}
	for i := 3; i < 200; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 || (*calls)[0].reason != addrReasonObserved || !(*calls)[0].announce {
		t.Fatalf("calls = %+v, want one %q recovery", *calls, addrReasonObserved)
	}
}

// When our own address moves, the beacon's view moves with it. That must not
// count as a second change and run a second recovery after the cooldown.
func TestAddrWatchLocalChangeDoesNotDoubleFireOnObserved(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.78.0.3", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.tunnels.observedEndpoint.Store(&net.UDPAddr{IP: net.IPv4(10, 78, 0, 3), Port: 4000})
	d.addrWatchTick(st, src.fn, now)

	src.ip = "10.78.0.77"
	d.addrWatchTick(st, src.fn, now.Add(time.Second))
	if d.tunnels.ObservedEndpoint() != nil {
		t.Fatal("the pre-move beacon reply was kept; it would be re-read as the new baseline")
	}
	d.addrWatchTick(st, src.fn, now.Add(2*time.Second))
	// The beacon's reply to the recovery's registration lands.
	d.tunnels.observedEndpoint.Store(&net.UDPAddr{IP: net.IPv4(10, 78, 0, 77), Port: 4000})
	for i := 3; i < 200; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 {
		t.Fatalf("recoveries = %d, want 1: %+v", len(*calls), *calls)
	}
}

// If the registry could not be reached right after the change, only the
// registry half is retried, a bounded number of times, one per cooldown.
func TestAddrWatchRegistryRetryIsBounded(t *testing.T) {
	ok := false
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	d.addrWatchTick(st, src.fn, now)
	src.ip = "10.0.0.77"
	for i := 1; i < 3600; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1+addrRegistryRetryMax {
		t.Fatalf("recoveries = %d, want 1 + %d registry retries", len(*calls), addrRegistryRetryMax)
	}
	for i, c := range (*calls)[1:] {
		if c.reason != addrReasonRegistry || c.announce {
			t.Fatalf("retry %d = %+v, want a registry-only retry", i, c)
		}
	}

	// A retry that succeeds stops the retries.
	ok = false
	*calls = nil
	st = &addrWatchState{}
	d.addrWatchTick(st, src.fn, now)
	src.ip = "10.0.0.78"
	d.addrWatchTick(st, src.fn, now.Add(time.Second))
	ok = true
	for i := 2; i < 3600; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 2 {
		t.Fatalf("recoveries = %d, want 2 (the change, then one successful retry)", len(*calls))
	}
}

// The production source: the kernel's choice of source address for a target.
// Toward loopback that is loopback, every time; an unrelated interface
// appearing, a link-local address or a rotating IPv6 temporary address cannot
// change the answer unless the route to the target itself moves.
func TestRouteSourceIP(t *testing.T) {
	t.Parallel()
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9001}
	for i := 0; i < 3; i++ {
		ip, ok := routeSourceIP(target)
		if !ok || ip != "127.0.0.1" {
			t.Fatalf("routeSourceIP(loopback) = %q, %v; want 127.0.0.1, true", ip, ok)
		}
	}
	if ip, ok := routeSourceIP(nil); ok || ip != "" {
		t.Fatalf("routeSourceIP(nil) = %q, %v; want no address", ip, ok)
	}
}

func TestParseDiscoverReply(t *testing.T) {
	t.Parallel()
	v4 := []byte{4, 203, 0, 113, 7, 0x9c, 0x40}
	if got := parseDiscoverReply(v4); got == nil || got.String() != "203.0.113.7:40000" {
		t.Fatalf("v4 = %v", got)
	}
	v6 := append([]byte{16}, net.ParseIP("2001:db8::1")...)
	v6 = binary.BigEndian.AppendUint16(v6, 4000)
	if got := parseDiscoverReply(v6); got == nil || got.String() != "[2001:db8::1]:4000" {
		t.Fatalf("v6 = %v", got)
	}
	for _, bad := range [][]byte{nil, {}, {4}, {4, 1, 2, 3, 4}, {4, 1, 2, 3, 4, 0}, {5, 1, 2, 3, 4, 5, 0, 1}, {16, 1, 2}} {
		if got := parseDiscoverReply(bad); got != nil {
			t.Fatalf("parseDiscoverReply(%v) = %v, want nil", bad, got)
		}
	}
}

// Only the beacon's own reply may set the observed endpoint: anyone can send
// a datagram that looks like a discover reply to the tunnel port.
func TestObservedEndpointOnlyFromBeacon(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SetBeaconAddr("192.0.2.1:9001"); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}
	reply := []byte{protocol.BeaconMsgDiscoverReply, 4, 203, 0, 113, 7, 0x9c, 0x40}

	tm.handleBeaconMessage(reply, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 66), Port: 9001})
	if got := tm.ObservedEndpoint(); got != nil {
		t.Fatalf("observed endpoint set from a non-beacon source: %v", got)
	}
	tm.handleBeaconMessage(reply, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9001})
	if got := tm.ObservedEndpoint(); got == nil || got.String() != "203.0.113.7:40000" {
		t.Fatalf("observed endpoint = %v, want 203.0.113.7:40000", got)
	}
}

// addrAnnounceRig is a daemon with a real loopback tunnel socket and one
// peer that is a plain UDP listener, so the test sees exactly which datagrams
// the announce puts on the wire and where.
type addrAnnounceRig struct {
	d      *Daemon
	peer   *net.UDPConn
	beacon *net.UDPConn
}

const addrAnnouncePeer = 77

func newAddrAnnounceRig(t *testing.T) *addrAnnounceRig {
	t.Helper()
	listen := func() *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	conn, peer, beacon := listen(), listen(), listen()

	d := newAddrWatchTestDaemon()
	d.bus = newInProcessBus(func() uint32 { return 1 })
	d.tunnels.sock = udpio.WrapConn(conn)
	d.tunnels.routing.SetSocket(d.tunnels.sock)
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := d.tunnels.SetBeaconAddr(beacon.LocalAddr().String()); err != nil {
		t.Fatalf("SetBeaconAddr: %v", err)
	}
	// Install the session before the address so AddPeer's key exchange
	// (which would also write to the peer) is the only extra datagram.
	pc := fakePC(t)
	pc.Authenticated = true
	d.tunnels.envelope.Install(addrAnnouncePeer, pc)
	d.tunnels.mu.Lock()
	d.tunnels.peers[addrAnnouncePeer] = peer.LocalAddr().(*net.UDPAddr)
	d.tunnels.mu.Unlock()
	return &addrAnnounceRig{d: d, peer: peer, beacon: beacon}
}

// readOne returns the next datagram on c, or nil if none arrives in time.
func readOne(c *net.UDPConn, wait time.Duration) []byte {
	buf := make([]byte, 2048)
	_ = c.SetReadDeadline(time.Now().Add(wait))
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	return buf[:n]
}

func TestAnnounceToPeersSendsDirectEncryptedProbe(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	if got := r.d.announceToPeers(time.Time{}); got != 1 {
		t.Fatalf("announced to %d peers, want 1", got)
	}
	frame := readOne(r.peer, 2*time.Second)
	if frame == nil {
		t.Fatal("peer received nothing")
	}
	if len(frame) < 4 || string(frame[:4]) != string(protocol.TunnelMagicSecure[:]) {
		t.Fatalf("peer received a frame that is not an encrypted tunnel frame: % x", frame[:min(len(frame), 8)])
	}
}

// A peer we flipped to relay while our own address was gone (send errors
// during the outage) must still be told directly: a relayed frame reaches it
// from the beacon and teaches it nothing.
func TestAnnounceToPeersBypassesRelayFlag(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	r.d.tunnels.SetRelayPeerPinned(addrAnnouncePeer, true)
	if got := r.d.announceToPeers(time.Time{}); got != 1 {
		t.Fatalf("announced to %d peers, want 1", got)
	}
	if readOne(r.peer, 2*time.Second) == nil {
		t.Fatal("relay-flagged peer was not probed directly")
	}
	if got := readOne(r.beacon, 200*time.Millisecond); got != nil {
		t.Fatalf("announce went through the beacon (%d bytes)", len(got))
	}
}

// A relay-only node hides its real address; a direct probe would reveal it.
func TestAnnounceToPeersRelayOnlyNodeStaysSilent(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	r.d.config.RelayOnly = true
	if got := r.d.announceToPeers(time.Time{}); got != 0 {
		t.Fatalf("relay-only node announced to %d peers, want 0", got)
	}
	if got := readOne(r.peer, 200*time.Millisecond); got != nil {
		t.Fatal("relay-only node sent a direct frame to a peer")
	}
}

// A peer whose only known address is the beacon placeholder has no direct
// endpoint to probe.
func TestAnnounceToPeersSkipsBeaconPlaceholder(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	r.d.tunnels.mu.Lock()
	r.d.tunnels.peers[addrAnnouncePeer] = r.beacon.LocalAddr().(*net.UDPAddr)
	r.d.tunnels.mu.Unlock()
	if got := r.d.announceToPeers(time.Time{}); got != 0 {
		t.Fatalf("announced to %d peers, want 0", got)
	}
}

// The retry rounds leave alone a peer that has already answered directly
// since the recovery started.
func TestAnnounceToPeersSkipsPeersThatAnswered(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	started := time.Now()
	if got := r.d.announceToPeers(started); got != 1 {
		t.Fatalf("unanswered peer: announced to %d, want 1", got)
	}
	r.d.tunnels.routing.RecordDirectRecv(addrAnnouncePeer, started.Add(time.Millisecond))
	if got := r.d.announceToPeers(started); got != 0 {
		t.Fatalf("answered peer: announced to %d, want 0", got)
	}
}

// The whole recovery without a registry: beacon registration, peer probe and
// the event on the bus.
func TestRecoverFromAddrChangePublishesEventAndNotifies(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	events, cancel := r.d.bus.Subscribe("tunnel.addr_changed")
	defer cancel()

	if r.d.recoverFromAddrChange(addrReasonLocal, "10.0.0.4", "10.0.0.77", true) {
		t.Fatal("reported registry success with no registry configured")
	}
	close(r.d.stopCh) // end the retry goroutine
	r.d.bgWG.Wait()

	if readOne(r.peer, 2*time.Second) == nil {
		t.Fatal("peer was not probed")
	}
	msg := readOne(r.beacon, 2*time.Second)
	if len(msg) != 5 || msg[0] != protocol.BeaconMsgDiscover {
		t.Fatalf("beacon did not receive a discover: % x", msg)
	}
	select {
	case ev := <-events:
		p := ev.Payload
		if p["reason"] != addrReasonLocal || p["previous"] != "10.0.0.4" || p["current"] != "10.0.0.77" ||
			p["peers_notified"] != 1 || p["registry_ok"] != false {
			t.Fatalf("event payload = %+v", p)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no tunnel.addr_changed event")
	}
}
