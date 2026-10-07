// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"strings"
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

func (f *fakeAddrSource) fn(*net.UDPAddr) (string, bool) { return f.ip, f.ok }

// addrWatchTestBeacon is the beacon newAddrWatchTestDaemon's tunnel uses.
var addrWatchTestBeacon = &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9001}

func newAddrWatchTestDaemon() *Daemon {
	d := &Daemon{
		tunnels:   NewTunnelManager(),
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
	d.tunnels.routing.SetBeaconAddrUDP(addrWatchTestBeacon)
	return d
}

// observe hands d one discover reply from its current beacon, arriving at
// now in answer to a discover sent just before.
func observe(d *Daemon, ip net.IP, now time.Time) {
	d.tunnels.lastDiscoverNano.Store(now.Add(-50 * time.Millisecond).UnixNano())
	d.tunnels.noteDiscoverReply(&net.UDPAddr{IP: ip, Port: 40000}, d.tunnels.BeaconUDPAddr(), now)
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
	if got := st.cooldown(addrReasonLocal); got != 4*addrRecoverCooldown {
		t.Fatalf("cooldown after 3 recoveries = %v, want %v", got, 4*addrRecoverCooldown)
	}
	st.noteLocal("10.0.0.5", true)
	st.began(now.Add(2*time.Minute+addrRecoverQuiet), addrReasonLocal)
	if got := st.cooldown(addrReasonLocal); got != addrRecoverCooldown {
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
	tick := func(sec int) bool { return d.addrWatchTick(st, src.fn, now.Add(time.Duration(sec)*time.Second)) }
	a, b := net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 9)

	observe(d, a, now)
	tick(0)
	observe(d, a, now.Add(time.Second))
	tick(1) // two agreeing replies: the baseline

	// Same IP, different port: a NAT renumbering ports is not a move.
	d.tunnels.lastDiscoverNano.Store(now.Add(2 * time.Second).UnixNano())
	d.tunnels.noteDiscoverReply(&net.UDPAddr{IP: a, Port: 40001}, addrWatchTestBeacon, now.Add(2*time.Second))
	if tick(2) {
		t.Fatal("fired on a port-only change of the observed endpoint")
	}

	observe(d, b, now.Add(3*time.Second))
	observe(d, b, now.Add(3*time.Second+100*time.Millisecond))
	if !tick(3) {
		t.Fatal("did not fire when the beacon reported a new public IP twice")
	}
	for i := 4; i < 200; i++ {
		tick(i)
	}
	if len(*calls) != 1 || (*calls)[0].reason != addrReasonObserved || !(*calls)[0].announce {
		t.Fatalf("calls = %+v, want one %q recovery", *calls, addrReasonObserved)
	}
	// The event reports the IPs the beacon saw, not the unchanged local one.
	if c := (*calls)[0]; c.previous != a.String() || c.current != b.String() {
		t.Fatalf("recovery moved %q -> %q, want %v -> %v", c.previous, c.current, a, b)
	}
}

// One reply is not enough: a datagram from the beacon's address may be
// forged, and some NATs show us at several public IPs. Only two replies in a
// row that agree move the observed IP.
func TestAddrWatchObservedNeedsTwoAgreeingReplies(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "192.168.1.20", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	sec := 0
	step := func(ip net.IP) bool {
		sec++
		at := now.Add(time.Duration(sec) * time.Second)
		observe(d, ip, at)
		return d.addrWatchTick(st, src.fn, at)
	}
	a, b := net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 9)
	step(a)
	step(a) // baseline

	// A, B, A, B, A, ...: no two replies in a row agree on B.
	for i := 0; i < 20; i++ {
		ip := b
		if i%2 == 1 {
			ip = a
		}
		if step(ip) {
			t.Fatalf("fired on reply %d of an alternating sequence", i)
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("recoveries = %d, want 0", len(*calls))
	}
	step(b)
	if !step(b) {
		t.Fatal("two agreeing replies on a new IP did not fire")
	}
}

// A lone reply naming a new IP is checked at once with one more discover,
// not left until the next keepalive registration a minute later. That
// discover is sent once per reply and at most once per addrObservedConfirmGap.
func TestAddrWatchLoneReplyAsksForConfirmation(t *testing.T) {
	t.Parallel()
	r := newAddrAnnounceRig(t)
	d := r.d
	beacon := d.tunnels.BeaconUDPAddr()
	src := &fakeAddrSource{ip: "192.168.1.20", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	reply := func(ip net.IP, at time.Time) {
		d.tunnels.lastDiscoverNano.Store(at.Add(-50 * time.Millisecond).UnixNano())
		d.tunnels.noteDiscoverReply(&net.UDPAddr{IP: ip, Port: 40000}, beacon, at)
	}
	confirmSent := func() bool {
		msg := readOne(r.beacon, 300*time.Millisecond)
		return len(msg) == 5 && msg[0] == protocol.BeaconMsgDiscover
	}
	a, b, c := net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 9), net.IPv4(198, 51, 100, 10)

	reply(a, now)
	d.addrWatchTick(st, src.fn, now)
	if !confirmSent() {
		t.Fatal("first reply was not confirmed with a second discover")
	}
	reply(a, now.Add(100*time.Millisecond))
	d.addrWatchTick(st, src.fn, now.Add(time.Second))
	if confirmSent() {
		t.Fatal("sent a confirming discover for an IP two replies already agree on")
	}

	reply(b, now.Add(60*time.Second))
	d.addrWatchTick(st, src.fn, now.Add(61*time.Second))
	if !confirmSent() {
		t.Fatal("a reply naming a new IP was not confirmed")
	}
	d.addrWatchTick(st, src.fn, now.Add(62*time.Second))
	if confirmSent() {
		t.Fatal("asked twice about the same reply")
	}
	reply(c, now.Add(63*time.Second))
	d.addrWatchTick(st, src.fn, now.Add(64*time.Second))
	if confirmSent() {
		t.Fatal("confirming discovers less than addrObservedConfirmGap apart")
	}
	d.addrWatchTick(st, src.fn, now.Add(61*time.Second+addrObservedConfirmGap))
	if !confirmSent() {
		t.Fatal("no confirming discover once the gap had passed")
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
	observe(d, net.IPv4(10, 78, 0, 3), now)
	observe(d, net.IPv4(10, 78, 0, 3), now)
	d.addrWatchTick(st, src.fn, now)

	src.ip = "10.78.0.77"
	d.addrWatchTick(st, src.fn, now.Add(time.Second))
	if d.tunnels.ObservedEndpoint() != nil {
		t.Fatal("the pre-move beacon replies were kept; they would be re-read as the new baseline")
	}
	d.addrWatchTick(st, src.fn, now.Add(2*time.Second))
	// The beacon's replies to the recovery's registrations land.
	observe(d, net.IPv4(10, 78, 0, 77), now.Add(2*time.Second))
	observe(d, net.IPv4(10, 78, 0, 77), now.Add(2*time.Second))
	for i := 3; i < 200; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 {
		t.Fatalf("recoveries = %d, want 1: %+v", len(*calls), *calls)
	}
}

// A→B→A on the observed IP inside the cooldown is cancelled, as it is for
// the local address: by the time the cooldown ends the beacon sees us where
// the last recovery already said we are.
func TestAddrWatchObservedFlapBackIsCancelled(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "192.168.1.20", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	at := func(sec int) time.Time { return now.Add(time.Duration(sec) * time.Second) }
	twice := func(ip net.IP, sec int) {
		observe(d, ip, at(sec))
		observe(d, ip, at(sec).Add(100*time.Millisecond))
	}
	a, b := net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 9)
	twice(a, 0)
	d.addrWatchTick(st, src.fn, at(0))
	twice(b, 1)
	if !d.addrWatchTick(st, src.fn, at(1)) { // announces B
		t.Fatal("first change did not fire")
	}
	twice(a, 10) // back to A inside the cooldown...
	d.addrWatchTick(st, src.fn, at(10))
	twice(b, 20) // ...and to B again before it ends
	for i := 20; i < 600; i++ {
		d.addrWatchTick(st, src.fn, at(i))
	}
	if len(*calls) != 1 {
		t.Fatalf("recoveries = %d, want 1 (the excursion back to A was never announced): %+v", len(*calls), *calls)
	}
}

// A NAT that keeps moving us between public IPs (an address pool, per-flow
// balancing) must not cost a recovery every two minutes forever: the
// observed IP's gap grows to addrObservedCooldownMax.
func TestAddrWatchObservedFlappingBacksOffToTheLongCap(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "192.168.1.20", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	ips := []net.IP{net.IPv4(203, 0, 113, 7), net.IPv4(198, 51, 100, 9)}

	var fired []time.Duration
	const hours = 12
	for sec := 0; sec <= hours*3600; sec++ {
		at := now.Add(time.Duration(sec) * time.Second)
		if sec%60 == 0 { // a keepalive registration; the IP flips every 2 minutes
			ip := ips[(sec/120)%2]
			observe(d, ip, at)
			observe(d, ip, at.Add(100*time.Millisecond))
		}
		if d.addrWatchTick(st, src.fn, at) {
			fired = append(fired, time.Duration(sec)*time.Second)
		}
	}
	if len(*calls) != len(fired) {
		t.Fatalf("recoveries = %d, fired ticks = %d", len(*calls), len(fired))
	}
	// 1m, 2m, 4m, ... 32m, then the 1h cap: about 7 in the first two hours
	// and one an hour after that. The local-address schedule (2 minute cap)
	// would have run over 300.
	if max := 8 + hours; len(fired) > max {
		t.Fatalf("%d recoveries in %dh of a flapping observed IP, want at most %d: %v", len(fired), hours, max, fired)
	}
	for i := 1; i < len(fired); i++ {
		if gap := fired[i] - fired[i-1]; gap < addrObservedCooldown {
			t.Fatalf("recoveries %v apart, under the observed-IP minimum %v: %v", gap, addrObservedCooldown, fired)
		}
	}
	var late []time.Duration
	for i := 1; i < len(fired); i++ {
		if fired[i] > 4*time.Hour {
			late = append(late, fired[i]-fired[i-1])
		}
	}
	for _, gap := range late {
		if gap < addrObservedCooldownMax {
			t.Fatalf("gap %v after four hours of flapping, want the %v cap: %v", gap, addrObservedCooldownMax, fired)
		}
	}
}

// A beacon switch is not a move. The new beacon can be reached over another
// route (a private bootstrap beacon beside public ones) and see us at another
// public IP (NAT that picks the address per destination, dual WAN); both
// baselines start over, and the old beacon's stored replies are never
// compared with the new one's.
func TestAddrWatchBeaconSwitchIsNotAMove(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	private := &net.UDPAddr{IP: net.IPv4(10, 128, 0, 5), Port: 9001}
	src := func(b *net.UDPAddr) (string, bool) {
		if b.String() == private.String() {
			return "10.128.0.20", true
		}
		return "192.168.1.20", true
	}
	st := &addrWatchState{}
	now := time.Now()
	at := func(sec int) time.Time { return now.Add(time.Duration(sec) * time.Second) }

	observe(d, net.IPv4(203, 0, 113, 7), at(0))
	observe(d, net.IPv4(203, 0, 113, 7), at(0))
	for i := 0; i < 5; i++ {
		d.addrWatchTick(st, src, at(i))
	}

	// beaconRefreshTick moves us to the private beacon. Its stored replies
	// are still the public beacon's for a while.
	d.tunnels.routing.SetBeaconAddrUDP(private)
	for i := 5; i < 10; i++ {
		d.addrWatchTick(st, src, at(i))
	}
	observe(d, net.IPv4(10, 128, 0, 20), at(10))
	observe(d, net.IPv4(10, 128, 0, 20), at(10))
	for i := 10; i < 600; i++ {
		d.addrWatchTick(st, src, at(i))
	}
	if len(*calls) != 0 {
		t.Fatalf("a beacon switch ran %d recoveries, want 0: %+v", len(*calls), *calls)
	}

	// Moves seen through the new beacon are still caught.
	observe(d, net.IPv4(10, 128, 0, 21), at(600))
	observe(d, net.IPv4(10, 128, 0, 21), at(600))
	if !d.addrWatchTick(st, src, at(600)) {
		t.Fatal("an observed change through the new beacon did not fire")
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
	tm.RegisterWithBeacon() // opens the reply window; no socket, so nothing is sent

	tm.handleBeaconMessage(reply, &net.UDPAddr{IP: net.IPv4(198, 51, 100, 66), Port: 9001})
	if got := tm.ObservedEndpoint(); got != nil {
		t.Fatalf("observed endpoint set from a non-beacon source: %v", got)
	}
	tm.handleBeaconMessage(reply, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9001})
	if got := tm.ObservedEndpoint(); got == nil || got.String() != "203.0.113.7:40000" {
		t.Fatalf("observed endpoint = %v, want 203.0.113.7:40000", got)
	}
}

// A reply from the beacon's address counts only as the answer to a discover
// this node sent less than discoverReplyWindow earlier. The beacon never
// replies unasked, and the source address of a UDP datagram is easy to forge.
func TestDiscoverReplyMustAnswerADiscover(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	beacon := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 9001}
	tm.routing.SetBeaconAddrUDP(beacon)
	ep := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40000}
	now := time.Now()

	if tm.noteDiscoverReply(ep, beacon, now) {
		t.Fatal("kept a reply although no discover was ever sent")
	}
	tm.lastDiscoverNano.Store(now.UnixNano())
	if tm.noteDiscoverReply(ep, beacon, now.Add(discoverReplyWindow+time.Millisecond)) {
		t.Fatal("kept a reply that arrived after the window")
	}
	if tm.noteDiscoverReply(ep, beacon, now.Add(-time.Millisecond)) {
		t.Fatal("kept a reply that arrived before the discover was sent")
	}
	if !tm.noteDiscoverReply(ep, beacon, now.Add(300*time.Millisecond)) {
		t.Fatal("dropped the answer to a discover")
	}
	latest, prev := tm.beaconObservations()
	if latest.endpoint != ep || latest.beacon != beacon.String() || prev.endpoint != nil {
		t.Fatalf("stored latest=%+v prev=%+v", latest, prev)
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

// The beacon takes at most one endpoint update per node every 30 s and drops
// the rest. A move within 30 s of a keepalive registration has the
// recovery's own registrations dropped, so the recovery registers once more
// after addrBeaconReregisterDelay.
func TestRecoverFromAddrChangeRepeatsBeaconRegistrationAfterTheBeaconLimit(t *testing.T) {
	// Not parallel: swaps package-level delays.
	prevRetries, prevDelay := addrAnnounceRetryDelays, addrBeaconReregisterDelay
	addrAnnounceRetryDelays = []time.Duration{10 * time.Millisecond}
	addrBeaconReregisterDelay = 600 * time.Millisecond
	t.Cleanup(func() { addrAnnounceRetryDelays, addrBeaconReregisterDelay = prevRetries, prevDelay })

	r := newAddrAnnounceRig(t)
	defer func() {
		close(r.d.stopCh)
		r.d.bgWG.Wait()
	}()
	start := time.Now()
	r.d.recoverFromAddrChange(addrReasonLocal, "10.0.0.4", "10.0.0.77", true)

	// The recovery's own registrations are already queued at the beacon.
	immediate := 0
	for readOne(r.beacon, 150*time.Millisecond) != nil {
		immediate++
	}
	if immediate == 0 {
		t.Fatal("the recovery did not register with the beacon")
	}
	msg := readOne(r.beacon, 3*time.Second)
	if len(msg) != 5 || msg[0] != protocol.BeaconMsgDiscover {
		t.Fatalf("no beacon registration after the recovery's own (got % x)", msg)
	}
	if since := time.Since(start); since < addrBeaconReregisterDelay {
		t.Fatalf("repeat registration %v after the start, want it after %v (the beacon would drop it)", since, addrBeaconReregisterDelay)
	}
}

// -no-addr-watch (Config.DisableAddrWatch) keeps the watcher from running at
// all; without it the loop runs until the daemon stops.
func TestAddrWatchLoopHonoursDisableAddrWatch(t *testing.T) {
	t.Parallel()
	d := newAddrWatchTestDaemon()
	d.config.DisableAddrWatch = true
	done := make(chan struct{})
	go func() { d.addrWatchLoop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("addrWatchLoop ran with DisableAddrWatch set")
	}

	d = newAddrWatchTestDaemon()
	done = make(chan struct{})
	go func() { d.addrWatchLoop(); close(done) }()
	select {
	case <-done:
		t.Fatal("addrWatchLoop returned at once without DisableAddrWatch")
	case <-time.After(1500 * time.Millisecond):
	}
	close(d.stopCh)
	<-done
}

// A move to .5, then to .6 inside the cooldown, then a beacon switch: the
// switch starts the baselines over, but .6 was never announced and must
// still be once the cooldown ends.
func TestAddrWatchChangeDeferredByCooldownSurvivesBeaconSwitch(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	at := func(sec int) time.Time { return now.Add(time.Duration(sec) * time.Second) }
	d.addrWatchTick(st, src.fn, at(0))

	src.ip = "10.0.0.5"
	d.addrWatchTick(st, src.fn, at(1)) // announces .5
	src.ip = "10.0.0.6"
	d.addrWatchTick(st, src.fn, at(2)) // deferred by the cooldown
	d.tunnels.routing.SetBeaconAddrUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 9001})
	for i := 3; i < 120; i++ {
		d.addrWatchTick(st, src.fn, at(i))
	}
	if len(*calls) != 2 {
		t.Fatalf("recoveries = %d, want 2 (.5, then .6 once the cooldown ended): %+v", len(*calls), *calls)
	}
	if c := (*calls)[1]; c.reason != addrReasonLocal || c.previous != "10.0.0.5" || c.current != "10.0.0.6" {
		t.Fatalf("second recovery = %+v, want .5 -> .6", c)
	}
}

// A move and a beacon switch in the same tick: the old route shows the move,
// so the switch does not swallow it as a new baseline.
func TestAddrWatchMoveInTheSameTickAsABeaconSwitchRuns(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now()
	for i := 0; i < 5; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}

	src.ip = "10.0.0.77"
	d.tunnels.routing.SetBeaconAddrUDP(&net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 9001})
	if !d.addrWatchTick(st, src.fn, now.Add(5*time.Second)) {
		t.Fatal("a move in the same tick as a beacon switch did not run a recovery")
	}
	for i := 6; i < 120; i++ {
		d.addrWatchTick(st, src.fn, now.Add(time.Duration(i)*time.Second))
	}
	if len(*calls) != 1 || (*calls)[0].previous != "10.0.0.4" || (*calls)[0].current != "10.0.0.77" {
		t.Fatalf("calls = %+v, want one .4 -> .77 recovery", *calls)
	}
}

// The watcher's cooldowns must count the time the host spent asleep. Go
// takes the difference of two readings that both carry a monotonic reading
// on the monotonic clock, which on Linux stops during suspend. A test cannot
// suspend the host, so this checks the clock the loop hands addrWatchTick:
// it must carry no monotonic reading, which makes every gap the watcher
// measures a wall-clock one.
func TestAddrWatchClockIsTheWallClock(t *testing.T) {
	t.Parallel()
	if s := addrWatchNow().String(); strings.Contains(s, " m=") {
		t.Fatalf("addrWatchNow() = %s carries a monotonic reading; a cooldown would not count a suspend", s)
	}
}

// The wall clock can be stepped back (NTP, a VM restored from a snapshot).
// A last recovery that now lies in the future says nothing about how long
// ago it was, and must not hold a real change back until the clock catches
// up.
func TestAddrWatchClockSteppedBackDoesNotBlockRecovery(t *testing.T) {
	ok := true
	calls := swapAddrRecoverForTest(t, &ok)
	d := newAddrWatchTestDaemon()
	src := &fakeAddrSource{ip: "10.0.0.4", ok: true}
	st := &addrWatchState{}
	now := time.Now().Round(0)
	d.addrWatchTick(st, src.fn, now)
	src.ip = "10.0.0.5"
	d.addrWatchTick(st, src.fn, now.Add(time.Second))

	stepped := now.Add(-time.Hour)
	src.ip = "10.0.0.6"
	if !d.addrWatchTick(st, src.fn, stepped) {
		t.Fatalf("a change after the clock stepped back an hour waited: %+v", *calls)
	}
}
