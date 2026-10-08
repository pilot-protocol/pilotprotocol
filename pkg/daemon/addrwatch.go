// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"net"
	"time"
)

// Own-address watcher (L4).
//
// Failure mode this exists for: this host's IP address changes under a
// running daemon — Wi-Fi to Ethernet, a new DHCP lease, a VPN taking the
// default route, a container moved to another address. The tunnel socket is
// bound to the wildcard address and keeps working, but everyone else still
// holds the old address: peers keep sending to it, the beacon relays to it and
// the registry hands it out. Nothing in the daemon noticed, so recovery waited
// for other nodes' timeouts — a peer's blackhole flip to relay (8s silence
// plus three sends) or our own 25s NAT keepalive finally reaching the peer
// from the new address. Measured on v1.14.0-rc.1: 23–32s without traffic in
// either direction, and a registry entry still pointing at the old address
// minutes later.
//
// Detection: once a second, ask the kernel which source address it would use
// toward the beacon (a connected UDP socket; nothing is sent). That is the
// address the daemon's traffic actually leaves from, so it changes exactly
// when the daemon's path changes, and stays put when an unrelated interface
// appears (a Docker bridge, a VPN that does not take the route) or when a
// link-local address comes and goes. An IPv6 temporary address rotating is
// seen only when it is the address the route to the beacon uses, and then it
// is a real change of our source address. No route at all reads as
// "offline" and triggers nothing: there is nobody to tell until an address
// comes back, and if the same one comes back nothing has changed.
//
// A node behind NAT sees no local change when the NAT's public address
// changes. The second input covers that: the beacon's reply to a discover
// (RegisterWithBeacon, every keepalive interval) carries the address the
// beacon sees us at (TunnelManager.noteDiscoverReply). That input is noisier
// than the first. Anyone can send a datagram from the beacon's address, and
// some NATs show one node at more than one public IP (carrier-grade NAT
// pools, cloud NAT with several addresses, per-flow load balancing). So a
// reply counts only if it arrives within 2 s of a discover this node sent,
// and a new IP counts only once two replies in a row agree on it. When one
// reply names a new IP the watcher sends one more discover at once, so the
// second opinion arrives within a round trip instead of a keepalive interval.
//
// Both baselines belong to one beacon. The beacon refresh can move us to
// another one, which may be reached over another route (a private bootstrap
// beacon beside public ones) or see us at another public IP (a NAT that picks
// the public address per destination, dual WAN). A beacon switch therefore
// starts both baselines over instead of reading as a move. A local change
// still waiting to be announced at that moment is kept and still runs.
//
// Recovery (recoverFromAddrChange), in the order that matters for latency:
//  1. beacon: re-register, so relay delivery and hole-punching use the new
//     endpoint (one datagram). The beacon takes at most one endpoint update
//     per node every 30 s and drops the rest, so a move within 30 s of the
//     last keepalive registration would not reach it until the next one; the
//     registration is repeated addrBeaconReregisterDelay later to cover that;
//  2. peers: one authenticated probe straight to every tunnel peer, so each
//     overwrites its entry for us from the packet's source (one datagram per
//     peer, repeated only for peers that have not answered);
//  3. registry: a fresh connection — the pooled one is bound to the address
//     we no longer have — and an endpoint-only re-registration
//     (reRegisterEndpoint): the registry still holds our visibility,
//     hostname and trust pairs, so they are not written again.
//
// Rate limit: two recoveries are always at least addrRecoverCooldown apart.
// On top of that each input has its own backoff: the gap doubles with every
// recovery in a row, up to addrRecoverCooldownMax for a local change and
// addrObservedCooldownMax for a beacon-observed one, and drops back after a
// quiet period. A flapping interface costs a handful of re-registrations and
// then one every two minutes; a NAT whose public IP keeps flapping costs one
// an hour. The registry-only retries (addrRegistryRetryMax) have a backoff of
// their own, on the local-address schedule and started over by every move,
// so they never hold the next move back. A change seen during the cooldown
// is not lost: it runs when the cooldown ends, unless the address has gone
// back to the one already announced. The gaps are measured on the wall clock
// (addrWatchNow), so time the host spends asleep counts.
//
// -no-addr-watch (Config.DisableAddrWatch) turns the watcher off.
const (
	// addrWatchPollInterval is how often the source address is sampled.
	addrWatchPollInterval = time.Second

	// addrRecoverCooldown is the minimum gap between two recoveries, and the
	// first gap of the local-address backoff.
	addrRecoverCooldown = 10 * time.Second

	// addrRecoverCooldownMax caps the doubling of the local-address gap.
	addrRecoverCooldownMax = 2 * time.Minute

	// addrRecoverQuiet is how long without a local-address recovery before
	// that gap drops back to addrRecoverCooldown.
	addrRecoverQuiet = 10 * time.Minute

	// addrObservedCooldown, addrObservedCooldownMax and addrObservedQuiet
	// are the same three for the beacon-observed IP. A real change of a
	// NAT's public address is rare, and an IP that keeps changing is far
	// more likely a NAT that maps us to several addresses, so the gap starts
	// longer and grows to an hour. The quiet period is longer than that cap,
	// or a steady flap at the cap would reset the backoff every time.
	addrObservedCooldown    = time.Minute
	addrObservedCooldownMax = time.Hour
	addrObservedQuiet       = 2 * addrObservedCooldownMax

	// addrObservedConfirmGap is the minimum gap between two confirming
	// discovers (see wantConfirm).
	addrObservedConfirmGap = 30 * time.Second

	// addrRegistryRetryMax is how many more times the registry half of a
	// recovery is retried (one per cooldown) when the registry could not be
	// reached right after the change.
	addrRegistryRetryMax = 3
)

// addrAnnounceRetryDelays are the waits before the peer probe is repeated
// for peers that have not answered directly since the recovery started. A
// single datagram can be lost, and a route that has just come up may drop
// the first one.
var addrAnnounceRetryDelays = []time.Duration{time.Second, 2 * time.Second}

// addrBeaconReregisterDelay is when, after a recovery started, the beacon
// registration is repeated: just past the beacon's 30 s per-node limit on
// endpoint updates, so the repeat is accepted even if the recovery's own
// registrations were not.
var addrBeaconReregisterDelay = 31 * time.Second

// Reasons a recovery ran — the "reason" field of tunnel.addr_changed.
const (
	addrReasonLocal    = "local_address"
	addrReasonObserved = "observed_endpoint"
	addrReasonRegistry = "registry_retry"
)

// addrWatchState is the watcher's memory between ticks. All decisions are
// made by its methods on values handed in, so tests drive it without real
// interfaces or clocks.
type addrWatchState struct {
	beacon     string       // the beacon both baselines were taken against ("" = none)
	beaconAddr *net.UDPAddr // the same beacon, for one last sample on its route at a switch

	local     string // source address seen on the latest sample with a route
	announced string // local address the last recovery announced (or the baseline)

	observed        string    // beacon-observed IP the last recovery announced (or the baseline)
	observedCurrent string    // latest IP two replies in a row agreed on
	confirmAskedFor time.Time // arrival of the reply the last confirming discover was for
	lastConfirm     time.Time // when that discover was sent

	registryRetries int // registry-only retries still owed

	lastRecover time.Time   // the latest recovery of any kind
	localGap    addrBackoff // local-address recoveries
	observedGap addrBackoff // observed-endpoint recoveries
	registryGap addrBackoff // registry-only retries, started over by every move
}

// addrBackoff is one input's run of recoveries.
type addrBackoff struct {
	last   time.Time
	streak int // recoveries in a row without a quiet pause
}

// noteBeacon records which beacon this tick's inputs come from. On a switch
// the baselines start over: the new beacon may be reached from another local
// address and see us at another public IP without anything having moved.
//
// A local change that is still waiting to be announced is kept, though:
// one deferred by the cooldown, or one the caller's last sample on the old
// route has just seen. Our address really did change, and the beacon switch
// tells the peers and the registry nothing. It runs when it is due and
// announces whatever address the new route uses by then.
func (st *addrWatchState) noteBeacon(beacon string) {
	if beacon == st.beacon {
		return
	}
	st.beacon = beacon
	if st.local == st.announced {
		st.local, st.announced = "", ""
	}
	st.observed, st.observedCurrent = "", ""
	st.confirmAskedFor, st.lastConfirm = time.Time{}, time.Time{}
}

// noteLocal records one sample of the local source address. ok is false when
// the host has no route (offline), which is remembered as nothing at all.
func (st *addrWatchState) noteLocal(addr string, ok bool) {
	if !ok || addr == "" {
		return
	}
	st.local = addr
	if st.announced == "" {
		st.announced = addr // first sample: baseline, not a change
	}
}

// noteObserved takes the two latest discover replies (newest first). An IP
// becomes where the beacon sees us only when both come from the current
// beacon and agree on it; a lone reply that disagrees changes nothing (see
// wantConfirm). Only the IP is compared: a NAT hands out a different port per
// destination and may renumber ports freely, and peers already follow a port
// change from our keepalives.
func (st *addrWatchState) noteObserved(latest, prev beaconObservation) {
	if latest.endpoint == nil || prev.endpoint == nil ||
		latest.beacon != st.beacon || prev.beacon != st.beacon ||
		!latest.endpoint.IP.Equal(prev.endpoint.IP) {
		return
	}
	st.observedCurrent = latest.endpoint.IP.String()
	if st.observed == "" {
		st.observed = st.observedCurrent // first agreed IP: baseline, not a change
	}
}

// wantConfirm reports whether to send a discover now to get a second opinion
// on the latest reply: it is from the current beacon, names an IP that two
// replies have not agreed on, has not had a confirming discover yet, and none
// was sent in the last addrObservedConfirmGap. The gap bounds the chain a
// beacon or NAT reporting a new IP on every reply could start.
func (st *addrWatchState) wantConfirm(latest beaconObservation, now time.Time) bool {
	if latest.endpoint == nil || latest.beacon != st.beacon ||
		latest.endpoint.IP.String() == st.observedCurrent || latest.at.Equal(st.confirmAskedFor) {
		return false
	}
	if recentlyAt(st.lastConfirm, now, addrObservedConfirmGap) {
		return false
	}
	st.confirmAskedFor, st.lastConfirm = latest.at, now
	return true
}

// pending names the reason a recovery is wanted, or "" if none is.
func (st *addrWatchState) pending() string {
	switch {
	case st.local != st.announced:
		return addrReasonLocal
	case st.observed != "" && st.observedCurrent != st.observed:
		return addrReasonObserved
	case st.registryRetries > 0:
		return addrReasonRegistry
	}
	return ""
}

// addrGapParams is the backoff schedule of the input behind reason: the
// first gap, its cap, and how long without a recovery before it drops back.
// Registry retries follow the local-address schedule.
func addrGapParams(reason string) (base, max, quiet time.Duration) {
	if reason == addrReasonObserved {
		return addrObservedCooldown, addrObservedCooldownMax, addrObservedQuiet
	}
	return addrRecoverCooldown, addrRecoverCooldownMax, addrRecoverQuiet
}

// gapFor returns the backoff of the input behind reason.
func (st *addrWatchState) gapFor(reason string) *addrBackoff {
	switch reason {
	case addrReasonObserved:
		return &st.observedGap
	case addrReasonRegistry:
		return &st.registryGap
	}
	return &st.localGap
}

// cooldown is the gap required after the last recovery of reason's input.
func (st *addrWatchState) cooldown(reason string) time.Duration {
	base, max, _ := addrGapParams(reason)
	gap := base
	for i := 1; i < st.gapFor(reason).streak && gap < max; i++ {
		gap *= 2
	}
	if gap > max {
		gap = max
	}
	return gap
}

// due reports whether a recovery should run now, and why. It does not change
// state; the caller follows up with began.
func (st *addrWatchState) due(now time.Time) (reason string, ok bool) {
	reason = st.pending()
	if reason == "" {
		return "", false
	}
	if recentlyAt(st.lastRecover, now, addrRecoverCooldown) {
		return "", false
	}
	if b := st.gapFor(reason); recentlyAt(b.last, now, st.cooldown(reason)) {
		return "", false
	}
	return reason, true
}

// recentlyAt reports whether t is set and less than d before now. The
// watcher runs on the wall clock (addrWatchNow), which can be stepped back;
// a t that lies ahead of now says nothing about how long ago it was, so it
// does not hold anything back.
func recentlyAt(t, now time.Time, d time.Duration) bool {
	if t.IsZero() {
		return false
	}
	since := now.Sub(t)
	return since >= 0 && since < d
}

// began marks a recovery for reason as started at now, and returns the
// addresses it moves us from and to: the local source address, or for
// addrReasonObserved the IP the beacon sees us at.
func (st *addrWatchState) began(now time.Time, reason string) (previous, current string) {
	b := st.gapFor(reason)
	if _, _, quiet := addrGapParams(reason); !b.last.IsZero() && now.Sub(b.last) >= quiet {
		b.streak = 0
	}
	b.streak++
	b.last = now
	st.lastRecover = now

	previous, current = st.announced, st.local
	if reason == addrReasonObserved {
		previous, current = st.observed, st.observedCurrent
		st.observed = st.observedCurrent
	}
	st.announced = st.local
	// Our own move changes what the beacon sees too. Forget the old value
	// so the replies to the recovery's own discovers become the baseline
	// instead of a second change.
	if reason == addrReasonLocal {
		st.observed, st.observedCurrent = "", ""
	}
	if reason == addrReasonRegistry {
		st.registryRetries--
	} else {
		st.registryRetries = 0
		// The retries this move may leave owed are spaced from it, on their
		// own backoff. Counted in the move's, each one would hold the next
		// move back as if the address had changed again.
		st.registryGap = addrBackoff{last: now, streak: 1}
	}
	return previous, current
}

// finished records whether the registry took the new endpoint.
func (st *addrWatchState) finished(reason string, registryOK bool) {
	if registryOK {
		st.registryRetries = 0
		return
	}
	if reason != addrReasonRegistry {
		st.registryRetries = addrRegistryRetryMax
	}
}

// addrSourceFn reports the local IP the kernel would use for traffic to the
// control plane — toward beacon, or when it is nil toward the registry — and
// whether there is a route at all.
type addrSourceFn func(beacon *net.UDPAddr) (ip string, ok bool)

// routeSourceIP is the production address source for one target: connecting
// a UDP socket performs the route lookup and binds the source address without
// sending anything.
func routeSourceIP(target *net.UDPAddr) (string, bool) {
	if target == nil {
		return "", false
	}
	c, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return "", false // no route: offline
	}
	defer c.Close()
	la, _ := c.LocalAddr().(*net.UDPAddr)
	if la == nil || la.IP == nil || la.IP.IsUnspecified() {
		return "", false
	}
	return la.IP.String(), true
}

// addrWatchSource builds the address source: the route toward the beacon
// the tunnel currently uses, or, for a daemon with no beacon, toward the
// registry.
func (d *Daemon) addrWatchSource() addrSourceFn {
	var registry *net.UDPAddr // resolved once; only the route to it matters
	var nextResolve time.Time // a failed lookup is not repeated every second
	return func(beacon *net.UDPAddr) (string, bool) {
		if beacon != nil {
			return routeSourceIP(beacon)
		}
		if registry == nil && d.config.RegistryAddr != "" && !time.Now().Before(nextResolve) {
			registry, _ = net.ResolveUDPAddr("udp", d.config.RegistryAddr)
			nextResolve = time.Now().Add(30 * time.Second)
		}
		return routeSourceIP(registry)
	}
}

func (d *Daemon) addrWatchLoop() {
	if d.config.DisableAddrWatch {
		return
	}
	// A compat-mode daemon has no UDP socket and no direct paths: all its
	// traffic rides one WSS connection to the beacon, which reconnects on
	// its own when the address under it changes.
	if d.config.TransportMode == TransportCompat {
		return
	}
	src := d.addrWatchSource()
	st := &addrWatchState{}
	ticker := time.NewTicker(addrWatchPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.addrWatchTick(st, src, addrWatchNow())
		}
	}
}

// addrWatchNow is the watcher's clock: the wall clock, with the monotonic
// reading stripped. Go measures the time between two readings that both
// carry a monotonic reading on the monotonic clock, and on Linux that clock
// does not advance while the host is suspended. A laptop that recovered,
// slept for an hour and woke on a new network would still be "inside" its
// 10 s cooldown, and its backoff would never see the quiet hour; a host
// waking somewhere else is exactly when the watcher matters.
func addrWatchNow() time.Time { return time.Now().Round(0) }

// addrWatchTick takes one sample and runs a recovery if one is due.
// Extracted for testability — production drives it from addrWatchLoop.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): a panic drops
// this tick and the next one resamples from clean state.
func (d *Daemon) addrWatchTick(st *addrWatchState, src addrSourceFn, now time.Time) (fired bool) {
	defer recoverLayer("L4", "addrWatchTick", d.bus, nil)

	// The beacon can change under us (beaconRefreshTick); read it once so the
	// sample, the replies and the baselines all refer to the same one.
	beacon := d.tunnels.BeaconUDPAddr()
	beaconKey := ""
	if beacon != nil {
		beaconKey = beacon.String()
	}
	if beaconKey != st.beacon {
		// One more sample on the old route before the baselines start
		// over: a move in the same second as the switch shows up there,
		// and noteBeacon keeps it as a change still to announce.
		if st.announced != "" {
			st.noteLocal(src(st.beaconAddr))
		}
		st.noteBeacon(beaconKey)
		st.beaconAddr = beacon
	}
	ip, ok := src(beacon)
	st.noteLocal(ip, ok)
	latest, prev := d.tunnels.beaconObservations()
	st.noteObserved(latest, prev)
	if ok && st.wantConfirm(latest, now) {
		// One reply puts us at an IP no second reply has confirmed. Ask
		// again now rather than wait a keepalive interval for the next.
		d.tunnels.RegisterWithBeacon()
	}
	reason, due := st.due(now)
	if !due {
		return false
	}
	if !ok {
		// Offline right now. Whatever is owed runs once a route is back.
		return false
	}
	previous, current := st.began(now, reason)
	if reason == addrReasonLocal {
		// began dropped the observed baseline; drop the stored replies too,
		// so the baseline is taken from replies that arrive after the move
		// rather than from ones that describe the old address.
		d.tunnels.forgetObservedEndpoints()
	}
	registryOK := addrWatchRecover(d, reason, previous, current, reason != addrReasonRegistry)
	st.finished(reason, registryOK)
	return true
}

// addrWatchRecover is swapped by tests to observe recoveries without a live
// registry or beacon (mirrors pathWatchResetPeer).
var addrWatchRecover = func(d *Daemon, reason, previous, current string, announce bool) bool {
	return d.recoverFromAddrChange(reason, previous, current, announce)
}

// RecoverFromAddrChangeForTest runs the address-change recovery on d now, as
// the watcher does when it sees this host's address change, without the
// watcher's rate limit, and reports whether the registry accepted the
// re-registration. It exists for the end-to-end tests in ./tests, which run
// outside this package and cannot give a daemon a new address; nothing else
// should call it.
func RecoverFromAddrChangeForTest(d *Daemon) bool {
	return d.recoverFromAddrChange("manual", "", "", true)
}

// recoverFromAddrChange tells the beacon, the tunnel peers (when announce is
// set) and the registry where this node now is. See the file comment for the
// order. Returns whether the registry accepted the re-registration.
func (d *Daemon) recoverFromAddrChange(reason, previous, current string, announce bool) bool {
	started := time.Now()
	if announce {
		slog.Warn("own address changed — re-announcing to beacon, peers and registry",
			"reason", reason, "previous", previous, "current", current)
	} else {
		slog.Warn("own address changed — retrying the registry re-registration", "current", current)
	}

	notified := 0
	if announce {
		// Beacon first: it is one datagram, and a peer that cannot be
		// reached directly is reached through the beacon's mapping.
		d.tunnels.RegisterWithBeacon()
		notified = d.announceToPeers(time.Time{})
	}
	if announce && !d.stopping() {
		d.bgWG.Add(1)
		go func() {
			defer d.bgWG.Done()
			defer recoverLayer("L4", "addrAnnounceFollowUp", d.bus, nil)
			d.addrAnnounceFollowUp(started)
		}()
	}

	// The port may be unchanged but the private addresses we advertise for
	// same-LAN detection are not.
	d.refreshLANAddrs()

	// Registry last: it is TCP with dial retries and may take seconds, and
	// nothing above should wait for it. reestablishTransport also repeats
	// the beacon registration, which costs one datagram and covers a first
	// one lost while the route was still settling. It is never skipped for
	// a run that just finished: that run may have registered the old address.
	registryOK := d.reestablishTransport("addr-change",
		reestablishOpts{freshConn: true, endpointOnly: true, always: true})

	d.publishEvent("tunnel.addr_changed", map[string]any{
		"reason":         reason,
		"previous":       previous,
		"current":        current,
		"peers_notified": notified,
		"registry_ok":    registryOK,
	})
	slog.Info("address-change recovery done",
		"reason", reason, "peers_notified", notified, "registry_ok", registryOK,
		"took", time.Since(started).Truncate(time.Millisecond).String())
	return registryOK
}

// addrAnnounceFollowUp repeats the parts of a recovery that one datagram may
// not have achieved. The peer probe is repeated after each of
// addrAnnounceRetryDelays for peers that have not answered directly since the
// recovery started. The beacon registration is repeated once,
// addrBeaconReregisterDelay after the start: the beacon accepts at most one
// endpoint update per node every 30 s and drops the rest without telling us,
// so when the move came within 30 s of a keepalive registration it would
// otherwise relay to the old address until the next keepalive, up to a
// minute later.
func (d *Daemon) addrAnnounceFollowUp(started time.Time) {
	sleep := func(wait time.Duration) bool {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-d.stopCh:
			return false
		case <-t.C:
			return true
		}
	}
	for _, wait := range addrAnnounceRetryDelays {
		if !sleep(wait) {
			return
		}
		if d.announceToPeers(started) == 0 {
			break
		}
	}
	if !sleep(time.Until(started.Add(addrBeaconReregisterDelay))) {
		return
	}
	d.tunnels.RegisterWithBeacon()
}

// announceToPeers sends one direct, authenticated probe to every peer with
// an established session, and returns how many were sent. With a non-zero
// since, peers that have already sent us a direct frame after that time are
// skipped: a direct frame can only have reached us at the new address, so
// that peer has learned it.
//
// A relay-only node (-relay-only / compat) never sends: a direct frame would
// show the peer the real address the node is hiding. Peers we only know
// through the beacon are skipped by SendDirectProbe, and stay reachable
// through the beacon registration.
func (d *Daemon) announceToPeers(since time.Time) int {
	if d.config.RelayOnly {
		return 0
	}
	sent := 0
	for _, nodeID := range d.tunnels.ReadyPeerIDs() {
		if !since.IsZero() && d.tunnels.LastDirectRecv(nodeID).After(since) {
			continue
		}
		if err := d.tunnels.SendDirectPathProbe(nodeID); err != nil {
			slog.Debug("address announce: probe not sent", "peer_node_id", nodeID, "err", err)
			continue
		}
		sent++
	}
	return sent
}

// currentLANAddrs returns the private addresses advertised to the registry.
func (d *Daemon) currentLANAddrs() []string {
	d.addrMu.RLock()
	defer d.addrMu.RUnlock()
	return d.lanAddrs
}

// refreshLANAddrs re-collects the advertised private addresses after an
// address change. A compat daemon advertises none.
func (d *Daemon) refreshLANAddrs() {
	if d.config.TransportMode == TransportCompat {
		return
	}
	la := d.tunnels.LocalAddr()
	if la == nil {
		return
	}
	_, port, err := net.SplitHostPort(la.String())
	if err != nil || port == "" || port == "0" {
		return
	}
	addrs := collectLANAddrs(port)
	d.addrMu.Lock()
	d.lanAddrs = addrs
	d.addrMu.Unlock()
}
