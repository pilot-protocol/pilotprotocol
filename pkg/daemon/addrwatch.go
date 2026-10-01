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
// changes. The second input covers that: the beacon's reply to our periodic
// RegisterWithBeacon carries the address the beacon sees us at
// (TunnelManager.ObservedEndpoint); a different IP there is the same event,
// noticed within one keepalive interval instead of one second.
//
// Recovery (recoverFromAddrChange), in the order that matters for latency:
//  1. beacon: re-register, so relay delivery and hole-punching use the new
//     endpoint (one datagram);
//  2. peers: one authenticated probe straight to every tunnel peer, so each
//     overwrites its entry for us from the packet's source (one datagram per
//     peer, repeated only for peers that have not answered);
//  3. registry: a fresh connection — the pooled one is bound to the address
//     we no longer have — and a re-registration.
//
// Rate limit: a recovery is never run more often than addrRecoverCooldown,
// and the gap doubles with every recovery in a row up to
// addrRecoverCooldownMax, so a flapping interface costs a handful of
// re-registrations and then one every two minutes. A change seen during the
// cooldown is not lost: it runs when the cooldown ends, unless the address
// has gone back to the one already announced.
const (
	// addrWatchPollInterval is how often the source address is sampled.
	addrWatchPollInterval = time.Second

	// addrRecoverCooldown is the minimum gap between two recoveries.
	addrRecoverCooldown = 10 * time.Second

	// addrRecoverCooldownMax caps the doubling of that gap.
	addrRecoverCooldownMax = 2 * time.Minute

	// addrRecoverQuiet is how long without a recovery before the gap drops
	// back to addrRecoverCooldown.
	addrRecoverQuiet = 10 * time.Minute

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
	local     string // source address seen on the latest sample with a route
	announced string // local address the last recovery announced (or the baseline)

	observed      string // beacon-observed IP the last recovery announced (or the baseline)
	observedDirty bool   // the beacon has since reported a different one

	registryRetries int // registry-only retries still owed

	lastRecover time.Time
	streak      int // recoveries in a row without an addrRecoverQuiet pause
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

// noteObserved records the IP the beacon reports seeing us at ("" = no reply
// yet). Only the IP is compared: a NAT hands out a different port per
// destination and may renumber ports freely, and peers already follow a port
// change from our keepalives.
func (st *addrWatchState) noteObserved(ip string) {
	if ip == "" {
		return
	}
	if st.observed == "" {
		st.observed = ip
		return
	}
	if ip != st.observed {
		st.observed = ip
		st.observedDirty = true
	}
}

// pending names the reason a recovery is wanted, or "" if none is.
func (st *addrWatchState) pending() string {
	switch {
	case st.local != st.announced:
		return addrReasonLocal
	case st.observedDirty:
		return addrReasonObserved
	case st.registryRetries > 0:
		return addrReasonRegistry
	}
	return ""
}

// cooldown is the gap required after the last recovery.
func (st *addrWatchState) cooldown() time.Duration {
	gap := addrRecoverCooldown
	for i := 1; i < st.streak && gap < addrRecoverCooldownMax; i++ {
		gap *= 2
	}
	if gap > addrRecoverCooldownMax {
		gap = addrRecoverCooldownMax
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
	if !st.lastRecover.IsZero() && now.Sub(st.lastRecover) < st.cooldown() {
		return "", false
	}
	return reason, true
}

// began marks a recovery as started at now and returns the address it
// replaces.
func (st *addrWatchState) began(now time.Time, reason string) (previous string) {
	if !st.lastRecover.IsZero() && now.Sub(st.lastRecover) >= addrRecoverQuiet {
		st.streak = 0
	}
	st.streak++
	st.lastRecover = now

	previous = st.announced
	st.announced = st.local
	st.observedDirty = false
	// Our own move changes what the beacon sees too. Forget the old value
	// so its next reply becomes the baseline instead of a second change.
	if reason == addrReasonLocal {
		st.observed = ""
	}
	if reason == addrReasonRegistry {
		st.registryRetries--
	} else {
		st.registryRetries = 0
	}
	return previous
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
// control plane, and whether there is a route at all.
type addrSourceFn func() (ip string, ok bool)

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
// the tunnel currently uses (it can migrate, so it is read every time), or,
// for a daemon with no beacon, toward the registry.
func (d *Daemon) addrWatchSource() addrSourceFn {
	var registry *net.UDPAddr // resolved once; only the route to it matters
	var nextResolve time.Time // a failed lookup is not repeated every second
	return func() (string, bool) {
		if b := d.tunnels.BeaconUDPAddr(); b != nil {
			return routeSourceIP(b)
		}
		if registry == nil && d.config.RegistryAddr != "" && !time.Now().Before(nextResolve) {
			registry, _ = net.ResolveUDPAddr("udp", d.config.RegistryAddr)
			nextResolve = time.Now().Add(30 * time.Second)
		}
		return routeSourceIP(registry)
	}
}

func (d *Daemon) addrWatchLoop() {
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
			d.addrWatchTick(st, src, time.Now())
		}
	}
}

// addrWatchTick takes one sample and runs a recovery if one is due.
// Extracted for testability — production drives it from addrWatchLoop.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): a panic drops
// this tick and the next one resamples from clean state.
func (d *Daemon) addrWatchTick(st *addrWatchState, src addrSourceFn, now time.Time) (fired bool) {
	defer recoverLayer("L4", "addrWatchTick", d.bus, nil)

	ip, ok := src()
	st.noteLocal(ip, ok)
	if ep := d.tunnels.ObservedEndpoint(); ep != nil {
		st.noteObserved(ep.IP.String())
	}
	reason, due := st.due(now)
	if !due {
		return false
	}
	if !ok {
		// Offline right now. Whatever is owed runs once a route is back.
		return false
	}
	previous := st.began(now, reason)
	if reason == addrReasonLocal {
		// began dropped the observed baseline; drop the stored reply too,
		// so the baseline is taken from a reply that arrives after the
		// move rather than from the one that describes the old address.
		d.tunnels.ForgetObservedEndpoint()
	}
	registryOK := addrWatchRecover(d, reason, previous, st.announced, reason != addrReasonRegistry)
	st.finished(reason, registryOK)
	return true
}

// addrWatchRecover is swapped by tests to observe recoveries without a live
// registry or beacon (mirrors pathWatchResetPeer).
var addrWatchRecover = func(d *Daemon, reason, previous, current string, announce bool) bool {
	return d.recoverFromAddrChange(reason, previous, current, announce)
}

// RecoverFromAddrChange runs the address-change recovery now, as the address
// watcher does when it sees this host's address change: beacon, tunnel peers,
// then registry. It reports whether the registry accepted the
// re-registration. It is not rate-limited; the watcher is what rate-limits.
func (d *Daemon) RecoverFromAddrChange() bool {
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
			defer recoverLayer("L4", "addrAnnounceRetry", d.bus, nil)
			for _, wait := range addrAnnounceRetryDelays {
				select {
				case <-d.stopCh:
					return
				case <-time.After(wait):
				}
				if d.announceToPeers(started) == 0 {
					return
				}
			}
		}()
	}

	// The port may be unchanged but the private addresses we advertise for
	// same-LAN detection are not.
	d.refreshLANAddrs()

	// Registry last: it is TCP with dial retries and may take seconds, and
	// nothing above should wait for it. reestablishTransport also repeats
	// the beacon registration, which costs one datagram and covers a first
	// one lost while the route was still settling.
	registryOK := d.reestablishTransport("addr-change", true)

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
