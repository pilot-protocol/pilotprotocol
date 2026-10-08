// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"sync/atomic"
	"time"
)

// PeerIdleAfter is how long a peer may go without application traffic
// before the daemon stops maintaining its path in the background.
//
// The daemon keeps a session warm with three periodic jobs: NAT keepalives
// every TunnelKeepaliveInterval, path-watchdog probes when the peer goes
// quiet, and a direct-path upgrade attempt (registry lookup, beacon punch,
// five probes) every RelayProbeInterval for each relayed peer. All three
// ran for every peer the daemon had ever exchanged keys with, forever: a
// public service agent that had answered a few thousand clients spent
// about 1,600 packets a second on them while serving a few requests a
// minute.
//
// Sending to an idle peer works as before: the first packet re-establishes
// the path through the usual fallbacks (address learning, blackhole
// detection, relay) if a NAT mapping expired in the meantime. Five minutes
// after the last frame either way, the stale-peer reaper drops the peer
// (reapStalePeers), which the keepalives used to prevent; the next contact
// then runs a fresh key exchange, as first contact does. A peer with an open
// connection is never idle.
var PeerIdleAfter = 2 * time.Minute

// peerActivity records, per peer, when application traffic last went to or
// came from it. Path upkeep (keepalives, path probes, upgrade probes, key
// exchange) is not application traffic and does not count.
type peerActivity struct {
	mu sync.RWMutex
	m  map[uint32]*atomic.Int64 // unix nanoseconds
}

func newPeerActivity() *peerActivity {
	return &peerActivity{m: make(map[uint32]*atomic.Int64)}
}

func (a *peerActivity) note(nodeID uint32, now time.Time) {
	a.mu.RLock()
	v := a.m[nodeID]
	a.mu.RUnlock()
	if v == nil {
		a.mu.Lock()
		if v = a.m[nodeID]; v == nil {
			v = new(atomic.Int64)
			a.m[nodeID] = v
		}
		a.mu.Unlock()
	}
	v.Store(now.UnixNano())
}

// last reports the last activity, and false when none was ever recorded.
func (a *peerActivity) last(nodeID uint32) (time.Time, bool) {
	a.mu.RLock()
	v := a.m[nodeID]
	a.mu.RUnlock()
	if v == nil {
		return time.Time{}, false
	}
	return time.Unix(0, v.Load()), true
}

func (a *peerActivity) forget(nodeID uint32) {
	a.mu.Lock()
	delete(a.m, nodeID)
	a.mu.Unlock()
}

// noteAppActivity marks application traffic to or from a peer.
func (tm *TunnelManager) noteAppActivity(nodeID uint32) {
	if tm.activity != nil {
		tm.activity.note(nodeID, time.Now())
	}
}

// SetOpenConnPeers installs the daemon's view of which peers have an open
// connection; such a peer is never idle however quiet the connection is.
func (tm *TunnelManager) SetOpenConnPeers(fn func() map[uint32]bool) {
	tm.openConnPeers = fn
}

// idleFilter returns a predicate reporting whether a peer is idle at now.
// It reads the open-connection set once, so callers sweeping many peers
// pay for it once per sweep. A peer with no recorded activity counts as
// active: every session records activity when it is first established, so
// only state that predates tracking falls in that case.
func (tm *TunnelManager) idleFilter(now time.Time) func(nodeID uint32) bool {
	var open map[uint32]bool
	if tm.openConnPeers != nil {
		open = tm.openConnPeers()
	}
	return func(nodeID uint32) bool {
		if PeerIdleAfter <= 0 || tm.activity == nil || open[nodeID] {
			return false
		}
		last, ok := tm.activity.last(nodeID)
		if !ok {
			return false
		}
		return now.Sub(last) > PeerIdleAfter
	}
}

// peerInUse reports whether a peer has an open connection or carried
// application traffic within PeerIdleAfter. Unlike idleFilter, a peer with
// no recorded activity is not in use: it is one this node only ever
// exchanged upkeep with (a key request it never answered, a frame it could
// not decrypt). With PeerIdleAfter off every peer is in use, as before
// idleness was tracked.
func (tm *TunnelManager) peerInUse(nodeID uint32, now time.Time) bool {
	if PeerIdleAfter <= 0 || tm.activity == nil {
		return true
	}
	if tm.openConnPeers != nil && tm.openConnPeers()[nodeID] {
		return true
	}
	last, ok := tm.activity.last(nodeID)
	return ok && now.Sub(last) <= PeerIdleAfter
}

// PeerIdle reports whether one peer is idle now.
func (tm *TunnelManager) PeerIdle(nodeID uint32) bool {
	return tm.idleFilter(time.Now())(nodeID)
}
