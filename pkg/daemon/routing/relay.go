// SPDX-License-Identifier: AGPL-3.0-or-later

package routing

import (
	"net"
	"time"
)

// SetRelayPeer marks a peer as needing relay through the beacon. Pinning
// is left clear — the relay flag may be auto-cleared by direct-path
// observations. Use SetRelayPeerPinned for authoritative-signal cases.
func (m *Manager) SetRelayPeer(nodeID uint32, relay bool) {
	m.mu.Lock()
	m.relayPeers[nodeID] = relay
	m.mu.Unlock()
}

// SetRelayPeerPinned marks the peer as relay-bound and pins the flag —
// ClearRelayOnDirect will never auto-flip a pinned peer back to direct
// based on observed packet sources. Used by ensureTunnel when the
// registry's resolve response carries relay_only=true, or by writeFrame
// when an empirically-confirmed signal triggers the flip.
func (m *Manager) SetRelayPeerPinned(nodeID uint32, relay bool) {
	m.mu.Lock()
	m.relayPeers[nodeID] = relay
	m.relayPinned[nodeID] = relay
	if !relay {
		// Caller is explicitly clearing both flag and pin.
		delete(m.relayPinned, nodeID)
	}
	m.mu.Unlock()
}

// UnpinRelayPeer clears the pin on a peer and leaves its relay flag as it
// is. Traffic keeps using the relay; ClearRelayOnDirect may now move the
// peer back to direct once DirectClearsRequired direct packets arrive.
// SetRelayPeerPinned(id, false) is not a substitute: it clears the relay
// flag too, which sends traffic direct before anything has shown the
// direct path works.
func (m *Manager) UnpinRelayPeer(nodeID uint32) {
	m.mu.Lock()
	delete(m.relayPinned, nodeID)
	m.mu.Unlock()
}

// IsRelayPeer reports whether the peer is currently in relay mode.
func (m *Manager) IsRelayPeer(nodeID uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.relayPeers[nodeID]
}

// IsRelayPinned reports whether the peer's relay flag is pinned.
func (m *Manager) IsRelayPinned(nodeID uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.relayPinned[nodeID]
}

// RelayPeerIDs returns the node IDs of all relay-flagged peers.
func (m *Manager) RelayPeerIDs() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var ids []uint32
	for id, isRelay := range m.relayPeers {
		if isRelay {
			ids = append(ids, id)
		}
	}
	return ids
}

// RelayPeerCount returns the number of peers currently in relay mode.
// Cheaper than RelayPeerIDs when only the size matters.
func (m *Manager) RelayPeerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.relayPeers)
}

// AdmitRelayFromBeacon is called when an inbound key-exchange or
// "no key" rekey arrives from the beacon's listen port. It atomically:
//
//   - returns true if the peer was admitted (relay flag set + pinned),
//   - returns false if the relay-peer cap is full and the peer was a
//     fresh entry (no prior relay flag).
//
// Caller (TunnelManager) handles the surrounding peers-map mutation.
func (m *Manager) AdmitRelayFromBeacon(peerNodeID uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, capped := m.relayPeers[peerNodeID]; !capped && len(m.relayPeers) >= MaxRelayPeers {
		return false
	}
	m.relayPeers[peerNodeID] = true
	m.relayPinned[peerNodeID] = true
	return true
}

// MarkRelayActivatedIfHadCrypto is called from HandleRelayDeliver. It
// returns:
//
//   - admitted: false if hadCrypto && relay-cap reached for fresh
//     entry — caller should drop the relay packet.
//   - newlyActivated: true if hadCrypto && this is the first time the
//     peer was added to relayPeers — caller should publish the
//     "tunnel.relay_activated" event.
//   - shouldAliasPeer: true if hadCrypto && peer was promoted to
//     relayPeers and caller should alias peers[srcNodeID] = beaconAddr
//     when no entry exists.
func (m *Manager) MarkRelayActivatedIfHadCrypto(srcNodeID uint32, hadCrypto bool) (admitted, newlyActivated, shouldAliasPeer bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	wasRelay := m.relayPeers[srcNodeID]
	if hadCrypto {
		if !wasRelay && len(m.relayPeers) >= MaxRelayPeers {
			return false, false, false
		}
		m.relayPeers[srcNodeID] = true
		return true, !wasRelay, true
	}
	return true, false, false
}

// ClearRelayOnDirect is called from the L7 handleEncrypted path after a
// successful decrypt. Resets blackholeMissCount unconditionally. For
// unpinned relay peers, increments directClearCount and clears the relay
// flag once DirectClearsRequired consecutive direct packets have arrived.
// Pinned peers (registry relay_only=true, beacon-admitted symmetric NAT)
// are never auto-cleared — only an explicit SetRelayPeerPinned(id, false)
// can clear them.
func (m *Manager) ClearRelayOnDirect(peerNodeID uint32, from *net.UDPAddr) bool {
	if from == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.beaconAddr != nil && from.IP.Equal(m.beaconAddr.IP) && from.Port == m.beaconAddr.Port {
		// Relay decrypt — peer is alive. Reset the blackhole miss
		// counter so writeFrame doesn't trip the silent-direct heuristic
		// while the peer is reachable via relay. This prevents the
		// "8s silent → flip to relay-pin" auto-flip from firing for
		// peers that happen to route their first replies through the
		// beacon (race vs the hole-punched direct path). Without this,
		// every dialer-initiated session would eventually pin to relay
		// even when direct is working — the very regression the patches
		// in handleRelayDeliver / onKeyInstalled / maybeRequestRekey
		// were designed to prevent.
		m.blackholeMissCount[peerNodeID] = 0
		return false
	}
	// A direct packet just arrived. Reset blackholeMissCount unconditionally.
	m.blackholeMissCount[peerNodeID] = 0
	if !m.relayPeers[peerNodeID] {
		return false
	}
	if m.relayPinned[peerNodeID] {
		// Authoritative pin (registry or beacon-admitted symmetric NAT) —
		// do not auto-clear on direct observations.
		return false
	}
	m.directClearCount[peerNodeID]++
	if m.directClearCount[peerNodeID] >= DirectClearsRequired {
		m.relayPeers[peerNodeID] = false
		m.directClearCount[peerNodeID] = 0
		return true
	}
	return false
}

// PeerStateEntries counts the entries in every per-peer map this manager
// keeps. It drops back as peers are removed (RemovePeer): a count that
// only grows is per-peer state that outlives its peer.
func (m *Manager) PeerStateEntries() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.relayPeers) + len(m.relayPinned) + len(m.lastOutboundSend) +
		len(m.firstOutboundSend) + len(m.sendErrCount) + len(m.lastDirectRecv) +
		len(m.blackholeMissCount) + len(m.directClearCount)
}

// PeerIDs lists every node this manager holds per-peer state for.
func (m *Manager) PeerIDs() []uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	seen := make(map[uint32]struct{}, len(m.lastOutboundSend))
	for _, t := range []map[uint32]time.Time{m.lastOutboundSend, m.firstOutboundSend, m.lastDirectRecv} {
		for id := range t {
			seen[id] = struct{}{}
		}
	}
	for _, b := range []map[uint32]bool{m.relayPeers, m.relayPinned} {
		for id := range b {
			seen[id] = struct{}{}
		}
	}
	for _, c := range []map[uint32]int{m.sendErrCount, m.blackholeMissCount, m.directClearCount} {
		for id := range c {
			seen[id] = struct{}{}
		}
	}
	ids := make([]uint32, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	return ids
}

// RemovePeer wipes per-peer L4 state.
func (m *Manager) RemovePeer(nodeID uint32) {
	m.mu.Lock()
	delete(m.relayPeers, nodeID)
	delete(m.relayPinned, nodeID)
	delete(m.lastOutboundSend, nodeID)
	delete(m.firstOutboundSend, nodeID)
	delete(m.sendErrCount, nodeID)
	delete(m.lastDirectRecv, nodeID)
	delete(m.blackholeMissCount, nodeID)
	delete(m.directClearCount, nodeID)
	m.mu.Unlock()
}
