// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"math/rand"
	"time"
)

// Per-peer path watchdog (L4).
//
// Failure mode this exists for (2026-07-17 incident): a peer session's
// NAT/relay mapping dies for ONE peer while the rest stay healthy. The
// global rx-watchdog (rxwatchdog.go) never fires — any single live peer
// keeps PktsRecv moving — so the dead peer stays dark until an operator
// notices and restarts something. Observed shape: 9 peers healthy,
// list-agents unreachable for hours; a restart "fixed" it only by
// rebuilding EVERY session (and cost minutes of total re-establishment).
//
// Detection: every Ready peer exchanges encrypted keepalives both ways
// at TunnelKeepaliveInterval (25s), so a live path refreshes the peer's
// lastInboundDecrypt at least every ~30s regardless of the peer's
// version. If a peer goes inbound-silent past pathSilenceThreshold, the
// watchdog sends up to pathProbeMax pong-soliciting probes (see
// TunnelManager.SendPathProbe — plain PortPing control frames that every
// deployed version answers; no new wire format). Any authenticated
// inbound — pong or otherwise — clears the suspicion.
//
// Recovery: still silent after the probe budget → the peer's path is
// declared dead and resetPeerPath runs the same in-place re-establish
// sequence as `pilotctl prefer-direct`: drop cached resolve/endpoint,
// drop the tunnel (but not the session keys), clear rekey cooldowns,
// re-resolve, proactively push a fresh PILA and probe. Per-peer,
// in-place, seconds — instead of a full daemon restart that drops every
// healthy session too.
//
// Backward compatibility (v1.10.0 fleet): old peers send keepalives on
// the same cadence (their keepalives bump our lastInboundDecrypt), and
// their handleControlPacket answers non-empty PortPing frames with a
// pong (verified against the v1.10.0 tree: isTunnelKeepalive only
// swallows EMPTY payloads). A peer that neither sends nor pongs within
// the full window is genuinely unreachable — resetting its path state
// is correct on every version, and rate-limited by pathResetCooldown.
const (
	// pathWatchTickInterval is how often the watchdog scans peers.
	pathWatchTickInterval = 10 * time.Second

	// pathSilenceThreshold is how long a Ready peer must be
	// inbound-silent before probing starts. Above 2× the 25s keepalive
	// interval so a single lost keepalive never triggers probing.
	pathSilenceThreshold = 55 * time.Second

	// pathProbeMax is how many pong-soliciting probes are sent (one per
	// tick) before the path is declared dead. With a 10s tick this puts
	// worst-case detection at ~threshold + 3 ticks ≈ 85s.
	pathProbeMax = 3

	// pathResetCooldown rate-limits resets per peer. A peer that is
	// genuinely offline (not a path problem) would otherwise be reset
	// on every probe-budget cycle; the cooldown caps that churn while
	// still retrying often enough to catch the peer coming back.
	pathResetCooldown = 2 * time.Minute
)

// pathPeerState is the watchdog's per-peer memory between ticks.
type pathPeerState struct {
	probesSent  int
	lastResetAt time.Time
}

// pathWatchAction names what a tick decided for one peer — returned
// from pathWatchPeer for tests and logs.
type pathWatchAction string

const (
	pathActionHealthy  pathWatchAction = "healthy"
	pathActionProbe    pathWatchAction = "probe"
	pathActionReset    pathWatchAction = "reset"
	pathActionCooldown pathWatchAction = "cooldown"
	pathActionSkip     pathWatchAction = "skip"
)

// pathWatchResetPeer is swapped by tests to observe resets without a
// live registry/beacon (mirrors the rxWatchdogExit pattern).
var pathWatchResetPeer = func(d *Daemon, nodeID uint32) {
	res := d.resetPeerPath(nodeID)
	slog.Warn("path watchdog: peer path reset",
		"peer_node_id", nodeID,
		"had_tunnel", res.HadTunnel,
		"was_relay_active", res.WasRelayActive,
		"session_kept", res.SessionKept,
		"pila_pushed", res.PilaPushed,
		"resolve_error", res.ResolveErr)
}

func (d *Daemon) pathWatchLoop() {
	if d.config.DisablePathWatch {
		return
	}
	// Independent jitter so this loop does not align with the others.
	// #nosec G404 -- startup-jitter scheduling only (same pattern as the
	// sibling loops); not security-sensitive randomness
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	states := make(map[uint32]*pathPeerState)
	ticker := time.NewTicker(pathWatchTickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.pathWatchTick(states, time.Now())
		}
	}
}

// pathWatchTick runs one scan over all Ready peers. Extracted for
// testability — production drives it from pathWatchLoop.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): the tick
// calls into resolve/rekey machinery; a panic drops this tick and the
// next one rescans from clean state.
func (d *Daemon) pathWatchTick(states map[uint32]*pathPeerState, now time.Time) {
	defer recoverLayer("L4", "pathWatchTick", d.bus, nil)

	ready := d.tunnels.ReadyPeerIDs()
	live := make(map[uint32]bool, len(ready))
	for _, nodeID := range ready {
		live[nodeID] = true
		st := states[nodeID]
		if st == nil {
			st = &pathPeerState{}
			states[nodeID] = st
		}
		d.pathWatchPeer(nodeID, st, now)
	}
	// Drop state for peers that no longer have a session so the map
	// doesn't grow unboundedly.
	for nodeID := range states {
		if !live[nodeID] {
			delete(states, nodeID)
		}
	}
}

// pathWatchPeer evaluates one peer: healthy / probe / reset / cooldown.
func (d *Daemon) pathWatchPeer(nodeID uint32, st *pathPeerState, now time.Time) pathWatchAction {
	last, ok := d.tunnels.LastInboundDecrypt(nodeID)
	if !ok {
		// Session marked Ready but no decrypt recorded yet — key
		// exchange just completed. Leave it to the rekey machinery.
		// (A DESYNCED peer with no usable key is not Ready and so is not
		// scanned here at all — that case is handled event-driven by the
		// rekey-gave-up hook, onRekeyGaveUp, not by this silence loop.)
		return pathActionSkip
	}
	silence := now.Sub(last)

	if silence < pathSilenceThreshold {
		if st.probesSent > 0 {
			slog.Info("path watchdog: peer path recovered",
				"peer_node_id", nodeID,
				"silent_for", silence.Truncate(time.Second).String(),
				"probes_sent", st.probesSent)
			d.publishEvent("tunnel.path_recovered", map[string]any{
				"peer_node_id":       nodeID,
				"silent_for_seconds": int64(silence.Seconds()),
				"probes_sent":        st.probesSent,
			})
		}
		st.probesSent = 0
		return pathActionHealthy
	}

	// Inside the post-reset cooldown: don't re-probe/re-reset a peer
	// that is likely just offline.
	if !st.lastResetAt.IsZero() && now.Sub(st.lastResetAt) < pathResetCooldown {
		return pathActionCooldown
	}

	if st.probesSent < pathProbeMax {
		st.probesSent++
		if err := d.tunnels.SendPathProbe(nodeID); err != nil {
			slog.Debug("path watchdog: probe send failed",
				"peer_node_id", nodeID, "attempt", st.probesSent, "err", err)
		}
		return pathActionProbe
	}

	// Probe budget exhausted with no authenticated inbound: the path is
	// dead. Reset it in place.
	slog.Warn("path watchdog: peer inbound-silent past probe budget — resetting path",
		"peer_node_id", nodeID,
		"silent_for", silence.Truncate(time.Second).String(),
		"probes_sent", st.probesSent)
	d.publishEvent("tunnel.path_suspect", map[string]any{
		"peer_node_id":       nodeID,
		"silent_for_seconds": int64(silence.Seconds()),
		"probes_sent":        st.probesSent,
	})
	pathWatchResetPeer(d, nodeID)
	st.probesSent = 0
	st.lastResetAt = now
	return pathActionReset
}

// peerPathReset reports what resetPeerPath found and did.
type peerPathReset struct {
	HadTunnel      bool
	WasRelayActive bool
	WasRelayPinned bool
	SessionKept    bool // an established session survived the reset
	PilaPushed     bool
	ResolveErr     string
}

// resetPeerPath drops a peer's tunnel + sticky routing state and
// proactively re-establishes, so the next traffic takes a freshly
// resolved + punched path. Shared by the prefer-direct IPC handler
// (operator-initiated) and the path watchdog (automatic).
//
// Step-by-step rationale (kept from the original prefer-direct
// implementation — see the Mac↔GCP-VM dual-NAT postmortem):
//
//   - Unpin relay (but keep it ACTIVE) so the proactive PILA below still
//     travels via the beacon relay when that is the only working path,
//     while a future direct receive can promote the path.
//   - forgetPeerResolution drops the cached resolve/endpoint so
//     ensureTunnel hits the registry fresh instead of short-circuiting.
//   - RemovePeerPath wipes the tunnel + per-peer metadata but KEEPS the
//     session keys (see RemovePeerPath for why dropping them wedged the
//     peer until a restart). It also wipes the relay flags as a side
//     effect, so the captured relay-active state is re-applied (without
//     the pin) right after.
//   - ClearLastRekeyReq / ClearRekeyGaveUp lift the per-peer rekey
//     cooldowns that survive RemovePeerPath — without this the recovery PILA
//     would be silently skipped by the 3s rate gate.
//   - ensureTunnel + sendKeyExchangeToNode push a fresh signed PILA
//     immediately, making recovery deterministic instead of waiting for
//     the peer's next keepalive. Best-effort: with the registry
//     unreachable the state reset still happened and the next inbound
//     packet from the peer triggers the rekey path.
//
// When a session survived (SessionKept), the reset works for both
// possible states of the peer, with no second reset and no restart:
//
//   - The peer still holds its half (the 2026-09-23 case): the PILA is a
//     same-session keepalive to it, and the path probe sent right after
//     gets a pong within one RTT on a live path, refreshing liveness.
//   - The peer lost its half (e.g. a v1.13 peer's own reset or drop gate
//     threw it away): the PILA lets it re-derive, and it replies. Its
//     re-derived half restarts its send counter under a new nonce prefix;
//     envelope.DecryptFrame recognises the new epoch and gives it a fresh
//     replay window, so its first frame (the pong) is accepted instead of
//     tripping the aged replay fast-drop on our kept half. Our send
//     counter simply continues, which its fresh window accepts.
//
// Dropping our keys on a later reset (main's behaviour) is deliberately
// NOT used as an escalation: by the time a second reset could fire, the
// peer has re-derived from our first PILA, so a drop would leave US
// keyless against a peer holding a fresh session — the state v1.11–v1.13
// peers never answer.
//
// For a kept session the PILA is fire-and-forget: its pending rekey is
// cleared right away. A peer holding the session answers it with
// nothing, so the rekey could only clear on an inbound decrypt; if the
// one probe or its pong was lost, the retransmits would flip a healthy
// direct peer to relay after ~4s (RekeyRelayFallbackAfter) and give up
// after ~20s, firing onRekeyGaveUp's full reset for nothing. A peer that
// lost its half does not need our retransmits either: it keeps sending
// its own PILAs (its pending rekey, or "no key" on our probe/keepalives),
// and HandleAuthFrame answers those once it has been silent for
// KeyExchangeReplyStaleThreshold. Liveness of a kept session is the path
// watchdog's job, and the session's lastInboundDecrypt survives the
// reset so the watchdog keeps measuring it.
//
// If the re-resolve fails, a kept session is left detached (no tm.peers
// entry, as on main); the peer's next frame or key exchange re-attaches
// it, and ReapDetachedSessions drops it if the peer stays silent.
func (d *Daemon) resetPeerPath(nodeID uint32) peerPathReset {
	res := peerPathReset{
		HadTunnel:      d.tunnels.HasPeer(nodeID),
		WasRelayActive: d.tunnels.IsRelayPeer(nodeID),
		WasRelayPinned: d.tunnels.IsRelayPinned(nodeID),
	}

	if res.WasRelayPinned {
		d.tunnels.SetRelayPeerPinned(nodeID, false)
	}

	d.forgetPeerResolution(nodeID)

	if res.HadTunnel {
		d.tunnels.RemovePeerPath(nodeID)
	}
	res.SessionKept = d.tunnels.IsEncrypted(nodeID)
	if res.WasRelayActive {
		d.tunnels.SetRelayPeer(nodeID, true)
	}

	d.tunnels.ClearLastRekeyReq(nodeID)
	d.tunnels.ClearRekeyGaveUp(nodeID)

	// Guarded for watchdog-driven callers in minimal configurations
	// (tests, registry-less setups): the IPC path always has a regConn.
	if d.reg() == nil {
		res.ResolveErr = "no registry connection"
		return res
	}
	if err := d.ensureTunnel(nodeID); err != nil {
		res.ResolveErr = err.Error()
	} else {
		d.tunnels.sendKeyExchangeToNode(nodeID)
		res.PilaPushed = true
		if res.SessionKept {
			// Fire-and-forget (see above): no retransmits, no relay
			// fallback, no give-up for a session that is still installed.
			d.tunnels.clearPendingRekey(nodeID)
			if err := d.tunnels.SendPathProbe(nodeID); err != nil {
				slog.Debug("path reset: probe send failed", "peer_node_id", nodeID, "err", err)
			}
		}
	}
	return res
}

// gaveUpResetCooldown bounds how often a single peer's path is reset in
// response to a rekey-gave-up event. The rekey machinery re-arms roughly
// every RekeyRetransmitInterval*MaxRekeyAttempts + rekeyGaveUpCooldown
// (~30s) for a persistently-desynced peer; this cooldown prevents a
// genuinely-offline peer from triggering a resolve/punch every cycle.
const gaveUpResetCooldown = 30 * time.Second

// onRekeyGaveUp is the daemon-owned handler wired to the keyexchange
// gave-up hook (SetRekeyGaveUpHook). A peer the rekey machinery has
// abandoned is desynced — no usable key, so it is NOT Ready and the
// inbound-silence path watchdog never scans it. This is the recovery
// path: reset the peer (drop cached endpoint + tunnel, re-resolve fresh,
// re-punch, push a fresh PILA) so a working session can re-establish.
// Runs the reset asynchronously (it does registry I/O) and rate-limits
// per peer so a flapping/offline peer can't storm resolves. Fired from
// the keyexchange retransmit loop goroutine.
func (d *Daemon) onRekeyGaveUp(nodeID uint32) {
	now := time.Now()
	d.gaveUpResetMu.Lock()
	if last, ok := d.lastGaveUpReset[nodeID]; ok && now.Sub(last) < gaveUpResetCooldown {
		d.gaveUpResetMu.Unlock()
		return
	}
	d.lastGaveUpReset[nodeID] = now
	// Opportunistic prune so the map can't grow without bound.
	if len(d.lastGaveUpReset) > 1024 {
		for id, t := range d.lastGaveUpReset {
			if now.Sub(t) > 5*gaveUpResetCooldown {
				delete(d.lastGaveUpReset, id)
			}
		}
	}
	d.gaveUpResetMu.Unlock()

	go func() {
		defer recoverLayer("L4", "onRekeyGaveUp", d.bus, nil)
		res := gaveUpResetPeer(d, nodeID)
		slog.Warn("rekey gave up (session desync) — reset peer path",
			"peer_node_id", nodeID,
			"had_tunnel", res.HadTunnel,
			"was_relay_active", res.WasRelayActive,
			"session_kept", res.SessionKept,
			"pila_pushed", res.PilaPushed,
			"resolve_error", res.ResolveErr)
		d.publishEvent("tunnel.path_suspect", map[string]any{
			"peer_node_id": nodeID,
			"reason":       "rekey_gave_up",
		})
	}()
}

// gaveUpResetPeer is swapped by tests to observe the reset without a live
// registry/beacon (mirrors pathWatchResetPeer).
var gaveUpResetPeer = func(d *Daemon, nodeID uint32) peerPathReset {
	return d.resetPeerPath(nodeID)
}
