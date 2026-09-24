// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/routing"
)

// probeBeaconsParallel sends a discover probe to each beacon in parallel
// and returns a map of addr → measured RTT for those that responded within
// timeout. Probes use an ephemeral UDP socket and never touch the live
// tunnel socket. Called only when BeaconRTTProbe feature flag is set.
func (d *Daemon) probeBeaconsParallel(list []string, timeout time.Duration) map[string]time.Duration {
	type result struct {
		addr string
		rtt  time.Duration
	}
	ch := make(chan result, len(list))
	d.addrMu.RLock()
	nodeID := d.nodeID
	d.addrMu.RUnlock()
	for _, addr := range list {
		go func(a string) {
			rtt, err := routing.ProbeBeaconRTT(a, nodeID, timeout)
			if err == nil {
				ch <- result{a, rtt}
			} else {
				ch <- result{a, 0}
			}
		}(addr)
	}
	rttMap := make(map[string]time.Duration, len(list))
	for range list {
		r := <-ch
		if r.rtt > 0 {
			rttMap[r.addr] = r.rtt
		}
	}
	return rttMap
}

// Pre-extraction names re-exposed as aliases / thin shims over routing/.
// Canonical definitions live at pkg/daemon/routing/discovery.go (L4).

const (
	beaconRefreshInterval = routing.BeaconRefreshInterval
	beaconRefreshJitter   = routing.BeaconRefreshJitter
	beaconCacheFilename   = routing.BeaconCacheFilename
	beaconCacheMaxAge     = routing.BeaconCacheMaxAge
)

type beaconLister = routing.BeaconLister
type beaconCacheEntry = routing.BeaconCacheEntry
type beaconSelectionState = routing.BeaconSelectionState
type refreshDecision = routing.RefreshDecision

func newBeaconSelectionState(bootstrap []string) *beaconSelectionState {
	return routing.NewBeaconSelectionState(bootstrap)
}

func fetchBeaconList(client beaconLister) ([]string, error) {
	return routing.FetchBeaconList(client)
}

func beaconCachePath(identityPath string) string {
	return routing.BeaconCachePath(identityPath)
}

func saveBeaconCache(identityPath string, addrs []string) error {
	return routing.SaveBeaconCache(identityPath, addrs)
}

func loadBeaconCache(identityPath string) ([]string, error) {
	return routing.LoadBeaconCache(identityPath)
}

func computeRefreshDecision(state *beaconSelectionState, discovered []string, identityKey []byte) refreshDecision {
	return routing.ComputeRefreshDecision(state, discovered, identityKey)
}

func initialJitter() time.Duration {
	return routing.InitialJitter()
}

// beaconRefreshLoop runs in a background goroutine and refreshes the
// daemon's beacon selection from the registry every beaconRefreshInterval
// (60s) plus initial jitter. Started from Daemon.Start() after
// registration. Exits when d.stopCh closes.
//
// Per-tick work:
//  1. Call regConn.Send({"type":"beacon_list"}). On error: log+skip;
//     keep current pick. (Don't repick on registry blip.)
//  2. Merge with bootstrap; compute decision against current state.
//  3. If ShouldSwap: SetBeaconAddr(newPick), RegisterWithBeacon, log.
//  4. Persist the merged list to disk so a future cold-start with
//     unreachable registry can fall back to a recent list.
//
// Cold-start fallback (registry unreachable on FIRST tick): if the
// daemon's bootstrap list is single-entry AND fetch fails AND a cache
// file exists, the cached list is merged into the bootstrap so the
// daemon at least gets a chance at the previously-known beacons.
// (We don't run this on every tick — only at first-tick to keep the
// hot path simple.)
func (d *Daemon) beaconRefreshLoop() {
	if d.beaconSelection == nil || d.reg() == nil || d.identity == nil {
		// Nothing to refresh — single-beacon static config without
		// identity/registry. Exit cleanly.
		return
	}

	// Initial jitter (0..beaconRefreshJitter) avoids fleet thundering
	// herd when daemons restart simultaneously after a registry restart.
	select {
	case <-time.After(initialJitter()):
	case <-d.stopCh:
		return
	}

	firstTick := true
	ticker := time.NewTicker(beaconRefreshInterval)
	defer ticker.Stop()

	for {
		d.beaconRefreshTick(firstTick)
		firstTick = false

		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// beaconRefreshTick runs one iteration of the discovery loop. Extracted
// from beaconRefreshLoop for testability — production drives this from
// the loop; tests can drive it directly.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): the
// discovery tick walks registry-supplied data through user-defined
// hash/sort logic and disk I/O. A panic here would otherwise kill the
// daemon; instead we drop this tick (current beacon pick stays in
// effect) and continue. The next tick will retry from a clean state.
func (d *Daemon) beaconRefreshTick(firstTick bool) {
	defer recoverLayer("L4", "beaconRefreshTick", d.bus, nil)

	// Concrete-pointer nil check (NOT the interface form). A typed-nil
	// *registry.Client wrapped in the beaconLister interface is not
	// equal to interface nil, so fetchBeaconList's `client == nil`
	// guard wouldn't catch it — and (*Client).Send panics on a nil
	// receiver. Bail early from this tick if no registry connection.
	if d.reg() == nil {
		if firstTick {
			slog.Debug("beacon discovery skipped (no registry connection)")
		}
		return
	}

	discovered, err := fetchBeaconList(d.reg())
	if err != nil {
		// On the FIRST tick, try the on-disk cache as a fallback —
		// the registry may have been briefly unreachable at startup.
		// On subsequent ticks, just keep the current pick.
		if firstTick {
			cached, cacheErr := loadBeaconCache(d.config.IdentityPath)
			if cacheErr == nil && len(cached) > 0 {
				// Reject the cache if it is older than BeaconCacheMaxAge.
				// A stale cache keeps the daemon trying offline beacons
				// indefinitely; fall through to the bootstrap list instead.
				savedAt, savedAtErr := routing.BeaconCacheSavedAt(d.config.IdentityPath)
				if savedAtErr == nil {
					age := time.Since(savedAt)
					if age > beaconCacheMaxAge {
						slog.Warn("beacon discovery: rejecting stale on-disk cache",
							"err", err,
							"cache_age", age.Truncate(time.Second),
							"max_age", beaconCacheMaxAge,
						)
						slog.Debug("beacon discovery skipped (registry error, stale cache)",
							"err", err)
						return
					}
				}
				slog.Info("beacon discovery: using on-disk cache (registry unreachable)",
					"err", err, "cached_count", len(cached))
				discovered = cached
			} else {
				slog.Debug("beacon discovery skipped (registry error, no usable cache)",
					"err", err)
				return
			}
		} else {
			slog.Debug("beacon discovery skipped (registry error)", "err", err)
			return
		}
	}

	// Take identityMu.RLock for the read — RotateKey writes d.identity under
	// identityMu.Lock, and the §4.8 stress test's rekey group is concurrent
	// with the beacon refresh ticker.
	d.identityMu.RLock()
	identityPubKey := d.identity.PublicKey
	d.identityMu.RUnlock()
	decision := computeRefreshDecision(d.beaconSelection, discovered, identityPubKey)

	// BeaconRTTProbe (feature flag): probe each beacon and override the
	// hash pick when it is >2× slower than the fastest reachable beacon.
	// Probes run in parallel with a 2s timeout each; total added latency
	// per refresh tick is bounded by one probe round-trip (~200ms typical,
	// 2s max). The override is logged at Debug so ablation tests can grep
	// for "beacon RTT probe".
	// Compat mode has no UDP path (the probes would only time out or trip
	// an egress guard), so Start logs once and the probe never runs.
	if d.config.BeaconRTTProbe && d.config.TransportMode != "compat" && len(decision.NewList) > 1 {
		rttMap := d.probeBeaconsParallel(decision.NewList, 2*time.Second)
		if len(rttMap) > 0 {
			rttPick := routing.PickBeaconWithRTT(decision.NewList, identityPubKey, rttMap)
			if rttPick != "" && rttPick != decision.NewPick {
				slog.Debug("beacon RTT probe overrides hash pick",
					"hash_pick", decision.NewPick,
					"rtt_pick", rttPick)
				decision.NewPick = rttPick
			}
			// Recompute ShouldSwap based on final pick.
			currentPick := d.beaconSelection.GetCurrentPick()
			decision.ShouldSwap = decision.NewPick != currentPick
		}
	}

	if !decision.ShouldSwap {
		// Refresh the cache even on no-op so it tracks the latest
		// known list — useful for cold-start fallback.
		// Save only the discovered (registry-supplied, already filtered)
		// list, NOT the merged list. Bootstrap entries come from the
		// -beacon flag at runtime and must not be written to disk:
		// a private bootstrap (e.g. swarm VMs on 10.128.0.x) would
		// be re-injected into the cache every 60s and survive into
		// off-VPC daemons that cold-start from the file.
		if len(discovered) > 0 {
			_ = saveBeaconCache(d.config.IdentityPath, discovered)
		}
		return
	}

	if decision.NewPick == "" {
		// Empty merged list — no beacons known. Keep current.
		return
	}

	if err := d.tunnels.SetBeaconAddr(decision.NewPick); err != nil {
		slog.Warn("beacon refresh: SetBeaconAddr failed", "addr", decision.NewPick, "err", err)
		return
	}
	d.beaconSelection.ApplyRefreshDecision(decision)
	d.tunnels.RegisterWithBeacon()
	if err := saveBeaconCache(d.config.IdentityPath, discovered); err != nil {
		slog.Debug("beacon cache save failed (non-fatal)", "err", err)
	}
	slog.Info("beacon refresh: pick changed",
		"new", decision.NewPick,
		"available", len(decision.NewList))
}
