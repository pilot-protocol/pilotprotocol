// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Inbound-path watchdog (L4).
//
// Failure mode this exists for (2026-07-13 incident): a daemon with days
// of uptime keeps transmitting — keepalives, beacon registrations, sends —
// while the inbound UDP path is silently dead (stale NAT / relay mapping
// the transport never re-establishes). Control plane stays healthy: the
// registry heartbeat is TCP and keeps succeeding, so trustRepublishLoop
// never re-registers, and every peer/service-agent contact fails with
// "cannot connect (data exchange port 1001)" until an operator restarts
// the daemon. Observed signature: 43.5 MB / 572K pkts sent vs 102 KB /
// 1443 pkts received over 2d19h, 0 direct connections.
//
// Detection: PktsRecv (delivered tunnel packets — peer keepalives bump it,
// so any live mutual peer feeds it) stalls for rxSilenceThreshold while
// PktsSent keeps growing. TunnelManager.LastRecvNano (any raw datagram,
// including beacon replies) is read alongside to tell a dead socket path
// from a dead session layer in the logs.
//
// Recovery escalates:
//  1. Soft (up to rxWatchdogSoftMax ticks): RegisterWithBeacon — the
//     MsgDiscover reply doubles as an active inbound probe — plus
//     reRegister with the registry. Heals transient beacon endpoint
//     staleness without touching the transport.
//  2. Hard: exit with rxWedgeExitCode, after a graceful shutdown that
//     stops the plugins (and so the app-store's child apps) — see
//     exit.go. launchd (KeepAlive SuccessfulExit=false) and systemd
//     (Restart=always) respawn the daemon with a fresh socket +
//     registration — the remedy that is known to clear the wedge.
//     Guarded so it cannot flap:
//     only after PktsRecv has progressed at least once this process
//     (a never-worked config soft-recovers forever instead of
//     boot-looping), only when the registry was reachable within
//     rxWedgeRegistryFresh (otherwise the whole network is down and a
//     restart fixes nothing), and only after rxWedgeMinUptime.
const (
	// rxWatchdogTickInterval is how often the watchdog samples counters.
	rxWatchdogTickInterval = 30 * time.Second

	// suspendGapThreshold is how late a tick must be before the watchdog
	// concludes this process was not running — a laptop sleeping, a paused
	// VM, a migrated hypervisor guest.
	//
	// 4x the tick interval: far beyond scheduler jitter or a slow tick, but
	// still under the shortest realistic lid-close. Deliberately measured
	// from observed ticker lateness rather than any OS power API, so it
	// works identically on macOS, Linux and inside a VM, and needs no
	// platform-specific code (there was none in the tree at all).
	suspendGapThreshold = 4 * rxWatchdogTickInterval

	// rxSilenceThreshold is how long PktsRecv must stall (with tx active)
	// before the first soft recovery fires.
	rxSilenceThreshold = 3 * time.Minute

	// rxSilenceMinSentDelta gates on tx activity: at least this many
	// packets sent since the last rx progress. An idle daemon (no peers,
	// nothing to send) never triggers.
	rxSilenceMinSentDelta = 30

	// dialWedgeThreshold: consecutive DialConnection timeouts (each a full
	// direct+relay retry budget with no SYN-ACK) that mark the outbound
	// path as wedged. A run this long means separate dials to (typically)
	// distinct peers all failed — implausible unless our own send path is
	// dead, not the peers. This is the PARTIAL wedge the rx-silence check
	// misses: rx keeps trickling (keepalives) so silence never trips, but
	// no new connection can be opened. 4 = at least four back-to-back
	// user-visible dial failures with zero successes in between.
	dialWedgeThreshold = 4

	// rxWatchdogSoftMax is how many consecutive soft recoveries run
	// before the watchdog considers the hard exit.
	rxWatchdogSoftMax = 3

	// rxWedgeMinUptime: never hard-exit a young process. Caps worst-case
	// restart churn if a wedge reappears immediately after respawn.
	rxWedgeMinUptime = 30 * time.Minute

	// rxWedgeRegistryFresh: hard exit requires a successful registry
	// interaction within this window — the wedge signature is data plane
	// dead + control plane alive.
	rxWedgeRegistryFresh = 5 * time.Minute

	// rxWedgeExitCode is the non-zero exit status for the hard escalation.
	// Non-zero so launchd KeepAlive/SuccessfulExit=false respawns; a
	// distinctive value so `pilotctl`/operators can attribute the restart.
	rxWedgeExitCode = 86

	// rxWedgeLoopWindow bounds how far back the restart-loop circuit
	// breaker counts prior hard exits. Exits older than this don't count.
	rxWedgeLoopWindow = 2 * time.Hour

	// rxWedgeLoopMax is how many hard exits within rxWedgeLoopWindow are
	// tolerated before the breaker OPENS and further exits are withheld.
	// The hard exit assumes a restart CLEARS the wedge (stale NAT/relay
	// mapping). When it doesn't — a NAT/firewall/topology change a
	// restart can't fix — the daemon would otherwise boot-loop every
	// ~30-40 min forever (wedge → 3 soft attempts → exit → respawn →
	// wedge → …), each restart dropping every live tunnel for nothing.
	// After this many restarts the breaker keeps the daemon UP and
	// soft-recovering instead, and surfaces the condition for an operator.
	rxWedgeLoopMax = 3
)

// rxWatchdogExit is swapped by tests to observe the hard escalation
// without killing the test process. It requests a graceful shutdown
// followed by exit(code) rather than calling os.Exit directly, so the
// app-store plugin still reaps its child apps (see exit.go).
var rxWatchdogExit = func(code int) {
	requestSupervisorExit(ExitRequest{Code: code, Reason: "rx-wedge"})
}

// rxWatchdogState carries the loop's tick-to-tick memory. Kept as a
// struct (not loop locals) so tests can drive rxWatchdogTick directly,
// mirroring the beaconRefreshTick pattern.
type rxWatchdogState struct {
	lastProgress   time.Time // when recvSeen last advanced
	recvSeen       uint64    // PktsRecv at lastProgress
	sentAtProgress uint64    // PktsSent at lastProgress
	softAttempts   int       // consecutive soft recoveries this silence

	// suspendSeen records that the host suspended during this process's
	// lifetime. It permanently unlocks the "never progressed" guard.
	//
	// That guard withholds the hard exit when PktsRecv has not advanced
	// once this process, on the theory that restarting would reproduce the
	// same state and boot-loop. Sound for a host that never had working
	// inbound — and wrong after a resume, where the transport worked
	// before the gap and a restart is exactly what recovers it. In the
	// field this guard was the dominant blocker: of 344 withheld restarts
	// on one laptop, 301 were "never progressed" and only 4 were the
	// registry check.
	suspendSeen bool
}

// rxWatchdogAction names what a tick did — returned for tests and logs.
type rxWatchdogAction string

const (
	rxActionNone         rxWatchdogAction = ""
	rxActionProgress     rxWatchdogAction = "progress"
	rxActionSoftRecover  rxWatchdogAction = "soft-recover"
	rxActionExitWithheld rxWatchdogAction = "exit-withheld"
	rxActionExit         rxWatchdogAction = "exit"
	rxActionRestartLoop  rxWatchdogAction = "restart-loop-withheld"
)

func (d *Daemon) rxWatchdogLoop() {
	if d.config.DisableRxWatchdog {
		return
	}
	// Independent jitter so this loop does not align with the others.
	// #nosec G404 -- startup-jitter scheduling only (same pattern as the
	// sibling loops in daemon.go); not security-sensitive randomness
	time.Sleep(time.Duration(rand.Int63n(int64(5 * time.Second))))

	st := &rxWatchdogState{
		lastProgress:   time.Now(),
		recvSeen:       atomic.LoadUint64(&d.tunnels.PktsRecv),
		sentAtProgress: atomic.LoadUint64(&d.tunnels.PktsSent),
	}
	ticker := time.NewTicker(rxWatchdogTickInterval)
	defer ticker.Stop()
	lastTick := time.Now()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			if gap := now.Sub(lastTick); gap >= suspendGapThreshold {
				d.rxWatchdogResume(st, now, gap)
			}
			lastTick = now
			if d.rxWatchdogTick(st, now) == rxActionExit {
				// Exit requested; shutdown is in flight. Stop ticking so
				// a slow teardown can't re-escalate and record a second
				// exit against the restart-loop breaker.
				return
			}
		}
	}
}

// rxWatchdogResume handles coming back from a host suspend (laptop lid
// closed, VM paused, hypervisor migration).
//
// This is the gap the watchdog had. On resume every UDP path is stale —
// the NAT mapping the beacon punched is gone, the peer sessions are dead,
// and the pooled registry conn is half-open. Nothing in the daemon noticed:
// there was no suspend/resume awareness anywhere in the tree (no
// IORegisterForSystemPower, no wake notification, nothing), so recovery had
// to wait for the ordinary rx-silence path — which then deadlocked against
// its own safety guard (see the active probe in rxWatchdogTick).
//
// Detection is deliberately clock-agnostic: a ticker set to fire every
// rxWatchdogTickInterval that instead fires suspendGapThreshold late means
// this process was not running. Whether that was a laptop sleeping, a
// paused VM, or brutal CPU starvation does not matter — in every case the
// transport state predating the gap is untrustworthy and re-establishing it
// is both correct and cheap.
//
// Two actions, neither of which restarts anything:
//
//  1. Re-punch and re-register: RegisterWithBeacon refreshes the NAT
//     mapping (its discover reply doubles as an inbound probe) and the
//     registry gets a fresh conn, since the pooled one did not survive the
//     suspend and has no liveness ping of its own.
//  2. Reset the wedge baseline. The pre-suspend counters describe a
//     different epoch: PktsRecv/PktsSent are frozen at their pre-sleep
//     values while lastProgress is hours old, so the very first tick after
//     resume would otherwise read as a multi-hour rx silence and burn soft
//     attempts on a wedge that had not been given a chance to recover yet.
func (d *Daemon) rxWatchdogResume(st *rxWatchdogState, now time.Time, gap time.Duration) {
	defer recoverLayer("L4", "rxWatchdogResume", d.bus, nil)

	slog.Warn("host resumed from suspend — re-establishing transport",
		"gap", gap.Truncate(time.Second).String(),
		"tick_interval", rxWatchdogTickInterval.String())
	d.publishEvent("tunnel.host_resumed", map[string]any{
		"gap_seconds": int64(gap.Seconds()),
	})

	d.tunnels.RegisterWithBeacon()
	if d.reg() != nil {
		// The pooled registry conn cannot have survived the suspend, and it
		// has no half-open detection of its own, so force a fresh one rather
		// than waiting for a request to hang on the dead socket.
		if err := d.forceReconnectRegistry(); err != nil {
			slog.Warn("registry reconnect after resume failed", "error", err)
		} else {
			d.reRegister()
		}
	}

	// Fresh epoch: re-baseline so the first post-resume tick measures
	// recovery, not the suspend.
	st.recvSeen = atomic.LoadUint64(&d.tunnels.PktsRecv)
	st.sentAtProgress = atomic.LoadUint64(&d.tunnels.PktsSent)
	st.lastProgress = now
	st.softAttempts = 0
	st.suspendSeen = true
	d.consecutiveDialTimeouts.Store(0)
}

// rxWatchdogTick runs one watchdog iteration. Extracted for testability —
// production drives it from rxWatchdogLoop; tests drive it directly.
//
// L4 panic boundary (architecture-notes/03-INVARIANTS.md §8): the tick
// calls into beacon/registry re-registration; a panic drops this tick and
// the next one retries from clean state.
func (d *Daemon) rxWatchdogTick(st *rxWatchdogState, now time.Time) (action rxWatchdogAction) {
	defer recoverLayer("L4", "rxWatchdogTick", d.bus, nil)

	recv := atomic.LoadUint64(&d.tunnels.PktsRecv)
	sent := atomic.LoadUint64(&d.tunnels.PktsSent)
	dialTimeouts := d.consecutiveDialTimeouts.Load()

	rxProgressed := recv != st.recvSeen
	// PARTIAL wedge: the outbound path is dead — a run of DialConnection
	// timeouts to (typically) distinct peers with zero successes between
	// them — even though rx is still trickling. rx progress alone no
	// longer counts as healthy while this holds.
	dialWedged := dialTimeouts >= dialWedgeThreshold

	if rxProgressed && !dialWedged {
		if st.softAttempts > 0 {
			slog.Info("transport recovered",
				"silent_for", now.Sub(st.lastProgress).Truncate(time.Second).String(),
				"soft_attempts", st.softAttempts)
			d.publishEvent("tunnel.rx_recovered", map[string]any{
				"silent_for_seconds": int64(now.Sub(st.lastProgress).Seconds()),
				"soft_attempts":      st.softAttempts,
			})
		}
		st.recvSeen = recv
		st.sentAtProgress = sent
		st.lastProgress = now
		st.softAttempts = 0
		return rxActionProgress
	}

	// Keep the rx-silence measure honest even when we don't reset the soft
	// counter: if rx trickled forward (dial-wedged case), advance the
	// baseline so `silence` reflects real inbound stall, not the trickle.
	if rxProgressed {
		st.recvSeen = recv
		st.sentAtProgress = sent
		st.lastProgress = now
	}

	silence := now.Sub(st.lastProgress)
	sentDelta := sent - st.sentAtProgress
	rxSilentWedge := silence >= rxSilenceThreshold && sentDelta >= rxSilenceMinSentDelta

	if !rxSilentWedge && !dialWedged {
		return rxActionNone
	}

	wedgeReason := "inbound-silent"
	if dialWedged {
		wedgeReason = "outbound-dial-wedged"
		if rxSilentWedge {
			wedgeReason = "inbound-silent+outbound-dial-wedged"
		}
	}

	// rawRxAge separates "socket path dead" (old) from "session layer
	// dead" (fresh — datagrams arrive but nothing decrypts/delivers).
	rawRxAge := time.Duration(0)
	if last := d.tunnels.LastRecvTime(); !last.IsZero() {
		rawRxAge = now.Sub(last)
	}

	if st.softAttempts < rxWatchdogSoftMax {
		st.softAttempts++
		slog.Warn("transport wedged while transmitting — attempting soft recovery",
			"reason", wedgeReason,
			"silent_for", silence.Truncate(time.Second).String(),
			"pkts_sent_during_silence", sentDelta,
			"dial_timeouts", dialTimeouts,
			"raw_rx_age", rawRxAge.Truncate(time.Second).String(),
			"attempt", st.softAttempts,
			"max_soft_attempts", rxWatchdogSoftMax)
		d.publishEvent("tunnel.rx_silence", map[string]any{
			"reason":                   wedgeReason,
			"silent_for_seconds":       int64(silence.Seconds()),
			"pkts_sent_during_silence": sentDelta,
			"dial_timeouts":            dialTimeouts,
			"raw_rx_age_seconds":       int64(rawRxAge.Seconds()),
			"attempt":                  st.softAttempts,
		})
		// Re-register with the beacon (re-punches our NAT mapping; the
		// discover reply also doubles as an active inbound probe) and the
		// registry. This is what a manual restart effectively did to clear
		// the partial wedge.
		d.tunnels.RegisterWithBeacon()
		if d.reg() != nil {
			d.reRegister()
		}
		// Reset the dial counter so the next real dial re-tests the path:
		// if recovery worked the next dial succeeds (counter stays 0); if
		// not, failures re-accumulate to threshold and softAttempts climbs
		// toward the hard exit. Avoids a stale counter forcing an exit when
		// no new dials have happened to confirm the wedge persists.
		d.consecutiveDialTimeouts.Store(0)
		return rxActionSoftRecover
	}

	registryAge := time.Duration(-1)
	if ok := d.lastRegistryOKNano.Load(); ok > 0 {
		registryAge = now.Sub(time.Unix(0, ok))
	}
	uptime := now.Sub(d.startTime)
	switch {
	case st.recvSeen == 0 && !st.suspendSeen:
		// Never received a tunnel packet this process — a restart would
		// reproduce the same state (boot loop). Keep soft-recovering.
		//
		// Skipped once the host has suspended: after a resume, "no inbound
		// yet this process" is a symptom of the gap, not evidence that
		// inbound can never work here, and a restart is precisely what
		// clears it.
		slog.Warn("inbound path silent and never progressed — withholding restart, will keep soft-recovering",
			"silent_for", silence.Truncate(time.Second).String())
	case registryAge < 0 || registryAge > rxWedgeRegistryFresh:
		// Registry unreachable too — likely the machine/network is
		// offline, not a wedged transport. Restarting fixes nothing.
		slog.Warn("inbound path silent but registry also unreachable — withholding restart",
			"silent_for", silence.Truncate(time.Second).String(),
			"registry_ok_age", registryAge.Truncate(time.Second).String())
	case uptime < rxWedgeMinUptime:
		slog.Warn("inbound path silent but process too young — withholding restart",
			"silent_for", silence.Truncate(time.Second).String(),
			"uptime", uptime.Truncate(time.Second).String())
	default:
		// Restart-loop circuit breaker. The hard exit is premised on a
		// restart CLEARING the wedge; when it doesn't (a NAT/firewall/
		// topology change no restart can fix), exiting just boot-loops
		// the daemon and drops every live tunnel each cycle. If we have
		// already respawned rxWedgeLoopMax times within rxWedgeLoopWindow
		// (tracked in a sidecar file next to the identity so it survives
		// the respawn), stop exiting: stay up, keep soft-recovering, and
		// surface the condition for an operator.
		exitLog := rxWedgeExitLogPath(d.config.IdentityPath)
		if recent := recentRxWedgeExits(exitLog, now, rxWedgeLoopWindow); len(recent) >= rxWedgeLoopMax {
			slog.Error("transport wedged but restart-loop detected — withholding exit, staying up to soft-recover",
				"reason", wedgeReason,
				"recent_exits", len(recent),
				"window", rxWedgeLoopWindow.String(),
				"silent_for", silence.Truncate(time.Second).String())
			d.publishEvent("tunnel.rx_wedge_restart_loop", map[string]any{
				"reason":             wedgeReason,
				"recent_exits":       len(recent),
				"window_seconds":     int64(rxWedgeLoopWindow.Seconds()),
				"silent_for_seconds": int64(silence.Seconds()),
			})
			st.softAttempts = 0
			return rxActionRestartLoop
		}
		slog.Error("transport wedged — exiting for supervisor respawn",
			"reason", wedgeReason,
			"silent_for", silence.Truncate(time.Second).String(),
			"pkts_sent_during_silence", sentDelta,
			"dial_timeouts", dialTimeouts,
			"raw_rx_age", rawRxAge.Truncate(time.Second).String(),
			"soft_attempts", st.softAttempts,
			"exit_code", rxWedgeExitCode)
		d.publishEvent("tunnel.rx_wedged_exit", map[string]any{
			"reason":                   wedgeReason,
			"silent_for_seconds":       int64(silence.Seconds()),
			"pkts_sent_during_silence": sentDelta,
			"dial_timeouts":            dialTimeouts,
			"soft_attempts":            st.softAttempts,
			"exit_code":                rxWedgeExitCode,
		})
		// Record this exit BEFORE calling exit so the respawned process
		// sees it in the recent-exits count.
		recordRxWedgeExit(exitLog, now, rxWedgeLoopWindow)
		rxWatchdogExit(rxWedgeExitCode)
		return rxActionExit
	}
	// Withheld: reset the soft counter so recovery attempts continue on
	// later ticks instead of re-evaluating the exit every 30s.
	st.softAttempts = 0
	return rxActionExitWithheld
}

// rxWedgeExitLogPath returns the sidecar file that records recent hard-
// exit timestamps, stored next to the identity file so the count
// survives the respawn. An empty identityPath (no persistence) returns
// "", which disables the restart-loop breaker — the daemon behaves
// exactly as before (always allowed to exit).
func rxWedgeExitLogPath(identityPath string) string {
	if identityPath == "" {
		return ""
	}
	return identityPath + ".rxwedge"
}

// recentRxWedgeExits reads hard-exit timestamps from path and returns
// those within window of now. A missing or unreadable file yields an
// empty slice (breaker closed — exit allowed); malformed lines are
// skipped. Never errors: a read problem must not itself block a
// legitimate wedge exit.
func recentRxWedgeExits(path string, now time.Time, window time.Duration) []int64 {
	if path == "" {
		return nil
	}
	// #nosec G304 -- path is derived from the daemon's own configured
	// IdentityPath (rxWedgeExitLogPath), not from any peer/user input.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	cutoff := now.Add(-window).UnixNano()
	var recent []int64
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		ts, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			continue
		}
		if ts >= cutoff {
			recent = append(recent, ts)
		}
	}
	return recent
}

// recordRxWedgeExit appends now to the exit log (pruned to window) so the
// respawned process sees an accurate recent-exit count. Best-effort: a
// failed write just under-counts, degrading to the prior always-restart
// behavior — never worse.
func recordRxWedgeExit(path string, now time.Time, window time.Duration) {
	if path == "" {
		return
	}
	recent := recentRxWedgeExits(path, now, window)
	recent = append(recent, now.UnixNano())
	var b strings.Builder
	for _, ts := range recent {
		b.WriteString(strconv.FormatInt(ts, 10))
		b.WriteByte('\n')
	}
	_ = os.WriteFile(path, []byte(b.String()), 0o600)
}
