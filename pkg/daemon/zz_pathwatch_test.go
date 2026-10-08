// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// newPathWatchTestDaemon builds the minimal Daemon the path-watch tick
// needs: a TunnelManager with one Ready peer installed, no socket, no
// registry (resetPeerPath's network steps are guarded/best-effort).
func newPathWatchTestDaemon(t *testing.T, peerID uint32) *Daemon {
	t.Helper()
	d := &Daemon{
		tunnels:   NewTunnelManager(),
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 4000}
	d.tunnels.AddPeer(peerID, addr)
	pc := fakePC(t) // real AEAD so SendPathProbe's encryptFrame works
	pc.Authenticated = true
	d.tunnels.envelope.Install(peerID, pc)
	return d
}

// swapPathResetForTest stubs the reset hook and returns a counter of
// invocations per peer. Tests using it must NOT run in parallel with
// each other (global hook), mirroring swapExitForTest.
func swapPathResetForTest(t *testing.T) *[]uint32 {
	t.Helper()
	var resets []uint32
	prev := pathWatchResetPeer
	pathWatchResetPeer = func(d *Daemon, nodeID uint32) { resets = append(resets, nodeID) }
	t.Cleanup(func() { pathWatchResetPeer = prev })
	return &resets
}

func TestPathWatchHealthyPeerNoAction(t *testing.T) {
	const peer = 42
	d := newPathWatchTestDaemon(t, peer)
	resets := swapPathResetForTest(t)
	now := time.Now()

	// Fresh inbound — like a live peer's keepalives (any daemon version
	// sends them every 25s).
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now.Add(-10*time.Second))

	st := &pathPeerState{}
	if got := d.pathWatchPeer(peer, st, now); got != pathActionHealthy {
		t.Fatalf("action = %q, want %q", got, pathActionHealthy)
	}
	if st.probesSent != 0 || len(*resets) != 0 {
		t.Fatalf("healthy peer must not accrue probes/resets (probes=%d resets=%d)",
			st.probesSent, len(*resets))
	}
}

func TestPathWatchStalePeerProbesThenResets(t *testing.T) {
	const peer = 43
	d := newPathWatchTestDaemon(t, peer)
	resets := swapPathResetForTest(t)
	now := time.Now()

	// Inbound-silent well past the threshold, and staying silent.
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now.Add(-2*pathSilenceThreshold))

	st := &pathPeerState{}
	for i := 1; i <= pathProbeMax; i++ {
		if got := d.pathWatchPeer(peer, st, now); got != pathActionProbe {
			t.Fatalf("tick %d action = %q, want %q", i, got, pathActionProbe)
		}
		if st.probesSent != i {
			t.Fatalf("tick %d probesSent = %d, want %d", i, st.probesSent, i)
		}
		now = now.Add(pathWatchTickInterval)
	}

	// Budget exhausted, still silent: reset fires exactly once.
	if got := d.pathWatchPeer(peer, st, now); got != pathActionReset {
		t.Fatalf("post-budget action = %q, want %q", got, pathActionReset)
	}
	if len(*resets) != 1 || (*resets)[0] != peer {
		t.Fatalf("resets = %v, want exactly [%d]", *resets, peer)
	}
	if st.probesSent != 0 || st.lastResetAt.IsZero() {
		t.Fatalf("reset must clear probes and stamp cooldown (probes=%d resetAt=%v)",
			st.probesSent, st.lastResetAt)
	}
}

func TestPathWatchRecoveryClearsProbeState(t *testing.T) {
	const peer = 44
	d := newPathWatchTestDaemon(t, peer)
	resets := swapPathResetForTest(t)
	now := time.Now()

	// Silent → one probe...
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now.Add(-pathSilenceThreshold-time.Second))
	st := &pathPeerState{}
	if got := d.pathWatchPeer(peer, st, now); got != pathActionProbe {
		t.Fatalf("action = %q, want %q", got, pathActionProbe)
	}

	// ...then the pong (or any authenticated inbound) lands.
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now)
	if got := d.pathWatchPeer(peer, st, now.Add(time.Second)); got != pathActionHealthy {
		t.Fatalf("post-recovery action = %q, want %q", got, pathActionHealthy)
	}
	if st.probesSent != 0 || len(*resets) != 0 {
		t.Fatalf("recovery must clear probe state without reset (probes=%d resets=%d)",
			st.probesSent, len(*resets))
	}
}

func TestPathWatchCooldownPreventsResetStorm(t *testing.T) {
	const peer = 45
	d := newPathWatchTestDaemon(t, peer)
	resets := swapPathResetForTest(t)
	now := time.Now()

	// Peer is genuinely offline: permanently silent.
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now.Add(-time.Hour))
	st := &pathPeerState{lastResetAt: now.Add(-pathResetCooldown / 2)}

	if got := d.pathWatchPeer(peer, st, now); got != pathActionCooldown {
		t.Fatalf("in-cooldown action = %q, want %q", got, pathActionCooldown)
	}
	if len(*resets) != 0 {
		t.Fatalf("cooldown must suppress resets, got %v", *resets)
	}

	// After the cooldown expires, the probe cycle starts over (not an
	// instant reset — the peer gets a fresh probe budget).
	later := now.Add(pathResetCooldown)
	if got := d.pathWatchPeer(peer, st, later); got != pathActionProbe {
		t.Fatalf("post-cooldown action = %q, want %q", got, pathActionProbe)
	}
}

func TestPathWatchTickPrunesGonePeers(t *testing.T) {
	const peer = 46
	d := newPathWatchTestDaemon(t, peer)
	_ = swapPathResetForTest(t)
	now := time.Now()
	d.tunnels.kx.SetLastInboundDecryptForTest(peer, now)

	states := make(map[uint32]*pathPeerState)
	d.pathWatchTick(states, now)
	if states[peer] == nil {
		t.Fatalf("tick must create state for ready peer %d", peer)
	}

	// Peer session goes away → state pruned on the next tick.
	d.tunnels.RemovePeer(peer)
	d.pathWatchTick(states, now.Add(pathWatchTickInterval))
	if states[peer] != nil {
		t.Fatalf("tick must prune state for removed peer %d", peer)
	}
}

// TestPathProbeIsNotSwallowedByOldKeepaliveFilter pins the backward-
// compatibility invariant this whole design rests on: the probe must
// NOT match isTunnelKeepalive — the filter every deployed version
// (v1.10.0+) uses to silently swallow keepalives before they reach the
// pong-answering control handler. isTunnelKeepalive only matches EMPTY
// ProtoControl/PortPing frames, so the probe's non-empty payload is
// what earns it a pong from old peers. If someone "optimises" the
// payload away, old peers stop answering and the watchdog would reset
// healthy old-peer paths — this test is the tripwire.
func TestPathProbeIsNotSwallowedByOldKeepaliveFilter(t *testing.T) {
	t.Parallel()
	probe := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Payload:  pathProbePayload,
	}
	if isTunnelKeepalive(probe) {
		t.Fatal("path probe matches isTunnelKeepalive — old peers would swallow it instead of ponging")
	}
	if len(pathProbePayload) == 0 {
		t.Fatal("pathProbePayload must be non-empty (see isTunnelKeepalive)")
	}
	// And the real keepalive still matches, so we haven't broken the
	// filter from the other side.
	tm := NewTunnelManager()
	if !isTunnelKeepalive(tm.newKeepalivePacket()) {
		t.Fatal("regular keepalive no longer matches isTunnelKeepalive")
	}
}

// TestResetPeerPathPreservesRelayActive pins the relay-state contract
// resetPeerPath inherited from prefer-direct: relay ACTIVE survives the
// reset (the recovery PILA must travel via the beacon when relay is the
// only working path), while the PIN is cleared (a direct receive may
// promote the path).
func TestResetPeerPathPreservesRelayActive(t *testing.T) {
	const peer = 47
	d := newPathWatchTestDaemon(t, peer)
	d.tunnels.SetRelayPeer(peer, true)
	d.tunnels.SetRelayPeerPinned(peer, true)

	res := d.resetPeerPath(peer)

	if !res.HadTunnel || !res.WasRelayActive || !res.WasRelayPinned {
		t.Fatalf("captured state wrong: %+v", res)
	}
	if !d.tunnels.IsRelayPeer(peer) {
		t.Fatal("relay ACTIVE must be restored after reset")
	}
	if d.tunnels.IsRelayPinned(peer) {
		t.Fatal("relay PIN must be cleared after reset")
	}
	if d.tunnels.HasPeer(peer) {
		t.Fatal("tunnel must be dropped by reset")
	}
	// No registry in this fixture: the network step reports, not panics.
	if res.ResolveErr == "" {
		t.Fatal("expected resolve error with no registry connection")
	}
}

// TestOnRekeyGaveUpResetsWithCooldown pins the event-driven T2 recovery:
// the rekey-gave-up hook resets a peer's path, and a per-peer cooldown
// prevents a persistently-desynced/offline peer from storming resolves.
// The 2026-07-22 live test proved the earlier poll-from-pathwatch
// approach never fired (a desynced peer isn't Ready, so pathwatch never
// scanned it) — this hook fires straight from the giveup site.
func TestOnRekeyGaveUpResetsWithCooldown(t *testing.T) {
	d := &Daemon{
		tunnels:         NewTunnelManager(),
		startTime:       time.Now(),
		stopCh:          make(chan struct{}),
		lastGaveUpReset: make(map[uint32]time.Time),
	}
	var resets []uint32
	var mu sync.Mutex
	prev := gaveUpResetPeer
	gaveUpResetPeer = func(_ *Daemon, id uint32) peerPathReset {
		mu.Lock()
		resets = append(resets, id)
		mu.Unlock()
		return peerPathReset{}
	}
	t.Cleanup(func() { gaveUpResetPeer = prev })

	const peer = 77
	d.tunnels.noteAppActivity(peer) // a peer someone is using
	d.onRekeyGaveUp(peer)           // fires an async reset
	// second giveup immediately: cooldown must suppress it
	d.onRekeyGaveUp(peer)

	// let the async reset goroutine run
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(resets)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(resets) != 1 || resets[0] != peer {
		t.Fatalf("resets = %v, want exactly [%d] (cooldown must suppress the 2nd giveup)", resets, peer)
	}
}
