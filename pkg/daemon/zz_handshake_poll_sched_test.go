// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"
)

// schedAt returns a scheduler on a clock the test advances by hand.
func schedAt(start time.Time) (*handshakePollSched, func(time.Duration)) {
	now := start
	s := newHandshakePollSched()
	s.now = func() time.Time { return now }
	return s, func(d time.Duration) { now = now.Add(d) }
}

func TestHandshakeFastPollWindowStartsAndEnds(t *testing.T) {
	t.Parallel()
	s, advance := schedAt(time.Unix(1_700_000_000, 0))
	never := func(uint32) bool { return false }

	if s.fastActive(never) {
		t.Fatal("idle scheduler reports a fast window")
	}
	s.requestSent(7, true)
	select {
	case <-s.wake:
	default:
		t.Fatal("starting a fast window did not wake the loop")
	}
	if !s.fastActive(never) {
		t.Fatal("no fast window after a request was sent")
	}

	// A repeat while waiting does not push the end out.
	advance(handshakeFastPollWindow - time.Second)
	s.requestSent(7, true)
	if !s.fastActive(never) {
		t.Fatal("window ended early")
	}
	advance(time.Second)
	if s.fastActive(never) {
		t.Fatalf("window still open %s after the request", handshakeFastPollWindow)
	}

	// The peer's answer ends it at once; so does the peer becoming trusted.
	s.requestSent(7, true)
	s.answered(7)
	if s.fastActive(never) {
		t.Fatal("window still open after the answer arrived")
	}
	s.requestSent(8, true)
	if s.fastActive(func(peer uint32) bool { return peer == 8 }) {
		t.Fatal("window still open for a peer that is now trusted")
	}
}

// An application redialing a peer that never answers re-sends the automatic
// handshake every autoHandshakeCooldown. That must not keep fast polling on.
func TestHandshakeFastPollAutomaticRequestCannotHoldWindowOpen(t *testing.T) {
	t.Parallel()
	s, advance := schedAt(time.Unix(1_700_000_000, 0))
	never := func(uint32) bool { return false }

	s.requestSent(7, false)
	fast := 0
	for elapsed := time.Duration(0); elapsed < handshakeAutoRearm; elapsed += autoHandshakeCooldown {
		if s.fastActive(never) {
			fast++
		}
		advance(autoHandshakeCooldown)
		s.requestSent(7, false)
	}
	if want := int(handshakeFastPollWindow / autoHandshakeCooldown); fast != want {
		t.Fatalf("fast window open at %d of the %s checks, want %d (one window)", fast, autoHandshakeCooldown, want)
	}
	if !s.fastActive(never) {
		t.Fatalf("automatic request could not start a window %s after the last one", handshakeAutoRearm)
	}

	// An explicit request is never held back.
	advance(handshakeFastPollWindow)
	s.requestSent(7, true)
	if !s.fastActive(never) {
		t.Fatal("explicit request did not start a window")
	}
}

func TestHandshakeFastPollTracksBoundedPeers(t *testing.T) {
	t.Parallel()
	s, _ := schedAt(time.Unix(1_700_000_000, 0))
	for peer := uint32(1); peer <= 4*handshakeMaxWaiting; peer++ {
		s.requestSent(peer, true)
	}
	if n := len(s.waiting); n != handshakeMaxWaiting {
		t.Fatalf("tracking %d peers, want the cap %d", n, handshakeMaxWaiting)
	}
}

func TestHandshakePollClaimRateLimit(t *testing.T) {
	t.Parallel()
	s, advance := schedAt(time.Unix(1_700_000_000, 0))

	granted := 0
	for i := 0; i < 600; i++ { // a client asking every 100ms for a minute
		if s.claim(handshakeOnDemandGap) {
			granted++
		}
		advance(100 * time.Millisecond)
	}
	if want := int(time.Minute / handshakeOnDemandGap); granted != want {
		t.Fatalf("%d on-demand polls in a minute of constant asking, want %d", granted, want)
	}
	// The baseline tick is never refused.
	if !s.claim(0) {
		t.Fatal("baseline poll refused")
	}
}

func TestHandshakePokeRateLimit(t *testing.T) {
	t.Parallel()
	s, advance := schedAt(time.Unix(1_700_000_000, 0))

	// A flood: 100 pokes a second for a minute. The loop polls whenever a
	// poke is owed a poll and the gap since the last poll has passed.
	polls := 0
	for i := 0; i < 6000; i++ {
		s.poke()
		if due, wait := s.pokeWait(); due && wait == 0 && s.claim(handshakeOnDemandGap) {
			polls++
		}
		advance(10 * time.Millisecond)
	}
	if max := handshakePokeBurst + int(time.Minute/handshakePokeRefill); polls > max || polls < max-1 {
		t.Fatalf("%d polls from a one-minute poke flood, want about %d (burst + one per %s)", polls, max, handshakePokeRefill)
	}

	// Quiet for a while: the bucket refills to the burst, no further.
	advance(time.Hour)
	polls = 0
	for i := 0; i < 50; i++ {
		s.poke()
		if due, _ := s.pokeWait(); due {
			advance(handshakeOnDemandGap)
			if s.claim(handshakeOnDemandGap) {
				polls++
			}
		}
	}
	if polls < handshakePokeBurst || polls > handshakePokeBurst+int(50*handshakeOnDemandGap/handshakePokeRefill)+1 {
		t.Fatalf("%d polls after an idle hour, want the burst %d plus refill", polls, handshakePokeBurst)
	}
}

func TestHandshakePokeWaitsOutARecentPoll(t *testing.T) {
	t.Parallel()
	s, advance := schedAt(time.Unix(1_700_000_000, 0))

	if !s.claim(0) {
		t.Fatal("first poll refused")
	}
	advance(500 * time.Millisecond)
	if !s.poke() {
		t.Fatal("poke refused with a full bucket")
	}
	due, wait := s.pokeWait()
	if !due || wait != handshakeOnDemandGap-500*time.Millisecond {
		t.Fatalf("poke 500ms after a poll: due=%v wait=%s, want a poll owed in %s", due, wait, handshakeOnDemandGap-500*time.Millisecond)
	}
	// Further pokes while one poll is owed take no more tokens.
	tokens := s.pokeTokens
	for i := 0; i < 10; i++ {
		if s.poke() {
			t.Fatal("a second poll was scheduled while one is owed")
		}
	}
	if s.pokeTokens != tokens {
		t.Fatalf("pokes while a poll is owed spent tokens: %d -> %d", tokens, s.pokeTokens)
	}
	// Any poll settles the debt.
	advance(wait)
	if !s.claim(handshakeOnDemandGap) {
		t.Fatal("owed poll refused after the gap")
	}
	if due, _ := s.pokeWait(); due {
		t.Fatal("poll still owed after one ran")
	}
}

// A notify is honoured only when it comes from the beacon's address.
func TestBeaconNotifyOnlyFromBeacon(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SetBeaconAddr("192.0.2.10:9001"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	tm.SetBeaconNotifyHandler(func() { calls++ })

	frame := []byte{beaconMsgNotify, 0x01}
	tm.handleBeaconMessage(frame, &net.UDPAddr{IP: net.ParseIP("192.0.2.66"), Port: 9001})
	tm.handleBeaconMessage(frame, &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 4444})
	if calls != 0 {
		t.Fatalf("notify from a non-beacon source ran the handler %d times", calls)
	}
	tm.handleBeaconMessage(frame, &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9001})
	if calls != 1 {
		t.Fatalf("notify from the beacon ran the handler %d times, want 1", calls)
	}
}

// TestHandshakePollLoopExtraPollsAreBounded drives the real loop against a
// registry with the baseline tick out of the way (1h): an idle loop polls
// nothing, a burst of pokes costs one poll, a request in flight is polled
// at the fast period, and the loop goes quiet again once it is answered.
func TestHandshakePollLoopExtraPollsAreBounded(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })

	d := New(Config{KeepaliveInterval: time.Hour})
	d.regConn.Store(rc)
	done := make(chan struct{})
	go func() { d.handshakePollLoop(); close(done) }()
	t.Cleanup(func() { close(d.stopCh); <-done })

	waitPolls := func(want uint64, within time.Duration) {
		t.Helper()
		deadline := time.Now().Add(within)
		for d.RelayedHandshakePolls() < want && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if got := d.RelayedHandshakePolls(); got != want {
			t.Fatalf("registry polls = %d, want %d", got, want)
		}
	}

	time.Sleep(time.Second)
	waitPolls(0, 0) // idle: nothing beyond the baseline

	for i := 0; i < 200; i++ {
		d.handshakePoke()
	}
	waitPolls(1, 2*time.Second) // served even during the startup jitter
	time.Sleep(handshakeOnDemandGap + time.Second)
	waitPolls(1, 0) // the rest of the burst bought nothing

	d.hsPoll.requestSent(42, true)
	time.Sleep(2*handshakeFastPollInterval + handshakeFastPollInterval/2)
	if got := d.RelayedHandshakePolls(); got < 2 || got > 4 {
		t.Fatalf("registry polls = %d after 2.5 fast periods with a request in flight, want 3 (1 + 2)", got)
	}
	d.hsPoll.answered(42)
	time.Sleep(handshakeFastPollInterval + 200*time.Millisecond) // at most one already-armed poll
	settled := d.RelayedHandshakePolls()
	time.Sleep(2 * handshakeFastPollInterval)
	if got := d.RelayedHandshakePolls(); got != settled {
		t.Fatalf("loop kept polling after the answer: %d -> %d", settled, got)
	}
}
