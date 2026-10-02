// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"sync/atomic"
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
	// The first poke is served at once, even during the startup jitter. A
	// poke that lands after that poll began is owed one more, deferred by
	// handshakeOnDemandGap; whether any of the burst does is a matter of
	// scheduling. So the whole burst buys one poll or two, never more.
	deadline := time.Now().Add(2 * time.Second)
	for d.RelayedHandshakePolls() < 1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(handshakeOnDemandGap + time.Second)
	burst := d.RelayedHandshakePolls()
	if burst < 1 || burst > 2 {
		t.Fatalf("a burst of 200 pokes caused %d registry polls, want 1 or 2", burst)
	}
	time.Sleep(handshakeOnDemandGap + time.Second)
	waitPolls(burst, 0) // and nothing after that

	d.hsPoll.requestSent(42, true)
	time.Sleep(2*handshakeFastPollInterval + handshakeFastPollInterval/2)
	if got := d.RelayedHandshakePolls() - burst; got < 1 || got > 3 {
		t.Fatalf("%d registry polls in 2.5 fast periods with a request in flight, want 1 to 3", got)
	}
	d.hsPoll.answered(42)
	time.Sleep(handshakeFastPollInterval + 200*time.Millisecond) // at most one already-armed poll
	settled := d.RelayedHandshakePolls()
	time.Sleep(2 * handshakeFastPollInterval)
	if got := d.RelayedHandshakePolls(); got != settled {
		t.Fatalf("loop kept polling after the answer: %d -> %d", settled, got)
	}
}

// A poll the caller stops waiting for must still run to completion. The
// registry empties a node's handshake inbox as it answers, so a reply that
// arrives after its caller has gone and is then thrown away is a request or
// an approval lost for good — `pilotctl pending` against a registry that took
// four seconds lost whatever was in the inbox.
func TestOnDemandPollOutlivesTheCallerThatGaveUp(t *testing.T) {
	t.Parallel()
	reg, rc := startTestRegistry(t)
	t.Cleanup(func() { reg.Close() })
	t.Cleanup(func() { rc.Close() })
	d := New(Config{KeepaliveInterval: time.Hour})
	d.regConn.Store(rc)

	release := make(chan struct{})
	var started, finished atomic.Int32
	d.hsPoll.run = func() {
		started.Add(1)
		<-release // a registry that is slow to answer
		finished.Add(1)
	}

	const wait = 80 * time.Millisecond
	begin := time.Now()
	d.pollHandshakes(handshakeOnDemandGap, wait)
	if held := time.Since(begin); held > wait+500*time.Millisecond {
		t.Fatalf("caller was held %v, want about %v", held, wait)
	}
	if started.Load() != 1 || finished.Load() != 0 {
		t.Fatalf("after the caller gave up: started=%d finished=%d, want the poll still in flight", started.Load(), finished.Load())
	}

	// Callers arriving while it is in flight start no second poll, and one
	// arriving after the wait has already been used up is not held at all.
	time.Sleep(wait)
	begin = time.Now()
	for i := 0; i < 5; i++ {
		d.pollHandshakes(handshakeOnDemandGap, wait)
	}
	if held := time.Since(begin); held > wait {
		t.Fatalf("five callers behind a poll already running past its wait were held %v in total", held)
	}
	if n := started.Load(); n != 1 {
		t.Fatalf("%d polls started while one was in flight, want 1", n)
	}

	// The reply lands: the poll finishes its work.
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for finished.Load() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if finished.Load() != 1 {
		t.Fatal("the poll its caller stopped waiting for never completed")
	}
	if got := d.RelayedHandshakePolls(); got != 1 {
		t.Fatalf("registry polls = %d, want 1", got)
	}
}

// fastActive asks the handshake plugin whether a peer is trusted, and the
// plugin can hold its lock across a registry lookup. The tunnel read loop
// takes the scheduler's lock for every beacon notify, so that question must
// not be asked with the scheduler's lock held.
func TestFastActiveAsksAboutTrustWithoutHoldingTheLock(t *testing.T) {
	t.Parallel()
	s := newHandshakePollSched()
	s.requestSent(7, true)
	s.requestSent(8, true)

	result := make(chan bool, 1)
	go func() {
		result <- s.fastActive(func(peer uint32) bool {
			s.poke() // what the read loop does; deadlocks if s.mu is held
			return peer == 7
		})
	}()
	select {
	case active := <-result:
		if !active {
			t.Fatal("peer 8 is still waiting: fastActive should report true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fastActive called the trust check with the scheduler's lock held")
	}
	if s.waitingOn(7) {
		t.Fatal("peer 7 was reported trusted and should be settled")
	}
	if !s.waitingOn(8) {
		t.Fatal("peer 8 should still be waited on")
	}
}

// Peers stay tracked for handshakeAutoRearm after their window closes, so
// that an automatic handshake cannot reopen it. Sixty-four of those must not
// stop a new request from getting its fast polling.
func TestSettledPeersDoNotCrowdOutANewRequest(t *testing.T) {
	t.Parallel()
	s := newHandshakePollSched()
	for peer := uint32(1); peer <= handshakeMaxWaiting; peer++ {
		s.requestSent(peer, true)
		s.answered(peer)
	}
	s.requestSent(1000, true)
	if !s.waitingOn(1000) {
		t.Fatalf("with %d answered peers tracked, a new request got no fast polling", handshakeMaxWaiting)
	}

	// Still a cap on requests that are genuinely outstanding.
	s = newHandshakePollSched()
	for peer := uint32(1); peer <= handshakeMaxWaiting; peer++ {
		s.requestSent(peer, true)
	}
	s.requestSent(1000, true)
	if s.waitingOn(1000) {
		t.Fatalf("a request beyond %d outstanding ones was tracked", handshakeMaxWaiting)
	}
}

// Wait-for-trust polls only when there is an answer to wait for. pilotctl
// calls it with a zero timeout before every send, connect and ping.
func TestWaitingOnTracksOnlyOutstandingRequests(t *testing.T) {
	t.Parallel()
	s := newHandshakePollSched()
	if s.waitingOn(5) {
		t.Fatal("no request was sent to peer 5")
	}
	s.requestSent(5, true)
	if !s.waitingOn(5) {
		t.Fatal("a request to peer 5 is outstanding")
	}
	s.answered(5)
	if s.waitingOn(5) {
		t.Fatal("peer 5 answered")
	}
}

// Only the handshake kind triggers a poll. A bare type byte, or a kind this
// daemon does not know, is dropped.
func TestBeaconNotifyOfUnknownKindIsDropped(t *testing.T) {
	t.Parallel()
	tm := NewTunnelManager()
	if err := tm.SetBeaconAddr("192.0.2.10:9001"); err != nil {
		t.Fatal(err)
	}
	calls := 0
	tm.SetBeaconNotifyHandler(func() { calls++ })
	beacon := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9001}

	tm.handleBeaconMessage([]byte{beaconMsgNotify}, beacon)
	tm.handleBeaconMessage([]byte{beaconMsgNotify, 0x02}, beacon)
	tm.handleBeaconMessage([]byte{beaconMsgNotify, beaconNotifyHandshake, 0x00}, beacon)
	if calls != 0 {
		t.Fatalf("a malformed or unknown notify ran the handler %d times", calls)
	}
	tm.handleBeaconMessage([]byte{beaconMsgNotify, beaconNotifyHandshake}, beacon)
	if calls != 1 {
		t.Fatalf("a handshake notify ran the handler %d times, want 1", calls)
	}
}
