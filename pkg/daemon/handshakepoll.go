// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"sync/atomic"
	"time"
)

// Relayed-handshake poll scheduling (L11).
//
// A trust handshake between two private nodes cannot go direct: neither
// side can resolve the other before trust exists, so the request and its
// answer are parked at the registry and each node learns of them only when
// it polls (pollRelayedHandshakes). With one poll per keepalive interval
// (60s) a manual handshake took about two minutes end to end.
//
// The 60s poll stays as the baseline and is all an idle node ever does.
// Three things add polls, each bounded:
//
//   - Waiting on an answer: after this node sends a handshake request it
//     polls every handshakeFastPollInterval until the peer answers, becomes
//     trusted, or handshakeFastPollWindow has passed.
//   - On demand: a local client asking for pending requests or the trust
//     list, approving or rejecting triggers one poll first, at most one per
//     handshakeOnDemandGap. Waiting for trust does too, but only while a
//     request this node sent that peer is unanswered.
//   - Poke: the beacon can tell this node that something is waiting for it
//     at the registry (beaconMsgNotify). A poke triggers one poll, from a
//     small token bucket, and never sooner than handshakeOnDemandGap after
//     the previous poll.
const (
	// handshakeFastPollInterval is the poll period while a request this
	// node sent is unanswered.
	handshakeFastPollInterval = 2 * time.Second

	// handshakeFastPollWindow bounds fast polling per request.
	handshakeFastPollWindow = 2 * time.Minute

	// handshakeAutoRearm is how long a peer that was the target of an
	// automatic (dial-driven) handshake cannot start another fast window.
	// An application redialing a peer that never answers re-sends the
	// request every autoHandshakeCooldown; without this it would hold the
	// fast window open forever. Explicit requests are not held back.
	handshakeAutoRearm = 10 * time.Minute

	// handshakeMaxWaiting caps the peers tracked at once. Fast polling is
	// one timer however many peers are waiting, so this bounds memory, not
	// request rate.
	handshakeMaxWaiting = 64

	// handshakeOnDemandGap is the minimum spacing of polls triggered by a
	// local client or a beacon poke.
	handshakeOnDemandGap = 2 * time.Second

	// handshakePollSlack is how much sooner than handshakeOnDemandGap a
	// timer-driven poll may start, so a timer armed for exactly the gap is
	// not refused for firing a hair early by the scheduler's clock.
	handshakePollSlack = 100 * time.Millisecond

	// handshakeOnDemandTimeout bounds how long a local client's request is
	// held up by a poll when the registry is slow or unreachable, counted
	// from when that poll started. The poll itself is not cut short: the
	// registry empties a node's handshake inbox as it answers, so a reply
	// nobody waits for would be a request or an approval lost for good.
	handshakeOnDemandTimeout = 3 * time.Second

	// handshakePokeBurst / handshakePokeRefill: token bucket for polls
	// triggered by beacon pokes. A flood of pokes costs at most the burst
	// plus one poll per refill period.
	handshakePokeBurst  = 3
	handshakePokeRefill = 5 * time.Second
)

// handshakePollSched decides when relayed handshakes are polled. It holds
// no timers and makes no calls; handshakePollLoop and the IPC handlers
// drive it, and tests drive it with their own clock.
type handshakePollSched struct {
	mu  sync.Mutex
	now func() time.Time

	// lastPoll is when the most recent poll started, whatever triggered it.
	lastPoll time.Time

	// waiting maps a peer we sent a request to → the end of its fast-poll
	// window. Entries stay (expired) until rearm passes, so the automatic
	// path cannot restart a window early.
	waiting map[uint32]handshakeWait

	// pokeDue is set when a poke was accepted but a poll had just run; the
	// loop polls once handshakeOnDemandGap has passed since lastPoll.
	pokeDue bool

	pokeTokens int
	pokeFill   time.Time

	// wake nudges handshakePollLoop to re-evaluate its timers (capacity 1,
	// never blocks the sender).
	wake chan struct{}

	// running is non-nil while a poll is in flight and is closed when it
	// finishes. At most one poll is in flight; a trigger that arrives
	// meanwhile waits for that one instead of starting another.
	running chan struct{}

	// closed is set by shutdown: no poll starts after it.
	closed bool

	// run performs one poll. It is d.pollRelayedHandshakes; tests replace it.
	run func()

	// polls counts registry polls, for tests.
	polls atomic.Uint64
}

type handshakeWait struct {
	until time.Time // fast polling ends
	rearm time.Time // automatic handshakes may not restart the window before this
}

func newHandshakePollSched() *handshakePollSched {
	return &handshakePollSched{
		now:        time.Now,
		waiting:    make(map[uint32]handshakeWait),
		pokeTokens: handshakePokeBurst,
		wake:       make(chan struct{}, 1),
	}
}

func (s *handshakePollSched) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// requestSent starts the fast-poll window for a peer we just sent a
// handshake request to. explicit is true for a request a local client asked
// for; an automatic one cannot restart a window for the same peer within
// handshakeAutoRearm.
func (s *handshakePollSched) requestSent(peer uint32, explicit bool) {
	s.mu.Lock()
	now := s.now()
	w, tracked := s.waiting[peer]
	switch {
	case tracked && now.Before(w.until):
		// Already waiting on this peer; a repeat does not extend it.
		s.mu.Unlock()
		return
	case tracked && !explicit && now.Before(w.rearm):
		s.mu.Unlock()
		return
	case !tracked && len(s.waiting) >= handshakeMaxWaiting:
		s.pruneLocked(now)
		if len(s.waiting) >= handshakeMaxWaiting {
			// Still full, partly of peers whose window has closed and that
			// are only kept for their rearm time. Let the one whose rearm
			// ends soonest go rather than refuse a new request its fast
			// polling; the others keep their hold-off.
			var oldest uint32
			var oldestRearm time.Time
			found := false
			for p, w := range s.waiting {
				if !now.Before(w.until) && (!found || w.rearm.Before(oldestRearm)) {
					oldest, oldestRearm, found = p, w.rearm, true
				}
			}
			if found {
				delete(s.waiting, oldest)
			}
		}
		if len(s.waiting) >= handshakeMaxWaiting {
			s.mu.Unlock()
			return
		}
	}
	s.waiting[peer] = handshakeWait{until: now.Add(handshakeFastPollWindow), rearm: now.Add(handshakeAutoRearm)}
	s.mu.Unlock()
	s.nudge()
}

// answered ends the wait for a peer whose answer arrived.
func (s *handshakePollSched) answered(peer uint32) {
	s.mu.Lock()
	if w, ok := s.waiting[peer]; ok {
		w.until = time.Time{}
		s.waiting[peer] = w
	}
	s.mu.Unlock()
}

func (s *handshakePollSched) pruneLocked(now time.Time) {
	for peer, w := range s.waiting {
		if !now.Before(w.until) && !now.Before(w.rearm) {
			delete(s.waiting, peer)
		}
	}
}

// waitingOn reports whether a request this node sent to peer is still inside
// its fast-poll window.
func (s *handshakePollSched) waitingOn(peer uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.waiting[peer]
	return ok && s.now().Before(w.until)
}

// fastActive reports whether any request is still inside its fast-poll
// window. Peers that trusted reports as trusted are settled first.
//
// trusted is called without s.mu held. It takes the handshake plugin's
// lock, which the plugin can hold across a registry lookup, and s.mu is also
// taken by poke on the tunnel read loop: calling it under s.mu would stall
// inbound packets for as long as that lookup took.
func (s *handshakePollSched) fastActive(trusted func(uint32) bool) bool {
	s.mu.Lock()
	now := s.now()
	s.pruneLocked(now)
	var open []uint32
	for peer, w := range s.waiting {
		if now.Before(w.until) {
			open = append(open, peer)
		}
	}
	s.mu.Unlock()

	active := false
	var settled []uint32
	for _, peer := range open {
		if trusted != nil && trusted(peer) {
			settled = append(settled, peer)
		} else {
			active = true
		}
	}
	if len(settled) > 0 {
		s.mu.Lock()
		for _, peer := range settled {
			if w, ok := s.waiting[peer]; ok {
				w.until = time.Time{}
				s.waiting[peer] = w
			}
		}
		s.mu.Unlock()
	}
	return active
}

// claim reports whether a poll may start now: no poll started within
// minGap. It records the start when it says yes.
func (s *handshakePollSched) claim(minGap time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claimLocked(minGap)
}

func (s *handshakePollSched) claimLocked(minGap time.Duration) bool {
	now := s.now()
	if !s.lastPoll.IsZero() && now.Sub(s.lastPoll) < minGap {
		return false
	}
	s.lastPoll = now
	s.pokeDue = false
	return true
}

// begin is what a trigger calls when it wants a poll. It returns the channel
// that is closed when the poll covering this trigger finishes — nil if none
// is needed because one started within minGap — and whether the caller is
// the one that must run it (and call end when it is done). While a poll is
// in flight every trigger gets that poll's channel and starts nothing.
func (s *handshakePollSched) begin(minGap time.Duration) (done chan struct{}, start bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running != nil {
		return s.running, false
	}
	if s.closed {
		return nil, false
	}
	if !s.claimLocked(minGap) {
		return nil, false
	}
	s.running = make(chan struct{})
	return s.running, true
}

// end marks the poll in flight as finished and wakes the loop, which may owe
// a poll to a poke that arrived while this one was running.
func (s *handshakePollSched) end() {
	s.mu.Lock()
	if s.running != nil {
		close(s.running)
		s.running = nil
	}
	s.mu.Unlock()
	s.nudge()
}

// shutdown stops any further poll from starting and waits until deadline
// for the one in flight to finish, reporting whether none is running when it
// returns. The daemon calls it before stopping the handshake manager and
// closing the registry client: the registry empties the node's handshake
// inbox as it answers, so a poll whose reply is cut off, or processed by a
// stopped manager, loses what it carried. Setting closed under the same lock
// that begin takes means no poll can slip in after the check.
func (s *handshakePollSched) shutdown(deadline time.Time) bool {
	s.mu.Lock()
	s.closed = true
	running := s.running
	s.mu.Unlock()
	if running == nil {
		return true
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-running:
		return true
	case <-t.C:
		return false
	}
}

// sinceLastPoll is how long ago the most recent poll started.
func (s *handshakePollSched) sinceLastPoll() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Sub(s.lastPoll)
}

// poke handles a beacon notification. It returns true when the loop should
// be woken: the poke took a token and a poll is now due (immediately, or
// once handshakeOnDemandGap has passed since the last one).
func (s *handshakePollSched) poke() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.pokeDue {
		return false // one poll is already owed; it will cover this poke too
	}
	if s.pokeFill.IsZero() {
		s.pokeFill = now
	}
	if n := int(now.Sub(s.pokeFill) / handshakePokeRefill); n > 0 {
		s.pokeTokens += n
		if s.pokeTokens >= handshakePokeBurst {
			s.pokeTokens = handshakePokeBurst
			s.pokeFill = now
		} else {
			s.pokeFill = s.pokeFill.Add(time.Duration(n) * handshakePokeRefill)
		}
	}
	if s.pokeTokens <= 0 {
		return false
	}
	s.pokeTokens--
	s.pokeDue = true
	return true
}

// pokeWait reports whether a poke-triggered poll is owed and how long the
// loop must still wait before running it.
func (s *handshakePollSched) pokeWait() (due bool, wait time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pokeDue {
		return false, 0
	}
	if s.running != nil {
		// A poll is in flight; end() wakes the loop when it finishes.
		// Until then there is nothing to do but look again later.
		return true, handshakeOnDemandGap
	}
	if s.lastPoll.IsZero() {
		return true, 0
	}
	if wait = handshakeOnDemandGap - s.now().Sub(s.lastPoll); wait < 0 {
		wait = 0
	}
	return true, wait
}

// pollHandshakes makes sure a relayed-handshake poll has run recently: it
// starts one unless one is in flight or started within minGap. Polls never
// overlap.
//
// The poll runs on its own goroutine and always runs to completion,
// processing whatever the registry returns however late. wait is how long
// the caller is prepared to be held up, counted from when the poll it is
// waiting for started; 0 means not at all, which is what the background loop
// uses. Giving up on waiting does not cancel the poll: the registry empties
// the node's handshake inbox as it answers, so a reply that was abandoned
// would be handshakes lost.
func (d *Daemon) pollHandshakes(minGap, wait time.Duration) {
	s := d.hsPoll
	if d.stopping() {
		// No new poll once shutdown has begun: the registry client is about
		// to be closed, and a poll cut off by that loses what it fetched.
		return
	}
	if d.reg() == nil {
		// Nothing to poll; do not leave a poke owed (the loop would keep
		// re-arming its timer for a poll that cannot run).
		s.mu.Lock()
		s.pokeDue = false
		s.mu.Unlock()
		return
	}
	done, start := s.begin(minGap)
	if done == nil {
		return
	}
	if start {
		s.polls.Add(1)
		run := s.run
		if run == nil {
			run = d.pollRelayedHandshakes
		}
		go func() {
			defer s.end()
			defer recoverLayer("L11", "pollRelayedHandshakes", d.bus, nil)
			run()
		}()
	}
	if wait <= 0 {
		return
	}
	remaining := wait - s.sinceLastPoll()
	if remaining <= 0 {
		// The poll in flight has already been running longer than a
		// client should be held; do not add to it.
		return
	}
	t := time.NewTimer(remaining)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-d.stopCh:
	}
}

// pollHandshakesOnDemand is called before a local client is shown, or acts
// on, handshake state, so a relayed request or answer parked at the
// registry is visible at once instead of after the next background poll.
func (d *Daemon) pollHandshakesOnDemand() {
	d.pollHandshakes(handshakeOnDemandGap, handshakeOnDemandTimeout)
}

// pollHandshakesForTrustWait is the on-demand poll for wait-for-trust. It
// polls only when there is an answer to wait for: the peer is not trusted
// yet and a request this node sent it is still outstanding. pilotctl asks
// wait-for-trust with a zero timeout before every send, connect and ping, so
// polling unconditionally here put a registry round trip — and, with the
// registry hung, a three-second stall — in front of every command to a peer
// that was trusted all along.
func (d *Daemon) pollHandshakesForTrustWait(peer uint32) {
	if d.handshakes != nil && d.handshakes.IsTrusted(peer) {
		return
	}
	if !d.hsPoll.waitingOn(peer) {
		return
	}
	d.pollHandshakesOnDemand()
}

// handshakePoke is the tunnel layer's callback for a beacon notification
// that something is waiting for this node at the registry. Runs on the
// tunnel read loop, so it only records the poke; the poll loop does the
// work.
func (d *Daemon) handshakePoke() {
	if d.hsPoll.poke() {
		d.hsPoll.nudge()
	}
}

// RelayedHandshakePolls returns how many relayed-handshake polls this
// daemon has sent to the registry since it started.
func (d *Daemon) RelayedHandshakePolls() uint64 { return d.hsPoll.polls.Load() }
