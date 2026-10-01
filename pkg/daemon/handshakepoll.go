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
//     list, approving, rejecting or waiting for trust triggers one poll
//     first, at most one per handshakeOnDemandGap.
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

	// handshakeOnDemandTimeout bounds how long a local client's request is
	// held up by its poll when the registry is slow or unreachable.
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

	// sem serializes polls so two triggers never overlap (capacity 1).
	sem chan struct{}

	// polls counts registry polls, for tests and the info reply.
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
		sem:        make(chan struct{}, 1),
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

// fastActive reports whether any request is still inside its fast-poll
// window. Peers that trusted reports as trusted are settled first.
func (s *handshakePollSched) fastActive(trusted func(uint32) bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.pruneLocked(now)
	active := false
	for peer, w := range s.waiting {
		if !now.Before(w.until) {
			continue
		}
		if trusted != nil && trusted(peer) {
			w.until = time.Time{}
			s.waiting[peer] = w
			continue
		}
		active = true
	}
	return active
}

// claim reports whether a poll may start now: no poll started within
// minGap. It records the start when it says yes.
func (s *handshakePollSched) claim(minGap time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if !s.lastPoll.IsZero() && now.Sub(s.lastPoll) < minGap {
		return false
	}
	s.lastPoll = now
	s.pokeDue = false
	return true
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
	if s.lastPoll.IsZero() {
		return true, 0
	}
	if wait = handshakeOnDemandGap - s.now().Sub(s.lastPoll); wait < 0 {
		wait = 0
	}
	return true, wait
}

// pollHandshakes runs one relayed-handshake poll unless one started within
// minGap. Polls never overlap; a caller arriving while one is running waits
// for it (up to timeout when timeout > 0) and then finds it fresh enough.
// timeout also bounds the registry call itself; 0 means no bound, which is
// what the background loop has always used.
func (d *Daemon) pollHandshakes(minGap, timeout time.Duration) {
	s := d.hsPoll
	if d.reg() == nil {
		// Nothing to poll; do not leave a poke owed (the loop would keep
		// re-arming its timer for a poll that cannot run).
		s.mu.Lock()
		s.pokeDue = false
		s.mu.Unlock()
		return
	}
	if timeout > 0 {
		t := time.NewTimer(timeout)
		defer t.Stop()
		select {
		case s.sem <- struct{}{}:
		case <-t.C:
			return
		case <-d.stopCh:
			return
		}
	} else {
		select {
		case s.sem <- struct{}{}:
		case <-d.stopCh:
			return
		}
	}
	defer func() { <-s.sem }()
	if !s.claim(minGap) {
		return
	}
	s.polls.Add(1)
	d.pollRelayedHandshakes(timeout)
}

// pollHandshakesOnDemand is called before a local client is shown, or acts
// on, handshake state, so a relayed request or answer parked at the
// registry is visible at once instead of after the next background poll.
func (d *Daemon) pollHandshakesOnDemand() {
	d.pollHandshakes(handshakeOnDemandGap, handshakeOnDemandTimeout)
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
