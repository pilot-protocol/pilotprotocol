// SPDX-License-Identifier: AGPL-3.0-or-later

package envelope_test

// Receive epochs (2026-09-23 desync loop, case B). A peer that throws its
// half of our session away and re-derives it — from our next PILA, with
// the same X25519 keys on both sides, so the SAME AEAD key — restarts its
// send counter at 1. It also picks a fresh random nonce prefix, as every
// version since v1.9 does for every Crypto it derives. The receiver used
// to see only the restarted counter: a replay (or an outside-window frame)
// on the window it kept, which on an aged session dropped the receiver's
// half on the first frame. The prefix is what tells the two apart:
// same prefix = the same sender Crypto, whose counter only grows, so a
// lower counter is a duplicate/late frame/replay; a never-seen prefix =
// the peer's new epoch.
//
// Because every epoch shares the AEAD key, every recorded frame of every
// earlier epoch still authenticates. An epoch is therefore never
// forgotten: once its window is evicted it is retired and all its frames
// are rejected, so no frame is accepted twice by one Crypto.

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// rederiveSender replaces the local (sending) side's Crypto the way a peer
// that dropped its half and re-derived the session does: same AEAD key,
// send counter restarted at 0, a fresh random nonce prefix.
func rederiveSender(t *testing.T, s *peerSetup) {
	t.Helper()
	old := s.localStore.Get(s.peerID)
	var prefix [4]byte
	for {
		if _, err := rand.Read(prefix[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if prefix != old.NoncePrefix {
			break
		}
	}
	rederiveSenderWithPrefix(s, prefix)
}

// rederiveSenderWithPrefix is rederiveSender with a chosen nonce prefix,
// for tests that open many epochs and must not depend on random prefixes
// never colliding.
func rederiveSenderWithPrefix(s *peerSetup, prefix [4]byte) {
	old := s.localStore.Get(s.peerID)
	s.localStore.Install(s.peerID, &keyexchange.Crypto{
		AEAD:          old.AEAD,
		NoncePrefix:   prefix,
		Ready:         true,
		Authenticated: old.Authenticated,
		PeerX25519Key: old.PeerX25519Key,
		CreatedAt:     time.Now(),
	})
}

// distinctPrefix returns the k-th of a run of nonce prefixes that are
// distinct from each other and from avoid.
func distinctPrefix(k int, avoid [4]byte) [4]byte {
	p := [4]byte{0xE0, byte(k >> 16), byte(k >> 8), byte(k)}
	if p == avoid {
		p[0] = 0xE1
	}
	return p
}

func sealLocal(t *testing.T, s *peerSetup, msg string) []byte {
	t.Helper()
	f, err := envelope.EncryptFrame(s.localStore, s.peerID, []byte(msg))
	if err != nil {
		t.Fatalf("encrypt %q: %v", msg, err)
	}
	return f[4:]
}

func faultCounts(c *keyexchange.Crypto) (replays, outside int) {
	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	return c.ReplayCount, c.OutsideWindowCount
}

func accepted(r envelope.DecryptResult, want string, epoch keyexchange.RecvEpoch) bool {
	return r.Err == nil && string(r.Plaintext) == want && r.Epoch == epoch
}

// TestPeerNewEpochRestartsReceiveWindow: the first frame of the peer's new
// epoch is accepted — whether its restarted counter lands inside the old
// window (in-window replay before) or behind it (outside-window before) —
// and neither drop gate is armed on the aged session.
func TestPeerNewEpochRestartsReceiveWindow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames int
	}{
		{"restarted counter inside the old window", 10},
		{"restarted counter behind the old window", keyexchange.ReplayWindowSize + 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newPeerSetup(t)
			for i := 0; i < tc.frames; i++ {
				r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "old"))
				// The first frame on a Crypto is not a new epoch.
				if !accepted(r, "old", keyexchange.RecvEpochNewest) {
					t.Fatalf("old-epoch frame %d: err=%v epoch=%v", i, r.Err, r.Epoch)
				}
			}
			c := s.peerStore.Get(s.localID)
			backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

			rederiveSender(t, s)
			r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-1"))
			if !accepted(r, "new-1", keyexchange.RecvEpochNew) || r.Counter != 1 {
				t.Fatalf("first frame of the peer's new epoch: err=%v counter=%d plaintext=%q epoch=%v; "+
					"want accepted at counter 1 as a new epoch", r.Err, r.Counter, r.Plaintext, r.Epoch)
			}
			if r = envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-2")); !accepted(r, "new-2", keyexchange.RecvEpochNewest) {
				t.Fatalf("second frame of the new epoch: err=%v epoch=%v", r.Err, r.Epoch)
			}
			if rp, ow := faultCounts(c); rp != 0 || ow != 0 {
				t.Fatalf("new epoch must not count as replay/outside-window (replays=%d outside=%d)", rp, ow)
			}
			if s.peerStore.ShouldDropOnReplay(s.localID, c) || s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
				t.Fatal("the peer's new epoch armed a drop gate on the aged session")
			}
		})
	}
}

// TestNewEpochOnAgedSessionGetsDrainGrace: the replay and outside-window
// gates judge the age of the peer's newest epoch, not of the Crypto. A
// duplicate or a late frame of an epoch the peer JUST started on a session
// we kept (always aged in production: a reset alone needs ~85s of silence)
// is the post-rekey drain their threshold and grace exist for. Judged by
// the Crypto's age, the first one dropped our half — and against a
// v1.10.9–v1.13 peer, which then holds the fresh half and never answers a
// same-key exchange, the pair wedged. A settled epoch keeps the aged fast
// path.
func TestNewEpochOnAgedSessionGetsDrainGrace(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	first := sealLocal(t, s, "first")
	if r := envelope.DecryptFrame(s.peerStore, first); r.Err != nil {
		t.Fatalf("first: %v", r.Err)
	}
	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

	// Control: in the settled first epoch a single duplicate still arms
	// the aged fast path.
	if r := envelope.DecryptFrame(s.peerStore, first); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("duplicate in the settled epoch: err=%v, want ErrReplay", r.Err)
	}
	if !s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatal("control: one duplicate in a settled epoch must still arm the aged fast path")
	}
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "clears")); r.Err != nil {
		t.Fatalf("genuine frame after the duplicate: %v", r.Err)
	}

	rederiveSender(t, s)
	newFirst := sealLocal(t, s, "new-1")
	heldBack := sealLocal(t, s, "new-2") // delayed on the relay
	if r := envelope.DecryptFrame(s.peerStore, newFirst); !accepted(r, "new-1", keyexchange.RecvEpochNew) {
		t.Fatalf("new epoch: err=%v epoch=%v", r.Err, r.Epoch)
	}

	// One duplicate of the new epoch's first frame.
	if r := envelope.DecryptFrame(s.peerStore, newFirst); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("duplicate in the new epoch: err=%v, want ErrReplay", r.Err)
	}
	if s.peerStore.ShouldDropOnReplay(s.localID, c) {
		t.Fatal("BUG: one duplicate of an early frame of the peer's brand-new epoch drops the aged session")
	}

	// A burst past the window, then the held-back frame lands.
	for i := 0; i < keyexchange.ReplayWindowSize+44; i++ {
		if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "burst")); r.Err != nil {
			t.Fatalf("burst frame %d: %v", i, r.Err)
		}
	}
	if r := envelope.DecryptFrame(s.peerStore, heldBack); !errors.Is(r.Err, envelope.ErrOutsideWindow) {
		t.Fatalf("late frame of the new epoch: err=%v, want ErrOutsideWindow", r.Err)
	}
	if s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatal("BUG: one late frame of the peer's brand-new epoch drops the aged session")
	}
}

// TestEarlierEpochFramesUseTheirOwnWindow: once the peer's new epoch is
// newest, frames of its previous epoch are judged in that epoch's own
// window — a late frame it never saw is delivered, a duplicate is
// ErrStaleEpoch — and neither moves the newest window or feeds a drop gate.
func TestEarlierEpochFramesUseTheirOwnWindow(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	seen := sealLocal(t, s, "seen")
	if r := envelope.DecryptFrame(s.peerStore, seen); r.Err != nil {
		t.Fatalf("seen: %v", r.Err)
	}
	late := sealLocal(t, s, "late") // in flight while the peer re-derives
	c := s.peerStore.Get(s.localID)
	backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

	rederiveSender(t, s)
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-1")); !accepted(r, "new-1", keyexchange.RecvEpochNew) {
		t.Fatalf("new epoch: err=%v epoch=%v", r.Err, r.Epoch)
	}
	newest := func() uint64 {
		c.ReplayMu.Lock()
		defer c.ReplayMu.Unlock()
		return c.MaxRecvNonce
	}
	before := newest()

	if r := envelope.DecryptFrame(s.peerStore, late); !accepted(r, "late", keyexchange.RecvEpochOlder) {
		t.Fatalf("late frame of the previous epoch: err=%v plaintext=%q epoch=%v; want delivered from its own window",
			r.Err, r.Plaintext, r.Epoch)
	}
	for name, f := range map[string][]byte{"duplicate of a seen frame": seen, "duplicate of the late frame": late} {
		r := envelope.DecryptFrame(s.peerStore, f)
		if !errors.Is(r.Err, envelope.ErrStaleEpoch) || r.Plaintext != nil {
			t.Fatalf("%s from the previous epoch: err=%v plaintext=%q; want ErrStaleEpoch", name, r.Err, r.Plaintext)
		}
	}
	if after := newest(); after != before {
		t.Fatalf("previous-epoch frames moved the newest window: MaxRecvNonce %d -> %d", before, after)
	}
	if rp, ow := faultCounts(c); rp != 0 || ow != 0 {
		t.Fatalf("previous-epoch frames bumped drop-gate counters (replays=%d outside=%d)", rp, ow)
	}
	if s.peerStore.ShouldDropOnReplay(s.localID, c) || s.peerStore.ShouldDropOnOutsideWindow(s.localID, c) {
		t.Fatal("previous-epoch duplicates armed a drop gate on the aged session")
	}
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-2")); !accepted(r, "new-2", keyexchange.RecvEpochNewest) {
		t.Fatalf("the new epoch must stay newest: err=%v epoch=%v", r.Err, r.Epoch)
	}
}

// TestEvictedEpochIsRetiredNotReopened: once more epochs have passed than
// RetainedRecvEpochs keeps windows for, an evicted epoch's frames are
// rejected for good. They used to come back as a "new" epoch with a fresh
// window, so replaying recorded frames of RetainedRecvEpochs+2 epochs
// round-robin evicted, and re-opened, the replayed epoch on every frame:
// every replay was accepted, without limit, on a session that stayed
// healthy both ways.
func TestEvictedEpochIsRetiredNotReopened(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	const epochs = 3 * (keyexchange.RetainedRecvEpochs + 2)
	initial := s.localStore.Get(s.peerID).NoncePrefix
	var recorded [][]byte
	for k := 0; k < epochs; k++ {
		if k > 0 {
			rederiveSenderWithPrefix(s, distinctPrefix(k, initial))
		}
		f := sealLocal(t, s, "cmd")
		want := keyexchange.RecvEpochNew
		if k == 0 {
			want = keyexchange.RecvEpochNewest
		}
		if r := envelope.DecryptFrame(s.peerStore, f); !accepted(r, "cmd", want) {
			t.Fatalf("genuine frame of epoch %d: err=%v epoch=%v", k, r.Err, r.Epoch)
		}
		recorded = append(recorded, f)
	}
	c := s.peerStore.Get(s.localID)

	// An attacker re-sends the recorded frames, byte for byte, round-robin.
	for round := 0; round < 20; round++ {
		for k, f := range recorded {
			r := envelope.DecryptFrame(s.peerStore, f)
			if r.Plaintext != nil || r.Err == nil {
				t.Fatalf("BUG: round %d: the recorded frame of epoch %d was accepted again (epoch=%v)", round, k, r.Epoch)
			}
			want := envelope.ErrStaleEpoch
			if k == len(recorded)-1 {
				want = envelope.ErrReplay // the newest epoch's own window
			}
			if !errors.Is(r.Err, want) {
				t.Fatalf("round %d, epoch %d: err=%v, want %v", round, k, r.Err, want)
			}
		}
	}

	// The live epoch was never locked out, and earlier epochs' rejections
	// fed no drop gate beyond the newest epoch's own duplicates.
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "live-next")); !accepted(r, "live-next", keyexchange.RecvEpochNewest) {
		t.Fatalf("the live epoch was locked out: err=%v epoch=%v", r.Err, r.Epoch)
	}
	if rp, ow := faultCounts(c); rp != 0 || ow != 0 {
		t.Fatalf("drop-gate counters after a successful frame: replays=%d outside=%d", rp, ow)
	}
}

// TestRecvEpochLimitRefusesANewEpoch: a Crypto tracks at most
// MaxRecvEpochs peer epochs. The next one is refused — not accepted by
// forgetting an earlier epoch — with ErrRecvEpochsExhausted, which arms
// the session drop; nothing about the tracked epochs changes.
func TestRecvEpochLimitRefusesANewEpoch(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	initial := s.localStore.Get(s.peerID).NoncePrefix
	var first []byte
	for k := 0; k < keyexchange.MaxRecvEpochs; k++ {
		if k > 0 {
			rederiveSenderWithPrefix(s, distinctPrefix(k, initial))
		}
		f := sealLocal(t, s, "cmd")
		if r := envelope.DecryptFrame(s.peerStore, f); r.Err != nil {
			t.Fatalf("epoch %d of %d: %v", k+1, keyexchange.MaxRecvEpochs, r.Err)
		}
		if k == 0 {
			first = f
		}
	}
	c := s.peerStore.Get(s.localID)
	if !s.peerStore.ShouldDropOnRecvEpochsExhausted(s.localID, c) {
		t.Fatal("a Crypto tracking MaxRecvEpochs epochs must report that the next one would be refused")
	}
	lastSender := s.localStore.Get(s.peerID)

	rederiveSenderWithPrefix(s, distinctPrefix(keyexchange.MaxRecvEpochs, initial))
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "one-too-many")); !errors.Is(r.Err, envelope.ErrRecvEpochsExhausted) || r.Plaintext != nil {
		t.Fatalf("epoch %d: err=%v plaintext=%q; want ErrRecvEpochsExhausted", keyexchange.MaxRecvEpochs+1, r.Err, r.Plaintext)
	}
	if r := envelope.DecryptFrame(s.peerStore, first); !errors.Is(r.Err, envelope.ErrStaleEpoch) {
		t.Fatalf("the first (retired) epoch must stay rejected: err=%v", r.Err)
	}
	next := envelope.EncryptWith(s.localStore, lastSender, []byte("newest-next"))[4:]
	if r := envelope.DecryptFrame(s.peerStore, next); !accepted(r, "newest-next", keyexchange.RecvEpochNewest) {
		t.Fatalf("the newest tracked epoch must keep working: err=%v epoch=%v", r.Err, r.Epoch)
	}
}

// TestSameEpochReplayIsStillAReplay: the epoch check changes nothing for
// the current epoch — a duplicate is ErrReplay and counts toward the gate.
func TestSameEpochReplayIsStillAReplay(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	rederiveSender(t, s)
	f := sealLocal(t, s, "once")
	if r := envelope.DecryptFrame(s.peerStore, f); r.Err != nil {
		t.Fatalf("first delivery: %v", r.Err)
	}
	if r := envelope.DecryptFrame(s.peerStore, f); !errors.Is(r.Err, envelope.ErrReplay) {
		t.Fatalf("duplicate in the current epoch: err=%v, want ErrReplay", r.Err)
	}
	if rp, _ := faultCounts(s.peerStore.Get(s.localID)); rp != 1 {
		t.Fatalf("ReplayCount=%d after one same-epoch duplicate, want 1", rp)
	}
}

// TestForgedFrameCannotStartAnEpoch: only an authenticated frame can start
// an epoch. A forged frame with a never-seen prefix fails AEAD and leaves
// the current epoch and its window alone.
func TestForgedFrameCannotStartAnEpoch(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	for i := 0; i < 5; i++ {
		if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "genuine")); r.Err != nil {
			t.Fatalf("genuine %d: %v", i, r.Err)
		}
	}
	forged := forgeFrame(s.localID, 1<<40) // zero prefix, huge counter, junk tag
	if r := envelope.DecryptFrame(s.peerStore, forged); !errors.Is(r.Err, envelope.ErrAEAD) {
		t.Fatalf("forged frame: err=%v, want ErrAEAD", r.Err)
	}
	r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "genuine-after"))
	if !accepted(r, "genuine-after", keyexchange.RecvEpochNewest) || r.Counter != 6 || r.MaxRecvNonce != 6 {
		t.Fatalf("genuine frame after a forgery: err=%v epoch=%v counter=%d max=%d; want the same epoch, window intact",
			r.Err, r.Epoch, r.Counter, r.MaxRecvNonce)
	}
}
