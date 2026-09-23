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
	nc := &keyexchange.Crypto{
		AEAD:          old.AEAD,
		Ready:         true,
		Authenticated: old.Authenticated,
		PeerX25519Key: old.PeerX25519Key,
		CreatedAt:     time.Now(),
	}
	for {
		if _, err := rand.Read(nc.NoncePrefix[:]); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if nc.NoncePrefix != old.NoncePrefix {
			break
		}
	}
	s.localStore.Install(s.peerID, nc)
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
				if r.Err != nil {
					t.Fatalf("old-epoch frame %d: %v", i, r.Err)
				}
				if r.NewEpoch {
					t.Fatalf("old-epoch frame %d reported a new epoch (the first frame on a Crypto is not one)", i)
				}
			}
			c := s.peerStore.Get(s.localID)
			backdateCreatedAt(c, time.Now().Add(-2*keyexchange.AgedCryptoFastDropAge))

			rederiveSender(t, s)
			r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-1"))
			if r.Err != nil || string(r.Plaintext) != "new-1" || r.Counter != 1 {
				t.Fatalf("first frame of the peer's new epoch: err=%v counter=%d plaintext=%q; want accepted at counter 1",
					r.Err, r.Counter, r.Plaintext)
			}
			if !r.NewEpoch {
				t.Fatal("the first frame of a new peer epoch must be reported as NewEpoch")
			}
			r = envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-2"))
			if r.Err != nil || r.NewEpoch {
				t.Fatalf("second frame of the new epoch: err=%v newEpoch=%v", r.Err, r.NewEpoch)
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
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-1")); r.Err != nil || !r.NewEpoch {
		t.Fatalf("new epoch: err=%v newEpoch=%v", r.Err, r.NewEpoch)
	}
	newest := func() uint64 {
		c.ReplayMu.Lock()
		defer c.ReplayMu.Unlock()
		return c.MaxRecvNonce
	}
	before := newest()

	if r := envelope.DecryptFrame(s.peerStore, late); r.Err != nil || string(r.Plaintext) != "late" || r.NewEpoch {
		t.Fatalf("late frame of the previous epoch: err=%v plaintext=%q newEpoch=%v; want delivered",
			r.Err, r.Plaintext, r.NewEpoch)
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
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "new-2")); r.Err != nil || r.NewEpoch {
		t.Fatalf("the new epoch must stay newest: err=%v newEpoch=%v", r.Err, r.NewEpoch)
	}
}

// TestForgottenEpochCannotLockOutTheLiveEpoch: a frame of an epoch old
// enough to have been forgotten comes back as a new epoch (as any frame on
// a fresh window after a re-handshake does), but it cannot lock the peer's
// live epoch out: the live epoch keeps its own window, so its next frames
// are delivered and its duplicates are still rejected.
func TestForgottenEpochCannotLockOutTheLiveEpoch(t *testing.T) {
	t.Parallel()
	s := newPeerSetup(t)
	ancient := sealLocal(t, s, "ancient")
	if r := envelope.DecryptFrame(s.peerStore, ancient); r.Err != nil {
		t.Fatalf("ancient: %v", r.Err)
	}
	var live []byte
	for i := 0; i <= keyexchange.RetainedRecvEpochs; i++ { // push the first epoch out
		rederiveSender(t, s)
		live = sealLocal(t, s, "live")
		if r := envelope.DecryptFrame(s.peerStore, live); r.Err != nil || !r.NewEpoch {
			t.Fatalf("epoch %d: err=%v newEpoch=%v", i+2, r.Err, r.NewEpoch)
		}
	}

	if r := envelope.DecryptFrame(s.peerStore, ancient); r.Err != nil || !r.NewEpoch {
		t.Fatalf("frame of a forgotten epoch: err=%v newEpoch=%v; want a fresh window", r.Err, r.NewEpoch)
	}
	if r := envelope.DecryptFrame(s.peerStore, sealLocal(t, s, "live-next")); r.Err != nil || string(r.Plaintext) != "live-next" {
		t.Fatalf("the live epoch was locked out: err=%v plaintext=%q", r.Err, r.Plaintext)
	}
	if r := envelope.DecryptFrame(s.peerStore, live); !errors.Is(r.Err, envelope.ErrStaleEpoch) {
		t.Fatalf("a duplicate of the live epoch must still be rejected by its own window: err=%v", r.Err)
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
	if r.Err != nil || r.NewEpoch || r.Counter != 6 || r.MaxRecvNonce != 6 {
		t.Fatalf("genuine frame after a forgery: err=%v newEpoch=%v counter=%d max=%d; want the same epoch, window intact",
			r.Err, r.NewEpoch, r.Counter, r.MaxRecvNonce)
	}
}
