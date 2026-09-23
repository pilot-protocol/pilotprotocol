// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"testing"
	"time"
)

// TestDropGatesJudgeTheNewestEpochsAge: the replay and outside-window
// gates count rejections in the window of the peer's newest send epoch,
// so they judge that epoch's age. A session we kept is always older than
// AgedCryptoFastDropAge by the time a path reset or drop gate meets it;
// the epoch a peer starts on it by re-deriving is not, and must get the
// threshold and grace of a fresh session instead of the aged fast path
// (which dropped our half on the first early duplicate or late frame).
func TestDropGatesJudgeTheNewestEpochsAge(t *testing.T) {
	t.Parallel()
	const peerID uint32 = 9
	store := NewStore()
	c := &Crypto{Ready: true, CreatedAt: time.Now().Add(-time.Hour)}
	store.Install(peerID, c)
	set := func(replays, outside int) {
		c.ReplayMu.Lock()
		c.ReplayCount, c.OutsideWindowCount = replays, outside
		c.ReplayMu.Unlock()
	}
	gates := func() (replay, outside bool) {
		return store.ShouldDropOnReplay(peerID, c), store.ShouldDropOnOutsideWindow(peerID, c)
	}

	// The peer's first epoch on an aged Crypto: the aged fast path.
	c.ReplayMu.Lock()
	c.CheckAndRecordEpochNonce([4]byte{1}, 50)
	c.ReplayMu.Unlock()
	set(1, 1)
	if r, o := gates(); !r || !o {
		t.Fatalf("settled first epoch: replay=%v outside=%v, want both armed on one rejection", r, o)
	}

	// The peer re-derives: its new epoch is judged as a fresh one.
	c.ReplayMu.Lock()
	if _, e := c.CheckAndRecordEpochNonce([4]byte{2}, 1); e != RecvEpochNew {
		c.ReplayMu.Unlock()
		t.Fatalf("epoch=%v, want RecvEpochNew", e)
	}
	c.ReplayMu.Unlock()
	set(1, 1)
	if r, o := gates(); r || o {
		t.Fatalf("one rejection in a brand-new epoch: replay=%v outside=%v, want neither armed", r, o)
	}
	set(ReplayDropThreshold, OutsideWindowDropThreshold)
	if r, o := gates(); r || o {
		t.Fatalf("threshold inside the grace of a brand-new epoch: replay=%v outside=%v, want neither armed", r, o)
	}

	backdateEpoch := func(age time.Duration) {
		c.ReplayMu.Lock()
		c.recvEpochAt = time.Now().Add(-age)
		c.ReplayMu.Unlock()
	}
	backdateEpoch(2 * ReplayDropGrace)
	set(1, 1)
	if r, o := gates(); r || o {
		t.Fatalf("one rejection in a young epoch past its grace: replay=%v outside=%v, want neither armed", r, o)
	}
	set(ReplayDropThreshold, OutsideWindowDropThreshold)
	if r, o := gates(); !r || !o {
		t.Fatalf("threshold in a young epoch past its grace: replay=%v outside=%v, want both armed", r, o)
	}

	backdateEpoch(2 * AgedCryptoFastDropAge)
	set(1, 1)
	if r, o := gates(); !r || !o {
		t.Fatalf("settled second epoch: replay=%v outside=%v, want the aged fast path again", r, o)
	}

	// A young Crypto is never judged older than it is.
	young := &Crypto{Ready: true, CreatedAt: time.Now()}
	young.recvEpochAt = time.Now().Add(-time.Hour)
	young.ReplayMu.Lock()
	age := young.dropGateAge(time.Now())
	young.ReplayMu.Unlock()
	if age > time.Second {
		t.Fatalf("dropGateAge=%v for a Crypto created just now", age)
	}
}
