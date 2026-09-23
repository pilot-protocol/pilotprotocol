// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestRecvEpochWindows pins the per-epoch replay windows envelope relies
// on: the first prefix is the newest epoch; each never-seen prefix starts
// a fresh newest window and keeps the previous one; a retained epoch is
// judged in its own window without disturbing the newest; and when a new
// epoch needs room, the least recently used of RetainedRecvEpochs older
// windows is dropped and its epoch retired — rejected for good, never
// re-opened as a new epoch.
func TestRecvEpochWindows(t *testing.T) {
	t.Parallel()
	c := &keyexchange.Crypto{Ready: true}
	prefix := func(i byte) [4]byte { return [4]byte{i, i, i, i} }
	check := func(p byte, counter uint64, wantOK bool, want keyexchange.RecvEpoch) {
		t.Helper()
		ok, got := c.CheckAndRecordEpochNonce(prefix(p), counter)
		if ok != wantOK || got != want {
			t.Fatalf("epoch %d counter %d: (ok=%v, epoch=%v), want (ok=%v, epoch=%v)",
				p, counter, ok, got, wantOK, want)
		}
	}

	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()

	check(1, 40, true, keyexchange.RecvEpochNewest) // first frame on the Crypto
	check(1, 40, false, keyexchange.RecvEpochNewest)
	check(2, 1, true, keyexchange.RecvEpochNew) // the peer re-derived
	if c.MaxRecvNonce != 1 {
		t.Fatalf("the new epoch must start a fresh window: MaxRecvNonce=%d", c.MaxRecvNonce)
	}
	check(1, 40, false, keyexchange.RecvEpochOlder) // epoch 1's own window still has 40
	check(1, 41, true, keyexchange.RecvEpochOlder)  // an unseen straggler of epoch 1
	if c.MaxRecvNonce != 1 {
		t.Fatalf("an older epoch's frame moved the newest window: MaxRecvNonce=%d", c.MaxRecvNonce)
	}
	check(2, 1, false, keyexchange.RecvEpochNewest) // a duplicate in the newest epoch
	check(2, 2, true, keyexchange.RecvEpochNewest)

	// Fill all RetainedRecvEpochs older windows (1..4 behind newest 5),
	// then touch epoch 1 so epoch 2 is the least recently used when
	// epoch 6 arrives.
	for p := byte(3); p <= 5; p++ {
		check(p, 1, true, keyexchange.RecvEpochNew)
	}
	check(1, 42, true, keyexchange.RecvEpochOlder)
	check(6, 1, true, keyexchange.RecvEpochNew) // evicts epoch 2
	check(1, 42, false, keyexchange.RecvEpochOlder)
	for p := byte(3); p <= 5; p++ {
		check(p, 1, false, keyexchange.RecvEpochOlder)
	}
	// Epoch 2 was retired: every frame of it is rejected — even a counter
	// its window never saw — and it never becomes a new epoch again.
	for _, counter := range []uint64{1, 2, 1000} {
		check(2, counter, false, keyexchange.RecvEpochRetired)
	}
	// Epoch 6 is still the newest, with its own window.
	check(6, 1, false, keyexchange.RecvEpochNewest)
	check(6, 2, true, keyexchange.RecvEpochNewest)
	// The retained older epochs are untouched.
	check(1, 43, true, keyexchange.RecvEpochOlder)
}

// TestRecvEpochLimit: a Crypto tracks at most MaxRecvEpochs peer epochs.
// Past that a new prefix is refused, with nothing recorded, instead of
// making room by forgetting one; the Store then reports the session for
// dropping.
func TestRecvEpochLimit(t *testing.T) {
	t.Parallel()
	const peerID uint32 = 7
	c := &keyexchange.Crypto{Ready: true}
	store := keyexchange.NewStore()
	store.Install(peerID, c)
	prefix := func(i int) [4]byte { return [4]byte{0xA0, byte(i >> 16), byte(i >> 8), byte(i)} }

	c.ReplayMu.Lock()
	for i := 0; i < keyexchange.MaxRecvEpochs; i++ {
		if ok, _ := c.CheckAndRecordEpochNonce(prefix(i), 1); !ok {
			c.ReplayMu.Unlock()
			t.Fatalf("epoch %d of %d refused", i+1, keyexchange.MaxRecvEpochs)
		}
	}
	c.ReplayMu.Unlock()
	if !store.ShouldDropOnRecvEpochsExhausted(peerID, c) {
		t.Fatal("a Crypto tracking MaxRecvEpochs epochs must be reported for dropping")
	}

	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	newestMax := c.MaxRecvNonce
	if ok, got := c.CheckAndRecordEpochNonce(prefix(keyexchange.MaxRecvEpochs), 1); ok || got != keyexchange.RecvEpochExhausted {
		t.Fatalf("epoch past the limit: (ok=%v, epoch=%v), want refused as RecvEpochExhausted", ok, got)
	}
	if c.MaxRecvNonce != newestMax {
		t.Fatal("a refused epoch must not touch the newest window")
	}
	if ok, got := c.CheckAndRecordEpochNonce(prefix(0), 2); ok || got != keyexchange.RecvEpochRetired {
		t.Fatalf("the first epoch: (ok=%v, epoch=%v), want still retired", ok, got)
	}
	if ok, got := c.CheckAndRecordEpochNonce(prefix(keyexchange.MaxRecvEpochs-1), 2); !ok || got != keyexchange.RecvEpochNewest {
		t.Fatalf("the newest epoch: (ok=%v, epoch=%v), want it to keep working", ok, got)
	}
}

// TestFreshCryptoIsNotReportedExhausted: the exhaustion gate only fires
// for the Crypto it is asked about, and only while it is installed.
func TestFreshCryptoIsNotReportedExhausted(t *testing.T) {
	t.Parallel()
	store := keyexchange.NewStore()
	c := &keyexchange.Crypto{Ready: true}
	store.Install(1, c)
	if store.ShouldDropOnRecvEpochsExhausted(1, c) || store.ShouldDropOnRecvEpochsExhausted(1, nil) {
		t.Fatal("a fresh Crypto must not be reported exhausted")
	}
}
