// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// TestRecvEpochWindows pins the per-epoch replay windows envelope relies
// on: the first prefix is the newest epoch; each never-seen prefix starts
// a fresh newest window and keeps the previous one; a retained epoch is
// judged in its own window without disturbing the newest; and only the
// least recently used of RetainedRecvEpochs older windows is forgotten.
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
	// Epoch 2 was forgotten: it comes back as a new epoch with a fresh
	// window — and every other epoch keeps its own.
	check(2, 1, true, keyexchange.RecvEpochNew)
	check(6, 1, false, keyexchange.RecvEpochOlder)
	check(6, 2, true, keyexchange.RecvEpochOlder)
}
