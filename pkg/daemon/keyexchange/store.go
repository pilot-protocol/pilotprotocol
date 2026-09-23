// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// MaxCryptoPeers caps the crypto map for unauth key-exchange insertions.
// HandleAuthFrame is implicitly bounded by the registry-verified pubkey
// lookup, but HandleUnauthFrame accepts any peerNodeID and performs an
// X25519 scalar multiplication per packet. Without a cap, a peer
// spraying unauth key-exchange frames with random node IDs can grow the
// map to 2^32 entries while also burning CPU on derivation. Set high
// enough that real deployments never hit it.
//
// Lives on L5 with the per-peer Store rather than as a free constant
// in L6 framing — the cap is a property of key-state ownership.
const MaxCryptoPeers = 16384

// ErrNoKey is returned when no Crypto is installed for a peer
// (encrypt-side: no key to wrap with; decrypt-side: nothing to unwrap
// with). Caller's responsibility to trigger a rekey request.
var ErrNoKey = errors.New("keyexchange: no key installed for peer")

// ErrNotReady is returned when a Crypto exists but is not yet marked
// Ready (key exchange in progress).
var ErrNotReady = errors.New("keyexchange: crypto installed but not ready")

// Store is the per-tunnel key-state registry. It owns the map of node ID
// → Crypto. Counter, replay-window, and salvage state live on the
// per-peer Crypto values; Store's mutex only protects the map itself.
//
// The mutex is intentionally a simple sync.RWMutex used as a leaf lock —
// it must NEVER be held while invoking a TunnelManager-side mutex
// (tm.mu, tm.rkPendingMu, tm.pendMu). All callers obey this by reading
// from Store first, then mutating tm state in a separate critical
// section.
//
// Store is L5-owned. L6 (envelope) imports Store to pull per-peer
// Crypto pointers when wrapping/unwrapping AEAD frames; the import
// direction is L6 → L5, matching docs/architecture/01-LAYERS.md.
type Store struct {
	mu     sync.RWMutex
	crypto map[uint32]*Crypto

	// localNodeID is our own node ID, written into the AEAD AAD (H3)
	// and the secure-frame header. Stored as atomic uint32 so SetLocalNodeID
	// can be called from any goroutine without locking the map.
	localNodeID atomic.Uint32

	// EncryptOK / EncryptFail track AEAD operation success/failure
	// counts. Exposed as atomic counters so L7 / metrics readers don't
	// need to take Store.mu. Bumped by the L6 framing functions in
	// pkg/daemon/envelope.
	EncryptOK   atomic.Uint64
	EncryptFail atomic.Uint64
}

// NewStore returns an empty Store.
func NewStore() *Store {
	return &Store{crypto: make(map[uint32]*Crypto)}
}

// SetLocalNodeID stores our own node ID (used in encrypt-side AAD and
// secure-frame headers). Safe to call concurrently with other Store
// operations.
func (s *Store) SetLocalNodeID(id uint32) {
	s.localNodeID.Store(id)
}

// LocalNodeID returns our own node ID.
func (s *Store) LocalNodeID() uint32 {
	return s.localNodeID.Load()
}

// Install adds (or replaces) the Crypto for the given peer. Caller is
// responsible for any "preserve on duplicate same-pubkey" logic — Store
// just unconditionally writes.
func (s *Store) Install(peerNodeID uint32, c *Crypto) {
	s.mu.Lock()
	s.crypto[peerNodeID] = c
	s.mu.Unlock()
}

// Get returns the Crypto installed for peerNodeID, or nil if none.
func (s *Store) Get(peerNodeID uint32) *Crypto {
	s.mu.RLock()
	c := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return c
}

// Has returns true if a Crypto is installed for peerNodeID.
func (s *Store) Has(peerNodeID uint32) bool {
	s.mu.RLock()
	_, ok := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return ok
}

// IsReady returns true if a Crypto is installed AND its handshake is
// complete (Ready=true).
func (s *Store) IsReady(peerNodeID uint32) bool {
	s.mu.RLock()
	c := s.crypto[peerNodeID]
	s.mu.RUnlock()
	return c != nil && c.Ready
}

// wipeCryptoSecrets clears any sensitive plaintext on a Crypto's salvage
// ring before the Crypto is dropped. PILOT-146: previously Drop simply
// did a map delete, leaving the salvage plaintext bytes alive on the heap
// until GC. Explicitly zero them on the way out so a heap dump taken
// shortly after eviction cannot recover the just-evicted plaintext.
//
// Caller must hold whatever lock(s) protect c.Salvage if there could be
// concurrent access — internal use only.
func wipeCryptoSecrets(c *Crypto) {
	if c == nil {
		return
	}
	c.SalvageMu.Lock()
	for i := range c.Salvage {
		for j := range c.Salvage[i].Plaintext {
			c.Salvage[i].Plaintext[j] = 0
		}
		c.Salvage[i].Plaintext = nil
	}
	c.Salvage = nil
	c.SalvageMu.Unlock()
}

// Drop removes the Crypto for peerNodeID. Safe even if no entry exists.
func (s *Store) Drop(peerNodeID uint32) {
	s.mu.Lock()
	c := s.crypto[peerNodeID]
	delete(s.crypto, peerNodeID)
	s.mu.Unlock()
	wipeCryptoSecrets(c) // PILOT-146: zero salvage plaintext on eviction
}

// CompareAndDrop deletes the entry only if the currently-installed
// pointer equals expected. Returns true if a delete occurred. Used by
// the decrypt-fail drop path to avoid deleting a Crypto that a
// concurrent rekey already replaced.
func (s *Store) CompareAndDrop(peerNodeID uint32, expected *Crypto) bool {
	s.mu.Lock()
	if s.crypto[peerNodeID] != expected {
		s.mu.Unlock()
		return false
	}
	c := s.crypto[peerNodeID]
	delete(s.crypto, peerNodeID)
	s.mu.Unlock()
	wipeCryptoSecrets(c) // PILOT-146
	return true
}

// Len returns the number of installed Cryptos. Used by the
// MaxCryptoPeers cap pre-check.
func (s *Store) Len() int {
	s.mu.RLock()
	n := len(s.crypto)
	s.mu.RUnlock()
	return n
}

// PeerIDs returns a snapshot of all peer IDs with installed Cryptos.
func (s *Store) PeerIDs() []uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]uint32, 0, len(s.crypto))
	for id := range s.crypto {
		ids = append(ids, id)
	}
	return ids
}

// ShouldDropOnDecryptFail implements the rc5 grace gate: returns true
// if the failing Crypto's DecryptFailCount has reached
// DecryptFailDropThreshold AND the Crypto is older than
// DecryptFailDropGrace AND it is still the currently-installed entry
// for peerNodeID.
//
// The caller (L6 framing path) is responsible for the side-effect: drop
// via CompareAndDrop and trigger a fresh key exchange. This split keeps
// the rekey-trigger / event-publish responsibility OUT of Store.
func (s *Store) ShouldDropOnDecryptFail(peerNodeID uint32, c *Crypto) bool {
	if c == nil {
		return false
	}
	c.ReplayMu.Lock()
	failures := c.DecryptFailCount
	c.ReplayMu.Unlock()
	if failures < DecryptFailDropThreshold {
		return false
	}
	if time.Since(c.CreatedAt) < DecryptFailDropGrace {
		return false
	}
	// Only drop if c is still the currently-installed entry.
	current := s.Get(peerNodeID)
	return current == c
}

// ShouldDropOnOutsideWindow mirrors ShouldDropOnDecryptFail for the
// outside-replay-window divergence path. Returns true when the peer's
// OutsideWindowCount has reached OutsideWindowDropThreshold AND the
// peer's newest send epoch on the Crypto (Crypto.dropGateAge) is older
// than OutsideWindowDropGrace AND it is still the currently-installed
// entry for peerNodeID.
//
// The caller (L7 handleEncrypted) is responsible for dropping the
// Crypto via CompareAndDrop and triggering a fresh key exchange when
// this returns true. This is the symmetric-state recovery for the
// case where our receive-window's high-water-mark has drifted so far
// past the peer's actual send counter that no in-band signal exists.
// Reproduces the rc3 list-agents bug on 2026-05-11 where MaxRecvNonce
// stayed at 8518 while the sender's outbound counter sat at ~400.
func (s *Store) ShouldDropOnOutsideWindow(peerNodeID uint32, c *Crypto) bool {
	if c == nil {
		return false
	}
	c.ReplayMu.Lock()
	rejections := c.OutsideWindowCount
	age := c.dropGateAge(time.Now())
	c.ReplayMu.Unlock()
	if rejections == 0 {
		return false
	}
	// Aged-Crypto fast path: a session that has lived past
	// AgedCryptoFastDropAge cannot be in a transient post-rekey
	// drain state. ANY outside-window event from it is real
	// divergence — drop on the first occurrence so very-quiet
	// peers recover without needing to send the full threshold.
	//
	// The age is that of the peer's newest send epoch: the rejections
	// counted are in that epoch's window, and an epoch the peer started
	// by re-deriving a session we kept is in exactly that drain state,
	// however old the Crypto is. Judging it by the Crypto's age dropped
	// our half on its first late frame — against a v1.10.9–v1.13 peer,
	// which now held the fresh half and never answers a same-key
	// exchange, a wedge.
	if age < AgedCryptoFastDropAge {
		if rejections < OutsideWindowDropThreshold {
			return false
		}
		if age < OutsideWindowDropGrace {
			return false
		}
	}
	current := s.Get(peerNodeID)
	return current == c
}

// ShouldDropOnReplay is the symmetric counterpart to
// ShouldDropOnOutsideWindow for the in-window replay-collision path.
// Returns true when ReplayCount has reached ReplayDropThreshold AND
// the peer's newest send epoch on the Crypto (Crypto.dropGateAge) is
// older than ReplayDropGrace AND it is still the currently-installed
// entry for peerNodeID.
//
// The caller (L7 handleEncrypted) is responsible for the side effect:
// drop via CompareAndDrop and request a fresh key exchange. This
// reproduces the recovery for the rc5 list-agents wedge (2026-05-11)
// where peer daemons restarted but kept their persisted X25519
// identity — no PILA was sent, their send counter reset to 1, our
// MaxRecvNonce stayed at ~50, every subsequent frame from the peer
// landed at an already-marked counter and was dropped before
// AEAD-Open ever ran. Neither DecryptFailCount nor OutsideWindowCount
// incremented, so the existing recovery gates never engaged.
func (s *Store) ShouldDropOnReplay(peerNodeID uint32, c *Crypto) bool {
	if c == nil {
		return false
	}
	c.ReplayMu.Lock()
	replays := c.ReplayCount
	age := c.dropGateAge(time.Now())
	c.ReplayMu.Unlock()
	if replays == 0 {
		return false
	}
	// Aged-Crypto fast path: see ShouldDropOnOutsideWindow comment.
	// A settled (>AgedCryptoFastDropAge) session cannot be in
	// post-rekey duplicate-delivery drain — a single replay is
	// real divergence (peer restart). Quiet peers that send only
	// 1 frame after restart recover here instead of waiting for
	// the count threshold they may never reach. As there, "settled"
	// is judged by the peer's newest send epoch: a duplicate of an
	// early frame of an epoch that just started is exactly the
	// post-rekey drain the threshold and grace exist for.
	if age < AgedCryptoFastDropAge {
		if replays < ReplayDropThreshold {
			return false
		}
		if age < ReplayDropGrace {
			return false
		}
	}
	current := s.Get(peerNodeID)
	return current == c
}

// ShouldDropOnRecvEpochsExhausted reports whether c, still the installed
// entry for peerNodeID, has refused a new peer send epoch because it
// already tracks MaxRecvEpochs of them (RecvEpochExhausted). The caller
// (L7 handleEncrypted) drops it via CompareAndDrop and requests a fresh
// key exchange: the Crypto that replaces it starts with no epochs, and
// making room by forgetting one would let that epoch's recorded frames
// be accepted again.
func (s *Store) ShouldDropOnRecvEpochsExhausted(peerNodeID uint32, c *Crypto) bool {
	if c == nil {
		return false
	}
	c.ReplayMu.Lock()
	exhausted := c.recvEpochsExhausted()
	c.ReplayMu.Unlock()
	return exhausted && s.Get(peerNodeID) == c
}

// RecordSalvage stashes a plaintext send into the per-peer ring buffer.
// On a subsequent peer-initiated rekey, DrainSalvage will hand back the
// entries; the caller re-encrypts with the new key and re-sends —
// recovering data that the peer dropped because our frame was keyed
// under their now-stale crypto context.
//
// Bounded by SalvageMaxEntries and SalvageMaxAge. The plaintext is
// copied, not referenced — caller can reuse its buffer.
//
// nil c is a no-op (safe for callers that don't gate on Ready).
func (s *Store) RecordSalvage(c *Crypto, plaintext []byte) {
	if c == nil {
		return
	}
	now := time.Now()
	cutoff := now.Add(-SalvageMaxAge)
	c.SalvageMu.Lock()
	// Trim aged entries from the head.
	// PILOT-146: zero the plaintext bytes before reslicing — otherwise the
	// backing array still holds the cleartext until GC walks it, which an
	// arena-co-resident attacker could (theoretically) observe before
	// reuse.
	for len(c.Salvage) > 0 && c.Salvage[0].When.Before(cutoff) {
		for i := range c.Salvage[0].Plaintext {
			c.Salvage[0].Plaintext[i] = 0
		}
		c.Salvage = c.Salvage[1:]
	}
	// Bound size — drop oldest.
	if len(c.Salvage) >= SalvageMaxEntries {
		for i := range c.Salvage[0].Plaintext {
			c.Salvage[0].Plaintext[i] = 0
		}
		c.Salvage = c.Salvage[1:]
	}
	cp := make([]byte, len(plaintext))
	copy(cp, plaintext)
	c.Salvage = append(c.Salvage, SalvageEntry{Plaintext: cp, When: now})
	c.SalvageMu.Unlock()
}

// DrainSalvage atomically removes and returns all non-aged salvage
// entries from c. Returns nil if c is nil or empty. Each returned
// Plaintext is the same byte slice that was stored — RecordSalvage
// already copied at insert time.
func (s *Store) DrainSalvage(c *Crypto) []SalvageEntry {
	if c == nil {
		return nil
	}
	c.SalvageMu.Lock()
	entries := c.Salvage
	c.Salvage = nil
	c.SalvageMu.Unlock()
	if len(entries) == 0 {
		return nil
	}
	cutoff := time.Now().Add(-SalvageMaxAge)
	out := entries[:0]
	for _, e := range entries {
		if e.When.Before(cutoff) {
			// PILOT-146: aged entry not returned to caller — zero its
			// plaintext before the slice header drops the reference.
			for i := range e.Plaintext {
				e.Plaintext[i] = 0
			}
			continue
		}
		out = append(out, e)
	}
	return out
}
