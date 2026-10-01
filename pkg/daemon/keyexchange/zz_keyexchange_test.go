// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Greenfield unit tests for L5 (pkg/daemon/keyexchange).
//
// Goals (from P4 brief):
//  1. DeriveSecret ECDH symmetry + HKDFInfo stability.
//  2. Store install/get/drop concurrency under -race.
//  3. Frame round-trip (PILA 136B / PILK 40B) via BuildAuthFrame /
//     BuildUnauthFrame → HandleAuthFrame / HandleUnauthFrame.
//  4. Rekey retransmit: MarkPendingRekey + RekeyRetransmitTick + give-up
//     event publish on the (MaxRekeyAttempts+1)th attempt.
//  5. Replay window: CheckAndRecordNonce — duplicates rejected, counters
//     below the window rejected.
//  6. Salvage ring: bounded by SalvageMaxEntries, aged out at SalvageMaxAge,
//     drained atomically.
//  7. DecryptFailDropGrace: ShouldDropOnDecryptFail honors threshold + grace
//     + still-installed gating.
//  8. Bootstrap exception marker on SendKeyExchangeToNode (the package
//     ships a single annotated bootstrap site — verify the function ships
//     a frame and registers a pending rekey).

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	icrypto "github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// ---------- helpers ----------

// genX25519 returns a fresh X25519 keypair.
func genX25519(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("X25519 generate: %v", err)
	}
	return priv, priv.PublicKey().Bytes()
}

// peer is a self-contained Manager with identity + X25519 keys + a node ID.
type peer struct {
	id       uint32
	mgr      *keyexchange.Manager
	identity *icrypto.Identity
	x25519   *ecdh.PrivateKey
	x25519Pb []byte
}

func newPeer(t *testing.T, id uint32) *peer {
	t.Helper()
	idn, err := icrypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	priv, pub := genX25519(t)
	m := keyexchange.New(nil)
	m.SetIdentity(idn)
	m.SetX25519Keys(priv, pub)
	m.SetLocalNodeIDFn(func() uint32 { return id })
	return &peer{id: id, mgr: m, identity: idn, x25519: priv, x25519Pb: pub}
}

// crossWireVerifyFuncs registers each peer's Ed25519 pubkey with the other,
// so HandleAuthFrame can resolve identities from the "registry" callback.
func crossWireVerifyFuncs(a, b *peer) {
	a.mgr.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		if nodeID == b.id {
			return b.identity.PublicKey, nil
		}
		return nil, nil
	})
	b.mgr.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		if nodeID == a.id {
			return a.identity.PublicKey, nil
		}
		return nil, nil
	})
}

// ---------- 1. DeriveSecret ----------

// TestDeriveSecretECDHSymmetry pins that A.derive(B.pub) and B.derive(A.pub)
// land on the same AEAD key — which is the contract every encrypted frame
// on the wire depends on. We don't have direct access to the raw key (it's
// zeroed inside DeriveSecret), so we verify by sealing on one side and
// opening on the other.
func TestDeriveSecretECDHSymmetry(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 1)
	b := newPeer(t, 2)

	pcA, err := a.mgr.DeriveSecret(b.x25519Pb)
	if err != nil {
		t.Fatalf("a.derive: %v", err)
	}
	pcB, err := b.mgr.DeriveSecret(a.x25519Pb)
	if err != nil {
		t.Fatalf("b.derive: %v", err)
	}

	// Use a constant nonce on both sides — we're checking symmetry of the
	// derived AEAD key, not nonce machinery.
	nonce := make([]byte, pcA.AEAD.NonceSize())
	plaintext := []byte("hello-symmetric-aead")
	ciphertext := pcA.AEAD.Seal(nil, nonce, plaintext, nil)
	got, err := pcB.AEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Fatalf("b.AEAD.Open of a.Seal: %v (HKDF info or ECDH mismatch)", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("symmetric ECDH plaintext mismatch: got %q want %q", got, plaintext)
	}

	// The other direction must also work.
	ciphertext2 := pcB.AEAD.Seal(nil, nonce, plaintext, nil)
	got2, err := pcA.AEAD.Open(nil, nonce, ciphertext2, nil)
	if err != nil {
		t.Fatalf("a.AEAD.Open of b.Seal: %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Fatalf("reverse-direction plaintext mismatch")
	}
}

// TestHKDFInfoFrozen pins the wire-frozen info string. Changing it would
// silently break every existing peer in the field.
func TestHKDFInfoFrozen(t *testing.T) {
	t.Parallel()
	if keyexchange.HKDFInfo != "pilot-tunnel-v1" {
		t.Fatalf("HKDFInfo changed: got %q want pilot-tunnel-v1", keyexchange.HKDFInfo)
	}
}

// TestDeriveSecretRejectsBadPubKey asserts a malformed peer pubkey is
// surfaced as an error rather than panicking inside ECDH.
func TestDeriveSecretRejectsBadPubKey(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	if _, err := p.mgr.DeriveSecret([]byte{0x01, 0x02}); err == nil {
		t.Fatalf("expected error for short peer pubkey, got nil")
	}
}

// TestDeriveSecretNoPrivKeyFails confirms ECDH is gated on local privkey.
func TestDeriveSecretNoPrivKeyFails(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)
	_, peerPub := genX25519(t)
	if _, err := m.DeriveSecret(peerPub); err == nil {
		t.Fatalf("expected error when local PrivKey is unset")
	}
}

// ---------- 2. Store ----------

// TestStoreInstallGetDrop is the core contract: install → get → drop.
func TestStoreInstallGetDrop(t *testing.T) {
	t.Parallel()

	s := keyexchange.NewStore()
	if s.Has(42) {
		t.Fatalf("empty store reported Has(42)=true")
	}
	if s.Get(42) != nil {
		t.Fatalf("empty store returned non-nil Get(42)")
	}
	if s.Len() != 0 {
		t.Fatalf("empty store Len()=%d want 0", s.Len())
	}

	c := &keyexchange.Crypto{Ready: true, CreatedAt: time.Now()}
	s.Install(42, c)
	if !s.Has(42) {
		t.Fatalf("after Install Has(42)=false")
	}
	if s.Get(42) != c {
		t.Fatalf("Get(42) returned different pointer")
	}
	if !s.IsReady(42) {
		t.Fatalf("IsReady(42)=false; expected true (Ready is set)")
	}
	if s.Len() != 1 {
		t.Fatalf("Len=%d want 1", s.Len())
	}

	// Drop and verify removal.
	s.Drop(42)
	if s.Has(42) {
		t.Fatalf("after Drop Has(42)=true")
	}
	if s.Len() != 0 {
		t.Fatalf("after Drop Len=%d want 0", s.Len())
	}
}

// TestStoreCompareAndDropMatches the lock-graph guarantee that a stale
// drop request from the decrypt-fail path doesn't evict a fresh Crypto
// from a concurrent rekey.
func TestStoreCompareAndDropMatches(t *testing.T) {
	t.Parallel()

	s := keyexchange.NewStore()
	first := &keyexchange.Crypto{Ready: true}
	s.Install(7, first)

	// Drop with stale expected → no-op.
	stale := &keyexchange.Crypto{Ready: true}
	if s.CompareAndDrop(7, stale) {
		t.Fatalf("CompareAndDrop with mismatched pointer should return false")
	}
	if s.Get(7) != first {
		t.Fatalf("CompareAndDrop with stale expected mutated the store")
	}

	// Drop with current pointer → success.
	if !s.CompareAndDrop(7, first) {
		t.Fatalf("CompareAndDrop with matching pointer returned false")
	}
	if s.Has(7) {
		t.Fatalf("CompareAndDrop did not remove entry")
	}
}

// TestStoreConcurrentInstallGet hammers the Store from many goroutines —
// run under -race to catch missing locks or read-during-rehash bugs.
func TestStoreConcurrentInstallGet(t *testing.T) {
	t.Parallel()

	s := keyexchange.NewStore()
	const writers = 8
	const readers = 8
	const peersPerWriter = 256

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < peersPerWriter; i++ {
				id := uint32(w)*uint32(peersPerWriter) + uint32(i)
				c := &keyexchange.Crypto{Ready: true}
				s.Install(id, c)
				if id%4 == 0 {
					s.Drop(id)
				}
			}
		}()
	}

	stop := make(chan struct{})
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = s.Has(uint32(r))
					_ = s.Get(uint32(r))
					_ = s.Len()
					_ = s.IsReady(uint32(r))
					_ = s.PeerIDs()
				}
			}
		}()
	}

	// Let writers finish, then close stop to release readers.
	go func() {
		// The Wait() below races with the stop channel — instead we
		// wait only for writers in this small goroutine and then signal.
		// Use a separate WaitGroup for clarity is overkill; close stop
		// after a short grace period.
		time.Sleep(50 * time.Millisecond)
		close(stop)
	}()

	wg.Wait()
}

// ---------- 3. Frame round-trip ----------

// TestBuildAuthFrameSize pins the on-wire size of an authenticated frame
// (PILA = 136 bytes). This is the contract observed by L4 framing logic.
func TestBuildAuthFrameSize(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 0xCAFEBABE)
	frame := p.mgr.BuildAuthFrame()
	if got, want := len(frame), 4+4+32+32+64; got != want {
		t.Fatalf("PILA frame size: got %d want %d", got, want)
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicAuthEx[:]) {
		t.Fatalf("PILA magic mismatch: got %x want %x", frame[0:4], protocol.TunnelMagicAuthEx[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0xCAFEBABE {
		t.Fatalf("PILA nodeID: got %x want CAFEBABE", got)
	}
	// Embedded X25519 pubkey matches local.
	if !bytes.Equal(frame[8:40], p.x25519Pb) {
		t.Fatalf("PILA X25519 slot does not match local pubkey")
	}
	// Embedded Ed25519 pubkey matches local identity.
	if !bytes.Equal(frame[40:72], []byte(p.identity.PublicKey)) {
		t.Fatalf("PILA Ed25519 slot does not match local identity")
	}
}

// TestBuildUnauthFrameSize pins the on-wire size of an unauthenticated
// frame (PILK = 40 bytes).
func TestBuildUnauthFrameSize(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 0xDEADBEEF)
	frame := p.mgr.BuildUnauthFrame()
	if got, want := len(frame), 4+4+32; got != want {
		t.Fatalf("PILK frame size: got %d want %d", got, want)
	}
	if !bytes.Equal(frame[0:4], protocol.TunnelMagicKeyEx[:]) {
		t.Fatalf("PILK magic mismatch: got %x want %x", frame[0:4], protocol.TunnelMagicKeyEx[:])
	}
	if got := binary.BigEndian.Uint32(frame[4:8]); got != 0xDEADBEEF {
		t.Fatalf("PILK nodeID: got %x want DEADBEEF", got)
	}
}

// TestBuildAuthFrameNilWhenNoKeys covers the early-return path when X25519
// keys are not set yet.
func TestBuildAuthFrameNilWhenNoKeys(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)
	if f := m.BuildAuthFrame(); f != nil {
		t.Fatalf("BuildAuthFrame without keys returned %d bytes; want nil", len(f))
	}
	if f := m.BuildUnauthFrame(); f != nil {
		t.Fatalf("BuildUnauthFrame without keys returned %d bytes; want nil", len(f))
	}
}

// TestBuildAuthFrameNilWithoutIdentity covers the path where X25519 is set
// but identity is missing.
func TestBuildAuthFrameNilWithoutIdentity(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)
	priv, pub := genX25519(t)
	m.SetX25519Keys(priv, pub)
	if f := m.BuildAuthFrame(); f != nil {
		t.Fatalf("BuildAuthFrame without identity returned non-nil")
	}
	// Unauth frame should still build.
	if f := m.BuildUnauthFrame(); len(f) != 40 {
		t.Fatalf("BuildUnauthFrame without identity: got %d bytes want 40", len(f))
	}
}

// TestHandleAuthFrameRoundTrip is the end-to-end PILA path: A builds a
// frame, B handles it, and B's Store ends up with an installed Crypto.
// Also asserts the post-install hook fires with the right authentication
// flag.
func TestHandleAuthFrameRoundTrip(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 100)
	b := newPeer(t, 200)
	crossWireVerifyFuncs(a, b)

	// Wire B's sender to a no-op (it will call SendKeyExchangeToNode in
	// the response path; we don't care about the wire bytes here, just
	// that nothing panics).
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	var hookFired atomic.Bool
	b.mgr.SetPostInstallHook(func(ev keyexchange.PostInstallEvent) {
		hookFired.Store(true)
		if ev.PeerNodeID != a.id {
			t.Errorf("hook: peer=%d want %d", ev.PeerNodeID, a.id)
		}
		if !ev.Authenticated {
			t.Errorf("hook: Authenticated=false on PILA path")
		}
	})

	frame := a.mgr.BuildAuthFrame()
	if frame == nil {
		t.Fatalf("BuildAuthFrame returned nil")
	}
	// HandleAuthFrame consumes the post-magic body.
	body := frame[4:]
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !b.mgr.HandleAuthFrame(body, from, false) {
		t.Fatalf("HandleAuthFrame returned false on a valid PILA frame")
	}
	if !b.mgr.Store().Has(a.id) {
		t.Fatalf("after PILA round-trip, B's store has no Crypto for A")
	}
	if !b.mgr.Store().IsReady(a.id) {
		t.Fatalf("installed Crypto not Ready")
	}
	if !hookFired.Load() {
		t.Fatalf("PostInstallHook did not fire")
	}
}

// TestHandleUnauthFrameRoundTrip is the PILK round-trip — no identity
// flow, so we don't need verifyFuncs; but the receiver must NOT have an
// identity (otherwise unauth is rejected and an auth frame is sent back
// instead).
func TestHandleUnauthFrameRoundTrip(t *testing.T) {
	t.Parallel()

	// Sender (no identity needed for PILK build).
	priv, pub := genX25519(t)
	sender := keyexchange.New(nil)
	sender.SetX25519Keys(priv, pub)
	sender.SetLocalNodeIDFn(func() uint32 { return 555 })

	// Receiver with X25519 but NO identity (so unauth path is allowed).
	rPriv, rPub := genX25519(t)
	receiver := keyexchange.New(nil)
	receiver.SetX25519Keys(rPriv, rPub)
	receiver.SetLocalNodeIDFn(func() uint32 { return 999 })
	receiver.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	frame := sender.BuildUnauthFrame()
	if frame == nil {
		t.Fatalf("BuildUnauthFrame returned nil")
	}
	body := frame[4:]
	if !receiver.HandleUnauthFrame(body, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, false) {
		t.Fatalf("HandleUnauthFrame returned false on valid PILK")
	}
	if !receiver.Store().Has(555) {
		t.Fatalf("PILK round-trip did not install Crypto")
	}
}

// TestHandleAuthFrameTooShort exercises the malformed-input early return.
func TestHandleAuthFrameTooShort(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	if p.mgr.HandleAuthFrame([]byte{0x00, 0x00, 0x00}, nil, false) {
		t.Fatalf("expected false on too-short PILA body")
	}
}

// TestHandleUnauthFrameTooShort guards the PILK length precondition.
func TestHandleUnauthFrameTooShort(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	if p.mgr.HandleUnauthFrame([]byte{0x00, 0x01}, nil, false) {
		t.Fatalf("expected false on too-short PILK body")
	}
}

// ---------- 4. Rekey retransmit loop ----------

// TestRekeyRetransmitGivesUp pins the give-up event publish path. We bypass
// real time by injecting a back-dated PendingRekeyState with attempts at
// the give-up boundary, then run a single tick.
func TestRekeyRetransmitGivesUp(t *testing.T) {
	t.Parallel()

	p := newPeer(t, 7)
	var giveUpCount atomic.Int32
	p.mgr.SetPublisher(func(topic string, payload map[string]any) {
		if topic == "tunnel.rekey_gave_up" {
			giveUpCount.Add(1)
			if id, _ := payload["peer_node_id"].(uint32); id != 99 {
				t.Errorf("give-up: peer=%v want 99", payload["peer_node_id"])
			}
		}
	})

	// At Attempts == MaxRekeyAttempts+1 (= 6) the loop short-circuits
	// straight to give-up, regardless of LastSentAt.
	st := &keyexchange.PendingRekeyState{
		FirstSentAt: time.Now().Add(-time.Minute),
		LastSentAt:  time.Now().Add(-time.Minute),
		Attempts:    keyexchange.MaxRekeyAttempts + 1,
	}
	p.mgr.InjectPendingRekeyForTest(99, st)
	p.mgr.RekeyRetransmitTick()

	if giveUpCount.Load() != 1 {
		t.Fatalf("give-up event count: got %d want 1", giveUpCount.Load())
	}
	if p.mgr.PendingRekeyHas(99) {
		t.Fatalf("after give-up, pendingRekey should be cleared")
	}
}

// TestRekeyRetransmitRetransmits asserts a stale (back-dated) entry that
// has not yet hit MaxRekeyAttempts triggers a retransmit via the wired
// FrameSender, AND that MarkPendingRekey bumps the attempt counter.
func TestRekeyRetransmitRetransmits(t *testing.T) {
	t.Parallel()

	p := newPeer(t, 7)
	var sends, keyRequests atomic.Int32
	p.mgr.SetSender(func(peer uint32, _ *net.UDPAddr, frame []byte) error {
		if peer != 50 {
			t.Errorf("retransmit dest: got %d want 50", peer)
		}
		if len(frame) == 0 {
			t.Errorf("retransmit frame is empty")
		}
		// No session key is installed for peer 50, so the retransmit
		// also carries a key request (PILK) next to the PILA; count the
		// PILA retransmits on their own.
		if bytes.Equal(frame[0:4], protocol.TunnelMagicKeyEx[:]) {
			keyRequests.Add(1)
			return nil
		}
		sends.Add(1)
		return nil
	})

	// Inject a state that's 10 s old (well beyond RekeyRetransmitInterval)
	// with Attempts=2 — the loop should retransmit once.
	p.mgr.InjectPendingRekeyForTest(50, &keyexchange.PendingRekeyState{
		FirstSentAt: time.Now().Add(-10 * time.Second),
		LastSentAt:  time.Now().Add(-10 * time.Second),
		Attempts:    2,
	})
	p.mgr.RekeyRetransmitTick()

	if got := sends.Load(); got != 1 {
		t.Fatalf("retransmit send count: got %d want 1", got)
	}
	if got := keyRequests.Load(); got != 1 {
		t.Fatalf("key requests with the retransmit: got %d want 1", got)
	}
	if attempts := p.mgr.PendingRekeyAttempts(50); attempts != 3 {
		t.Fatalf("after retransmit Attempts=%d want 3", attempts)
	}
}

// TestRekeyRetransmitSkipsFreshEntries asserts a recent send (within the
// retransmit interval) is left alone.
func TestRekeyRetransmitSkipsFreshEntries(t *testing.T) {
	t.Parallel()

	p := newPeer(t, 7)
	var sends atomic.Int32
	p.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error {
		sends.Add(1)
		return nil
	})

	// Sent just now → loop should skip.
	p.mgr.InjectPendingRekeyForTest(60, &keyexchange.PendingRekeyState{
		FirstSentAt: time.Now(),
		LastSentAt:  time.Now(),
		Attempts:    1,
	})
	p.mgr.RekeyRetransmitTick()

	if got := sends.Load(); got != 0 {
		t.Fatalf("fresh entry retransmitted %d times; want 0", got)
	}
}

// TestLoopExitsOnContextCancel exercises the goroutine lifecycle.
func TestLoopExitsOnContextCancel(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.mgr.Loop(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("Loop did not exit after context cancel")
	}
}

// TestMarkAndClearPendingRekey is the basic state-machine test for
// MarkPendingRekey / ClearPendingRekey.
func TestMarkAndClearPendingRekey(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	if p.mgr.PendingRekeyHas(42) {
		t.Fatalf("fresh manager has pending entry")
	}
	p.mgr.MarkPendingRekey(42)
	if !p.mgr.PendingRekeyHas(42) {
		t.Fatalf("MarkPendingRekey did not record")
	}
	if got := p.mgr.PendingRekeyAttempts(42); got != 1 {
		t.Fatalf("Attempts after first Mark: got %d want 1", got)
	}
	p.mgr.MarkPendingRekey(42)
	if got := p.mgr.PendingRekeyAttempts(42); got != 2 {
		t.Fatalf("Attempts after second Mark: got %d want 2", got)
	}
	p.mgr.ClearPendingRekey(42)
	if p.mgr.PendingRekeyHas(42) {
		t.Fatalf("ClearPendingRekey did not remove entry")
	}
}

// ---------- 5. Replay window ----------

// TestReplayWindowDuplicate covers the "exact same nonce twice" path —
// CheckAndRecordNonce returns false on the second call.
func TestReplayWindowDuplicate(t *testing.T) {
	t.Parallel()
	c := &keyexchange.Crypto{}
	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	if !c.CheckAndRecordNonce(100) {
		t.Fatalf("first call rejected nonce 100")
	}
	if c.CheckAndRecordNonce(100) {
		t.Fatalf("duplicate nonce 100 accepted (replay)")
	}
}

// TestReplayWindowOldCounter covers nonces below MaxRecvNonce − ReplayWindowSize.
func TestReplayWindowOldCounter(t *testing.T) {
	t.Parallel()
	c := &keyexchange.Crypto{}
	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	// Advance the high-water mark.
	if !c.CheckAndRecordNonce(10_000) {
		t.Fatalf("first call rejected high counter")
	}
	// A counter older than (10_000 - ReplayWindowSize) must be rejected.
	if c.CheckAndRecordNonce(10_000 - uint64(keyexchange.ReplayWindowSize)) {
		t.Fatalf("expected reject on counter at the lower window edge")
	}
	if c.CheckAndRecordNonce(1) {
		t.Fatalf("expected reject on counter far below window")
	}
}

// TestReplayWindowInsideWindowAccepted covers the typical reorder-tolerance
// path: a counter inside the window but below max is OK once.
func TestReplayWindowInsideWindowAccepted(t *testing.T) {
	t.Parallel()
	c := &keyexchange.Crypto{}
	c.ReplayMu.Lock()
	defer c.ReplayMu.Unlock()
	if !c.CheckAndRecordNonce(500) {
		t.Fatalf("first call rejected")
	}
	// 490 is 10 below max, well inside the 256-wide window — first sight
	// is accepted, replay rejected.
	if !c.CheckAndRecordNonce(490) {
		t.Fatalf("expected accept for first-sight in-window counter")
	}
	if c.CheckAndRecordNonce(490) {
		t.Fatalf("expected reject for duplicate in-window counter")
	}
}

// TestReplayWindowSizeFrozen pins the constant — it's a wire-adjacent
// behavior knob that operators tune logging dashboards against.
func TestReplayWindowSizeFrozen(t *testing.T) {
	t.Parallel()
	if keyexchange.ReplayWindowSize != 256 {
		t.Fatalf("ReplayWindowSize: got %d want 256", keyexchange.ReplayWindowSize)
	}
}

// ---------- 6. Salvage ring ----------

// TestSalvageBoundedBySize asserts the cap at SalvageMaxEntries with
// oldest-first eviction.
func TestSalvageBoundedBySize(t *testing.T) {
	t.Parallel()
	if keyexchange.SalvageMaxEntries != 4 {
		t.Fatalf("SalvageMaxEntries: got %d want 4", keyexchange.SalvageMaxEntries)
	}

	s := keyexchange.NewStore()
	c := &keyexchange.Crypto{Ready: true, CreatedAt: time.Now()}

	// Insert 1..6 → only the last 4 survive (oldest dropped first).
	for i := 0; i < 6; i++ {
		s.RecordSalvage(c, []byte{byte(i)})
	}
	entries := s.DrainSalvage(c)
	if len(entries) != keyexchange.SalvageMaxEntries {
		t.Fatalf("salvage size: got %d want %d", len(entries), keyexchange.SalvageMaxEntries)
	}
	// Plaintexts should be 2,3,4,5 in order.
	for i, e := range entries {
		want := byte(i + 2)
		if len(e.Plaintext) != 1 || e.Plaintext[0] != want {
			t.Fatalf("entry[%d]: got %v want [%d]", i, e.Plaintext, want)
		}
	}
}

// TestSalvageDrainEmptyAfterDrain ensures DrainSalvage is destructive.
func TestSalvageDrainEmptyAfterDrain(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	c := &keyexchange.Crypto{Ready: true}
	s.RecordSalvage(c, []byte("hello"))
	if got := len(s.DrainSalvage(c)); got != 1 {
		t.Fatalf("first drain count: got %d want 1", got)
	}
	if got := len(s.DrainSalvage(c)); got != 0 {
		t.Fatalf("second drain returned %d entries; want 0", got)
	}
}

// TestSalvageBoundedByAge feeds an aged entry to RecordSalvage and asserts
// the trim-on-insert path discards it. We sidestep clock fakes by
// hand-injecting an ancient entry into the ring.
func TestSalvageBoundedByAge(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	c := &keyexchange.Crypto{Ready: true}

	// Manually inject a stale entry older than SalvageMaxAge.
	c.SalvageMu.Lock()
	c.Salvage = append(c.Salvage, keyexchange.SalvageEntry{
		Plaintext: []byte("stale"),
		When:      time.Now().Add(-2 * keyexchange.SalvageMaxAge),
	})
	c.SalvageMu.Unlock()

	// RecordSalvage trims ahead of the append.
	s.RecordSalvage(c, []byte("fresh"))

	entries := s.DrainSalvage(c)
	if len(entries) != 1 {
		t.Fatalf("after age trim got %d entries; want 1 (fresh only)", len(entries))
	}
	if string(entries[0].Plaintext) != "fresh" {
		t.Fatalf("survivor plaintext: got %q want 'fresh'", entries[0].Plaintext)
	}
}

// TestSalvageNilCryptoIsNoop guards the early-return on nil pc.
func TestSalvageNilCryptoIsNoop(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	s.RecordSalvage(nil, []byte("ignored"))
	if got := s.DrainSalvage(nil); got != nil {
		t.Fatalf("DrainSalvage(nil): got %v want nil", got)
	}
}

// TestSalvagePlaintextCopied confirms the buffer is owned by the entry —
// the caller can mutate its argument after RecordSalvage returns.
func TestSalvagePlaintextCopied(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	c := &keyexchange.Crypto{Ready: true}
	buf := []byte{1, 2, 3}
	s.RecordSalvage(c, buf)
	buf[0] = 0xFF
	entries := s.DrainSalvage(c)
	if len(entries) != 1 || entries[0].Plaintext[0] != 1 {
		t.Fatalf("salvage entry was not copied: %v", entries)
	}
}

// ---------- 7. DecryptFailDropGrace ----------

// TestShouldDropOnDecryptFailGracePeriod walks the three-clause gate:
//   - failures below threshold → no
//   - failures at threshold but Crypto younger than grace → no
//   - failures at threshold AND Crypto past grace → yes
//   - mismatched Store entry (rekey already replaced) → no
func TestShouldDropOnDecryptFailGracePeriod(t *testing.T) {
	t.Parallel()
	if keyexchange.DecryptFailDropGrace != 3*time.Second {
		t.Fatalf("DecryptFailDropGrace: got %v want 3s", keyexchange.DecryptFailDropGrace)
	}
	if keyexchange.DecryptFailDropThreshold != 5 {
		t.Fatalf("DecryptFailDropThreshold: got %d want 5", keyexchange.DecryptFailDropThreshold)
	}

	s := keyexchange.NewStore()

	// Fresh Crypto, no failures → false.
	fresh := &keyexchange.Crypto{Ready: true, CreatedAt: time.Now()}
	s.Install(1, fresh)
	if s.ShouldDropOnDecryptFail(1, fresh) {
		t.Fatalf("ShouldDrop on fresh+0 fails returned true")
	}

	// Threshold reached but inside grace window → still false.
	fresh.DecryptFailCount = keyexchange.DecryptFailDropThreshold
	if s.ShouldDropOnDecryptFail(1, fresh) {
		t.Fatalf("ShouldDrop within grace returned true")
	}

	// Past grace, threshold reached, still installed → true.
	old := &keyexchange.Crypto{
		Ready:            true,
		CreatedAt:        time.Now().Add(-2 * keyexchange.DecryptFailDropGrace),
		DecryptFailCount: keyexchange.DecryptFailDropThreshold,
	}
	s.Install(2, old)
	if !s.ShouldDropOnDecryptFail(2, old) {
		t.Fatalf("ShouldDrop past grace returned false")
	}

	// Same Crypto but Store now points at a fresh replacement (concurrent
	// rekey landed) → false, even though our pointer satisfies threshold+age.
	replacement := &keyexchange.Crypto{Ready: true, CreatedAt: time.Now()}
	s.Install(2, replacement)
	if s.ShouldDropOnDecryptFail(2, old) {
		t.Fatalf("ShouldDrop after rekey-replace returned true; expected false")
	}
}

// TestShouldDropOnDecryptFailNilCrypto guards the nil-input path.
func TestShouldDropOnDecryptFailNilCrypto(t *testing.T) {
	t.Parallel()
	s := keyexchange.NewStore()
	if s.ShouldDropOnDecryptFail(1, nil) {
		t.Fatalf("ShouldDrop(nil) returned true")
	}
}

// ---------- 8. Bootstrap exception ----------

// TestSendKeyExchangeBootstrapAuth is the L5 → L2 bootstrap-exception path:
// SendKeyExchangeToNode bypasses L6 envelope, builds an auth (or unauth)
// frame directly, hands it to the FrameSender, and registers a pending
// rekey.
func TestSendKeyExchangeBootstrapAuth(t *testing.T) {
	t.Parallel()

	p := newPeer(t, 11)

	var sentFrame []byte
	var sentPeer uint32
	p.mgr.SetSender(func(peer uint32, _ *net.UDPAddr, frame []byte) error {
		sentPeer = peer
		sentFrame = append([]byte(nil), frame...)
		return nil
	})
	p.mgr.SetAddrLookup(func(uint32) *net.UDPAddr {
		return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}
	})

	p.mgr.SendKeyExchangeToNode(22)

	if sentPeer != 22 {
		t.Fatalf("sender called for peer=%d want 22", sentPeer)
	}
	// With identity present, we expect the PILA path (136 bytes).
	if len(sentFrame) != 136 {
		t.Fatalf("expected PILA frame (136B) on identity path; got %d bytes", len(sentFrame))
	}
	if !bytes.Equal(sentFrame[0:4], protocol.TunnelMagicAuthEx[:]) {
		t.Fatalf("expected PILA magic; got %x", sentFrame[0:4])
	}
	if !p.mgr.PendingRekeyHas(22) {
		t.Fatalf("SendKeyExchangeToNode did not register pendingRekey")
	}
	if attempts := p.mgr.PendingRekeyAttempts(22); attempts != 1 {
		t.Fatalf("Attempts after first Send: got %d want 1", attempts)
	}
}

// TestSendKeyExchangeBootstrapUnauthFallback covers the no-identity branch
// in SendKeyExchangeToNode.
func TestSendKeyExchangeBootstrapUnauthFallback(t *testing.T) {
	t.Parallel()

	priv, pub := genX25519(t)
	m := keyexchange.New(nil)
	m.SetX25519Keys(priv, pub)
	m.SetLocalNodeIDFn(func() uint32 { return 5 })

	var sentFrame []byte
	m.SetSender(func(_ uint32, _ *net.UDPAddr, frame []byte) error {
		sentFrame = append([]byte(nil), frame...)
		return nil
	})

	m.SendKeyExchangeToNode(99)
	if len(sentFrame) != 40 {
		t.Fatalf("expected PILK frame (40B) without identity; got %d bytes", len(sentFrame))
	}
	if !bytes.Equal(sentFrame[0:4], protocol.TunnelMagicKeyEx[:]) {
		t.Fatalf("expected PILK magic; got %x", sentFrame[0:4])
	}
}

// TestSendKeyExchangeNoSenderIsNoop confirms the early-return when no
// FrameSender is wired.
func TestSendKeyExchangeNoSenderIsNoop(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	// No sender wired.
	p.mgr.SendKeyExchangeToNode(2)
	if p.mgr.PendingRekeyHas(2) {
		t.Fatalf("SendKeyExchangeToNode without sender should not register pendingRekey")
	}
}

// ---------- pubkey cache ----------

// TestPeerPubKeyCacheRoundTrip pins the cache fast-path + verifyFunc fallback.
func TestPeerPubKeyCacheRoundTrip(t *testing.T) {
	t.Parallel()
	m := keyexchange.New(nil)

	// No verifyFunc + empty cache → errNoVerify-style failure.
	if _, err := m.GetPeerPubKey(1); err == nil {
		t.Fatalf("expected error with no cache and no verifyFunc")
	}

	// Wire a verifyFunc that counts calls.
	var calls atomic.Int32
	idn, _ := icrypto.GenerateIdentity()
	m.SetPeerVerifyFunc(func(nodeID uint32) (ed25519.PublicKey, error) {
		calls.Add(1)
		return idn.PublicKey, nil
	})

	pk, err := m.GetPeerPubKey(7)
	if err != nil {
		t.Fatalf("GetPeerPubKey: %v", err)
	}
	if !bytes.Equal(pk, idn.PublicKey) {
		t.Fatalf("returned pubkey mismatch")
	}
	if calls.Load() != 1 {
		t.Fatalf("verifyFunc calls: got %d want 1 on cache miss", calls.Load())
	}

	// Second call hits the cache.
	if _, err := m.GetPeerPubKey(7); err != nil {
		t.Fatalf("cached lookup failed: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("verifyFunc calls after cache hit: got %d want 1", calls.Load())
	}

	// Invalidate → next call re-fetches.
	m.InvalidatePeerPubKey(7)
	if _, err := m.GetPeerPubKey(7); err != nil {
		t.Fatalf("post-invalidate lookup failed: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("verifyFunc calls after invalidate: got %d want 2", calls.Load())
	}
}

// TestInboundDecryptStaleness covers the staleness gate used by
// HandleAuthFrame to decide whether to re-reply.
func TestInboundDecryptStaleness(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	if !p.mgr.InboundDecryptStale(42) {
		t.Fatalf("never-seen peer should be stale")
	}
	p.mgr.RecordInboundDecrypt(42)
	if p.mgr.InboundDecryptStale(42) {
		t.Fatalf("just-recorded peer reported stale")
	}
	// Back-date past the threshold.
	p.mgr.SetLastInboundDecryptForTest(42, time.Now().Add(-2*keyexchange.KeyExchangeReplyStaleThreshold))
	if !p.mgr.InboundDecryptStale(42) {
		t.Fatalf("back-dated peer not reported stale")
	}
}

// TestRemovePeerWipesAllState pins the cleanup contract used by
// TunnelManager.RemovePeer.
func TestRemovePeerWipesAllState(t *testing.T) {
	t.Parallel()
	p := newPeer(t, 1)
	idn, _ := icrypto.GenerateIdentity()
	p.mgr.SetPeerPubKey(99, idn.PublicKey)
	p.mgr.MarkPendingRekey(99)
	p.mgr.RecordInboundDecrypt(99)

	p.mgr.RemovePeer(99)

	if p.mgr.HasPeerPubKey(99) {
		t.Fatalf("RemovePeer left peerPubKeys entry")
	}
	if p.mgr.PendingRekeyHas(99) {
		t.Fatalf("RemovePeer left pendingRekey entry")
	}
	if p.mgr.LastInboundDecryptHas(99) {
		t.Fatalf("RemovePeer left lastInboundDecrypt entry")
	}
}
