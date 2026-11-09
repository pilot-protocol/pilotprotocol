// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Unauthenticated key exchange (PILK) must not open a session under a node
// ID this node cannot confirm is keyless. A PILK carries no proof of who
// sent it: whoever sends one names any node ID it likes and holds the
// X25519 private key for the session that results. Once installed, that
// session decrypts frames whose source is the claimed node ID, so the
// tunnel's source check passes and every node-ID trust decision above it
// (the private-node SYN and datagram gates, applications reading the
// caller's node ID) answers for the impostor.
//
// Every registered node has had an Ed25519 identity since registration
// started requiring one (0 keyless among 218,655 live registrations), and
// every released daemon sends a PILK only as a key request beside its
// PILA. So a PILK is only ever legitimate from a node the registry
// authoritatively reports as having no key.

import (
	"crypto/ed25519"
	"errors"
	"net"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// attackerPILK builds the 36-byte PILK body (after magic) claiming
// claimedID, with a fresh X25519 key the sender keeps.
func attackerPILK(t *testing.T, claimedID uint32) []byte {
	t.Helper()
	priv, pub := genX25519(t)
	m := keyexchange.New(nil)
	m.SetX25519Keys(priv, pub)
	m.SetLocalNodeIDFn(func() uint32 { return claimedID })
	return m.BuildUnauthFrame()[4:]
}

// receiverWithLookup is a node with an identity whose registry lookup is
// answered by lookup.
func receiverWithLookup(t *testing.T, lookup keyexchange.VerifyFunc) (*keyexchange.Manager, *magicRecorder) {
	t.Helper()
	r := newPeer(t, 900)
	rec := &magicRecorder{}
	r.mgr.SetSender(rec.send)
	r.mgr.SetPeerVerifyFunc(lookup)
	return r.mgr, rec
}

var attackerAddr = &net.UDPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 40000}

// A registry error (outage, timeout, a node reaped after 30 minutes
// silent) says nothing about whether the peer has a key, so it must not
// open the unauthenticated path.
func TestPILKRefusedWhenRegistryLookupFails(t *testing.T) {
	t.Parallel()
	const victim = uint32(77)
	mgr, rec := receiverWithLookup(t, func(uint32) (ed25519.PublicKey, error) {
		return nil, errors.New("registry: connection refused")
	})

	if mgr.HandleUnauthFrame(attackerPILK(t, victim), attackerAddr, false) {
		t.Fatal("PILK accepted although the registry lookup failed")
	}
	if mgr.Store().Has(victim) {
		t.Fatal("PILK installed a session under a node ID whose identity could not be checked")
	}
	if _, pilk, _ := rec.take(); pilk != 0 {
		t.Fatalf("answered a refused PILK with %d PILK frames", pilk)
	}
}

// The negative lookup cache (NegativePubKeyCacheTTL) must not turn one
// failed lookup into a window in which PILKs are accepted.
func TestPILKRefusedWhileLookupFailureIsNegativelyCached(t *testing.T) {
	t.Parallel()
	const victim = uint32(78)
	calls := 0
	mgr, _ := receiverWithLookup(t, func(uint32) (ed25519.PublicKey, error) {
		calls++
		return nil, errors.New("registry: timeout")
	})

	// First contact attempt fails the lookup and is negatively cached.
	if _, err := mgr.GetPeerPubKey(victim); err == nil {
		t.Fatal("setup: lookup should fail")
	}
	if mgr.HandleUnauthFrame(attackerPILK(t, victim), attackerAddr, false) {
		t.Fatal("PILK accepted inside the negative-cache window")
	}
	if mgr.Store().Has(victim) {
		t.Fatal("PILK installed a session inside the negative-cache window")
	}
	if calls != 1 {
		t.Fatalf("lookup called %d times; the negative cache should still coalesce", calls)
	}
}

// The one PILK path still open: the registry answers that the node is
// registered without a key. Such a node cannot make a PILA, so refusing
// its PILK would cut it off. The answer is negatively cached with its
// meaning, so a rekey inside the cache window is still taken.
func TestPILKAcceptedFromPeerRegisteredWithoutKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		lookup keyexchange.VerifyFunc
	}{
		{"ErrPeerHasNoKey", func(id uint32) (ed25519.PublicKey, error) {
			return nil, errors.Join(errors.New("node has no key"), keyexchange.ErrPeerHasNoKey)
		}},
		{"nil, nil", func(uint32) (ed25519.PublicKey, error) { return nil, nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const keyless = uint32(81)
			mgr, _ := receiverWithLookup(t, tc.lookup)
			if !mgr.HandleUnauthFrame(attackerPILK(t, keyless), attackerAddr, false) {
				t.Fatal("PILK refused from a node the registry reports as keyless")
			}
			first := mgr.Store().Get(keyless)
			if first == nil || first.Authenticated {
				t.Fatal("keyless peer: want an unauthenticated session")
			}
			// Rekey with a new X25519 key inside the negative-cache window.
			if !mgr.HandleUnauthFrame(attackerPILK(t, keyless), attackerAddr, false) {
				t.Fatal("rekey PILK from a keyless node refused inside the cache window")
			}
			if mgr.Store().Get(keyless) == first {
				t.Fatal("rekey PILK did not install the new session")
			}
		})
	}
}

// A node in the local trust store was trusted against its Ed25519 key, so
// it never gets a PILK session, even if the registry claims it has no
// key. It is answered with our PILA, as a known identity is, so a real
// peer's key request still works.
func TestPILKRefusedForTrustStoreNodeWhateverTheRegistrySays(t *testing.T) {
	t.Parallel()
	const trusted = uint32(82)
	mgr, rec := receiverWithLookup(t, func(uint32) (ed25519.PublicKey, error) {
		return nil, keyexchange.ErrPeerHasNoKey
	})
	mgr.SetTrustStoreFn(func(id uint32) bool { return id == trusted })

	if mgr.HandleUnauthFrame(attackerPILK(t, trusted), attackerAddr, false) {
		t.Fatal("PILK accepted for a node ID in the trust store")
	}
	if mgr.Store().Has(trusted) {
		t.Fatal("PILK installed a session for a node ID in the trust store")
	}
	if pila, _, _ := rec.take(); pila != 1 {
		t.Fatalf("answered the refused PILK with %d PILA, want 1", pila)
	}
}

// Before this node has an identity (the read loop runs before
// registration) a trusted node ID is refused too, silently: there is no
// PILA to answer with yet.
func TestPILKRefusedForTrustStoreNodeBeforeIdentity(t *testing.T) {
	t.Parallel()
	const trusted = uint32(83)
	priv, pub := genX25519(t)
	mgr := keyexchange.New(nil)
	mgr.SetX25519Keys(priv, pub)
	rec := &magicRecorder{}
	mgr.SetSender(rec.send)
	mgr.SetTrustStoreFn(func(id uint32) bool { return id == trusted })

	if mgr.HandleUnauthFrame(attackerPILK(t, trusted), attackerAddr, false) {
		t.Fatal("PILK accepted for a trusted node ID before this node had an identity")
	}
	if pila, pilk, _ := rec.take(); pila+pilk != 0 {
		t.Fatalf("answered with %d PILA, %d PILK before having an identity", pila, pilk)
	}
	// Untrusted node IDs keep the no-identity behaviour.
	if !mgr.HandleUnauthFrame(attackerPILK(t, trusted+1), attackerAddr, false) {
		t.Fatal("PILK from an untrusted node ID refused on a node without identity")
	}
}

// A PILK never replaces a session the peer authenticated, whatever the
// registry answers by then. Replacing it would downgrade the session and
// re-encrypt recent sends (salvage) under the PILK sender's key.
func TestPILKNeverReplacesAuthenticatedSession(t *testing.T) {
	t.Parallel()
	a := newPeer(t, 10)
	b := newPeer(t, 20)
	crossWireVerifyFuncs(a, b)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })
	if !b.mgr.HandleAuthFrame(a.mgr.BuildAuthFrame()[4:], attackerAddr, false) {
		t.Fatal("setup: PILA rejected")
	}
	authed := b.mgr.Store().Get(10)
	if authed == nil || !authed.Authenticated {
		t.Fatal("setup: no authenticated session")
	}
	if !authed.PeerEd25519.Equal(a.identity.PublicKey) {
		t.Fatal("authenticated session does not record the key that signed its PILA")
	}

	// The key drops out of the cache and the registry now says "no key".
	b.mgr.InvalidatePeerPubKey(10)
	b.mgr.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) { return nil, keyexchange.ErrPeerHasNoKey })

	if b.mgr.HandleUnauthFrame(attackerPILK(t, 10), attackerAddr, false) {
		t.Fatal("PILK accepted over an authenticated session")
	}
	if b.mgr.Store().Get(10) != authed {
		t.Fatal("PILK replaced an authenticated session")
	}
}

// SetIdentity reports the first identity so the tunnel can drop the PILK
// sessions taken before it; UnauthenticatedPeers lists them.
func TestSetIdentityReportsFirstIdentityAndUnauthenticatedPeers(t *testing.T) {
	t.Parallel()
	priv, pub := genX25519(t)
	mgr := keyexchange.New(nil)
	mgr.SetX25519Keys(priv, pub)
	mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	if !mgr.HandleUnauthFrame(attackerPILK(t, 91), attackerAddr, false) {
		t.Fatal("setup: PILK refused without identity")
	}
	if got := mgr.UnauthenticatedPeers(); len(got) != 1 || got[0] != 91 {
		t.Fatalf("UnauthenticatedPeers = %v, want [91]", got)
	}
	id := newPeer(t, 1).identity
	if !mgr.SetIdentity(id) {
		t.Fatal("first SetIdentity not reported")
	}
	if mgr.SetIdentity(newPeer(t, 1).identity) {
		t.Fatal("a later SetIdentity (rotation) reported as the first")
	}
}
