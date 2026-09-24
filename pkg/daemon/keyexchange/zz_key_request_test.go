// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

// Key request (KeyRequestAfterSends): when our key exchange to a peer we
// hold no session key for goes unanswered, each retransmit also sends a
// PILK, which every released daemon answers with its authenticated PILA
// (retransmitted until ours arrives). This breaks the first-contact
// deadlock where the peer's single reply was lost and it treats our
// same-key PILAs as keepalives.

import (
	"bytes"
	"net"
	"sync"
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

type magicRecorder struct {
	mu     sync.Mutex
	frames [][]byte
}

func (r *magicRecorder) send(_ uint32, _ *net.UDPAddr, frame []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, append([]byte(nil), frame...))
	return nil
}

func (r *magicRecorder) take() (pila, pilk int, all [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, f := range r.frames {
		switch {
		case bytes.Equal(f[:4], protocol.TunnelMagicAuthEx[:]):
			pila++
		case bytes.Equal(f[:4], protocol.TunnelMagicKeyEx[:]):
			pilk++
		}
	}
	all = r.frames
	r.frames = nil
	return pila, pilk, all
}

func TestKeyRequestRidesOnRetransmitsOnly(t *testing.T) {
	t.Parallel()
	a := newPeer(t, 1)
	rec := &magicRecorder{}
	a.mgr.SetSender(rec.send)

	if a.mgr.SendKeyExchangeToNode(2) {
		t.Fatal("first send reported a key request")
	}
	if pila, pilk, _ := rec.take(); pila != 1 || pilk != 0 {
		t.Fatalf("first send: %d PILA, %d PILK; want 1, 0", pila, pilk)
	}

	// Unanswered: the retransmit carries the key request, PILA first.
	if !a.mgr.SendKeyExchangeToNode(2) {
		t.Fatal("retransmit did not report a key request")
	}
	pila, pilk, frames := rec.take()
	if pila != 1 || pilk != 1 {
		t.Fatalf("retransmit: %d PILA, %d PILK; want 1, 1", pila, pilk)
	}
	if !bytes.Equal(frames[0][:4], protocol.TunnelMagicAuthEx[:]) {
		t.Fatal("the PILA must go out before the key request")
	}
	if got := a.mgr.KeyRequestsSent(); got != 1 {
		t.Fatalf("KeyRequestsSent = %d, want 1", got)
	}
}

func TestKeyRequestDueSendsOnFirstTry(t *testing.T) {
	t.Parallel()
	a := newPeer(t, 1)
	rec := &magicRecorder{}
	a.mgr.SetSender(rec.send)

	a.mgr.MarkKeyRequestDue(3)
	if !a.mgr.SendKeyExchangeToNode(3) {
		t.Fatal("a due key request was not sent")
	}
	if pila, pilk, _ := rec.take(); pila != 1 || pilk != 1 {
		t.Fatalf("%d PILA, %d PILK; want 1, 1", pila, pilk)
	}
	// The mark is consumed; the pending count alone decides from now on
	// (and a retransmit is due, so the next send still carries one).
	a.mgr.ClearPendingRekey(3)
	if a.mgr.SendKeyExchangeToNode(3) {
		t.Fatal("the due mark was not consumed")
	}
}

func TestNoKeyRequestOnceSessionInstalled(t *testing.T) {
	t.Parallel()
	a := newPeer(t, 1)
	b := newPeer(t, 2)
	crossWireVerifyFuncs(a, b)
	rec := &magicRecorder{}
	a.mgr.SetSender(rec.send)
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	// A has B's key: B's PILA arrived.
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !a.mgr.HandleAuthFrame(b.mgr.BuildAuthFrame()[4:], from, false) {
		t.Fatal("B's PILA rejected")
	}
	rec.take()
	a.mgr.MarkKeyRequestDue(2)
	a.mgr.SendKeyExchangeToNode(2)
	a.mgr.SendKeyExchangeToNode(2)
	if _, pilk, _ := rec.take(); pilk != 0 {
		t.Fatalf("%d key requests sent to a peer we hold a key for; want 0", pilk)
	}
}

// TestPeerAnswersKeyRequestWithRetransmittedPILA pins the peer-side
// behaviour the key request relies on (it has been the same in every
// released daemon): a PILK from a peer whose identity we know is
// rejected and answered with our PILA, and that answer is marked pending
// so it is retransmitted until the requester's PILA arrives.
func TestPeerAnswersKeyRequestWithRetransmittedPILA(t *testing.T) {
	t.Parallel()
	client := newPeer(t, 10)
	service := newPeer(t, 20)
	crossWireVerifyFuncs(client, service)
	rec := &magicRecorder{}
	service.mgr.SetSender(rec.send)
	client.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}

	// First contact: the service installs our key and answers once, then
	// clears its own retransmit state. That answer is the one lost.
	if !service.mgr.HandleAuthFrame(client.mgr.BuildAuthFrame()[4:], from, false) {
		t.Fatal("client PILA rejected")
	}
	rec.take()
	if service.mgr.PendingRekeyHas(10) {
		t.Fatal("setup: the first answer is not retransmitted")
	}

	// The key request.
	if service.mgr.HandleUnauthFrame(client.mgr.BuildUnauthFrame()[4:], from, false) {
		t.Fatal("a PILK from a peer with a known identity must not install anything")
	}
	if pila, _, _ := rec.take(); pila != 1 {
		t.Fatalf("service answered the key request with %d PILA, want 1", pila)
	}
	if !service.mgr.PendingRekeyHas(10) {
		t.Fatal("the answer to a key request must be retransmitted until the requester's PILA arrives")
	}
	// The requester's PILA (sent when it installs the service's key) ends it.
	service.mgr.HandleAuthFrame(client.mgr.BuildAuthFrame()[4:], from, false)
	if service.mgr.PendingRekeyHas(10) {
		t.Fatal("the requester's PILA must clear the service's retransmits")
	}
}
