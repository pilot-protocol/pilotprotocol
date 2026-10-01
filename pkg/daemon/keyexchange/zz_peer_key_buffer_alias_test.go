// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

// The tunnel read loop hands HandleAuthFrame a slice of its one reused
// receive buffer, valid only until the next packet is read. The peer's
// Ed25519 key was cached as a sub-slice of that buffer, so the next
// packet overwrote the cached key in place. Every consumer of the cache
// then saw garbage: the next PILA from the peer mismatched and forced a
// registry lookup on the read loop, and the key-bound trust check
// (Daemon.handshakeTrusts) compared the trust record against bytes of an
// unrelated packet.
func TestCachedPeerKeySurvivesReceiveBufferReuse(t *testing.T) {
	t.Parallel()

	a := newPeer(t, 100)
	b := newPeer(t, 200)
	crossWireVerifyFuncs(a, b)
	a.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })
	b.mgr.SetSender(func(uint32, *net.UDPAddr, []byte) error { return nil })

	bFrame := b.mgr.BuildAuthFrame()
	if bFrame == nil {
		t.Fatal("B.BuildAuthFrame returned nil")
	}

	// Stand-in for the socket's receive buffer: the frame is read into
	// it, handled, and the same bytes are then reused for the next packet.
	recvBuf := make([]byte, 1500)
	n := copy(recvBuf, bFrame)
	want := append([]byte(nil), recvBuf[4+36:4+68]...)

	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000}
	if !a.mgr.HandleAuthFrame(recvBuf[4:n], from, false) {
		t.Fatal("PILA from B rejected by A")
	}

	// The next packet lands in the same buffer.
	for i := range recvBuf {
		recvBuf[i] = 0xAA
	}

	got, ok := a.mgr.PeerPubKeyCached(b.id)
	if !ok {
		t.Fatal("no cached key for B after a verified PILA")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("cached peer key changed when the receive buffer was reused:\n got %x\nwant %x", got, want)
	}

	// The post-install hook receives the key too; a retained copy must
	// not alias the buffer either.
	var hooked []byte
	a.mgr.Store().Drop(b.id)
	a.mgr.SetPostInstallHook(func(ev keyexchange.PostInstallEvent) { hooked = ev.PeerEd25519 })
	n = copy(recvBuf, bFrame)
	if !a.mgr.HandleAuthFrame(recvBuf[4:n], from, false) {
		t.Fatal("second PILA from B rejected by A")
	}
	for i := range recvBuf {
		recvBuf[i] = 0xBB
	}
	if hooked == nil {
		t.Fatal("post-install hook did not fire")
	}
	if !bytes.Equal(hooked, want) {
		t.Fatalf("key handed to the post-install hook changed when the receive buffer was reused:\n got %x\nwant %x", hooked, want)
	}
}
