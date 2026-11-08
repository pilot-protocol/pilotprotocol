// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// The trust checks outside the SYN and datagram gates: the echo service,
// the strict data-plane ping and key-exchange gates, and the IPC
// envelope verdict. Each checks handshake trust against a key the peer
// proved, or asks by node ID alone where that is the whole question,
// never against a key that was merely cached for the node ID.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
)

// unauthSessionAs installs a session for nodeID that no PILA
// authenticated (however it came about), with nodeID's registered key in
// the key cache, as a registry lookup leaves it. It returns the sender
// that holds the session.
func unauthSessionAs(t *testing.T, d *Daemon, nodeID uint32, registered ed25519.PublicKey, from *net.UDPAddr) *impostor {
	t.Helper()
	im := newImpostor(t, nodeID)
	c, err := d.tunnels.kx.DeriveSecret(im.pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	d.tunnels.envelope.Install(nodeID, c)
	d.tunnels.AddPeer(nodeID, from)
	d.tunnels.kx.SetPeerPubKey(nodeID, registered)
	im.keyWith(t, d.tunnels.kx.PubKey())
	return im
}

// echoServes runs handleEchoConn for a connection from nodeID with one
// payload queued, and reports whether the echo loop took it.
func echoServes(t *testing.T, d *Daemon, nodeID uint32) bool {
	t.Helper()
	conn := &Connection{ID: 77, RemoteAddr: protocol.Addr{Node: nodeID}, RecvBuf: make(chan []byte, 1)}
	conn.RecvBuf <- []byte("echo")
	done := make(chan struct{})
	go func() {
		d.handleEchoConn(conn)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleEchoConn did not return")
	}
	// Served: the loop read the payload (and returned when the reply
	// could not be sent on a connection that never opened). Refused: it
	// closed the connection without reading.
	return len(conn.RecvBuf) == 0
}

// pingFrom is a pong-soliciting ping. It carries a payload: the tunnel
// swallows an empty one as a keepalive.
func pingFrom(src uint32) *protocol.Packet {
	return &protocol.Packet{
		Payload:  pathProbePayload,
		Version:  protocol.Version,
		Protocol: protocol.ProtoControl,
		Src:      protocol.Addr{Node: src},
		Dst:      protocol.Addr{Node: gateTargetID},
		SrcPort:  protocol.PortPing,
		DstPort:  protocol.PortPing,
		Seq:      1,
	}
}

// gotSealedFrame reports whether the daemon sent c a sealed (PILS) frame,
// which is what a pong is, within half a second. Key-exchange frames the
// tunnel sends meanwhile are skipped.
func gotSealedFrame(c *net.UDPConn) bool {
	deadline := time.Now().Add(500 * time.Millisecond)
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 2048)
	for {
		c.SetReadDeadline(deadline)
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return false
		}
		if n >= 4 && [4]byte{buf[0], buf[1], buf[2], buf[3]} == protocol.TunnelMagicSecure {
			return true
		}
	}
}

// The echo service on a private node serves a handshake-trusted peer only
// over a session authenticated with the key its trust is bound to. It
// used to check the cached key, which a session it did not authenticate
// does not change.
func TestEchoTrustGateUsesSessionKey(t *testing.T) {
	t.Parallel()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	d, svc, _, sock := newGateTarget(t, registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: edPub}))
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(edPub)
	from := sock.LocalAddr().(*net.UDPAddr)

	unauthSessionAs(t, d, gateTrustedID, edPub, from)
	if echoServes(t, d, gateTrustedID) {
		t.Fatal("echo served a trusted node ID over a session no PILA authenticated")
	}

	d.tunnels.RemovePeer(gateTrustedID)
	realPeer(t, d, gateTrustedID, edPub, edPriv, from)
	if !echoServes(t, d, gateTrustedID) {
		t.Fatal("echo refused the trusted peer over its authenticated session")
	}
	if got := svc.gotKeyFor[gateTrustedID]; got != base64.StdEncoding.EncodeToString(edPub) {
		t.Fatalf("echo asked the trust store with key %q, want the session's key", got)
	}
}

// With strict data-plane trust, a ping is answered for handshake trust
// only over a session authenticated with the bound key, as at the SYN
// gate. It used to be answered on the cached key.
func TestStrictPingTrustGateUsesSessionKey(t *testing.T) {
	t.Parallel()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	d, svc, _, sock := newGateTarget(t, registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: edPub}))
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(edPub)
	d.config.StrictDataPlaneTrust = true
	wireTrustGate(d)
	from := sock.LocalAddr().(*net.UDPAddr)

	im := unauthSessionAs(t, d, gateTrustedID, edPub, from)
	d.tunnels.handleEncrypted(im.seal(t, pingFrom(gateTrustedID)), from)
	if !routeOne(t, d) {
		t.Fatal("setup: ping over the unauthenticated session was not delivered")
	}
	if gotSealedFrame(sock) {
		t.Fatal("strict node answered a ping over a session no PILA authenticated")
	}

	d.tunnels.RemovePeer(gateTrustedID)
	p := realPeer(t, d, gateTrustedID, edPub, edPriv, from)
	d.tunnels.handleEncrypted(p.seal(t, pingFrom(gateTrustedID)), from)
	if !routeOne(t, d) {
		t.Fatal("setup: ping over the authenticated session was not delivered")
	}
	if !gotSealedFrame(sock) {
		t.Fatal("strict node did not answer the trusted peer's ping over its authenticated session")
	}
}

// The strict gate in front of a key exchange asks by node ID: the frame's
// key is not verified yet (the exchange is, against the registry). It must
// not ask the trust store with an empty key, which no longer passes a
// key-bound record, or a trusted peer whose key is not cached yet could
// never open a session.
func TestStrictKeyExchangeGateAsksByNodeID(t *testing.T) {
	t.Parallel()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	d, svc, _, sock := newGateTarget(t, registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: edPub}))
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(edPub)
	d.config.StrictDataPlaneTrust = true
	wireTrustGate(d)

	if !d.admitDataPlanePeer(gateTrustedID) {
		t.Fatal("the key-exchange gate refused a handshake-trusted node ID")
	}
	if svc.withKeyHits != 0 {
		t.Fatal("the key-exchange gate asked the trust store with a key it had not verified")
	}
	// And the exchange itself goes through.
	realPeer(t, d, gateTrustedID, edPub, edPriv, sock.LocalAddr().(*net.UDPAddr))
}

// The envelope verdict's "trusted" is checked against the key that just
// verified the envelope.
func TestVerifyEnvelopeTrustedUsesEnvelopeKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		boundToIt bool
	}{
		{"trust bound to the signing key", true},
		{"trust bound to another key", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, s := newSimpleHandlerDaemon(t, nil)
			peer, _ := crypto.GenerateIdentity()
			other, _ := crypto.GenerateIdentity()
			d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) { return peer.PublicKey, nil })
			svc := newKeyBoundFake()
			if tc.boundToIt {
				svc.trusted[42] = base64.StdEncoding.EncodeToString(peer.PublicKey)
			} else {
				svc.trusted[42] = base64.StdEncoding.EncodeToString(other.PublicKey)
			}
			d.RegisterHandshakeService(svc)

			canonical, sigB64 := signedTestEnvelope(t, peer.PrivateKey, 0, 42, time.Now().Unix())
			verdict := runVerifyEnvelope(t, s, map[string]interface{}{"envelope": canonical, "signature": sigB64})
			if trusted, _ := verdict["trusted"].(bool); trusted != tc.boundToIt {
				t.Fatalf("trusted = %v, want %v", verdict["trusted"], tc.boundToIt)
			}
			if got := svc.gotKeyFor[42]; got != base64.StdEncoding.EncodeToString(peer.PublicKey) {
				t.Fatalf("trust store asked with key %q, want the envelope's key", got)
			}
		})
	}
}
