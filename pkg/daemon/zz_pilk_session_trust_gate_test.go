// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

// A session opened by an unauthenticated key exchange (PILK) proves only
// that its sender holds the X25519 key it chose, never which node it is.
// These tests drive the real decrypt and route path: a stranger opens a
// PILK session under the node ID of a peer this private node trusts by
// handshake, then sends a SYN and a datagram over it.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/common/protocol"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/envelope"
	"github.com/pilot-protocol/pilotprotocol/pkg/daemon/keyexchange"
)

const (
	gateTargetID  = uint32(42) // newPacketDaemon's node ID
	gateTrustedID = uint32(0x7001)
	gatePort      = uint16(1001)
)

// impostor holds the X25519 key behind a session it opened under someone
// else's node ID.
type impostor struct {
	claimed uint32
	priv    *ecdh.PrivateKey
	pub     []byte
	store   *keyexchange.Store
	session *keyexchange.Crypto
}

func newImpostor(t *testing.T, claimed uint32) *impostor {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("x25519: %v", err)
	}
	st := keyexchange.NewStore()
	st.SetLocalNodeID(claimed)
	return &impostor{claimed: claimed, priv: priv, pub: priv.PublicKey().Bytes(), store: st}
}

// pilk is the PILK body (after magic) naming the claimed node ID.
func (im *impostor) pilk() []byte {
	b := make([]byte, 36)
	binary.BigEndian.PutUint32(b[0:4], im.claimed)
	copy(b[4:], im.pub)
	return b
}

// keyWith derives the session the target installs for the impostor's
// PILK. The target's X25519 key is no secret: it answers every key
// exchange with it.
func (im *impostor) keyWith(t *testing.T, targetPub []byte) {
	t.Helper()
	m := keyexchange.New(nil)
	m.SetX25519Keys(im.priv, im.pub)
	c, err := m.DeriveSecret(targetPub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	im.session = c
}

// seal returns the PILS body (after magic) carrying pkt.
func (im *impostor) seal(t *testing.T, pkt *protocol.Packet) []byte {
	t.Helper()
	raw, err := pkt.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return envelope.EncryptWith(im.store, im.session, raw)[4:]
}

// newGateTarget is a private, encrypting node with an identity whose
// handshake store trusts gateTrustedID, bound to that peer's real key.
// lookup answers its registry key lookups.
func newGateTarget(t *testing.T, lookup func(uint32) (ed25519.PublicKey, error)) (*Daemon, *keyBoundFakeHandshakeService, ed25519.PublicKey, *net.UDPConn) {
	t.Helper()
	d, sock := newPacketDaemon(t, nil)
	d.config.Public = false
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	d.tunnels.SetNodeID(gateTargetID)
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	d.tunnels.SetIdentity(id)
	d.tunnels.SetPeerVerifyFunc(lookup)

	realKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	svc := newKeyBoundFake()
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(realKey)
	d.RegisterHandshakeService(svc)
	d.wireTunnelTrustStore()

	if _, err := d.ports.Bind(gatePort); err != nil {
		t.Fatalf("bind: %v", err)
	}
	return d, svc, realKey, sock
}

// routeOne takes the next packet the tunnel delivered and routes it the
// way routeLoop does. handleEncrypted queues synchronously, so a frame
// that decrypted is already waiting.
func routeOne(t *testing.T, d *Daemon) bool {
	t.Helper()
	select {
	case in := <-d.tunnels.RecvCh():
		d.routePacketWithRecover(in)
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

func gateSYN(src uint32) *protocol.Packet {
	return &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagSYN,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Node: src},
		Dst:      protocol.Addr{Node: gateTargetID},
		SrcPort:  5555,
		DstPort:  gatePort,
		Seq:      1,
		Window:   64,
	}
}

func registryDown(uint32) (ed25519.PublicKey, error) {
	return nil, errors.New("registry: connection refused")
}

// The audit lead end to end: with the registry lookup of the trusted peer
// failing, a stranger's PILK under that peer's node ID must not yield a
// session, and a SYN sent as that peer must not open a connection.
func TestForgedPILKCannotOpenStreamAsTrustedPeer(t *testing.T) {
	t.Parallel()
	d, _, _, sock := newGateTarget(t, registryDown)
	from := sock.LocalAddr().(*net.UDPAddr)

	im := newImpostor(t, gateTrustedID)
	d.tunnels.handleKeyExchange(im.pilk(), from, false)
	if d.tunnels.HasCrypto(gateTrustedID) {
		t.Error("a PILK under a trusted node ID opened a session while the registry lookup failed")
	}

	// Whether or not the PILK was refused, a SYN sealed under the
	// impostor's key must not open a connection as the trusted peer.
	im.keyWith(t, d.tunnels.kx.PubKey())
	d.tunnels.handleEncrypted(im.seal(t, gateSYN(gateTrustedID)), from)
	routeOne(t, d)
	if c := d.ports.FindConnection(gatePort, protocol.Addr{Node: gateTrustedID}, 5555); c != nil {
		t.Fatal("SYN over a forged PILK session was admitted as the handshake-trusted peer")
	}
}

// The same for the datagram gate.
func TestForgedPILKCannotSendDatagramAsTrustedPeer(t *testing.T) {
	t.Parallel()
	d, _, _, sock := newGateTarget(t, registryDown)
	from := sock.LocalAddr().(*net.UDPAddr)
	d.bus = newInProcessBus(d.NodeID)
	delivered, unsub := d.bus.Subscribe("data.datagram")
	defer unsub()

	im := newImpostor(t, gateTrustedID)
	d.tunnels.handleKeyExchange(im.pilk(), from, false)
	im.keyWith(t, d.tunnels.kx.PubKey())
	d.tunnels.handleEncrypted(im.seal(t, &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Src:      protocol.Addr{Node: gateTrustedID},
		Dst:      protocol.Addr{Node: gateTargetID},
		SrcPort:  5555,
		DstPort:  gatePort,
		Payload:  []byte("forged"),
	}), from)
	routeOne(t, d)
	select {
	case <-delivered:
		t.Fatal("datagram over a forged PILK session was delivered as the handshake-trusted peer")
	default:
	}
}

// Before registration the tunnel has no identity yet, so it takes PILKs
// without any lookup (the read loop starts before the node registers).
// A session opened in that window must not carry a trusted node ID's
// trust once the node is running.
func TestPILKFromBeforeIdentityCannotOpenStreamAsTrustedPeer(t *testing.T) {
	t.Parallel()
	d, sock := newPacketDaemon(t, nil)
	d.config.Public = false
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	realKey, _, _ := ed25519.GenerateKey(rand.Reader)
	svc := newKeyBoundFake()
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(realKey)
	d.RegisterHandshakeService(svc)
	d.wireTunnelTrustStore()
	if _, err := d.ports.Bind(gatePort); err != nil {
		t.Fatalf("bind: %v", err)
	}
	from := sock.LocalAddr().(*net.UDPAddr)

	im := newImpostor(t, gateTrustedID)
	d.tunnels.handleKeyExchange(im.pilk(), from, false) // no identity yet

	// Registration completes.
	d.tunnels.SetNodeID(gateTargetID)
	id, _ := crypto.GenerateIdentity()
	d.tunnels.SetIdentity(id)
	d.tunnels.SetPeerVerifyFunc(registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: realKey}))

	im.keyWith(t, d.tunnels.kx.PubKey())
	d.tunnels.handleEncrypted(im.seal(t, gateSYN(gateTrustedID)), from)
	routeOne(t, d)
	if c := d.ports.FindConnection(gatePort, protocol.Addr{Node: gateTrustedID}, 5555); c != nil {
		t.Fatal("SYN over a PILK session opened before the identity was set was admitted as the trusted peer")
	}
}

// realPeer completes an authenticated key exchange (PILA) with d under
// nodeID and key edPriv, and returns what it needs to seal frames.
func realPeer(t *testing.T, d *Daemon, nodeID uint32, edPub ed25519.PublicKey, edPriv ed25519.PrivateKey, from *net.UDPAddr) *impostor {
	t.Helper()
	p := newImpostor(t, nodeID)
	challenge := make([]byte, 4+4+32)
	copy(challenge[0:4], "auth")
	binary.BigEndian.PutUint32(challenge[4:8], nodeID)
	copy(challenge[8:40], p.pub)
	body := make([]byte, 132)
	binary.BigEndian.PutUint32(body[0:4], nodeID)
	copy(body[4:36], p.pub)
	copy(body[36:68], edPub)
	copy(body[68:132], ed25519.Sign(edPriv, challenge))
	d.tunnels.handleAuthKeyExchange(body, from, false)
	if !d.tunnels.HasCrypto(nodeID) {
		t.Fatal("setup: PILA from a registered peer did not open a session")
	}
	p.keyWith(t, d.tunnels.kx.PubKey())
	return p
}

// Positive control: the trusted peer itself, over a session it
// authenticated with the key its trust was granted against, gets in, and
// the gate hands the trust store that session's key.
func TestAuthenticatedTrustedPeerOpensStream(t *testing.T) {
	t.Parallel()
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	d, svc, _, sock := newGateTarget(t, registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: edPub}))
	svc.trusted[gateTrustedID] = base64.StdEncoding.EncodeToString(edPub)
	from := sock.LocalAddr().(*net.UDPAddr)

	p := realPeer(t, d, gateTrustedID, edPub, edPriv, from)
	d.tunnels.handleEncrypted(p.seal(t, gateSYN(gateTrustedID)), from)
	if !routeOne(t, d) {
		t.Fatal("authenticated SYN was not delivered by the tunnel")
	}
	if c := d.ports.FindConnection(gatePort, protocol.Addr{Node: gateTrustedID}, 5555); c == nil {
		t.Fatal("SYN from the trusted peer over its authenticated session was rejected")
	}
	if got := svc.gotKeyFor[gateTrustedID]; got != base64.StdEncoding.EncodeToString(edPub) {
		t.Fatalf("gate asked the trust store with key %q, want the session's key", got)
	}
}

// A node ID now registered to a different key than the one trust was
// granted against does not inherit the trust, even over an authenticated
// session.
func TestAuthenticatedPeerWithRotatedKeyDoesNotInheritTrust(t *testing.T) {
	t.Parallel()
	newPub, newPriv, _ := ed25519.GenerateKey(rand.Reader)
	d, _, _, sock := newGateTarget(t, registryKeys(map[uint32]ed25519.PublicKey{gateTrustedID: newPub}))
	from := sock.LocalAddr().(*net.UDPAddr)

	p := realPeer(t, d, gateTrustedID, newPub, newPriv, from)
	d.tunnels.handleEncrypted(p.seal(t, gateSYN(gateTrustedID)), from)
	routeOne(t, d)
	if c := d.ports.FindConnection(gatePort, protocol.Addr{Node: gateTrustedID}, 5555); c != nil {
		t.Fatal("a session authenticated with a key other than the trust binding was admitted")
	}
}

// The gate on its own: whatever let an unauthenticated session for a
// trusted node ID exist, traffic over it gets no handshake trust, and the
// trust store is never asked with an empty key (which it answers by node
// ID alone).
func TestUnauthenticatedSessionGetsNoHandshakeTrust(t *testing.T) {
	t.Parallel()
	d, svc, _, sock := newGateTarget(t, registryDown)
	from := sock.LocalAddr().(*net.UDPAddr)

	im := newImpostor(t, gateTrustedID)
	c, err := d.tunnels.kx.DeriveSecret(im.pub)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	d.tunnels.envelope.Install(gateTrustedID, c) // unauthenticated
	d.tunnels.AddPeer(gateTrustedID, from)
	im.keyWith(t, d.tunnels.kx.PubKey())

	d.tunnels.handleEncrypted(im.seal(t, gateSYN(gateTrustedID)), from)
	if !routeOne(t, d) {
		t.Fatal("setup: frame over the unauthenticated session was not delivered by the tunnel")
	}
	if conn := d.ports.FindConnection(gatePort, protocol.Addr{Node: gateTrustedID}, 5555); conn != nil {
		t.Fatal("SYN over an unauthenticated session was admitted by handshake trust")
	}
	if k, asked := svc.gotKeyFor[gateTrustedID]; asked && k == "" {
		t.Fatal("the gate asked the trust store with an empty key")
	}
}

// The PILK sessions taken before the first identity are dropped with
// their endpoints once the identity is set; a later rotation drops
// nothing.
func TestSetIdentityDropsSessionsOpenedWithoutIdentity(t *testing.T) {
	t.Parallel()
	d, sock := newPacketDaemon(t, nil)
	d.config.Encrypt = true
	if err := d.tunnels.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	from := sock.LocalAddr().(*net.UDPAddr)
	const early = uint32(0x7100)
	d.tunnels.handleKeyExchange(newImpostor(t, early).pilk(), from, false)
	if !d.tunnels.HasCrypto(early) {
		t.Fatal("setup: a node without identity should take the PILK")
	}

	id, _ := crypto.GenerateIdentity()
	d.tunnels.SetIdentity(id)
	if d.tunnels.HasCrypto(early) || d.tunnels.HasPeer(early) {
		t.Fatal("session (or endpoint) from before the identity survived SetIdentity")
	}

	// A keyless peer accepted after registration is kept across rotation.
	d.tunnels.SetPeerVerifyFunc(func(uint32) (ed25519.PublicKey, error) { return nil, keyexchange.ErrPeerHasNoKey })
	const keyless = uint32(0x7101)
	d.tunnels.handleKeyExchange(newImpostor(t, keyless).pilk(), from, false)
	if !d.tunnels.HasCrypto(keyless) {
		t.Fatal("setup: PILK from a keyless peer refused")
	}
	rotated, _ := crypto.GenerateIdentity()
	d.tunnels.SetIdentity(rotated)
	if !d.tunnels.HasCrypto(keyless) {
		t.Fatal("identity rotation dropped a vetted session")
	}
}

// lookupPeerPubKey reports a registry entry with an empty key (what the
// registry sends for a keyless node) as ErrPeerHasNoKey. A missing node
// (reaped after 30 minutes silent) and a reply without the field are
// something else, so only the former opens the PILK path.
func TestLookupPeerPubKeyNoKeyIsAuthoritative(t *testing.T) {
	t.Parallel()
	const keyless, missing, noField = uint32(0x7201), uint32(0x7202), uint32(0x7203)
	client, cleanup := startFakeRegistry(t, func(req map[string]interface{}) map[string]interface{} {
		if req["type"] != "lookup" {
			return map[string]interface{}{"type": "ok"}
		}
		switch uint32(req["node_id"].(float64)) {
		case keyless:
			return map[string]interface{}{"type": "lookup_ok", "node_id": keyless, "public_key": ""}
		case noField:
			return map[string]interface{}{"type": "lookup_ok", "node_id": noField}
		}
		return map[string]interface{}{"type": "error", "error": "node not found"}
	})
	defer cleanup()
	d, _ := newPacketDaemon(t, client)

	if _, err := d.lookupPeerPubKey(keyless); !errors.Is(err, keyexchange.ErrPeerHasNoKey) {
		t.Fatalf("keyless entry: err = %v, want ErrPeerHasNoKey", err)
	}
	for _, id := range []uint32{missing, noField} {
		if _, err := d.lookupPeerPubKey(id); err == nil || errors.Is(err, keyexchange.ErrPeerHasNoKey) {
			t.Fatalf("node %d: err = %v, want a non-authoritative error", id, err)
		}
	}
}
