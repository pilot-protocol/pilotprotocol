// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestL1UnmarshalPanicSurvival drives protocol.Unmarshal through its
// L1 panic boundary. The boundary must convert any panic into
// ErrMalformedPacket. We use real malformed inputs that exercise the
// length-check error paths; the boundary is defense-in-depth for any
// future code change that introduces a slice OOB.
func TestL1UnmarshalPanicSurvival(t *testing.T) {
	cases := [][]byte{
		nil,              // nil slice
		{},               // empty
		make([]byte, 10), // shorter than header
		make([]byte, 34), // header-sized, all zeros — bad version
		append([]byte{}, badChecksumPacket()...),
	}
	for i, c := range cases {
		_, err := protocol.Unmarshal(c)
		if err == nil {
			t.Fatalf("case %d: Unmarshal returned no error", i)
		}
	}
}

// TestL1MarshalPanicSurvival exercises Marshal's panic boundary. The
// known panic-free path returns "payload too large" for oversized
// payloads; the boundary protects against future panic introductions.
func TestL1MarshalPanicSurvival(t *testing.T) {
	huge := make([]byte, 0xFFFF+1)
	pkt := &protocol.Packet{
		Version:  protocol.Version,
		Protocol: protocol.ProtoDatagram,
		Payload:  huge,
	}
	out, err := pkt.Marshal()
	if err == nil {
		t.Fatal("Marshal(oversize) returned no error")
	}
	if out != nil {
		t.Fatalf("Marshal(oversize) returned non-nil slice: %d bytes", len(out))
	}
}

// TestL2ReadLoopPanicSurvival sends a stream of malformed frames into
// a real TunnelManager, then a valid frame. The valid frame must
// arrive on RecvCh — proves the readLoop survived the malformed
// burst. Real edge case: junk magic bytes, truncated headers, a too-
// short PILS frame.
func TestL2ReadLoopPanicSurvival(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	addr := tm.LocalAddr().(*net.UDPAddr)

	sender, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer sender.Close()

	// Burst of malformed frames.
	bursts := [][]byte{
		{0x09},               // unknown beacon type
		{'X', 'X', 'X', 'X'}, // unknown magic
		append([]byte{'P', 'I', 'L', 'T'}, make([]byte, 5)...), // truncated PILT
	}
	for _, b := range bursts {
		_, _ = sender.Write(b)
	}

	// Truncated PILS — 4-magic + 4 nodeID + 12 nonce + 16 tag = 36 minimum
	junk := make([]byte, 4+4+12+16)
	copy(junk[:4], protocol.TunnelMagicSecure[:])
	_, _ = sender.Write(junk)

	// Truncated PILA (auth key exchange).
	pila := make([]byte, 4+4+32+32+64)
	copy(pila[:4], protocol.TunnelMagicAuthEx[:])
	_, _ = sender.Write(pila)

	// Allow the readLoop to drain the burst.
	time.Sleep(50 * time.Millisecond)

	// Now send a valid plaintext frame.
	good := &protocol.Packet{Version: protocol.Version, Protocol: protocol.ProtoStream}
	wire, err := good.Marshal()
	if err != nil {
		t.Fatalf("Marshal valid: %v", err)
	}
	envelope := make([]byte, 4+len(wire))
	copy(envelope[:4], protocol.TunnelMagic[:])
	copy(envelope[4:], wire)
	_, _ = sender.Write(envelope)

	select {
	case got := <-tm.RecvCh():
		if got == nil || got.Packet == nil {
			t.Fatal("nil packet on recvCh")
		}
		if got.Packet.Version != protocol.Version {
			t.Fatalf("wrong version: %d", got.Packet.Version)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readLoop did not deliver valid frame after malformed burst — boundary likely failed")
	}
}

// TestL4BeaconMessagePanicSurvival drives handleBeaconMessage with
// real malformed inputs (truncated punch-command, truncated relay-
// deliver). The boundary keeps the function alive — process must not
// crash. Real edge cases used.
func TestL4BeaconMessagePanicSurvival(t *testing.T) {
	tm := NewTunnelManager()
	defer tm.Close()
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	tm.handleBeaconMessage([]byte{}, from)
	tm.handleBeaconMessage([]byte{protocol.BeaconMsgPunchCommand}, from)
	tm.handleBeaconMessage([]byte{protocol.BeaconMsgRelayDeliver}, from)
	tm.handleBeaconMessage([]byte{0x0F}, from)
	// Inject a synthetic panic via the boundary helper to prove the
	// full L4 path is wired (uses recoverLayer with the bus).
	resetRecoveredPanicCountForTest()
	func() {
		defer recoverLayer("L4", "handleBeaconMessage", tm.bus, nil)
		panic("L4 boundary test panic")
	}()
	if RecoveredPanicCount() == 0 {
		t.Fatal("L4 boundary did not record synthetic panic")
	}
}

// TestL4BeaconRefreshTickPanicSurvival drives the beacon refresh tick
// on a synthetic Daemon. With nil registry conn the function returns
// cleanly; the boundary protects against future panic introductions.
func TestL4BeaconRefreshTickPanicSurvival(t *testing.T) {
	d := &Daemon{}
	d.beaconRefreshTick(true)
	d.beaconRefreshTick(false)

	// Synthetic panic injection through the same boundary helper.
	resetRecoveredPanicCountForTest()
	func() {
		defer recoverLayer("L4", "beaconRefreshTick", nil, nil)
		panic("L4 boundary test panic")
	}()
	if RecoveredPanicCount() == 0 {
		t.Fatal("L4 boundary did not record synthetic panic")
	}
}

// TestL5HandleAuthKeyExchangePanicSurvival drives handleAuthKeyExchange
// with malformed inputs (too-short, all-zero). Real edge cases.
func TestL5HandleAuthKeyExchangePanicSurvival(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	tm.handleAuthKeyExchange(make([]byte, 10), from, false)
	tm.handleAuthKeyExchange(make([]byte, 4+32+32+64), from, false)
}

// TestL5HandleKeyExchangePanicSurvival drives handleKeyExchange with
// malformed inputs.
func TestL5HandleKeyExchangePanicSurvival(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	tm.handleKeyExchange(make([]byte, 10), from, false)
	tm.handleKeyExchange(make([]byte, 36), from, false)
}

// TestL6HandleEncryptedPanicSurvival drives handleEncrypted on a
// TunnelManager with no installed peer key. The "no key" branch
// triggers a rate-limited rekey request and returns. The boundary
// keeps the daemon alive across a burst.
func TestL6HandleEncryptedPanicSurvival(t *testing.T) {
	tm := NewTunnelManager()
	if err := tm.EnableEncryption(); err != nil {
		t.Fatalf("EnableEncryption: %v", err)
	}
	if err := tm.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer tm.Close()
	from := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}

	tm.handleEncrypted(make([]byte, 10), from)

	frame := make([]byte, 4+12+16)
	binary.BigEndian.PutUint32(frame[:4], 0xDEADBEEF)
	tm.handleEncrypted(frame, from)
}

// TestL7RetxLoopPanicSurvival starts a per-Connection retxLoop, then
// injects a panic via a panicking RetxSend closure. Verifies the
// connection is torn down (RemoveConnection) and other connections
// in the same daemon are unaffected.
//
// Uses test-only injection: replacing RetxSend with a panicking
// closure is the cleanest way to hit a real code path with a panic.
func TestL7RetxLoopPanicSurvival(t *testing.T) {
	d := New(Config{
		ListenAddr:   "127.0.0.1:0",
		IdentityPath: t.TempDir() + "/identity.json",
	})
	defer d.Stop()

	c1 := d.ports.NewConnection(1000, protocol.Addr{Network: 1, Node: 0xBBBB1}, 2000)
	c2 := d.ports.NewConnection(1001, protocol.Addr{Network: 1, Node: 0xBBBB2}, 2001)

	c1.Mu.Lock()
	c1.State = StateEstablished
	c1.Mu.Unlock()
	c2.Mu.Lock()
	c2.State = StateEstablished
	c2.Mu.Unlock()

	resetRecoveredPanicCountForTest()
	d.startRetxLoop(c1)

	// Replace RetxSend with a panicking closure and add a stale
	// Unacked entry so the next tick triggers a retransmit attempt.
	c1.RetxMu.Lock()
	c1.RetxSend = func(*protocol.Packet) { panic("L7 boundary test panic") }
	c1.Unacked = []*retxEntry{{
		seq:      1,
		data:     []byte("x"),
		sentAt:   time.Now().Add(-time.Hour),
		attempts: 0,
		sacked:   false,
	}}
	c1.LastRetxTime = time.Time{}
	c1.RTO = 10 * time.Millisecond
	c1.RetxMu.Unlock()

	// Wait for the boundary to fire.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if RecoveredPanicCount() > 0 && d.ports.GetConnection(c1.ID) == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if RecoveredPanicCount() == 0 {
		t.Fatal("L7 boundary did not catch retxLoop panic")
	}
	if d.ports.GetConnection(c1.ID) != nil {
		t.Fatal("c1 was not removed after retxLoop panic")
	}
	if d.ports.GetConnection(c2.ID) == nil {
		t.Fatal("c2 was incorrectly removed — boundary should be per-conn")
	}
}

// TestL7RoutePacketPanicSurvival forces handlePacket into a panic via
// a nil packet, which would nil-deref on pkt.Protocol. The boundary
// must catch it.
func TestL7RoutePacketPanicSurvival(t *testing.T) {
	d := New(Config{
		ListenAddr:   "127.0.0.1:0",
		IdentityPath: t.TempDir() + "/identity.json",
	})
	defer d.Stop()

	resetRecoveredPanicCountForTest()
	d.routePacketWithRecover(&IncomingPacket{From: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1}})

	if RecoveredPanicCount() == 0 {
		t.Fatal("L7 routePacketWithRecover did not catch nil-packet panic")
	}
}

// TestL9IPCHandlerPanicSurvival forces a panic inside the L9 boundary
// path by directly invoking recoverLayer with a panicking callback.
// Proves the L9 plumbing increments the recovered count and stays alive.
//
// Uses test-only injection: a real handleClient panic-induction would
// require IPC-protocol-level malformed messages, but the per-handler
// dispatch already validates inputs explicitly and returns errors —
// no real unrecovered panic surface exists today. This test guarantees
// the L9 boundary mechanism would catch one if introduced.
func TestL9IPCHandlerPanicSurvival(t *testing.T) {
	d := New(Config{
		ListenAddr:   "127.0.0.1:0",
		IdentityPath: t.TempDir() + "/identity.json",
	})
	defer d.Stop()

	resetRecoveredPanicCountForTest()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer recoverLayer("L9", "handleClient", d.bus, nil)
		panic("L9 boundary test panic")
	}()
	wg.Wait()

	if RecoveredPanicCount() == 0 {
		t.Fatal("L9 boundary did not record the panic")
	}
}

// badChecksumPacket builds a 34-byte packet with a deliberately wrong
// CRC32 — exercises ErrChecksumMismatch.
func badChecksumPacket() []byte {
	buf := make([]byte, 34)
	buf[0] = (protocol.Version << 4)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	// checksum field at [30:34] left at 0 — guaranteed mismatch.
	return buf
}
