// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"net"
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// What a stream segment gains on its way to the wire, and the room it has.
const (
	// [PILS][sender node ID][nonce] before the ciphertext, GCM tag after it.
	testTunnelFraming = 4 + 4 + 12 + 16
	// The plaintext frame the fixture below sends: [PILP] and nothing else.
	testPlainFraming = 4
	// [MsgRelay][sender node ID][destination node ID] when the beacon relays.
	testRelayHeader = 1 + 4 + 4
	// UDP payload that fits IPv6's minimum MTU (1280) after the IPv6 and UDP
	// headers. Any path that carries IP carries a datagram this size whole.
	testSafeDatagram = 1280 - 40 - 8
)

// A full stream segment used to be 4096 bytes, about 4.2 KB on the wire and
// three IP fragments on a 1500-byte path. Where fragments are dropped — NATs,
// firewalls, some virtual networks — pings and small messages worked and
// every full segment was lost.
func TestSendSegmentSizeFitsOneUnfragmentedDatagram(t *testing.T) {
	t.Parallel()
	onWire := protocol.PacketHeaderSize() + SendSegmentSize + testTunnelFraming + testRelayHeader
	if onWire > testSafeDatagram {
		t.Fatalf("a full segment is a %d-byte datagram on the relay path, want at most %d", onWire, testSafeDatagram)
	}
	if SendSegmentSize > MaxSegmentSize {
		t.Fatalf("SendSegmentSize %d exceeds MaxSegmentSize %d, the most a peer accepts", SendSegmentSize, MaxSegmentSize)
	}
}

// readDatagramSizes collects the sizes of the datagrams arriving on pc until
// want bytes of stream payload have been seen.
func readDatagramSizes(t *testing.T, pc *net.UDPConn, want int) (sizes []int, payload []byte) {
	t.Helper()
	buf := make([]byte, 65535)
	for len(payload) < want {
		pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read after %d of %d payload bytes: %v", len(payload), want, err)
		}
		pkt, err := protocol.Unmarshal(buf[testPlainFraming:n])
		if err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		sizes = append(sizes, n)
		payload = append(payload, pkt.Payload...)
	}
	return sizes, payload
}

func TestStreamWritesLeaveAsDatagramsThatFitOnePacket(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		noDelay bool
		node    uint32
	}{
		{"nagle", false, 0xD7D70001},
		{"nodelay", true, 0xD7D70002},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, pc, conn := newSendDataFixture(t, tc.node)
			conn.NoDelay = tc.noDelay

			data := make([]byte, 20000)
			for i := range data {
				data[i] = byte(i * 7)
			}
			if err := d.SendData(conn, data); err != nil {
				t.Fatalf("SendData: %v", err)
			}
			sizes, payload := readDatagramSizes(t, pc, len(data))
			if string(payload) != string(data) {
				t.Fatalf("payload reassembled from %d datagrams differs from what was written", len(sizes))
			}
			for i, n := range sizes {
				// The fixture's tunnel is plaintext; an encrypted, relayed
				// one adds the difference.
				onWire := n - testPlainFraming + testTunnelFraming + testRelayHeader
				if onWire > testSafeDatagram {
					t.Fatalf("datagram %d of %d would be %d bytes encrypted and relayed, want at most %d", i+1, len(sizes), onWire, testSafeDatagram)
				}
			}
		})
	}
}

// The peer advertises its window as free slots in its receive buffer, one per
// segment whatever the segment's size. Counting only bytes, a sender of short
// segments put more of them in flight than the peer had slots; the peer's
// packet loop then blocks on its full buffer, up to a second per segment,
// with every other connection on that node waiting behind it.
func TestWindowAvailableCountsSegmentsAgainstPeerSlots(t *testing.T) {
	t.Parallel()
	short := func(n int) []*retxEntry {
		out := make([]*retxEntry, n)
		for i := range out {
			out[i] = &retxEntry{seq: uint32(1000 + 10*i), data: make([]byte, 10), attempts: 1}
		}
		return out
	}
	const slots = 4
	c := &Connection{CongWin: MaxCongWin, PeerRecvWin: slots * SendSegmentSize}

	c.Unacked = short(slots - 1)
	if !c.WindowAvailable() {
		t.Fatalf("%d segments in flight against %d free slots: window should be open", slots-1, slots)
	}
	c.Unacked = short(slots)
	if c.WindowAvailable() {
		t.Fatalf("%d segments in flight against %d free slots: window should be closed (only %d bytes are in flight, but every slot is taken)", slots, slots, c.BytesInFlight())
	}
	// A SACKed segment still counts: it waits in the peer's reorder buffer
	// and takes a slot the moment the hole before it is filled.
	c.Unacked[0].sacked = true
	if c.WindowAvailable() {
		t.Fatalf("%d segments outstanding, one of them SACKed, against %d free slots: window should be closed", slots, slots)
	}
	// No advertisement yet (-1): only the congestion window applies.
	c.PeerRecvWin = -1
	c.Unacked = short(100)
	if !c.WindowAvailable() {
		t.Fatal("no peer window advertised yet: window should be open")
	}
}

func TestNagleHoldsTail(t *testing.T) {
	t.Parallel()
	full := func() *retxEntry { return &retxEntry{data: make([]byte, SendSegmentSize)} }
	short := func() *retxEntry { return &retxEntry{data: make([]byte, 100)} }
	sacked := func(e *retxEntry) *retxEntry { e.sacked = true; return e }
	fin := &retxEntry{data: []byte{0}, isFIN: true}
	for _, tc := range []struct {
		name     string
		inFlight []*retxEntry
		hold     bool
	}{
		{"nothing in flight", nil, false},
		{"a short segment in flight", []*retxEntry{short()}, true},
		{"2000-byte write: one full segment ahead", []*retxEntry{full()}, false},
		{"4096-byte write: three full segments ahead", []*retxEntry{full(), full(), full()}, false},
		{"bulk: forty full segments ahead", func() []*retxEntry {
			out := make([]*retxEntry, 40)
			for i := range out {
				out[i] = full()
			}
			return out
		}(), false},
		{"a short segment behind full ones", []*retxEntry{full(), short(), full()}, true},
		{"the short segment in flight is SACKed", []*retxEntry{sacked(short()), full()}, false},
		{"only the FIN sentinel", []*retxEntry{fin}, false},
	} {
		c := &Connection{Unacked: tc.inFlight}
		if got := c.nagleHoldsTail(); got != tc.hold {
			t.Errorf("%s: tail held = %v, want %v", tc.name, got, tc.hold)
		}
	}
}

// The tail of a write of a segment or more leaves with it, even while an
// earlier short segment is unacknowledged: it is the end of a message, and
// holding it delays the message by a round trip.
func TestSendDataSendsTailOfMultiSegmentWriteAtOnce(t *testing.T) {
	t.Parallel()
	const write = MaxSegmentSize // three full segments and a 640-byte tail
	d, pc, conn := newSendDataFixture(t, 0xD8D80001)
	conn.NoDelay = false
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{data: []byte("an earlier short segment"), seq: 500, sentAt: time.Now(), attempts: 1})
	conn.RetxMu.Unlock()

	if err := d.SendData(conn, make([]byte, write)); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	// Nothing ACKs here, so a tail left held would still be in the buffer.
	conn.NagleMu.Lock()
	left := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if left != 0 {
		t.Fatalf("%d bytes of a %d-byte write were held back", left, write)
	}
	if sizes, _ := readDatagramSizes(t, pc, write); len(sizes) != 4 {
		t.Fatalf("a %d-byte write left as %d datagrams, want 4", write, len(sizes))
	}
}

// readSegments reads stream packets off pc until n have arrived.
func readSegments(t *testing.T, pc *net.UDPConn, n int) []*protocol.Packet {
	t.Helper()
	var out []*protocol.Packet
	for len(out) < n {
		out = append(out, readOneSegment(t, pc, 2*time.Second))
	}
	return out
}

// A short write that Nagle holds does not hold its writer: the write
// returns, later writes join it in the buffer, full segments leave as they
// fill, and what is left goes out when the short segment ahead is ACKed.
// Holding the writer instead meant nothing could ever join a held write, and
// a stream of short writes moved at one write per round trip.
func TestShortWritesBehindAHeldTailCoalesce(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xD9D90001)
	conn.NoDelay = false
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{data: []byte("an earlier short segment"), seq: 500, sentAt: time.Now(), attempts: 1})
	conn.RetxMu.Unlock()

	const piece, pieces = 300, 5 // 1500 bytes: one full segment and 348 left
	var want []byte
	start := time.Now()
	for i := 0; i < pieces; i++ {
		b := make([]byte, piece)
		for j := range b {
			b[j] = byte('a' + i)
		}
		want = append(want, b...)
		if err := d.SendData(conn, b); err != nil {
			t.Fatalf("SendData %d: %v", i, err)
		}
	}
	if took := time.Since(start); took >= NagleTimeout {
		t.Fatalf("%d short writes took %v: a held write made its writer wait", pieces, took)
	}

	// The fourth write filled a segment; it left without waiting.
	first := readOneSegment(t, pc, time.Second)
	if len(first.Payload) != SendSegmentSize {
		t.Fatalf("first segment carries %d bytes, want a full one (%d) coalesced from the short writes", len(first.Payload), SendSegmentSize)
	}
	conn.NagleMu.Lock()
	left := len(conn.NagleBuf)
	conn.NagleMu.Unlock()
	if left != piece*pieces-SendSegmentSize {
		t.Fatalf("%d bytes left in the buffer, want %d held", left, piece*pieces-SendSegmentSize)
	}

	// The earlier short segment is acknowledged: the rest follows.
	conn.RetxMu.Lock()
	conn.Unacked = conn.Unacked[1:]
	conn.RetxMu.Unlock()
	select {
	case conn.NagleCh <- struct{}{}:
	default:
	}
	rest := readOneSegment(t, pc, time.Second)
	got := append(append([]byte{}, first.Payload...), rest.Payload...)
	if string(got) != string(want) {
		t.Fatalf("received %d bytes that differ from the %d written", len(got), len(want))
	}
	if rest.Seq != first.Seq+uint32(len(first.Payload)) {
		t.Fatalf("second segment seq %d, want %d (directly after the first)", rest.Seq, first.Seq+uint32(len(first.Payload)))
	}
}

// Closing a connection sends a write Nagle is still holding, ahead of the FIN.
func TestCloseSendsHeldTailBeforeFIN(t *testing.T) {
	t.Parallel()
	d, pc, conn := newSendDataFixture(t, 0xD9D90002)
	conn.NoDelay = false
	conn.RetxMu.Lock()
	conn.Unacked = append(conn.Unacked, &retxEntry{data: []byte("an earlier short segment"), seq: 500, sentAt: time.Now(), attempts: 1})
	conn.RetxMu.Unlock()

	if err := d.SendData(conn, []byte("last words")); err != nil {
		t.Fatalf("SendData: %v", err)
	}
	d.CloseConnection(conn)

	pkts := readSegments(t, pc, 2)
	if string(pkts[0].Payload) != "last words" {
		t.Fatalf("first packet after close carries %q, want the held write", pkts[0].Payload)
	}
	if pkts[1].Flags&protocol.FlagFIN == 0 {
		t.Fatalf("second packet after close has flags %#x, want FIN", pkts[1].Flags)
	}
	if want := pkts[0].Seq + uint32(len(pkts[0].Payload)); pkts[1].Seq != want {
		t.Fatalf("FIN seq %d, want %d (directly after the held write)", pkts[1].Seq, want)
	}
}
