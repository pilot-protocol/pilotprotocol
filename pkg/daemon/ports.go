// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// ErrEphemeralExhausted is returned by callers of AllocEphemeralPort when
// all 16384 ephemeral ports (49152..65535) are simultaneously in use.
var ErrEphemeralExhausted = errors.New("ephemeral ports exhausted")

// SACKBlock represents a contiguous range of received bytes.
// Left is the seq of the first byte; Right is the seq of the first byte AFTER the range.
type SACKBlock struct {
	Left  uint32
	Right uint32
}

// sackMagic identifies SACK data in ACK payloads.
var sackMagic = []byte("SACK")

// EncodeSACK encodes SACK blocks into a byte slice.
// Format: "SACK" (4 bytes) + count (1 byte) + N * 8 bytes (Left:4, Right:4).
func EncodeSACK(blocks []SACKBlock) []byte {
	if len(blocks) == 0 {
		return nil
	}
	n := len(blocks)
	if n > 4 {
		n = 4 // max 4 SACK blocks (same as TCP)
	}
	buf := make([]byte, 5+n*8)
	copy(buf[0:4], sackMagic)
	buf[4] = byte(n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		binary.BigEndian.PutUint32(buf[off:off+4], blocks[i].Left)
		binary.BigEndian.PutUint32(buf[off+4:off+8], blocks[i].Right)
	}
	return buf
}

// DecodeSACK parses SACK blocks from an ACK payload.
// Returns nil, false if the payload is not SACK data.
func DecodeSACK(data []byte) ([]SACKBlock, bool) {
	if len(data) < 5 || !bytes.Equal(data[0:4], sackMagic) {
		return nil, false
	}
	n := int(data[4])
	if n == 0 || n > 4 || len(data) < 5+n*8 {
		return nil, false
	}
	blocks := make([]SACKBlock, n)
	for i := 0; i < n; i++ {
		off := 5 + i*8
		blocks[i] = SACKBlock{
			Left:  binary.BigEndian.Uint32(data[off : off+4]),
			Right: binary.BigEndian.Uint32(data[off+4 : off+8]),
		}
	}
	return blocks, true
}

// MaxConnectionsPerPort and MaxTotalConnections defaults are defined in daemon.go Config.
// The daemon passes resolved values when checking limits.

// PortManager handles virtual port binding and connection tracking.
//
// Ephemeral port allocation uses a 16,384-bit bitmap (256 × uint64) covering
// the [PortEphemeralMin..PortEphemeralMax] range. A bit set means the port is
// owned by an active connection. AllocEphemeralPort finds the first clear bit
// at O(words / 64), starting from the round-robin cursor; RemoveConnection
// clears the owning bit. Replaces the prior O(N × 16384) linear scan, which
// took a write lock and serialized every concurrent dial behind it — under
// the inbound-handshake storm at cold start, that became a 400%+ CPU spike.
type PortManager struct {
	mu          sync.RWMutex
	listeners   map[uint16]*Listener
	connections map[uint32]*Connection // conn_id → connection
	nextConnID  uint32
	nextEphPort uint16
	ephBitmap   [256]uint64 // 256 × 64 = 16384 bits, one per ephemeral port
}

const ephBitmapWords = 256

// ephBitIndex maps a port in [PortEphemeralMin..PortEphemeralMax] to
// (word, bit) coordinates in ephBitmap. Returns -1,-1 for out-of-range ports.
func ephBitIndex(port uint16) (word, bit int) {
	if port < protocol.PortEphemeralMin || port > protocol.PortEphemeralMax {
		return -1, -1
	}
	idx := int(port - protocol.PortEphemeralMin)
	return idx / 64, idx % 64
}

// markEphPortUsedLocked sets the bit for port in the ephemeral bitmap.
// No-op for non-ephemeral ports. Must be called with pm.mu held.
func (pm *PortManager) markEphPortUsedLocked(port uint16) {
	w, b := ephBitIndex(port)
	if w < 0 {
		return
	}
	pm.ephBitmap[w] |= 1 << b
}

// clearEphPortLocked clears the bit for port. No-op for non-ephemeral ports
// or ports that another active connection still holds. Must be called with
// pm.mu held.
func (pm *PortManager) clearEphPortLocked(port uint16) {
	w, b := ephBitIndex(port)
	if w < 0 {
		return
	}
	// Don't clear if another connection still uses this port. Rare but
	// possible with the dial-self / two-connections-same-local-port edge
	// cases the existing FindConnection path handles.
	for _, c := range pm.connections {
		if c.LocalPort == port {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateClosed && st != StateTimeWait {
				return
			}
		}
	}
	pm.ephBitmap[w] &^= 1 << b
}

type Listener struct {
	Port     uint16
	AcceptCh chan *Connection
	mu       sync.Mutex
	closed   bool
}

// TrySend attempts a non-blocking push of conn to AcceptCh.
// Returns true if the connection was queued, false if the queue was full or
// the listener has been closed (via Unbind). Safe to call after Unbind —
// never panics even if AcceptCh is already closed.
//
// v1.9.1 fix: the closed flag is checked under mu before the channel send,
// eliminating the window where Unbind()'s close(AcceptCh) races with
// handleStreamPacket's send. Without this guard, a concurrent Unbind could
// close AcceptCh between GetListener's return and the send, causing a
// "send on closed channel" panic that killed routeLoop.
func (ln *Listener) TrySend(conn *Connection) bool {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if ln.closed {
		return false
	}
	select {
	case ln.AcceptCh <- conn:
		return true
	default:
		return false
	}
}

// close marks the listener as closed and drains + closes AcceptCh.
// Called by Unbind under pm.mu to ensure Listener.TrySend sees the closed
// flag atomically — no send can slip between closed=true and close(AcceptCh).
func (ln *Listener) close() {
	ln.mu.Lock()
	defer ln.mu.Unlock()
	if !ln.closed {
		ln.closed = true
		close(ln.AcceptCh)
	}
}

// retxEntry is a sent-but-unacknowledged data segment.
type retxEntry struct {
	data       []byte
	seq        uint32
	sentAt     time.Time // timer anchor; reset by RFC 6298 §5.3 and on retransmit
	origSentAt time.Time // original send time for RTT measurement; never reset
	attempts   int       // total transmissions (Karn's algorithm + retx budget guard)
	// rtoAttempts counts only RTO-timer retransmissions and alone feeds the
	// give-up RST decision. ACK-clocked retransmissions (fast retransmit,
	// retransmitLost bursts) are triggered BY arriving ACKs — proof the
	// path is alive — so they must never push a live connection toward the
	// MaxRetxAttempts RST. Only the RTO timer firing repeatedly with no ACK
	// progress is evidence of a dead peer.
	rtoAttempts int
	sacked      bool // true if covered by a SACK block (don't retransmit)
	isFIN       bool // true for the FIN sentinel entry (retransmit as FlagFIN, not data)
}

// recvSegment is an out-of-order received segment waiting for reassembly.
type recvSegment struct {
	seq  uint32
	data []byte
}

// Default window parameters.
//
// Sizing rationale (throughput = window / RTT): the overlay's typical
// relay path RTT is ~200 ms, so a 1 MB window capped goodput at ~5 MB/s
// and a small slow-start threshold capped short transfers well below
// that. With the receiver able to buffer a FULL congestion window out of
// order and loss recovery ACK-clocked (see retransmitLost), large windows
// are safe: overshoot loss heals in a few RTTs instead of collapsing the
// transfer, so the constants below favor bandwidth.
const (
	InitialCongWin = 10 * MaxSegmentSize          // 40 KB initial congestion window (IW10, RFC 6928)
	MaxCongWin     = 4 * 1024 * 1024              // 4 MB max congestion window (~18 MB/s at 214 ms RTT)
	MaxSegmentSize = 4096                         // MTU for virtual segments
	RecvBufSize    = 1024                         // receive buffer channel capacity (segments)
	MaxRecvWin     = RecvBufSize * MaxSegmentSize // 4 MB max receive window
	// MaxOOOBuf must be able to hold a full congestion window of segments
	// (MaxCongWin / MaxSegmentSize). If it is smaller, a single lost
	// segment with more than MaxOOOBuf segments in flight makes the receiver
	// silently drop every subsequent in-window segment (DeliverInOrder's
	// buffer bound), amplifying one loss into a whole-window loss and
	// collapsing throughput. 1024 = RecvBufSize, so the OOO buffer can cover
	// the entire advertised receive window (4 MB). Memory is only consumed
	// under actual loss, bounded at 4 MB per connection.
	MaxOOOBuf = 1024

	// InitialSSThresh is the hard upper stop for slow start. The PRIMARY
	// slow-start exit is adaptive: HyStart-style RTT-rise detection (RFC
	// 9406, see ProcessAck) hands over to congestion avoidance as soon as
	// the path's queue visibly starts filling, at whatever window the path
	// actually supports. This constant only bounds the exponential phase
	// on paths where no RTT signal appears (e.g. fixed-latency links with
	// tail-drop queues); real loss then halves SSThresh as usual, which
	// the window-sized OOO buffer plus ACK-clocked retransmission make
	// cheap (a few RTTs) rather than fatal.
	InitialSSThresh = MaxCongWin / 2

	// HyStart++ (RFC 9406, simplified) slow-start exit parameters: after
	// at least hsMinSamples RTT samples in a round, if the round's min RTT
	// exceeds the previous round's min by eta = clamp(lastMin/8, hsEtaMin,
	// hsEtaMax), the queue is building — set SSThresh = CongWin and enter
	// congestion avoidance at the discovered capacity.
	hsMinSamples   = 8
	AcceptQueueLen = 64   // listener accept channel capacity
	SendBufLen     = 1024 // send buffer channel capacity (segments) — covers a full cwnd

	// MaxNagleBuf caps the per-connection NagleBuf at 64 segments
	// (256 KB). v1.9.1 fix: SendData previously appended without bound,
	// so an application writing faster than the network could drain
	// (slow peer, full cwnd, packet loss) leaked memory linearly with
	// offered-but-undeliverable load. With many connections in that
	// state, daemon RSS climbed until OOM. SendData now returns
	// ErrSendBufFull when len(NagleBuf) + len(write) would exceed
	// this cap; callers must retry with backpressure.
	// 256 KB accommodates the largest single data-exchange frame
	// (64 KB) with headroom, while still bounding per-connection memory.
	MaxNagleBuf = 64 * MaxSegmentSize

	hsEtaMin = 4 * time.Millisecond  // min RTT-rise to trigger HyStart exit
	hsEtaMax = 16 * time.Millisecond // max RTT-rise threshold
)

// RTO parameters (RFC 6298)
const (
	ClockGranularity = 10 * time.Millisecond  // minimum RTTVAR for RTO calculation
	RTOMin           = 200 * time.Millisecond // minimum retransmission timeout
	RTOMax           = 10 * time.Second       // maximum retransmission timeout
	InitialRTO       = 1 * time.Second        // initial retransmission timeout
)

type Connection struct {
	Mu           sync.Mutex // protects State, SendSeq, RecvAck, LastActivity, Stats
	ID           uint32
	LocalAddr    protocol.Addr // our virtual address
	LocalPort    uint16
	RemoteAddr   protocol.Addr
	RemotePort   uint16
	State        ConnState
	LastActivity time.Time // updated on send/recv
	// Reliable delivery
	SendSeq uint32
	RecvAck uint32
	// SynAckSeq: sequence number used on the original outbound SYN-ACK.
	// P1-001 fix: retransmitted SYNs must receive the same seq, not a
	// stale `SendSeq-1` that has drifted forward once data flowed.
	SynAckSeq    uint32
	SynAckSeqSet bool
	SendBuf      chan []byte
	RecvBuf      chan []byte
	// Sliding window + retransmission (send side)
	RetxMu        sync.Mutex
	Unacked       []*retxEntry           // ordered by seq
	LastAck       uint32                 // highest cumulative ACK received
	DupAckCount   int                    // consecutive duplicate ACKs
	RTO           time.Duration          // retransmission timeout
	SRTT          time.Duration          // smoothed RTT
	RTTVAR        time.Duration          // RTT variance (RFC 6298)
	CongWin       int                    // congestion window in bytes
	SSThresh      int                    // slow-start threshold
	InRecovery    bool                   // true during timeout loss recovery
	FastRecovery  bool                   // true when recovery was entered via fast retransmit (not timeout)
	RecoveryPoint uint32                 // highest seq sent when entering recovery
	RetxStop      chan struct{}          // closed to stop retx goroutine
	RetxSend      func(*protocol.Packet) // callback to send retransmitted packets
	WindowCh      chan struct{}          // signaled when window opens up
	PeerRecvWin   int                    // peer's advertised receive window (-1 = not yet received, 0 = explicit zero-window)
	// HyStart++ slow-start exit state (RFC 9406, simplified; RetxMu).
	// Rounds are delimited by snd_nxt at round start: when the cumulative
	// ACK passes hsRoundEnd, one full flight has been acknowledged.
	hsRoundEnd   uint32        // ack that ends the current round (0 = uninitialized)
	hsCurrMinRTT time.Duration // min clean RTT sample seen this round
	hsLastMinRTT time.Duration // min clean RTT sample of the previous round
	hsSamples    int           // clean RTT samples seen this round
	// Nagle algorithm (write coalescing)
	NagleBuf []byte        // pending small write data
	NagleMu  sync.Mutex    // protects NagleBuf
	NagleCh  chan struct{} // signaled when Nagle should flush
	NoDelay  bool          // if true, disable Nagle (send immediately)
	// Receive window (reassembly)
	RecvMu      sync.Mutex
	ExpectedSeq uint32         // next in-order seq expected
	OOOBuf      []*recvSegment // out-of-order buffer
	// Delayed ACK
	AckMu       sync.Mutex  // protects PendingACKs and ACKTimer
	PendingACKs int         // count of unacked received segments
	ACKTimer    *time.Timer // delayed ACK timer
	// Keepalive dead-peer detection
	KeepaliveUnacked int // consecutive unanswered keepalive probes
	// Close
	CloseOnce  sync.Once // ensures RecvBuf is closed exactly once
	RecvClosed bool      // true after RecvBuf is closed (guarded by RecvMu)
	// recvSenders tracks in-flight Phase 2 senders into RecvBuf so CloseRecvBuf
	// can wait for them to drain before close()ing the channel. Without this,
	// `chansend1` and the close() race per the runtime data-race detector even
	// though Go's runtime makes it well-defined (close-then-send panics, the
	// Phase 2 defer recover()s — but the race detector still flags the
	// concurrent close-vs-send on the channel's internal state).
	recvSenders sync.WaitGroup
	// Retransmit state
	LastRetxTime time.Time // when last RTO retransmission fired (prevents cascading)
	// Per-connection statistics
	Stats ConnStats
}

// ConnStats tracks per-connection traffic and reliability metrics.
type ConnStats struct {
	BytesSent   uint64 // total user bytes sent
	BytesRecv   uint64 // total user bytes received
	SegsSent    uint64 // data segments sent
	SegsRecv    uint64 // data segments received
	Retransmits uint64 // timeout-based retransmissions
	FastRetx    uint64 // fast retransmissions (3 dup ACKs)
	SACKRecv    uint64 // SACK blocks received from peer
	SACKSent    uint64 // SACK blocks sent to peer
	DupACKs     uint64 // duplicate ACKs received
}

type ConnState uint8

const (
	StateClosed ConnState = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait
	StateCloseWait
	StateTimeWait
)

func (s ConnState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateListen:
		return "LISTEN"
	case StateSynSent:
		return "SYN_SENT"
	case StateSynReceived:
		return "SYN_RECV"
	case StateEstablished:
		return "ESTABLISHED"
	case StateFinWait:
		return "FIN_WAIT"
	case StateCloseWait:
		return "CLOSE_WAIT"
	case StateTimeWait:
		return "TIME_WAIT"
	default:
		return "unknown"
	}
}

func NewPortManager() *PortManager {
	return &PortManager{
		listeners:   make(map[uint16]*Listener),
		connections: make(map[uint32]*Connection),
		nextConnID:  1,
		nextEphPort: protocol.PortEphemeralMin,
	}
}

func (pm *PortManager) Bind(port uint16) (*Listener, error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if _, exists := pm.listeners[port]; exists {
		return nil, fmt.Errorf("port %d already bound", port)
	}

	ln := &Listener{
		Port:     port,
		AcceptCh: make(chan *Connection, AcceptQueueLen),
	}
	pm.listeners[port] = ln
	return ln, nil
}

func (pm *PortManager) Unbind(port uint16) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if ln, ok := pm.listeners[port]; ok {
		ln.close() // sets closed=true + close(AcceptCh) under ln.mu
		delete(pm.listeners, port)
	}
}

func (pm *PortManager) GetListener(port uint16) *Listener {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.listeners[port]
}

// ConnectionCountForPort returns the number of active connections on a port.
func (pm *PortManager) ConnectionCountForPort(port uint16) int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if c.LocalPort == port && st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

// TotalActiveConnections returns the total number of non-closed connections.
func (pm *PortManager) TotalActiveConnections() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	count := 0
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st != StateClosed && st != StateTimeWait {
			count++
		}
	}
	return count
}

// AllocEphemeralPort returns an unused ephemeral port in [PortEphemeralMin,
// PortEphemeralMax], or 0 when all 16384 ports are simultaneously in use.
// Callers must treat 0 as ErrEphemeralExhausted.
//
// Bitmap-backed: scans ephBitmap (256 uint64 words) starting from the
// round-robin cursor and returns the first clear bit. O(words) worst case,
// O(1) amortized — well within the write lock so concurrent dials don't
// queue behind a 16K-port linear scan as they did in the prior
// implementation.
//
// v1.9.1 wrap-bug protection retained: the cursor is incremented inside
// nextEphPort's uint16 range using a >= check before the bump, so the field
// can never overflow to 0.
func (pm *PortManager) AllocEphemeralPort() uint16 {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	total := int(protocol.PortEphemeralMax-protocol.PortEphemeralMin) + 1
	startIdx := int(pm.nextEphPort - protocol.PortEphemeralMin)
	for offset := 0; offset < total; offset++ {
		idx := (startIdx + offset) % total
		word, bit := idx/64, idx%64
		if pm.ephBitmap[word]&(1<<bit) == 0 {
			port := protocol.PortEphemeralMin + uint16(idx)
			pm.ephBitmap[word] |= 1 << bit
			// Advance the round-robin cursor past this allocation so the
			// next caller starts looking from the next slot. Wraps without
			// uint16 overflow.
			next := port
			if next >= protocol.PortEphemeralMax {
				next = protocol.PortEphemeralMin
			} else {
				next++
			}
			pm.nextEphPort = next
			return port
		}
	}
	return 0 // exhausted; callers must check and return ErrEphemeralExhausted
}

// portInUse returns true if any active connection is using the given local port.
// Must be called with pm.mu held.
func (pm *PortManager) portInUse(port uint16) bool {
	for _, c := range pm.connections {
		if c.LocalPort == port {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateClosed && st != StateTimeWait {
				return true
			}
		}
	}
	return false
}

func (pm *PortManager) NewConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	conn := &Connection{
		ID:           pm.nextConnID,
		LocalPort:    localPort,
		RemoteAddr:   remoteAddr,
		RemotePort:   remotePort,
		State:        StateClosed,
		LastActivity: time.Now(),
		SendBuf:      make(chan []byte, SendBufLen),
		RecvBuf:      make(chan []byte, RecvBufSize),
		CongWin:      InitialCongWin,
		SSThresh:     InitialSSThresh,
		WindowCh:     make(chan struct{}, 1),
		NagleCh:      make(chan struct{}, 1),
		PeerRecvWin:  -1, // sentinel: no window advertisement received yet
		// Initialize RetxStop here (instead of in startRetxLoop) so it is
		// safe to read concurrently from RemoveConnection / idleSweepLoop
		// before the retx loop is wired up after handshake completion.
		// Without this, the §4.8 stress test trips a write-vs-read race
		// between dialConnectionLocked → startRetxLoop and idleSweepLoop
		// → RemoveConnection on the same conn.
		RetxStop: make(chan struct{}),
	}
	pm.nextConnID++
	if pm.nextConnID == 0 {
		pm.nextConnID = 1 // wrap around, skip 0 (reserved)
	}
	pm.connections[conn.ID] = conn
	// Mark the local port used in the ephemeral bitmap if it falls in range.
	// For non-ephemeral well-known local ports (listener-accept paths,
	// listen/bind) this is a no-op — those don't go through
	// AllocEphemeralPort either.
	pm.markEphPortUsedLocked(localPort)
	return conn
}

func (pm *PortManager) GetConnection(id uint32) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.connections[id]
}

func (pm *PortManager) FindConnection(localPort uint16, remoteAddr protocol.Addr, remotePort uint16) *Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	// v1.9.1: prefer active (non-TIME_WAIT, non-CLOSED) connections when
	// multiple share the same 4-tuple (possible after port reuse on a
	// TIME_WAIT entry). Without this preference, Go's randomised map
	// iteration returned stale TIME_WAIT entries ~50% of the time, causing
	// data packets to be silently discarded by the "established" state guard.
	var fallback *Connection
	for _, c := range pm.connections {
		if c.LocalPort == localPort && c.RemoteAddr == remoteAddr && c.RemotePort == remotePort {
			c.Mu.Lock()
			st := c.State
			c.Mu.Unlock()
			if st != StateTimeWait && st != StateClosed {
				return c // active connection — always prefer over stale entries
			}
			fallback = c // stale; return only when no active match exists
		}
	}
	return fallback
}

// ConnectionInfo describes an active connection for diagnostics.
type ConnectionInfo struct {
	ID          uint32
	LocalPort   uint16
	RemoteAddr  string
	RemotePort  uint16
	State       string
	SendSeq     uint32
	RecvAck     uint32
	CongWin     int
	SSThresh    int
	InFlight    int
	SRTT        time.Duration
	RTTVAR      time.Duration
	Unacked     int
	OOOBuf      int
	PeerRecvWin int
	RecvWin     int
	InRecovery  bool
	Stats       ConnStats
}

// ConnectionList returns info about all active connections.
func (pm *PortManager) ConnectionList() []ConnectionInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var list []ConnectionInfo
	for _, c := range pm.connections {
		c.RetxMu.Lock()
		inFlight := c.BytesInFlight()
		unacked := len(c.Unacked)
		congWin := c.CongWin
		ssthresh := c.SSThresh
		srtt := c.SRTT
		rttvar := c.RTTVAR
		peerWin := c.PeerRecvWin
		inRecovery := c.InRecovery
		c.RetxMu.Unlock()
		recvWin := int(c.RecvWindow()) * MaxSegmentSize

		c.RecvMu.Lock()
		ooo := len(c.OOOBuf)
		c.RecvMu.Unlock()

		c.Mu.Lock()
		st := c.State
		sendSeq := c.SendSeq
		recvAck := c.RecvAck
		stats := c.Stats
		c.Mu.Unlock()

		list = append(list, ConnectionInfo{
			ID:          c.ID,
			LocalPort:   c.LocalPort,
			RemoteAddr:  c.RemoteAddr.String(),
			RemotePort:  c.RemotePort,
			State:       st.String(),
			SendSeq:     sendSeq,
			RecvAck:     recvAck,
			CongWin:     congWin,
			SSThresh:    ssthresh,
			InFlight:    inFlight,
			SRTT:        srtt,
			RTTVAR:      rttvar,
			Unacked:     unacked,
			OOOBuf:      ooo,
			PeerRecvWin: peerWin,
			RecvWin:     recvWin,
			InRecovery:  inRecovery,
			Stats:       stats,
		})
	}
	return list
}

// SynSentReapDuration is how long a SYN_SENT connection may sit before the
// idle sweeper closes it. Without this, a dial against an unreachable peer
// (NAT punch failed; peer offline; relay drops the SYN) leaves the conn —
// and the virtual ephemeral port it holds — pinned for the full retx ladder
// (~30 s+), and a cold-start handshake storm can pile thousands of such
// stuck SYN_SENT conns into the ephemeral pool. 5 s is comfortably past
// real WAN RTT plus a couple of SYN retransmits, while still letting the
// pool recover quickly under load.
const SynSentReapDuration = 5 * time.Second

// StaleConnections returns connections in a terminal state that should be cleaned up.
// CLOSED, FIN_WAIT, CLOSE_WAIT are cleaned up immediately.
// TIME_WAIT connections are cleaned up after timeWaitDur.
// SYN_SENT connections are cleaned up after SynSentReapDuration when no SYN-ACK
// has arrived — this prevents unreachable-peer dials from holding ephemeral
// ports through their retransmit ladder.
func (pm *PortManager) StaleConnections(timeWaitDur time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var stale []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		switch st {
		case StateClosed, StateCloseWait:
			stale = append(stale, c)
		case StateFinWait, StateTimeWait:
			if now.Sub(la) > timeWaitDur {
				stale = append(stale, c)
			}
		case StateSynSent:
			if now.Sub(la) > SynSentReapDuration {
				stale = append(stale, c)
			}
		}
	}
	return stale
}

// ActiveNodeIDs returns the set of node IDs with at least one
// non-closed, non-timewait connection. Used by the peer reaper
// to identify stale tunnel entries that can be safely removed.
func (pm *PortManager) ActiveNodeIDs() map[uint32]bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	nodes := make(map[uint32]bool)
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		c.Mu.Unlock()
		if st != StateClosed && st != StateTimeWait {
			nodes[c.RemoteAddr.Node] = true
		}
	}
	return nodes
}

// IdleConnections returns connections that have been idle longer than the given duration.
func (pm *PortManager) IdleConnections(maxIdle time.Duration) []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	now := time.Now()
	var idle []*Connection
	for _, c := range pm.connections {
		c.Mu.Lock()
		st := c.State
		la := c.LastActivity
		c.Mu.Unlock()
		if st == StateEstablished && now.Sub(la) > maxIdle {
			idle = append(idle, c)
		}
	}
	return idle
}

// AllConnections returns all active connections.
func (pm *PortManager) AllConnections() []*Connection {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	conns := make([]*Connection, 0, len(pm.connections))
	for _, c := range pm.connections {
		conns = append(conns, c)
	}
	return conns
}

func (pm *PortManager) RemoveConnection(id uint32) {
	pm.mu.Lock()
	c := pm.connections[id]
	delete(pm.connections, id)
	if c != nil {
		pm.clearEphPortLocked(c.LocalPort)
	}
	pm.mu.Unlock()
	// Stop retransmission goroutine
	if c != nil && c.RetxStop != nil {
		select {
		case <-c.RetxStop:
		default:
			close(c.RetxStop)
		}
	}
}

// BytesInFlight returns total unacknowledged bytes, excluding SACKed segments.
// SACKed segments remain in c.Unacked until a cumulative ACK removes them, but
// they are already at the peer so they must not consume congestion-window space.
func (c *Connection) BytesInFlight() int {
	total := 0
	for _, e := range c.Unacked {
		if !e.sacked {
			total += len(e.data)
		}
	}
	return total
}

// EffectiveWindow returns the effective send window (minimum of congestion
// window and peer's advertised receive window).
// Must be called with RetxMu held.
func (c *Connection) EffectiveWindow() int {
	win := c.CongWin
	if win <= 0 {
		win = InitialCongWin
	}
	if c.PeerRecvWin >= 0 && c.PeerRecvWin < win {
		win = c.PeerRecvWin
	}
	return win
}

// WindowAvailable returns true if the effective window allows more data.
// Must be called with RetxMu held.
func (c *Connection) WindowAvailable() bool {
	return c.BytesInFlight() < c.EffectiveWindow()
}

// TrackSend adds a sent data segment to the retransmission buffer.
func (c *Connection) TrackSend(seq uint32, data []byte) {
	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()
	saved := make([]byte, len(data))
	copy(saved, data)
	now := time.Now()
	c.Unacked = append(c.Unacked, &retxEntry{
		data:       saved,
		seq:        seq,
		sentAt:     now,
		origSentAt: now,
		attempts:   1,
	})
}

// ProcessAck removes segments acknowledged by the given ack number,
// updates RTT estimate, detects duplicate ACKs for fast retransmit,
// and grows the congestion window.
// If pureACK is true, duplicate ACK detection is enabled. Data packets
// with piggybacked ACKs should pass pureACK=false to avoid false
// fast retransmits (RFC 5681 Section 3.2).
//
// Lock-order note: Stats fields are guarded by Mu, but the rest of this
// function's state (Unacked, RTT, CongWin, etc.) is guarded by RetxMu.
// To avoid an Mu↔RetxMu inversion (a concurrent Stats() reader holds Mu
// then needs RetxMu, while we hold RetxMu and need Mu), we accumulate
// stats deltas locally and apply them under Mu AFTER RetxMu is released.
func (c *Connection) ProcessAck(ack uint32, pureACK bool) {
	// Capture RecvAck and SendSeq under Mu BEFORE taking RetxMu.
	// RecvAck: needed by fastRetransmit (lock-order-safe read).
	// SendSeq: needed to set RecoveryPoint when fast retransmit enters recovery.
	// Both advance monotonically; a slightly stale read is harmless.
	c.Mu.Lock()
	recvAck := c.RecvAck
	sendSeq := c.SendSeq
	c.Mu.Unlock()

	var dupAcks, fastRetx uint64
	defer func() {
		if dupAcks == 0 && fastRetx == 0 {
			return
		}
		c.Mu.Lock()
		c.Stats.DupACKs += dupAcks
		c.Stats.FastRetx += fastRetx
		c.Mu.Unlock()
	}()

	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	if seqAfter(c.LastAck, ack) {
		return // ack is behind LastAck (wrapping-safe)
	}

	if ack == c.LastAck {
		if !pureACK {
			return // data packets don't count as dup ACKs
		}
		// Dup-ACK counting is only meaningful when data is genuinely in flight
		// (RFC 5681 §3.2).  Use BytesInFlight() rather than len(Unacked) so
		// that all-SACKed Unacked entries (peer has them, no real loss) do not
		// count as "in flight" and trigger spurious fast retransmit with the
		// associated SSThresh halving.
		if c.BytesInFlight() == 0 {
			return
		}
		c.DupAckCount++
		dupAcks++
		// RFC 5681 §3.2 step 5: inflate cwnd for dup ACKs at count 1-2 while already
		// in fast recovery.  After a partial ACK resets DupAckCount to 0, subsequent
		// dup ACKs at count 1 and 2 do not reach the DupAckCount==3 (fast-retransmit
		// entry) or DupAckCount>3 (step-5 inflation) branches.  The 3-dup threshold
		// is only the ENTRY condition; every dup ACK "while in fast retransmit"
		// (InRecovery=true, FastRecovery=true) must inflate cwnd by SMSS regardless
		// of the current count.
		if c.DupAckCount < 3 && c.InRecovery && c.FastRecovery && len(c.Unacked) > 0 {
			c.CongWin += MaxSegmentSize
			if c.CongWin > MaxCongWin {
				c.CongWin = MaxCongWin
			}
			if c.WindowCh != nil && c.WindowAvailable() {
				select {
				case c.WindowCh <- struct{}{}:
				default:
				}
			}
			return
		}
		if c.DupAckCount == 3 && len(c.Unacked) > 0 {
			// Fast retransmit (RFC 5681). Only when there is data in flight:
			// keepalive probes and other spurious dup-ACKs with an empty Unacked
			// must not trigger congestion reduction (FlightSize == 0).
			// fastRetransmit returns true only when a packet was actually sent.
			// When it returns false (e.g. MaxRetxAttempts guard), skip all
			// congestion-state adjustments — no recovery was entered.
			if c.fastRetransmit(recvAck) {
				fastRetx++
				// RFC 6582 §3: enter a new recovery episode only when the highest
				// sequence number transmitted is above the current recover variable
				// (our RecoveryPoint).  This covers two cases:
				//   • Not in recovery at all (fresh new episode).
				//   • Already in timeout recovery AND new data was sent beyond the
				//     prior recovery window — a second, distinct loss event that
				//     requires its own multiplicative decrease.
				// Same-episode dup ACKs (InRecovery && sendSeq <= RecoveryPoint)
				// are excluded: they must not re-halve SSThresh or set FastRecovery.
				newEpisode := !c.InRecovery || seqAfter(sendSeq, c.RecoveryPoint)
				if newEpisode {
					// RFC 5681 §3.2 step 2: ssthresh = max(FlightSize/2, 2*SMSS).
					// FlightSize = bytes sent but not yet cumulatively acknowledged =
					// SND.NXT − SND.UNA = sum of ALL Unacked entry lengths (including
					// SACK'd entries that have not been covered by a cumulative ACK).
					var flightSize int
					for _, e := range c.Unacked {
						flightSize += len(e.data)
					}
					c.SSThresh = flightSize / 2
					if c.SSThresh < 2*MaxSegmentSize {
						c.SSThresh = 2 * MaxSegmentSize
					}
					c.InRecovery = true
					c.RecoveryPoint = sendSeq
					// Track that recovery was entered via fast retransmit (not timeout),
					// so that subsequent partial ACKs within this episode trigger RFC 6582
					// §3 step 6 retransmit + deflation even when DupAckCount was reset
					// to 0 by a prior partial ACK.
					c.FastRecovery = true
					c.CongWin = c.SSThresh + 3*MaxSegmentSize
					// For small CongWin (< 6*SMSS), SSThresh+3*MSS > old CongWin, so
					// the window may have opened.  Signal the sender so it doesn't stall.
					if c.WindowCh != nil && c.WindowAvailable() {
						select {
						case c.WindowCh <- struct{}{}:
						default:
						}
					}
				} else if c.InRecovery && c.FastRecovery {
					// RFC 5681 §3.2 step 5: same-episode 3rd dup ACK after a partial
					// ACK reset DupAckCount to 0.  fastRetransmit (above) is the RFC
					// 6582 §3 step 6a retransmit; the step-5 per-dup cwnd inflation
					// must also fire — it is not gated on newEpisode.
					c.CongWin += MaxSegmentSize
					if c.CongWin > MaxCongWin {
						c.CongWin = MaxCongWin
					}
					if c.WindowCh != nil && c.WindowAvailable() {
						select {
						case c.WindowCh <- struct{}{}:
						default:
						}
					}
				}
			}
		} else if c.DupAckCount > 3 && c.InRecovery && len(c.Unacked) > 0 {
			// RFC 5681 §3.2 step 5: inflate cwnd per additional dup ACK only
			// when in fast recovery (FastRecovery=true).  Timeout-based recovery
			// clears FastRecovery; those same-episode dup ACKs must not inflate.
			// After iter-79, RecoveryPoint is always updated to sendSeq when
			// entering a new episode, so seqAfter(sendSeq, RecoveryPoint) is
			// always false here — FastRecovery is the correct discriminator.
			if !c.FastRecovery {
				return
			}
			// Inflate window for each additional dup ACK (only in recovery)
			c.CongWin += MaxSegmentSize
			if c.CongWin > MaxCongWin {
				c.CongWin = MaxCongWin
			}
			// RFC 5681 §3.2 step 5: the inflation may open the window for the
			// sender. Signal WindowCh so a sendSegment blocked on a full cwnd
			// can wake up immediately rather than waiting for the probe timer
			// (ZeroWinProbeInitial = 500 ms).
			if c.WindowCh != nil && c.WindowAvailable() {
				select {
				case c.WindowCh <- struct{}{}:
				default:
				}
			}
		}
		return
	}

	// New ACK — advance.
	// Count only non-sacked, non-FIN bytes for AIMD (RFC 3465 §2: "newly
	// acknowledged bytes").  SACKed segments are already at the peer and
	// excluded from BytesInFlight(); counting them again here would inflate
	// AIMD growth by ~1 MSS per sacked entry covered by the cumulative ACK.
	// FIN entries use a 1-byte internal sentinel (isFIN=true, data=[]byte{0})
	// that is not user data; counting it causes the CA "< 1 → 1" minimum to
	// fire and grows CongWin by 1 spurious byte per connection close.
	bytesAcked := 0
	for _, e := range c.Unacked {
		if seqAfterOrEqual(ack, e.seq+uint32(len(e.data))) && !e.sacked && !e.isFIN {
			bytesAcked += len(e.data)
		}
	}
	c.LastAck = ack
	c.DupAckCount = 0
	c.LastRetxTime = time.Time{} // reset retransmit guard so ACK-driven recovery can proceed

	// Capture both flags before the recovery-exit check below may clear them.
	// wasInRecovery: needed by the deflation guard.
	// wasFastRecovery: needed so subsequent partial ACKs (with DupAckCount < 3
	// after the first partial ACK reset it to 0) still trigger RFC 6582 §3
	// step 6 retransmit + deflation unconditionally while in fast recovery.
	wasInRecovery := c.InRecovery
	wasFastRecovery := c.FastRecovery

	// Exit recovery when all loss-window data is acked.
	if c.InRecovery && seqAfterOrEqual(ack, c.RecoveryPoint) {
		c.InRecovery = false
		c.FastRecovery = false
	}

	// Remove acked entries and update RTT from the first once-sent segment.
	// RFC 6298 §2 requires at most one RTT sample per ACK event; taking a
	// sample per segment biases SRTT toward short-RTT late-in-batch entries
	// and inflates RTTVAR with within-batch variance that is not path-level.
	var remaining []*retxEntry
	rttUpdated := false
	var rttSample time.Duration
	for _, e := range c.Unacked {
		endSeq := e.seq + uint32(len(e.data))
		if seqAfterOrEqual(ack, endSeq) {
			// This segment is fully acked — update RTT from the first one only.
			// Karn's algorithm: skip retransmitted segments (attempts > 1).
			// SACK state is not excluded: a once-sent segment is a valid RTT
			// sample per RFC 6298 regardless of whether it was previously
			// reported via SACK (the cumulative ACK time is a conservative
			// upper bound that the EWMA smooths out).
			if e.attempts == 1 && !rttUpdated {
				// Use origSentAt (original send time, never overwritten by
				// RFC 6298 §5.3 timer restarts) so that the RTT sample
				// reflects actual path latency, not the inter-ACK interval.
				// Fall back to sentAt for test fixtures that pre-date this field.
				rttAnchor := e.origSentAt
				if rttAnchor.IsZero() {
					rttAnchor = e.sentAt
				}
				rtt := time.Since(rttAnchor)
				c.updateRTT(rtt)
				rttUpdated = true
				rttSample = rtt
			}
		} else {
			// Retain sacked state for remaining entries (RFC 2018 §5):
			// the peer has confirmed receiving SACKed segments and a
			// partial cumulative ACK above them does not invalidate that.
			remaining = append(remaining, e)
		}
	}
	c.Unacked = remaining

	// RFC 6298 §5.3: restart retransmit timer for ALL remaining outstanding
	// segments when SND.UNA advances.  RFC 6298 uses a single timer covering
	// all outstanding data; restarting it means no segment should time out
	// before now+RTO.  In the per-entry model, sentAt is each entry's timer
	// anchor; resetting it for every non-sacked remaining entry prevents
	// spurious retransmits when the path just proved active.
	ackNow := time.Now()
	for _, e := range c.Unacked {
		if !e.sacked {
			e.sentAt = ackNow
		}
		// New cumulative ACK = the peer is alive and progressing. Reset the
		// give-up counter so RST fires only after MaxRetxAttempts RTO
		// retransmissions with NO ACK progress at all (a genuinely dead
		// peer), not cumulatively across a long-but-moving recovery.
		e.rtoAttempts = 0
	}

	// HyStart++ (RFC 9406, simplified): while in slow start, watch for the
	// round-over-round min-RTT rise that signals the bottleneck queue is
	// starting to fill, and hand over to congestion avoidance at the
	// discovered window instead of doubling past capacity into mass loss.
	// Simplification vs the full RFC: no CSS (conservative slow start)
	// interlude — on trigger we exit directly (SSThresh = CongWin), which
	// is slightly conservative but avoids a second state machine.
	if c.CongWin < c.SSThresh && !c.InRecovery {
		if c.hsRoundEnd == 0 || seqAfterOrEqual(ack, c.hsRoundEnd) {
			c.hsLastMinRTT = c.hsCurrMinRTT
			c.hsCurrMinRTT = 0
			c.hsSamples = 0
			c.hsRoundEnd = sendSeq // current snd_nxt: acked ⇒ round over
		}
		if rttUpdated {
			c.hsSamples++
			if c.hsCurrMinRTT == 0 || rttSample < c.hsCurrMinRTT {
				c.hsCurrMinRTT = rttSample
			}
			if c.hsSamples >= hsMinSamples && c.hsLastMinRTT > 0 {
				eta := c.hsLastMinRTT / 8
				if eta < hsEtaMin {
					eta = hsEtaMin
				}
				if eta > hsEtaMax {
					eta = hsEtaMax
				}
				if c.hsCurrMinRTT >= c.hsLastMinRTT+eta {
					c.SSThresh = c.CongWin
				}
			}
		}
	}

	// Congestion-window deflation and fast-retransmit on ACKs in/after fast
	// recovery (RFC 6582 §3).
	//
	// Two guards combine:
	//  1. wasInRecovery: prevents deflation when recovery was never entered
	//     (no-op fastRetransmit case after iter-57/58).
	//  2. wasFastRecovery: ensures step 6 fires for EVERY partial ACK during
	//     fast recovery (not only the first one), while excluding timeout-based
	//     recovery where FastRecovery is never set.  After the first partial ACK
	//     resets DupAckCount=0, subsequent partial ACKs arrive when
	//     DupAckCount < 3; wasFastRecovery (captured before recovery-exit)
	//     ensures step 6 repeats per RFC 6582 §3 "As partial ACKs come in."
	//     oldDupAckCount >= 3 is intentionally NOT used here: leftover
	//     DupAckCount from a timeout-recovery episode (same-episode dup ACKs)
	//     must not trigger step-6 deflation — only explicitly fast-retransmit
	//     entered recovery (FastRecovery=true) should deflate cwnd.
	if wasFastRecovery && wasInRecovery {
		if !c.InRecovery {
			// Full ACK exit (RFC 6582 §3 case 2): ack covers RecoveryPoint —
			// deflate to ssthresh so we re-enter CA from a safe baseline.
			c.CongWin = c.SSThresh
		} else {
			// Partial ACK (RFC 6582 §3 step 6a+6b): ack below RecoveryPoint —
			// step 6b: partial-window deflation keeps the fast-recovery window
			// open. cwnd -= bytesAcked; add back SMSS when bytesAcked >= SMSS
			// so that a 1-SMSS partial ACK is neutral, and cwnd never falls
			// below ssthresh.
			c.CongWin -= bytesAcked
			if bytesAcked >= MaxSegmentSize {
				c.CongWin += MaxSegmentSize
			}
			if c.CongWin < c.SSThresh {
				c.CongWin = c.SSThresh
			}
			// step 6a: retransmit the first unacknowledged segment immediately.
			// Without this, the next lost segment is not retransmitted until
			// the 100ms RTO tick — up to one full RTO of unnecessary delay.
			// Extended beyond the single-segment step 6a: also resend further
			// un-SACKed segments below the SACK frontier (known-lost), up to
			// a cwnd of data, so a multi-segment loss heals in a few RTTs
			// instead of one segment per ACK (see retransmitLost).
			c.retransmitLost(recvAck, c.CongWin/MaxSegmentSize)
		}
	} else if wasInRecovery && c.InRecovery {
		// Partial ACK during TIMEOUT-based recovery (FastRecovery=false).
		// Historically nothing was retransmitted here: with the window
		// collapsed to 1 SMSS the sender cannot send new data to elicit dup
		// ACKs, so the only recovery driver left was the RTO timer at one
		// segment per (exponentially backed-off, up to 10 s) RTO — a
		// multi-segment loss drained at ~1 segment per several seconds.
		// Real TCP recovers from a timeout by retransmitting ACK-clocked out
		// of slow start (RFC 5681 §3.1); do the same: each partial ACK
		// proves the path is moving and pays for the next window of
		// retransmissions. AIMD growth for this ACK (below) is unaffected —
		// timeout-recovery partial ACKs grow cwnd via slow start, so the
		// retransmission budget doubles per RTT until the hole is filled.
		c.retransmitLost(recvAck, c.CongWin/MaxSegmentSize)
	}

	// Congestion window growth (Appropriate Byte Counting, RFC 3465).
	// Grow based on bytes ACKed, not number of ACKs — avoids delayed ACK penalty.
	// Skip entirely when bytesAcked==0 (all covered segments were already SACKed):
	// no new data was delivered, so no AIMD reward is due, and the CA "< 1 → 1"
	// minimum must not fire for a zero-delivery ACK.
	// Skip AIMD during fast-recovery partial ACKs (RFC 5681 §3.2 step 7): step 7
	// specifies only partial-window deflation; running AIMD on top double-counts the
	// ACK and inflates cwnd beyond the recovery window.  For full recovery exits
	// (wasFastRecovery && !c.InRecovery) AIMD is correct — the sender re-enters CA
	// from SSThresh.  Timeout-recovery partial ACKs (wasFastRecovery==false) are not
	// subject to step 7 deflation at all, so AIMD still applies for those.
	if bytesAcked > 0 && !(wasFastRecovery && wasInRecovery && c.InRecovery) {
		if c.CongWin < c.SSThresh {
			// Slow start: grow by acked bytes, capped at 2*SMSS per ACK
			// (RFC 3465 §2.1: ABC limit prevents over-reward from delayed ACKs
			// that cover 3+ segments — each ACK may add at most 2*SMSS).
			inc := bytesAcked
			if inc > 2*MaxSegmentSize {
				inc = 2 * MaxSegmentSize
			}
			c.CongWin += inc
		} else {
			// Congestion avoidance: grow by ~MSS per RTT (AIMD, RFC 3465 §2.2).
			// Cap the effective bytes at SMSS: when bytes_acked > SMSS (e.g. a
			// delayed ACK covering multiple segments), use SMSS*SMSS/cwnd, not
			// SMSS*bytes_acked/cwnd — the latter grows faster than one full
			// segment per RTT which is the RFC-defined CA rate.
			eff := bytesAcked
			if eff > MaxSegmentSize {
				eff = MaxSegmentSize
			}
			increment := MaxSegmentSize * eff / c.CongWin
			if increment < 1 {
				increment = 1
			}
			c.CongWin += increment
		}
		if c.CongWin > MaxCongWin {
			c.CongWin = MaxCongWin
		}
	}

	// Signal that window opened up
	if c.WindowCh != nil {
		select {
		case c.WindowCh <- struct{}{}:
		default:
		}
	}

	// Signal Nagle flush when no data is genuinely in flight.
	// Use BytesInFlight()==0 rather than len(c.Unacked)==0: after iter-49,
	// sacked entries remain in Unacked across partial ACKs, so len>0 even
	// when the peer already has every outstanding byte.
	if c.BytesInFlight() == 0 && c.NagleCh != nil {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
}

// fastRetransmit resends the first unacked-and-not-SACKed segment immediately.
// Must be called with RetxMu held. recvAck is captured by the caller BEFORE
// acquiring RetxMu, so we don't have to take Mu here (which would re-introduce
// the Mu↔RetxMu inversion that the rest of ProcessAck went out of its way
// to avoid).
// fastRetransmit returns true if a packet was sent, false if it was a no-op
// (empty/all-sacked Unacked, nil RetxSend, or MaxRetxAttempts guard).
// The caller gates all congestion-state adjustments on the return value so
// that a no-op does not produce phantom fast-recovery state.
func (c *Connection) fastRetransmit(recvAck uint32) bool {
	return c.retransmitLost(recvAck, 1) > 0
}

// maxRetxBurst caps how many segments one ACK event may retransmit via
// retransmitLost. The congestion window is the primary bound; this constant
// keeps a single partial ACK arriving with a large recovery window from
// dumping hundreds of retransmissions onto an already-lossy path in one
// burst.
const maxRetxBurst = 32

// retransmitLost retransmits up to maxSegs lost segments and returns how
// many were sent. The first un-SACKed segment is always eligible (it is the
// cumulative-ACK gap head — the dup ACKs or partial ACK that got us here
// prove it is missing). Beyond the head, only un-SACKed segments BELOW the
// highest SACKed sequence are retransmitted: the peer has explicitly
// acknowledged data after them, so they are lost with high confidence
// (RFC 6675 IsLost rationale). Segments above the SACK frontier may simply
// still be in flight and are left to the RTO timer.
//
// Mirrors retransmitUnacked's retry-budget guard for the head segment:
// when the head is out of attempts, nothing is sent (returns 0) and
// retransmitUnacked fires the RST on its next tick. Later entries at budget
// are skipped rather than aborting the whole pass.
//
// Must be called with RetxMu held.
func (c *Connection) retransmitLost(recvAck uint32, maxSegs int) int {
	if len(c.Unacked) == 0 || c.RetxSend == nil || maxSegs <= 0 {
		return 0
	}
	if maxSegs > maxRetxBurst {
		maxSegs = maxRetxBurst
	}

	// SACK frontier: end of the highest SACKed segment, if any.
	var frontier uint32
	haveFrontier := false
	for _, e := range c.Unacked {
		if e.sacked {
			end := e.seq + uint32(len(e.data))
			if !haveFrontier || seqAfter(end, frontier) {
				frontier = end
				haveFrontier = true
			}
		}
	}

	now := time.Now()
	sent := 0
	for _, e := range c.Unacked {
		if e.sacked {
			continue
		}
		if e.attempts >= MaxRetxAttempts {
			if sent == 0 {
				// Head segment out of retries: preserve the historical
				// fastRetransmit contract — no send, no recovery entry;
				// retransmitUnacked will RST on the next RTO tick.
				return 0
			}
			continue
		}
		// Beyond the head, only retransmit below the SACK frontier.
		if sent > 0 && (!haveFrontier || !seqAfter(frontier, e.seq)) {
			break
		}
		e.attempts++
		e.sentAt = now
		// FIN entries must be resent as FlagFIN with no payload; data entries
		// use FlagACK with their payload (mirrors retransmitUnacked's isFIN check).
		flags := protocol.FlagACK
		var payload []byte
		if e.isFIN {
			flags = protocol.FlagFIN
		} else {
			payload = e.data
		}
		pkt := &protocol.Packet{
			Version:  protocol.Version,
			Flags:    flags,
			Protocol: protocol.ProtoStream,
			Src:      c.LocalAddr,
			Dst:      c.RemoteAddr,
			SrcPort:  c.LocalPort,
			DstPort:  c.RemotePort,
			Seq:      e.seq,
			Ack:      recvAck,
			Window:   c.RecvWindow(),
			Payload:  payload,
		}
		c.RetxSend(pkt)
		sent++
		if sent >= maxSegs {
			break
		}
	}
	return sent
}

func (c *Connection) updateRTT(rtt time.Duration) {
	if c.SRTT == 0 {
		// First measurement (RFC 6298 Section 2.2)
		c.SRTT = rtt
		c.RTTVAR = rtt / 2
	} else {
		// Subsequent measurements (RFC 6298 Section 2.3)
		// RTTVAR = (1-β)·RTTVAR + β·|SRTT - R|  where β = 1/4
		diff := c.SRTT - rtt
		if diff < 0 {
			diff = -diff
		}
		c.RTTVAR = c.RTTVAR*3/4 + diff/4
		// SRTT = (1-α)·SRTT + α·R  where α = 1/8
		c.SRTT = c.SRTT*7/8 + rtt/8
	}
	// RTO = SRTT + max(G, K·RTTVAR) where K=4, G=clock granularity
	kvar := c.RTTVAR * 4
	if kvar < ClockGranularity {
		kvar = ClockGranularity
	}
	c.RTO = c.SRTT + kvar
	// Clamp RTO
	if c.RTO < RTOMin {
		c.RTO = RTOMin
	}
	if c.RTO > RTOMax {
		c.RTO = RTOMax
	}
}

// seqAfter returns true if a is after b in the circular uint32 sequence space.
// Uses RFC 1982 serial number arithmetic: a > b iff (a - b) interpreted as
// signed int32 is positive.
func seqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// seqAfterOrEqual returns true if a >= b in circular uint32 sequence space.
func seqAfterOrEqual(a, b uint32) bool {
	return a == b || int32(a-b) > 0
}

// DeliverInOrder handles an incoming data segment, buffering out-of-order
// segments and delivering in-order data to RecvBuf. Returns the cumulative
// ACK number (next expected seq).
//
// Three-phase design to avoid both deadlock and sequence leaks:
//
//	Phase 1: Collect segments to deliver under RecvMu (don't advance ExpectedSeq).
//	Phase 2: Deliver outside lock (prevents routeLoop deadlock, C1 fix).
//	Phase 3: Re-acquire lock, advance ExpectedSeq only for delivered segments,
//	         re-buffer undelivered OOO segments.
//
// Safe because routeLoop is single-goroutine — no concurrent DeliverInOrder
// calls for the same connection between Phase 2 and Phase 3.
func (c *Connection) DeliverInOrder(seq uint32, data []byte) uint32 {
	c.RecvMu.Lock()

	if c.RecvClosed {
		expectedSeq := c.ExpectedSeq
		c.RecvMu.Unlock()
		return expectedSeq
	}

	type pendingSeg struct {
		seq  uint32
		data []byte
		size uint32
	}
	var toDeliver []pendingSeg

	if seq == c.ExpectedSeq {
		// In order — collect for delivery (don't advance ExpectedSeq yet)
		toDeliver = append(toDeliver, pendingSeg{seq: seq, data: data, size: uint32(len(data))})
		nextSeq := seq + uint32(len(data))

		// Drain any buffered segments that would become contiguous
		for {
			found := false
			for i, seg := range c.OOOBuf {
				if seg.seq == nextSeq {
					toDeliver = append(toDeliver, pendingSeg{seq: seg.seq, data: seg.data, size: uint32(len(seg.data))})
					nextSeq = seg.seq + uint32(len(seg.data))
					c.OOOBuf = append(c.OOOBuf[:i], c.OOOBuf[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				break
			}
		}
	} else if seqAfter(seq, c.ExpectedSeq) {
		// Out of order — buffer it (avoid duplicates, enforce bound)
		if !c.hasOOOSeg(seq) && len(c.OOOBuf) < MaxOOOBuf {
			saved := make([]byte, len(data))
			copy(saved, data)
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seq, data: saved})
		}
	}
	// seq before ExpectedSeq means it's a duplicate — ignore

	// Hold a recvSenders slot for the entire Phase 2 so CloseRecvBuf has a
	// well-defined "no in-flight senders" point to wait on before close().
	// Take it under RecvMu so CloseRecvBuf's check-then-wait is atomic.
	c.recvSenders.Add(1)
	c.RecvMu.Unlock()

	// Phase 2: Deliver outside the lock to prevent deadlocking routeLoop
	// when RecvBuf is full (C1 fix). Stop at first failure — remaining
	// segments stay contiguous and will be re-buffered.
	delivered := 0
	for _, seg := range toDeliver {
		ok := func() bool {
			defer func() { recover() }() // handle closed RecvBuf
			// Use NewTimer + Stop so the timer goroutine is reclaimed
			// immediately when the channel send succeeds, instead of
			// lingering for the full 1s timeout (time.After leak).
			t := time.NewTimer(1 * time.Second)
			defer t.Stop()
			select {
			case c.RecvBuf <- seg.data:
				return true
			case <-t.C:
				return false
			}
		}()
		if !ok {
			break
		}
		delivered++
	}
	c.recvSenders.Done()

	// Phase 3: Commit — advance ExpectedSeq only for successfully delivered
	// segments. Re-buffer any OOO segments that couldn't be delivered.
	c.RecvMu.Lock()
	for i, seg := range toDeliver {
		if i < delivered {
			c.ExpectedSeq = seg.seq + seg.size
		} else if i > 0 {
			// Re-buffer OOO segments we removed in Phase 1.
			// Skip index 0 (the incoming segment) — sender retransmits
			// since we won't ACK it.
			c.OOOBuf = append(c.OOOBuf, &recvSegment{seq: seg.seq, data: seg.data})
		}
	}
	expectedSeq := c.ExpectedSeq
	c.RecvMu.Unlock()

	return expectedSeq
}

// CloseRecvBuf safely closes RecvBuf exactly once. Sets RecvClosed first so
// new Phase 2 senders bail in DeliverInOrder, then waits for in-flight
// senders to drain (recvSenders WG), then closes the channel. This ordering
// keeps `go test -race` clean — concurrent close-vs-send was previously
// flagged even though the runtime made it safe via defer recover().
func (c *Connection) CloseRecvBuf() {
	c.CloseOnce.Do(func() {
		c.RecvMu.Lock()
		c.RecvClosed = true
		c.RecvMu.Unlock()
		c.recvSenders.Wait()
		c.RecvMu.Lock()
		close(c.RecvBuf)
		c.RecvMu.Unlock()
	})
}

// RecvWindow returns the number of free segments in the receive buffer,
// used as the advertised receive window.
func (c *Connection) RecvWindow() uint16 {
	free := cap(c.RecvBuf) - len(c.RecvBuf)
	if free < 0 {
		free = 0
	}
	if free > 0xFFFF {
		free = 0xFFFF
	}
	return uint16(free)
}

func (c *Connection) hasOOOSeg(seq uint32) bool {
	for _, seg := range c.OOOBuf {
		if seg.seq == seq {
			return true
		}
	}
	return false
}

// SACKBlocks returns SACK blocks describing out-of-order received segments.
// Must be called with RecvMu held.
func (c *Connection) SACKBlocks() []SACKBlock {
	if len(c.OOOBuf) == 0 {
		return nil
	}

	// Sort OOO segments by seq
	sorted := make([]*recvSegment, len(c.OOOBuf))
	copy(sorted, c.OOOBuf)
	sort.Slice(sorted, func(i, j int) bool { return seqAfter(sorted[j].seq, sorted[i].seq) })

	// Merge into contiguous blocks
	var blocks []SACKBlock
	cur := SACKBlock{Left: sorted[0].seq, Right: sorted[0].seq + uint32(len(sorted[0].data))}

	for i := 1; i < len(sorted); i++ {
		seg := sorted[i]
		segEnd := seg.seq + uint32(len(seg.data))
		if seqAfterOrEqual(cur.Right, seg.seq) {
			// Contiguous or overlapping — extend
			if seqAfter(segEnd, cur.Right) {
				cur.Right = segEnd
			}
		} else {
			// Gap — emit current block, start new one
			blocks = append(blocks, cur)
			cur = SACKBlock{Left: seg.seq, Right: segEnd}
		}
	}
	blocks = append(blocks, cur)

	// Limit to 4 blocks, keeping the 4 highest-seq blocks (RFC 2018 §4 prefers
	// most-recently-received first; highest seq approximates most recently added
	// in a seq-sorted OOO buffer).  blocks[:4] would keep the lowest 4 and silently
	// drop the highest block, causing the sender to retransmit it every RTT.
	if len(blocks) > 4 {
		blocks = blocks[len(blocks)-4:]
	}
	return blocks
}

// ProcessSACK marks unacked segments that are covered by SACK blocks.
// This prevents unnecessary retransmission of segments the peer already has.
//
// Lock-order note: see ProcessAck. Stats writes are deferred out of the
// RetxMu hold to avoid an Mu↔RetxMu inversion.
func (c *Connection) ProcessSACK(blocks []SACKBlock) {
	sackRecv := uint64(len(blocks))
	defer func() {
		if sackRecv == 0 {
			return
		}
		c.Mu.Lock()
		c.Stats.SACKRecv += sackRecv
		c.Mu.Unlock()
	}()

	c.RetxMu.Lock()
	defer c.RetxMu.Unlock()

	for _, e := range c.Unacked {
		segEnd := e.seq + uint32(len(e.data))
		for _, b := range blocks {
			// RFC 2018 §3: a SACK block covers any segment that overlaps
			// it, not just segments fully contained within the block.
			if !seqAfterOrEqual(e.seq, b.Right) && !seqAfterOrEqual(b.Left, segEnd) {
				e.sacked = true
				break
			}
		}
	}

	// Excluding SACKed bytes from BytesInFlight may have opened the send window.
	// Signal WindowCh so a sender blocked in sendSegment wakes immediately.
	if c.WindowCh != nil && c.WindowAvailable() {
		select {
		case c.WindowCh <- struct{}{}:
		default:
		}
	}

	// When all outstanding bytes are now sacked, BytesInFlight()==0 means the
	// peer has received everything in flight.  Signal NagleCh so a nagleFlush
	// goroutine waiting for "all data ACKed" wakes immediately instead of
	// stalling for NagleTimeout (40 ms) until the cumulative ACK arrives.
	if c.NagleCh != nil && c.BytesInFlight() == 0 {
		select {
		case c.NagleCh <- struct{}{}:
		default:
		}
	}
}
