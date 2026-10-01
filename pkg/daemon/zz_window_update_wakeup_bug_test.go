// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"testing"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// TestWindowUpdateDoesNotWakeSender verifies that when the peer transitions
// from a zero receive window to a non-zero receive window via a "pure window
// update" ACK (same cumulative ACK number, larger Window field), the sender
// blocked in sendSegment wakes up promptly instead of waiting for the next
// zero-window probe timer to fire.
//
// Bug (pre-v1.9.1): handleStreamPacket updates conn.PeerRecvWin from the
// incoming pkt.Window on every data/ACK segment, but never signals WindowCh.
// WindowCh is only signaled inside ProcessAck, and only on the new-ACK path
// (ack > LastAck).  A "pure window update" has the same cumulative ACK as
// before (pkt.Ack == conn.LastAck), so ProcessAck takes the dup-ACK branch
// and returns at line:
//
//	if ack == c.LastAck {
//	    ...
//	    return   // ← no WindowCh signal here
//	}
//
// The sender in sendSegment is blocked in:
//
//	select {
//	case <-conn.WindowCh:  // never fires for window-update ACKs
//	case <-probeTimer.C:   // fires only after probe backoff (0.5s → 1s → 2s …)
//	}
//
// Consequence: after the peer explicitly opens its receive window (the normal
// recovery after flow control), the sender does not unblock immediately.
// It must wait for the next zero-window probe timer to fire — up to 30 s with
// exponential backoff — even though the window is already open.  Under
// sustained high traffic with bursty receivers this causes throughput to
// collapse while the window sits open but unnoticed.
//
// Fix (v1.9.1): in handleStreamPacket, after updating PeerRecvWin, signal
// WindowCh when the window transitions from 0 (closed) to > 0 (opened):
//
//	prevWin := conn.PeerRecvWin
//	conn.PeerRecvWin = int(pkt.Window) * MaxSegmentSize
//	if prevWin == 0 && conn.PeerRecvWin > 0 && conn.WindowCh != nil {
//	    select {
//	    case conn.WindowCh <- struct{}{}:
//	    default:
//	    }
//	}
//
// GREEN assertion: after processing a window-update ACK (Ack=LastAck,
// Window=1) when PeerRecvWin was 0, conn.WindowCh receives a value within
// 100 ms.  Against unpatched code the channel stays empty.
func TestWindowUpdateDoesNotWakeSender(t *testing.T) {
	t.Parallel()
	d := New(Config{})
	peerConn := addPeerOnDaemon(t, d, 0xCC550001)
	t.Cleanup(func() { peerConn.Close() })
	d.setNodeID_testhelper(0xDD660000)

	const (
		localPort  = uint16(8450)
		remotePort = uint16(9090)
		remoteNode = uint32(0xCC550001)
	)

	conn := d.ports.NewConnection(localPort,
		protocol.Addr{Network: 0, Node: remoteNode}, remotePort)
	conn.Mu.Lock()
	conn.LocalAddr = protocol.Addr{Network: 0, Node: 0xDD660000}
	conn.RemoteAddr = protocol.Addr{Network: 0, Node: remoteNode}
	conn.State = StateEstablished
	conn.SendSeq = 1000
	conn.Mu.Unlock()
	conn.RetxStop = make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-conn.RetxStop:
		default:
			close(conn.RetxStop)
		}
		d.ports.RemoveConnection(conn.ID)
	})

	// Place a sent-but-unacked segment (required so ProcessAck doesn't
	// skip dup-ACK detection when ack == LastAck).
	conn.RetxMu.Lock()
	conn.LastAck = 1000
	conn.PeerRecvWin = 0 // peer's window was (or is now) zero
	conn.Unacked = []*retxEntry{
		{seq: 1000, data: make([]byte, 100), attempts: 1},
	}
	conn.RetxMu.Unlock()

	// Drain any stale signal from WindowCh so the check is clean.
	select {
	case <-conn.WindowCh:
	default:
	}

	// Peer sends a window-update ACK: same cumulative ACK (1000 == LastAck),
	// but Window=2 (receiver window now open). The window is a count of free
	// receive slots and the unacked segment above will take one of them, so
	// two is the smallest update that leaves room for a new segment.
	// This is a dup-ACK from ProcessAck's point of view; ProcessAck will NOT
	// signal WindowCh on the dup-ACK path.
	windowUpdatePkt := &protocol.Packet{
		Version:  protocol.Version,
		Flags:    protocol.FlagACK,
		Protocol: protocol.ProtoStream,
		Src:      protocol.Addr{Network: 0, Node: remoteNode},
		Dst:      protocol.Addr{Network: 0, Node: 0xDD660000},
		SrcPort:  remotePort,
		DstPort:  localPort,
		Seq:      500,
		Ack:      1000, // == LastAck — dup-ACK path in ProcessAck
		Window:   2,    // room for the segment in flight plus one more
	}
	d.handleStreamPacket(windowUpdatePkt)

	// FIXED: handleStreamPacket must signal WindowCh when PeerRecvWin
	// transitions from 0 to > 0, even when ProcessAck doesn't (dup-ACK path).
	select {
	case <-conn.WindowCh:
		// good — sender wakes up promptly
	case <-time.After(100 * time.Millisecond):
		t.Errorf("window-update ACK (Ack=LastAck, Window=2 with PeerRecvWin=0) did not " +
			"signal conn.WindowCh within 100ms; " +
			"handleStreamPacket updates PeerRecvWin but never signals WindowCh; " +
			"ProcessAck is called with ack=LastAck (dup-ACK path) which returns " +
			"before the WindowCh signal at the bottom of the new-ACK path; " +
			"sendSegment blocked on WindowCh will not wake until the next " +
			"zero-window probe timer fires (up to 30s with exponential backoff); " +
			"fix: in handleStreamPacket, signal conn.WindowCh after setting " +
			"PeerRecvWin when transitioning from 0 to > 0")
	}
}
