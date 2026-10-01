// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"sync"
	"time"

	"github.com/pilot-protocol/common/protocol"
)

// Reply window: the private-node SYN trust gate admits a service's reply.
//
// A request/reply service answers on a NEW connection it dials back to
// the requester: data exchange replies arrive as a SYN to our port 1001,
// and a trust-handshake accept as a SYN to our port 444. A private node
// (the default) drops a SYN from any peer it does not trust yet, and
// with no RST, so on first contact the reply to our own request was
// dropped until the trust handshake with that peer happened to finish.
// Measured on clean GitHub runners: about 50 "SYN rejected: untrusted
// source" per failed first query to list-agents, and the reply was
// lost for good because the service does not retry for long.
//
// The gate now behaves like a stateful firewall: for replyWindow after
// this node dials a peer (or sends it a trust handshake), a SYN from that
// peer to one of the reply ports is admitted. Only the peer we contacted,
// only those two ports, and only for a bounded time; everything else
// still needs trust. The admitted connection is an ordinary inbound
// connection to a service that is already listening, so it reaches
// nothing a trusted peer could not.

// replyWindow is how long after we contact a peer its SYNs to the reply
// ports pass the private-node trust gate.
const replyWindow = 5 * time.Minute

// maxReplyWindowPeers bounds the reply-window table. It is filled only
// by our own outbound dials, never by inbound traffic, so the bound is a
// backstop: once full (after pruning expired entries) new peers simply
// fall back to the regular trust check.
const maxReplyWindowPeers = 4096

// replyWindowPort reports whether an inbound SYN to port is a reply a
// service may send back on a new connection.
func replyWindowPort(port uint16) bool {
	return port == protocol.PortDataExchange || port == protocol.PortHandshake
}

// outboundContacts records when this node last initiated contact with
// each peer (nodeID -> time of the last outbound dial or handshake).
type outboundContacts struct {
	mu sync.Mutex
	at map[uint32]time.Time
}

func (o *outboundContacts) note(peer uint32, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.at == nil {
		o.at = make(map[uint32]time.Time)
	}
	if _, ok := o.at[peer]; !ok && len(o.at) >= maxReplyWindowPeers {
		o.pruneLocked(now)
		if len(o.at) >= maxReplyWindowPeers {
			return
		}
	}
	o.at[peer] = now
}

func (o *outboundContacts) recent(peer uint32, now time.Time) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	t, ok := o.at[peer]
	return ok && now.Sub(t) < replyWindow
}

func (o *outboundContacts) prune(now time.Time) {
	o.mu.Lock()
	o.pruneLocked(now)
	o.mu.Unlock()
}

func (o *outboundContacts) pruneLocked(now time.Time) {
	for peer, t := range o.at {
		if now.Sub(t) >= replyWindow {
			delete(o.at, peer)
		}
	}
}

func (o *outboundContacts) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.at)
}

// noteOutboundContact records that we just initiated contact with peer
// (a dial, or a trust handshake), opening its reply window.
func (d *Daemon) noteOutboundContact(peer uint32) {
	d.outbound.note(peer, time.Now())
}

// replyWindowAdmits reports whether a SYN from srcNode to dstPort is a
// reply to contact we initiated within replyWindow.
func (d *Daemon) replyWindowAdmits(srcNode uint32, dstPort uint16) bool {
	return replyWindowPort(dstPort) && d.outbound.recent(srcNode, time.Now())
}
