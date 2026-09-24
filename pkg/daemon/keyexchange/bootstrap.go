// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"log/slog"
	"net"
)

// SendKeyExchangeToNode sends an authenticated key exchange if identity
// is available, otherwise falls back to unauthenticated.
//
// When we hold no session key for the peer and either an earlier send is
// still unanswered (KeyRequestAfterSends) or MarkKeyRequestDue flagged
// the peer, the authenticated frame is followed by an unauthenticated
// one (PILK) acting as a key request: a peer that already knows our
// identity rejects it and answers with its own PILA, retransmitted until
// ours arrives. This breaks the first-contact deadlock where the peer's
// single reply was lost and it treats our same-key retransmits as
// keepalives. keyRequest reports whether that PILK was sent, so the
// tunnel can give it the same relay copy as the PILA.
//
// This function carries the single annotated bootstrap-exception site
// (see the marker comment inside the body). After Stage 2 sub-pass 2,
// the canonical home for the marker is here in keyexchange/bootstrap.go;
// layers.yaml's bootstrap_exception.allowed_call_sites tracks this path.
func (m *Manager) SendKeyExchangeToNode(peerNodeID uint32) (keyRequest bool) {
	// BOOTSTRAP-EXCEPTION: bypasses L6 envelope
	// The peer key is not yet established, so the L6 AEAD wrap is
	// impossible here. This is the single annotated bootstrap site
	// whitelisted by layers.yaml's bootstrap_exception block and
	// enforced by tools/check-bootstrap (P8). Do not duplicate this
	// marker elsewhere — the checker fails if more than one site
	// carries it. See docs/architecture/05-VERIFICATION.md §3 P8.
	if m.sender == nil {
		return false
	}

	var addr *net.UDPAddr
	if m.addrLookup != nil {
		addr = m.addrLookup(peerNodeID)
	}

	hasIdentity := m.HasIdentity()
	unauthFrame := m.BuildUnauthFrame()
	if unauthFrame == nil {
		return false
	}
	frame := unauthFrame
	authed := false
	if hasIdentity {
		if authFrame := m.BuildAuthFrame(); authFrame != nil {
			frame = authFrame
			authed = true
		}
	}
	// Decide before MarkPendingRekey bumps the attempt count: the key
	// request rides on retransmits, never on the first send.
	keyRequest = authed && !m.env.Has(peerNodeID) && m.takeKeyRequest(peerNodeID)

	if err := m.sender(peerNodeID, addr, frame); err != nil {
		slog.Error("send key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return false
	}
	if keyRequest {
		if err := m.sender(peerNodeID, addr, unauthFrame); err != nil {
			slog.Debug("key request send failed", "peer_node_id", peerNodeID, "error", err)
			keyRequest = false
		} else {
			m.keyRequestsSent.Add(1)
			slog.Debug("key request sent (no session key, key exchange unanswered)",
				"peer_node_id", peerNodeID)
		}
	}

	// P1-010 tunnel-state half: register that we're waiting on a reply,
	// so rekeyRetransmitLoop can retransmit if the peer's response (or
	// our request) was dropped under loss.
	m.MarkPendingRekey(peerNodeID)
	return keyRequest
}
