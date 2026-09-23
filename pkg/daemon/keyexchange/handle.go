// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import (
	"crypto/ed25519"
	"encoding/binary"
	"log/slog"
	"net"
	"time"

	"github.com/pilot-protocol/common/crypto"
)

// HandleAuthFrame processes an authenticated key exchange packet (PILA).
//
// Frame layout (after 4-byte magic stripped by caller):
//
//	[4 nodeID][32 X25519 pubkey][32 Ed25519 pubkey][64 Ed25519 signature]
//
// The signature is over: "auth"(4) || nodeID(4 BE) || X25519-pubkey(32).
// fromRelay indicates this was received via beacon relay — the
// PostInstallHook decides what to do with the peer-endpoint update.
//
// Returns true if a Crypto was installed (or already-present-and-fresh
// crypto was kept), false on any reject path (signature mismatch,
// missing identity, encryption disabled, malformed input).
func (m *Manager) HandleAuthFrame(data []byte, from *net.UDPAddr, fromRelay bool) bool {
	if len(data) < 4+32+32+64 {
		return false
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerX25519PubKey := data[4:36]
	peerEd25519PubKey := ed25519.PublicKey(data[36:68])
	signature := data[68:132]

	// Encryption (X25519 priv) must be enabled.
	if m.PrivKey() == nil {
		return false
	}

	// Verify the Ed25519 signature.
	challenge := authChallenge(peerNodeID, peerX25519PubKey)

	// Fetch expected pubkey from registry FIRST — reject if unavailable.
	expectedPubKey, err := m.GetPeerPubKey(peerNodeID)
	if err != nil || expectedPubKey == nil {
		slog.Warn("auth key exchange rejected: cannot verify peer identity from registry",
			"peer_node_id", peerNodeID, "error", err)
		return false
	}

	// Verify the packet-provided Ed25519 pubkey matches the registry.
	// On mismatch, invalidate cache and re-fetch — peer may have restarted
	// with a new identity since we last cached their key.
	if !peerEd25519PubKey.Equal(expectedPubKey) {
		m.InvalidatePeerPubKey(peerNodeID)
		expectedPubKey, err = m.GetPeerPubKey(peerNodeID)
		if err != nil || expectedPubKey == nil {
			slog.Warn("auth key exchange rejected: cannot re-verify peer identity",
				"peer_node_id", peerNodeID, "error", err)
			return false
		}
		if !peerEd25519PubKey.Equal(expectedPubKey) {
			slog.Error("auth key exchange: Ed25519 pubkey mismatch with registry",
				"peer_node_id", peerNodeID)
			return false
		}
		slog.Info("auth key exchange: peer pubkey updated from registry",
			"peer_node_id", peerNodeID)
	}

	// Verify signature against the registry-verified key.
	if !crypto.Verify(expectedPubKey, challenge, signature) {
		slog.Error("auth key exchange signature verification failed",
			"peer_node_id", peerNodeID)
		return false
	}

	// Derive shared secret from X25519.
	pc, err := m.DeriveSecret(peerX25519PubKey)
	if err != nil {
		slog.Error("auth key exchange failed",
			"peer_node_id", peerNodeID, "error", err)
		return false
	}
	pc.Authenticated = true

	oldPC := m.env.Get(peerNodeID)
	hadCrypto := oldPC != nil
	keyChanged := hadCrypto && oldPC.PeerX25519Key != pc.PeerX25519Key
	// duplicate := same-pubkey frame arriving inside the debounce
	// window of a freshly-installed Crypto. See
	// DuplicateHandshakeDebounce — the goal is to coalesce the direct+
	// relay arrival pair and peer-side retransmits without dropping
	// real recovery work.
	duplicate := hadCrypto && !keyChanged && time.Since(oldPC.CreatedAt) < DuplicateHandshakeDebounce
	// Only replace the installed envelope.Crypto when there is no
	// existing entry OR the peer's X25519 ephemeral key actually changed.
	// Replacing on a duplicate key_exchange (same pubkey — common under
	// our retransmit loop or a peer's reply crossing on the wire) would
	// reset the nonce counter and replay-window bitmap, causing our
	// subsequent encrypted sends and any in-flight peer packets to look
	// wrong on the wire.
	// Pinned by TestHandleKeyExchangeDuplicatePreservesCryptoState.
	if !hadCrypto || keyChanged {
		m.env.Install(peerNodeID, pc)
	}
	// Cache the verified peer pubkey.
	m.SetPeerPubKey(peerNodeID, peerEd25519PubKey)

	// Side-effect routing:
	//
	//  - duplicate (same X25519 ephemeral within DuplicateHandshakeDebounce)
	//    is a tight direct+relay arrival pair or peer-side retransmit
	//    burst. All side effects suppressed.
	//
	//  - sameSession (hadCrypto && !keyChanged, past the debounce window)
	//    is the peer's slow keepalive retransmit. The session was
	//    established by the earlier PILA; nothing was installed by
	//    this one. The bus event and PostInstallHook STILL fire so
	//    downstream observers can refresh endpoint observation /
	//    keep-alive bookkeeping (pinned by
	//    TestDuplicatePILAOutsideDebounceFiresHookAgain), but the
	//    Info-level "encrypted tunnel established" log is demoted to
	//    Debug: observed against list-agents on 2026-05-29, a peer
	//    sending a PILA every ~8 s while relayed data is being dropped
	//    floods the operator log with 35 false "established" lines per
	//    peer per 5 minutes. Pinned by
	//    TestSameSessionPILALogsAtDebugButFiresHook.
	//
	//  - default (first install or real rekey): everything fires at
	//    Info level.
	//
	// The recovery-reply path below (SendKeyExchangeToNode) is gated
	// independently — see TestAsymmetricRecoveryRepliesOnDuplicatePILAWhenStale.
	sameSession := hadCrypto && !keyChanged
	if duplicate {
		slog.Debug("auth key exchange: duplicate frame coalesced",
			"peer_node_id", peerNodeID, "age", time.Since(oldPC.CreatedAt), "relay", fromRelay)
	} else {
		if keyChanged {
			slog.Info("peer rekeyed (auth), re-establishing tunnel", "peer_node_id", peerNodeID)
		} else if sameSession {
			slog.Debug("auth key exchange: same-session keepalive",
				"peer_node_id", peerNodeID, "age", time.Since(oldPC.CreatedAt),
				"endpoint", from, "relay", fromRelay)
		} else {
			slog.Info("encrypted tunnel established", "auth", true,
				"peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
		}
		authEstablishedEvent := map[string]any{
			"authenticated": true,
			"relay":         fromRelay,
			"rekeyed":       keyChanged,
		}
		if m.trustFn == nil || m.trustFn(peerNodeID) {
			authEstablishedEvent["peer_node_id"] = peerNodeID
		}
		m.publish("tunnel.established", authEstablishedEvent)

		if m.postInstall != nil {
			m.postInstall(PostInstallEvent{
				PeerNodeID:    peerNodeID,
				From:          from,
				FromRelay:     fromRelay,
				Authenticated: true,
				HadCrypto:     hadCrypto,
				KeyChanged:    keyChanged,
				OldCrypto:     oldPC,
				NewCrypto:     pc,
				PeerEd25519:   peerEd25519PubKey,
			})
		}
	}

	if !hadCrypto || keyChanged {
		// Respond with our key_exchange so the peer also has our session
		// state. SendKeyExchangeToNode marks pending, but since the peer
		// just proved they have our key (by sending us a valid
		// auth_key_exchange), we don't need retransmit safety on this
		// response. Clear pendingRekey AFTER the send so the
		// retransmit loop doesn't hammer the peer for 24 s with
		// redundant frames.
		m.SendKeyExchangeToNode(peerNodeID)
		m.ClearPendingRekey(peerNodeID)
	} else {
		// Already had a session and peer didn't rotate. If we have NO
		// recent successful decrypt from this peer, our previous reply
		// PILA may have been lost OR the peer dropped its crypto for us
		// (e.g. via the DecryptFailDropGrace path after a relay-buffered
		// stale-frame burst). In either case the peer needs our PILA to
		// re-derive the shared secret — silence here is the asymmetric-
		// crypto deadlock observed against list-agents on 2026-05-11.
		// KeyExchangeReplyStaleThreshold (6 s) gates this so an active
		// session with regular inbound traffic cannot trigger a reply
		// loop. Don't reinstall locally — preserves our nonce counter
		// and replay window for in-flight encrypted traffic.
		//
		// MarkReplyKeyExchangeSent additionally rate-limits this reply
		// at KeyExchangeReplyMinInterval (1 s). Without this gate, two
		// peers can both observe InboundDecryptStale on every incoming
		// PILA and ping-pong replies at the relay's send cadence — the
		// 466-establish-events storm against nasa-apod on 2026-05-26.
		//
		// The postInstall hook above has already run for this frame, so
		// it must not record inbound liveness for a same-session PILA:
		// doing so closed this gate on exactly the PILAs it exists for
		// (2026-09-23 desync loop). tunnel.onKeyInstalled only records it
		// for a real install.
		if m.InboundDecryptStale(peerNodeID) && m.MarkReplyKeyExchangeSent(peerNodeID) {
			m.SendKeyExchangeToNode(peerNodeID)
		}
		m.ClearPendingRekey(peerNodeID)
	}
	return true
}

// HandleUnauthFrame processes an unauthenticated key exchange packet (PILK).
//
// Frame layout (after 4-byte magic stripped by caller):
//
//	[4 nodeID][32 X25519 pubkey]
//
// If we have an identity AND the peer has a registered pubkey, reject
// the unauthenticated exchange and reply with our authenticated frame
// instead.
func (m *Manager) HandleUnauthFrame(data []byte, from *net.UDPAddr, fromRelay bool) bool {
	if len(data) < 36 {
		return false
	}

	peerNodeID := binary.BigEndian.Uint32(data[0:4])
	peerPubKey := data[4:36]

	// Encryption disabled → ignore silently.
	if m.PrivKey() == nil {
		return false
	}

	// If we have identity, check if peer has a registered pubkey — if so,
	// reject unauthenticated exchange and respond with authenticated.
	hasIdentity := m.HasIdentity()
	hadCryptoPre := m.env.Has(peerNodeID)
	cryptoSize := m.env.Len()
	if hasIdentity {
		expectedPubKey, err := m.GetPeerPubKey(peerNodeID)
		if err == nil && expectedPubKey != nil {
			slog.Warn("rejecting unauthenticated key exchange from peer with known identity",
				"peer_node_id", peerNodeID)
			m.SendKeyExchangeToNode(peerNodeID)
			return false
		}
	}

	// Budget check BEFORE the expensive scalar multiplication. Without this,
	// an attacker spraying unauth key-exchange frames at us can force CPU
	// burn even if the map-insert is later rejected. The TOCTOU here is
	// benign: concurrent bursts may overshoot by a handful of entries, but
	// the next call will see the raised count and reject.
	if !hadCryptoPre && cryptoSize >= MaxCryptoPeers {
		slog.Warn("crypto peers cap reached, dropping unauth key exchange",
			"peer_node_id", peerNodeID, "from", from)
		return false
	}

	// Derive shared secret.
	pc, err := m.DeriveSecret(peerPubKey)
	if err != nil {
		slog.Error("key exchange failed", "peer_node_id", peerNodeID, "error", err)
		return false
	}

	oldPC := m.env.Get(peerNodeID)
	hadCrypto := oldPC != nil
	keyChanged := hadCrypto && oldPC.PeerX25519Key != pc.PeerX25519Key
	// duplicate := same-pubkey frame arriving inside DuplicateHandshakeDebounce
	// of a freshly-installed Crypto. See HandleAuthFrame for the
	// rationale; same coalescing window applies to PILK as well.
	duplicate := hadCrypto && !keyChanged && time.Since(oldPC.CreatedAt) < DuplicateHandshakeDebounce
	// Same rationale as HandleAuthFrame: don't replace on a duplicate
	// key_exchange (same pubkey).
	if !hadCrypto || keyChanged {
		m.env.Install(peerNodeID, pc)
	}

	// Same routing as HandleAuthFrame: duplicate suppresses everything;
	// sameSession (past-debounce same-key keepalive) keeps the bus event
	// + postInstall hook firing for endpoint refresh but demotes the
	// Info log to Debug.
	sameSession := hadCrypto && !keyChanged
	if duplicate {
		slog.Debug("unauth key exchange: duplicate frame coalesced",
			"peer_node_id", peerNodeID, "age", time.Since(oldPC.CreatedAt), "relay", fromRelay)
	} else {
		if keyChanged {
			slog.Info("peer rekeyed, re-establishing tunnel", "peer_node_id", peerNodeID)
		} else if sameSession {
			slog.Debug("unauth key exchange: same-session keepalive",
				"peer_node_id", peerNodeID, "age", time.Since(oldPC.CreatedAt),
				"endpoint", from, "relay", fromRelay)
		} else {
			slog.Info("encrypted tunnel established",
				"peer_node_id", peerNodeID, "endpoint", from, "relay", fromRelay)
		}
		unauthEstablishedEvent := map[string]any{
			"authenticated": false,
			"relay":         fromRelay,
			"rekeyed":       keyChanged,
		}
		if m.trustFn == nil || m.trustFn(peerNodeID) {
			unauthEstablishedEvent["peer_node_id"] = peerNodeID
		}
		m.publish("tunnel.established", unauthEstablishedEvent)

		if m.postInstall != nil {
			m.postInstall(PostInstallEvent{
				PeerNodeID:    peerNodeID,
				From:          from,
				FromRelay:     fromRelay,
				Authenticated: false,
				HadCrypto:     hadCrypto,
				KeyChanged:    keyChanged,
				OldCrypto:     oldPC,
				NewCrypto:     pc,
			})
		}
	}

	// Respond with our key if this is a new peer or the peer rekeyed.
	// Then clear pendingRekey: peer just proved they have crypto (sent
	// us their key_exchange), so we don't need to retransmit ours.
	if !hadCrypto || keyChanged {
		m.SendKeyExchangeToNode(peerNodeID)
	}
	m.ClearPendingRekey(peerNodeID)
	return true
}
