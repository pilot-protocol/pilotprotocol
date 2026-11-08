// SPDX-License-Identifier: AGPL-3.0-or-later

package keyexchange

import "errors"

// errNoVerify mirrors the pre-extraction string ("no verify function")
// from tunnel.go's getPeerPubKey. Tests assert on this exact wording.
var errNoVerify = errors.New("no verify function")

var errPubKeyUnresolved = errors.New("peer pubkey unresolved (negatively cached)")

// ErrPeerHasNoKey is the authoritative answer that a node is registered
// without an Ed25519 key. A VerifyFunc returns an error wrapping it (or
// nil, nil) only when the registry said so; a failed or inconclusive
// lookup must return some other error. It is the one answer that lets an
// unauthenticated key exchange (PILK) open a session: see
// HandleUnauthFrame.
var ErrPeerHasNoKey = errors.New("peer is registered without a public key")
