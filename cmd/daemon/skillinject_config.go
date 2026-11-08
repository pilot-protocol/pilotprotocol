// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/pilot-protocol/skillinject"
)

// envSkillinjectPubkey replaces the key skillinject verifies fetched skill
// content with, for a host that follows a fork of pilot-skills signed with
// its own key. Unset, skillinject uses the key it has built in.
const envSkillinjectPubkey = "PILOT_SKILLINJECT_MANIFEST_PUBKEY"

// skillinjectConfigFromEnv builds the skill injector's config. The key in
// envSkillinjectPubkey may be hex or base64 (standard or unpadded), the
// forms skillinject itself accepts. A value that does not decode is an
// error, so the daemon stops at startup instead of refusing every tick.
func skillinjectConfigFromEnv(getenv func(string) string) (skillinject.Config, error) {
	cfg := skillinject.Config{}
	v := strings.TrimSpace(getenv(envSkillinjectPubkey))
	if v == "" {
		return cfg, nil
	}
	key, err := decodeSkillinjectKey(v)
	if err != nil {
		return cfg, fmt.Errorf("%s: %w", envSkillinjectPubkey, err)
	}
	cfg.ManifestPublicKey = key
	return cfg, nil
}

func decodeSkillinjectKey(s string) (ed25519.PublicKey, error) {
	for _, dec := range []func(string) ([]byte, error){
		hex.DecodeString,
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("must be a %d-byte ed25519 key in hex or base64", ed25519.PublicKeySize)
}
