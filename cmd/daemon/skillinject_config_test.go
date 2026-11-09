// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSkillinjectConfigFromEnv(t *testing.T) {
	t.Parallel()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == envSkillinjectPubkey {
				return v
			}
			return ""
		}
	}

	// Unset: skillinject's built-in key.
	cfg, err := skillinjectConfigFromEnv(env(""))
	if err != nil || cfg.ManifestPublicKey != nil {
		t.Fatalf("unset = %v, %v; want no override", cfg.ManifestPublicKey, err)
	}

	for name, v := range map[string]string{
		"hex":        hex.EncodeToString(pub),
		"base64":     base64.StdEncoding.EncodeToString(pub),
		"raw base64": base64.RawStdEncoding.EncodeToString(pub),
		"spaces":     " " + hex.EncodeToString(pub) + "\n",
	} {
		cfg, err := skillinjectConfigFromEnv(env(v))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if !cfg.ManifestPublicKey.Equal(pub) {
			t.Errorf("%s: key not used", name)
		}
	}

	for _, bad := range []string{"not-a-key", hex.EncodeToString(pub[:16]), base64.StdEncoding.EncodeToString(append(pub, 0))} {
		if _, err := skillinjectConfigFromEnv(env(bad)); err == nil || !strings.Contains(err.Error(), envSkillinjectPubkey) {
			t.Errorf("%q: err = %v, want an error naming %s", bad, err, envSkillinjectPubkey)
		}
	}
}
