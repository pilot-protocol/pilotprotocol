// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// send-message took its body only as a command-line argument, which the OS
// caps (a 1 MB --data fails with "Argument list too long"). It can now come
// from stdin or a file.
func TestMessagePayload(t *testing.T) {
	big := strings.Repeat("x", 2<<20)
	file := filepath.Join(t.TempDir(), "body")
	if err := os.WriteFile(file, []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name    string
		flags   map[string]string
		stdin   string
		want    string
		wantErr string
	}{
		{name: "argument", flags: map[string]string{"data": "hello"}, want: "hello"},
		{name: "stdin", flags: map[string]string{"data": "-"}, stdin: big, want: big},
		{name: "file", flags: map[string]string{"data-file": file}, want: big},
		{name: "neither", flags: map[string]string{}, wantErr: "--data is required"},
		{name: "empty stdin", flags: map[string]string{"data": "-"}, wantErr: "--data is required"},
		{name: "both", flags: map[string]string{"data": "a", "data-file": file}, wantErr: "not both"},
		{name: "file flag without a path", flags: map[string]string{"data-file": "true"}, wantErr: "needs a path"},
		{name: "missing file", flags: map[string]string{"data-file": filepath.Join(t.TempDir(), "nope")}, wantErr: "read --data-file"},
	} {
		got, err := messagePayload(tc.flags, strings.NewReader(tc.stdin))
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: err = %v, want one containing %q", tc.name, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %d bytes, want %d", tc.name, len(got), len(tc.want))
		}
	}
}
