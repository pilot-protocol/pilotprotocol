// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/dataexchange"
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
	empty := filepath.Join(t.TempDir(), "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
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
		{name: "empty file", flags: map[string]string{"data-file": empty}, wantErr: "is empty"},
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

// One message is one data-exchange frame. A larger payload was sent anyway
// and dropped by the receiver at the frame header, which the sender only saw
// as a missing acknowledgement.
func TestMessagePayloadFrameLimit(t *testing.T) {
	// A small frame limit keeps the test cheap.
	defer func(old uint32) { dataexchange.MaxFrameSize = old }(dataexchange.MaxFrameSize)
	dataexchange.MaxFrameSize = 64 << 10

	limit := maxMessageBytes()
	if _, err := messagePayload(map[string]string{"data": "-"}, strings.NewReader(strings.Repeat("x", limit+1))); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("a payload one byte over the limit: err = %v, want a size error", err)
	}
	if got, err := messagePayload(map[string]string{"data": "-"}, strings.NewReader(strings.Repeat("x", limit))); err != nil || len(got) != limit {
		t.Errorf("a payload at the limit: %d bytes, err = %v", len(got), err)
	}
}

// A send of several messages reported "ok" even when some were never sent or
// never acknowledged, so a caller could not tell that messages were lost.
func TestUndeliveredMessages(t *testing.T) {
	results := []map[string]interface{}{
		{"seq": 0, "ack": "ACK TEXT 5 bytes"},
		{"seq": 1, "error": "write: connection closed"},
		{"seq": 2, "ack_error": "EOF"},
		{"seq": 3, "ack": "ERR inbox not writable"},
		{"seq": 4, "ack": "ACK TEXT 5 bytes"},
	}
	failed, first := undelivered(results)
	if failed != 3 {
		t.Errorf("failed = %d, want 3", failed)
	}
	if first != "message 1: write: connection closed" {
		t.Errorf("first = %q", first)
	}
	if failed, _ := undelivered(results[4:]); failed != 0 {
		t.Errorf("an acknowledged message counted as undelivered")
	}
	if _, first := undelivered(results[2:3]); !strings.Contains(first, "not acknowledged (EOF)") {
		t.Errorf("first = %q, want the ACK read error", first)
	}
	if _, first := undelivered(results[3:4]); !strings.Contains(first, "ERR inbox not writable") {
		t.Errorf("first = %q, want the receiver's refusal", first)
	}
}
