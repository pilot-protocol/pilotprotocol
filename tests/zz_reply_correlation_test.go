// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build nightly

package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pilot-protocol/dataexchange"
)

// inboxRecordWith returns the inbox record whose key has the given value,
// waiting for the daemon to write it.
func inboxRecordWith(t *testing.T, dir, key, value string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var rec map[string]any
			if json.Unmarshal(raw, &rec) == nil && rec[key] == value {
				return rec
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no inbox record with %s=%q in %s (%d files)", key, value, dir, len(entries))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// What `pilotctl send-message --wait` relies on, between two real daemons: a
// request sent with a message ID is stored with that message_id, and an
// answer sent with reply_to is stored with that reply_to, so the requester
// can pick its own answer out of the inbox.
func TestDataExchangeRecordsMessageIDAndReplyTo(t *testing.T) {
	requireRealNetwork(t)
	// Both daemons run in this process and write to $HOME/.pilot/inbox.
	home := t.TempDir()
	t.Setenv("HOME", home)
	inbox := filepath.Join(home, ".pilot", "inbox")

	env := NewTestEnv(t)
	a := env.AddDaemon()
	b := env.AddDaemon()

	request, err := dataexchange.Dial(b.Driver, a.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial a: %v", err)
	}
	defer request.Close()
	id := dataexchange.NewMessageID()
	res, err := request.Send(&dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("ping"), MessageID: id})
	if err != nil || !res.Tagged {
		t.Fatalf("send request: %+v, %v; want it delivered with its ID", res, err)
	}
	got := inboxRecordWith(t, inbox, "message_id", id)
	if got["data"] != "ping" || got["from"] != b.Daemon.Addr().String() {
		t.Fatalf("request record = %v", got)
	}
	if _, has := got["reply_to"]; has {
		t.Fatalf("request record carries a reply_to: %v", got)
	}

	answer, err := dataexchange.Dial(a.Driver, b.Daemon.Addr())
	if err != nil {
		t.Fatalf("dial b: %v", err)
	}
	defer answer.Close()
	res, err = answer.Send(&dataexchange.Frame{Type: dataexchange.TypeText, Payload: []byte("pong"), ReplyTo: id})
	if err != nil || !res.Tagged {
		t.Fatalf("send answer: %+v, %v", res, err)
	}
	got = inboxRecordWith(t, inbox, "reply_to", id)
	if got["data"] != "pong" || got["from"] != a.Daemon.Addr().String() {
		t.Fatalf("answer record = %v", got)
	}
}
