// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// When the daemon could list only part of its peers, `peers` says so in
// both output modes instead of passing a partial list off as complete.
func TestCmdPeersReportsCutList(t *testing.T) {
	const reply = `{"node_id": 1, "peers": 10909, "peer_list_truncated": true,
		"peer_list": [{"node_id": 99, "encrypted": true, "authenticated": true, "relay": true}]}`

	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdInfo, tdCmdInfoOK, reply)
	out := captureStdout(t, func() { withText(func() { cmdPeers(nil) }) })
	if !strings.Contains(out, "the daemon has 10909 peers and listed 1") {
		t.Fatalf("text output does not say the list was cut:\n%s", out)
	}

	d2 := newFakeDaemon(t)
	d2.useDaemon(t)
	d2.onJSON(tdCmdInfo, tdCmdInfoOK, reply)
	out = captureStdout(t, func() { withJSON(func() { cmdPeers(nil) }) })
	var env struct {
		Data struct {
			Truncated   bool    `json:"truncated"`
			DaemonPeers float64 `json:"daemon_peers"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if !env.Data.Truncated || env.Data.DaemonPeers != 10909 {
		t.Fatalf("JSON output: truncated=%v daemon_peers=%v", env.Data.Truncated, env.Data.DaemonPeers)
	}
}

// The same for `trust`.
func TestCmdTrustReportsCutList(t *testing.T) {
	const reply = `{"trusted_truncated": true,
		"trusted": [{"node_id": 99, "public_key": "k", "approved_at": 1790000000, "mutual": true, "network": 0}]}`

	d := newFakeDaemon(t)
	d.useDaemon(t)
	d.onJSON(tdCmdHandshake, tdCmdHandshakeOK, reply)
	out := captureStdout(t, func() { withText(func() { cmdTrust(nil) }) })
	if !strings.Contains(out, "the daemon listed only its newest") {
		t.Fatalf("text output does not say the list was cut:\n%s", out)
	}

	d2 := newFakeDaemon(t)
	d2.useDaemon(t)
	d2.onJSON(tdCmdHandshake, tdCmdHandshakeOK, reply)
	out = captureStdout(t, func() { withJSON(func() { cmdTrust(nil) }) })
	if !strings.Contains(out, `"truncated":true`) {
		t.Fatalf("JSON output does not say the list was cut:\n%s", out)
	}
}
