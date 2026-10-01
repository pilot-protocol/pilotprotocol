// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdGatewayListPrintsNote(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, cmdGatewayList)
	for _, frag := range []string{"no mappings", "pilot-gateway"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdGatewayListJSON(t *testing.T) {
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, cmdGatewayList)
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["total"] != float64(0) {
		t.Errorf("total = %v", data["total"])
	}
	if data["note"] == nil {
		t.Errorf("note missing")
	}
}

// TestCmdDaemonStatusNoDaemon exercises the graceful-degrade path: no
// daemon → status returns text mode "Daemon: stopped" without exit.
func TestCmdDaemonStatusNoDaemon(t *testing.T) {
	tmp := withTempHomeFull(t)
	// Force socket to a path that can't possibly have a daemon.
	t.Setenv("PILOT_SOCKET", filepath.Join(tmp, "nope.sock"))

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdDaemonStatus(nil) })
	if !strings.Contains(out, "stopped") {
		t.Errorf("expected 'stopped' in: %s", out)
	}
}

func TestCmdDaemonStatusNoDaemonJSON(t *testing.T) {
	tmp := withTempHomeFull(t)
	t.Setenv("PILOT_SOCKET", filepath.Join(tmp, "nope.sock"))

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdDaemonStatus(nil) })
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	data := env["data"].(map[string]interface{})
	if data["responsive"] != false {
		t.Errorf("responsive = %v, want false", data["responsive"])
	}
	if data["running"] != false {
		t.Errorf("running = %v, want false", data["running"])
	}
}

func TestRequireAdminTokenHappyPath(t *testing.T) {
	withTempHomeFull(t)
	t.Setenv("PILOT_ADMIN_TOKEN", "happy-tok")
	if got := requireAdminToken(); got != "happy-tok" {
		t.Errorf("got %q", got)
	}
}

func TestRequireAdminTokenFromConfig(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"admin_token":"cfg-tok"}`)
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultConfigFile), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := requireAdminToken(); got != "cfg-tok" {
		t.Errorf("got %q", got)
	}
}

func TestPrintCommandHelpKnown(t *testing.T) {
	// Use a subtest pattern so individual commands surface in failure mode.
	for _, cmd := range []string{"send-message", "ping", "info", "init", "context"} {
		cmd := cmd
		t.Run(cmd, func(t *testing.T) {
			if _, ok := commandHelp[cmd]; !ok {
				t.Skipf("%s missing from commandHelp — skip", cmd)
			}
			txt := commandHelp[cmd]
			if !strings.Contains(txt, cmd) {
				t.Errorf("help for %q doesn't mention itself", cmd)
			}
		})
	}
}

// TestCommandHelpRegistryKeys pins the set of commands documented in the
// help registry against the cmdContext catalog — drift = test failure.
func TestCommandHelpRegistryHasCriticalKeys(t *testing.T) {
	t.Parallel()
	mustExist := []string{
		"send-message", "ping", "bench", "traceroute", "connect", "send", "recv",
		"listen", "find", "handshake", "peers", "inbox", "info", "health",
		"daemon start", "daemon stop", "daemon status",
		"init", "config", "version", "context",
		"network", "trust", "trusted", "pending", "approve", "reject", "untrust",
		"appstore",
	}
	for _, c := range mustExist {
		if _, ok := commandHelp[c]; !ok {
			t.Errorf("commandHelp missing key %q (regression?)", c)
		}
	}
}
