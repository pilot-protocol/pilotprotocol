// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSaveConfigPerms verifies the secret-bearing config.json is written
// 0600 and that a pre-existing loose-permission file does not retain its
// loose mode after a save (atomic rename installs a fresh 0600 file).
func TestSaveConfigPerms(t *testing.T) {
	withTempHomeFull(t)

	// Pre-create a world-readable config to prove perms are not preserved.
	dir := configDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(configPath(), []byte(`{"old":"loose"}`), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := saveConfig(map[string]interface{}{"admin_token": "s3cr3t"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	info, err := os.Stat(configPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("config perms = %o, want 0600", perm)
	}

	got := loadConfig()
	if got["admin_token"] != "s3cr3t" {
		t.Errorf("admin_token = %v", got["admin_token"])
	}
	if _, ok := got["old"]; ok {
		t.Errorf("stale key survived overwrite: %v", got)
	}
}

// TestSaveConfigAtomicNoTemp verifies a successful save leaves no temp file
// behind in the config dir — only config.json.
func TestSaveConfigAtomicNoTemp(t *testing.T) {
	withTempHomeFull(t)

	if err := saveConfig(map[string]interface{}{"hostname": "atomic"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	entries, err := os.ReadDir(configDir())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

// TestConfigDirHonorsPilotHome verifies PILOT_HOME relocates the .pilot dir
// and takes precedence over HOME.
func TestConfigDirHonorsPilotHome(t *testing.T) {
	home := withTempHomeFull(t)
	ph := t.TempDir()
	t.Setenv("PILOT_HOME", ph)

	if got, want := configDir(), filepath.Join(ph, ".pilot"); got != want {
		t.Errorf("configDir = %s, want %s (PILOT_HOME should win over HOME=%s)", got, want, home)
	}

	// And config written/read round-trips under PILOT_HOME.
	if err := saveConfig(map[string]interface{}{"hostname": "ph-agent"}); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ph, ".pilot", defaultConfigFile)); err != nil {
		t.Errorf("config not written under PILOT_HOME: %v", err)
	}
	if loadConfig()["hostname"] != "ph-agent" {
		t.Error("config not read back under PILOT_HOME")
	}
}

// TestCmdBenchRejectsBadSize covers the size-validation guard: negative,
// zero, and absurdly-large sizes are rejected before any daemon dial, so
// these run without a daemon and must exit non-zero with invalid_argument.
func TestCmdBenchRejectsBadSize(t *testing.T) {
	t.Parallel()
	bad := []string{"-5", "0", "999999", "nan"}
	for _, sz := range bad {
		sz := sz
		t.Run(sz, func(t *testing.T) {
			t.Parallel()
			_, stderr, code := runCLI(t, []string{
				"bench", "0:0000.0000.002A", sz,
			}, map[string]string{"PILOT_SOCKET": "/tmp/nope-bench-" + sz + ".sock"})
			if code == 0 {
				t.Errorf("size %q: expected non-zero exit", sz)
			}
			if !strings.Contains(stderr, "size") && !strings.Contains(stderr, "invalid") {
				t.Errorf("size %q: expected size/invalid hint, got: %s", sz, stderr)
			}
		})
	}
}

// TestCmdSendMessageJSONWaitSingleDoc verifies that send-message --json --wait
// emits exactly ONE JSON document (with the reply folded in), so machine
// parsers reading stdout don't choke on a second concatenated document.
func TestCmdSendMessageJSONWaitSingleDoc(t *testing.T) {
	sd := newStreamDaemon(t)
	home := sd.useDaemonNoRegistry(t)

	// The reply lands in the inbox after the request is sent, as a real
	// one does: --wait ignores files that were already there before the
	// send (an earlier request's reply, or a service's late duplicate).
	inbox := filepath.Join(home, ".pilot", "inbox")
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatalf("mkdir inbox: %v", err)
	}
	reply := map[string]interface{}{
		"from": "0:0000.0000.002A",
		"data": "pong",
	}
	body, _ := json.Marshal(reply)
	replyPath := filepath.Join(inbox, "TEXT-reply.json")
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for sd.sendCount.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		_ = os.WriteFile(replyPath, body, 0o600)
	}()

	out := captureStdout(t, func() {
		withJSON(func() {
			cmdSendMessage([]string{"0:0000.0000.002A", "--data", "ping", "--wait", "5s"})
		})
	})

	// Exactly one JSON document: a second Decode must hit EOF.
	dec := json.NewDecoder(strings.NewReader(out))
	var env map[string]interface{}
	if err := dec.Decode(&env); err != nil {
		t.Fatalf("first decode: %v\n%s", err, out)
	}
	var extra interface{}
	if err := dec.Decode(&extra); err == nil {
		t.Fatalf("expected single JSON document, found a second: %v\n%s", extra, out)
	}

	// The reply must be folded into the single envelope.
	data, ok := env["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing data object: %s", out)
	}
	replyObj, ok := data["reply"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing folded reply: %s", out)
	}
	if replyObj["data"] != "pong" {
		t.Errorf("reply.data = %v, want pong", replyObj["data"])
	}
}
