// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/updater"
)

// `pilotctl update --pin <older>` keeps config.json usable by the pinned
// daemon (fitTransportToDaemon) on top of #468's result reporting: a saved
// transport=auto, which a pre-auto daemon refuses, becomes udp and the JSON
// result carries the note next to the new fields.
func TestCmdUpdatePinnedOlderDaemonRewritesAuto(t *testing.T) {
	fake := &fakeUpdateRunner{status: updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.13.9", LatestVersion: "v1.14.0"}}
	home := withFakeUpdater(t, fake)
	withJSONOutput(t, true)
	old := writeFakeDaemon(t, append([]string{v1139TransportUsage}, baseDaemonFlags...), filepath.Join(t.TempDir(), "old"))
	script, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "pilot-daemon"), script, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(map[string]interface{}{"transport": "auto"}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() { cmdUpdate([]string{"--pin", "v1.13.9"}) })
	var env struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if note, _ := env.Data["note"].(string); !strings.Contains(note, "transport set to udp") {
		t.Errorf("note = %q, want the transport rewrite", env.Data["note"])
	}
	if env.Data["result"] != "updated" || env.Data["pinned"] != true {
		t.Errorf("data = %v, want #468's result fields too", env.Data)
	}
	if got, _ := loadConfig()["transport"].(string); got != "udp" {
		t.Errorf("config transport = %q, want udp", got)
	}
}
