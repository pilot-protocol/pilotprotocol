// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// minimalManifestJSON returns a manifest that passes JSON Parse but
// does NOT pass semantic Validate (no grants, weak publisher). Used to
// confirm error/skip code paths.
func minimalManifestJSON(id string, exposes []string) []byte {
	type bin struct {
		Runtime string `json:"runtime"`
		Path    string `json:"path"`
		SHA256  string `json:"sha256"`
	}
	type store struct {
		Publisher string `json:"publisher"`
		Signature string `json:"signature"`
	}
	body := map[string]any{
		"id":               id,
		"app_version":      "1.0.0",
		"manifest_version": 1,
		"binary":           bin{Runtime: "go", Path: "bin/app", SHA256: ""},
		"exposes":          exposes,
		"grants":           []any{},
		"protection":       "shareable",
		"store":            store{Publisher: "ed25519:test", Signature: "sig"},
	}
	out, _ := json.Marshal(body)
	return out
}

// validManifestJSON returns a manifest that passes BOTH Parse and
// Validate. Caller supplies the binary's sha256 (must be 64-hex).
// Used to drive the install/verify/status happy paths.
func validManifestJSON(id, binSHA string) []byte {
	body := map[string]any{
		"id":               id,
		"app_version":      "1.0.0",
		"manifest_version": 1,
		"binary": map[string]any{
			"runtime": "go",
			"path":    "bin/app",
			"sha256":  binSHA,
		},
		"grants": []any{
			map[string]any{
				"cap":    "fs.read",
				"target": "$APP/data",
			},
		},
		"protection": "shareable",
		"store": map[string]any{
			"publisher": "ed25519:AAAAB3NzaC1yc2EAAAADAQABAAABAQDXX0000000",
			"signature": "deadbeef",
		},
	}
	out, _ := json.Marshal(body)
	return out
}

// makeBundle creates a bundle directory containing manifest.json + bin/app,
// with the manifest's sha256 pinned to the binary's actual hash. Returns
// the bundle path and the bin's sha256 hex string.
func makeBundle(t *testing.T, id string) (bundleDir, binSHA string) {
	t.Helper()
	bundleDir = t.TempDir()
	binDir := filepath.Join(bundleDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binPath := filepath.Join(binDir, "app")
	binData := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(binPath, binData, 0o755); err != nil {
		t.Fatal(err)
	}
	binSHA = sha256File(binPath)
	if err := os.WriteFile(filepath.Join(bundleDir, "manifest.json"),
		validManifestJSON(id, binSHA), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundleDir, binSHA
}

func TestCmdAppStoreListEmptyRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreList(nil) })
	out = strings.TrimSpace(out)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty array JSON, got %q", out)
	}
}

func TestCmdAppStoreListMissingRoot(t *testing.T) {
	// Point at a non-existent root — list should print empty JSON, not exit.
	t.Setenv("PILOT_APPSTORE_ROOT", filepath.Join(t.TempDir(), "absent"))

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreList(nil) })
	out = strings.TrimSpace(out)
	if out != "[]" && out != "null" {
		t.Errorf("missing root → got %q, want [] or null", out)
	}
}

func TestCmdAppStoreListPopulated(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	for _, id := range []string{"z.app", "a.app"} {
		dir := filepath.Join(root, id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		mfRaw := minimalManifestJSON(id, []string{"do.thing"})
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), mfRaw, 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreList(nil) })
	var apps []appListEntry
	if err := json.Unmarshal([]byte(out), &apps); err != nil {
		t.Fatalf("parse list: %v\n%s", err, out)
	}
	if len(apps) != 2 {
		t.Fatalf("got %d apps, want 2: %+v", len(apps), apps)
	}
	// Should be sorted alphabetically: a.app before z.app
	if apps[0].ID != "a.app" || apps[1].ID != "z.app" {
		t.Errorf("not sorted: %s, %s", apps[0].ID, apps[1].ID)
	}
}

func TestCmdAppStoreListSkipsCorruptManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// Good app
	goodDir := filepath.Join(root, "good.app")
	if err := os.MkdirAll(goodDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(goodDir, "manifest.json"),
		minimalManifestJSON("good.app", nil), 0o600); err != nil {
		t.Fatal(err)
	}
	// Bad app — has dir + manifest file but it's garbage.
	badDir := filepath.Join(root, "bad.app")
	if err := os.MkdirAll(badDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(badDir, "manifest.json"), []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Plain file (not a directory) — should be skipped.
	if err := os.WriteFile(filepath.Join(root, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreList(nil) })
	var apps []appListEntry
	if err := json.Unmarshal([]byte(out), &apps); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(apps) != 1 || apps[0].ID != "good.app" {
		t.Errorf("expected only good.app, got %+v", apps)
	}
}

func TestCmdAppStoreRestartHappyPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "test.app"
	dir := filepath.Join(root, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreRestart([]string{appID}) })

	// Marker file must exist.
	if _, err := os.Stat(filepath.Join(dir, ".resume")); err != nil {
		t.Errorf(".resume marker not created: %v", err)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if resp["id"] != appID {
		t.Errorf("id = %v", resp["id"])
	}

	// Audit log written at root level.
	auditPath := filepath.Join(root, pilotctlAuditFileName)
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	if !strings.Contains(string(body), "restart-requested") {
		t.Errorf("audit missing event: %s", body)
	}
}

func TestCmdAppStoreActionsEmpty(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreActions(nil) })
	out = strings.TrimSpace(out)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty array, got %q", out)
	}
}

func TestCmdAppStoreActionsWithEntries(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// Write some audit entries directly.
	writePilotctlAudit(root, pilotctlAuditEvent{Event: "installed", AppID: "a.one", SHA256: "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567"})
	writePilotctlAudit(root, pilotctlAuditEvent{Event: "uninstalled", AppID: "a.two"})
	writePilotctlAudit(root, pilotctlAuditEvent{Event: "installed", AppID: "a.three"})

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	// All three with no filter.
	out := captureStdout(t, func() { cmdAppStoreActions(nil) })
	var all []pilotctlAuditEvent
	if err := json.Unmarshal([]byte(out), &all); err != nil {
		t.Fatalf("parse all: %v\n%s", err, out)
	}
	if len(all) != 3 {
		t.Errorf("got %d, want 3", len(all))
	}

	// Filter by event.
	out = captureStdout(t, func() { cmdAppStoreActions([]string{"--event", "installed"}) })
	var inst []pilotctlAuditEvent
	if err := json.Unmarshal([]byte(out), &inst); err != nil {
		t.Fatalf("parse filtered: %v\n%s", err, out)
	}
	if len(inst) != 2 {
		t.Errorf("filtered: got %d, want 2", len(inst))
	}
	for _, ev := range inst {
		if ev.Event != "installed" {
			t.Errorf("unexpected event: %s", ev.Event)
		}
	}

	// Tail to 1.
	out = captureStdout(t, func() { cmdAppStoreActions([]string{"--tail", "1"}) })
	var tail []pilotctlAuditEvent
	if err := json.Unmarshal([]byte(out), &tail); err != nil {
		t.Fatalf("parse tail: %v\n%s", err, out)
	}
	if len(tail) != 1 {
		t.Errorf("tail=1: got %d", len(tail))
	}
	if tail[0].AppID != "a.three" {
		t.Errorf("tail[0] = %s, want last entry a.three", tail[0].AppID)
	}
}

func TestCmdAppStoreActionsTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// Empty file path → "no actions logged yet" text branch.
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreActions(nil) })
	if !strings.Contains(out, "no pilotctl actions logged yet") {
		t.Errorf("expected 'no actions' text, got %q", out)
	}
}

func TestCmdAppStoreAuditEmpty(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// App dir without any log file.
	appID := "audit.test"
	if err := os.MkdirAll(filepath.Join(root, appID), 0o755); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreAudit([]string{appID}) })
	out = strings.TrimSpace(out)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty array, got %q", out)
	}
}

func TestCmdAppStoreAuditReadsLog(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "audit.app"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(appDir, "supervisor.log")
	// Write valid + malformed lines.
	body := `{"at":"2026-05-27T10:00:00Z","app":"audit.app","event":"spawn","pid":1234,"sha256":"abc"}
not-json garbage
{"at":"2026-05-27T10:05:00Z","app":"audit.app","event":"exit","pid":1234,"exit_code":0}
{"at":"2026-05-27T10:06:00Z","app":"audit.app","event":"spawn","pid":1235}
`
	if err := os.WriteFile(logPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreAudit([]string{appID}) })
	var lines []auditLine
	if err := json.Unmarshal([]byte(out), &lines); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(lines) != 3 {
		t.Errorf("got %d lines, want 3 (malformed skipped): %+v", len(lines), lines)
	}

	// Filter by event=spawn.
	out = captureStdout(t, func() { cmdAppStoreAudit([]string{appID, "--event", "spawn"}) })
	var spawns []auditLine
	if err := json.Unmarshal([]byte(out), &spawns); err != nil {
		t.Fatalf("parse spawns: %v", err)
	}
	if len(spawns) != 2 {
		t.Errorf("got %d spawns, want 2", len(spawns))
	}

	// Tail=1.
	out = captureStdout(t, func() { cmdAppStoreAudit([]string{appID, "--tail", "1"}) })
	var tail []auditLine
	if err := json.Unmarshal([]byte(out), &tail); err != nil {
		t.Fatalf("parse tail: %v", err)
	}
	if len(tail) != 1 {
		t.Errorf("tail size %d", len(tail))
	}
}

func TestCmdAppStoreAuditRotatedLog(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "rotated.app"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "supervisor.log.1"),
		[]byte(`{"at":"2026-05-27T08:00:00Z","app":"rotated.app","event":"spawn","pid":1}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "supervisor.log"),
		[]byte(`{"at":"2026-05-27T09:00:00Z","app":"rotated.app","event":"spawn","pid":2}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreAudit([]string{appID}) })
	var lines []auditLine
	if err := json.Unmarshal([]byte(out), &lines); err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Both files should have been read; rotated first (older PID 1) then active (newer PID 2).
	if len(lines) != 2 {
		t.Fatalf("got %d, want 2", len(lines))
	}
	if lines[0].PID != 1 || lines[1].PID != 2 {
		t.Errorf("order wrong: %d, %d", lines[0].PID, lines[1].PID)
	}
}

func TestCmdAppStoreCapsHappyPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "wallet.app"
	dir := filepath.Join(root, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Manifest with one cap grant.
	mf := `{
		"id": "wallet.app",
		"app_version": "1.0.0",
		"manifest_version": 1,
		"binary": {"runtime": "go", "path": "bin/app", "sha256": ""},
		"grants": [
			{"cap": "key.sign", "target": "x402-auth",
			 "if": {"kind": "cap", "params": {"asset": "USDC", "per": "hour", "limit": 100}}}
		],
		"store": {"publisher": "ed25519:test", "signature": "sig"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(mf), 0o600); err != nil {
		t.Fatal(err)
	}
	// cap-state — one entry inside the rolling window.
	if err := os.WriteFile(filepath.Join(dir, "cap-state.jsonl"),
		[]byte(`{"at":"`+timeNowMinus("1m")+`","asset":"USDC","amount":25}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreCaps([]string{appID}) })
	var reports []capUsageReport
	if err := json.Unmarshal([]byte(out), &reports); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if len(reports) != 1 {
		t.Fatalf("got %d reports, want 1", len(reports))
	}
	r := reports[0]
	if r.Asset != "USDC" {
		t.Errorf("asset = %q", r.Asset)
	}
	if r.Limit != 100 {
		t.Errorf("limit = %d", r.Limit)
	}
	if r.Used != 25 {
		t.Errorf("used = %d", r.Used)
	}
	if r.Remaining != 75 {
		t.Errorf("remaining = %d, want 75", r.Remaining)
	}
}

// timeNowMinus returns an RFC3339Nano string for "now - dur".
func timeNowMinus(d string) string {
	dur, err := time.ParseDuration(d)
	if err != nil {
		panic(err)
	}
	return time.Now().UTC().Add(-dur).Format(time.RFC3339Nano)
}

func TestCmdAppStoreVerifyHappyPath(t *testing.T) {
	bundleDir, binSHA := makeBundle(t, "io.test.verify")
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreVerify([]string{bundleDir}) })
	var rpt verifyReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !rpt.OK {
		t.Errorf("expected OK=true: %+v", rpt)
	}
	if rpt.AppID != "io.test.verify" {
		t.Errorf("AppID = %q", rpt.AppID)
	}
	if rpt.ExpectedSHA256 != binSHA || rpt.ActualSHA256 != binSHA {
		t.Errorf("sha mismatch: expected=%s actual=%s want=%s", rpt.ExpectedSHA256, rpt.ActualSHA256, binSHA)
	}
}

func TestCmdAppStoreInstallHappyPath(t *testing.T) {
	// isolateAppStoreTest points PILOT_SOCKET at a path nothing listens on:
	// with a daemon running on this machine, install would otherwise wait
	// for it to start an app it never sees. It also keeps telemetry and the
	// catalogue off the network.
	root := isolateAppStoreTest(t)
	bundleDir, _ := makeBundle(t, "io.test.install")

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	// Local-path installs now require --local; without it the install
	// command refuses (see TestCmdAppStoreInstallRefusesLocalPathWithoutFlag).
	out := captureStdout(t, func() { cmdAppStoreInstall([]string{bundleDir, "--local"}) })
	var rpt installReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if rpt.AppID != "io.test.install" {
		t.Errorf("AppID = %q", rpt.AppID)
	}
	// App should live under root/<id>/ and carry the .sideloaded marker
	// — local-path installs are sideloads by definition.
	installedPath := filepath.Join(root, "io.test.install")
	if _, err := os.Stat(filepath.Join(installedPath, "manifest.json")); err != nil {
		t.Errorf("manifest not placed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installedPath, "bin", "app")); err != nil {
		t.Errorf("binary not placed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(installedPath, manifest.SideloadMarkerName)); err != nil {
		t.Errorf("sideload marker not planted: %v", err)
	}
}

func TestCmdAppStoreInstallRefusesDuplicate(t *testing.T) {
	isolateAppStoreTest(t) // no daemon: see TestCmdAppStoreInstallHappyPath
	bundleDir, _ := makeBundle(t, "io.test.dup")
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	// First install OK.
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{bundleDir, "--local"}) })
	// Second install would fatalCode — can't catch os.Exit inline. But
	// install with --force should succeed.
	out := captureStdout(t, func() { cmdAppStoreInstall([]string{bundleDir, "--force", "--local"}) })
	var rpt installReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("force install parse: %v\n%s", err, out)
	}
	if rpt.AppID != "io.test.dup" {
		t.Errorf("got %q", rpt.AppID)
	}
}

func TestCmdAppStoreStatusHappyPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	bundleDir, binSHA := makeBundle(t, "io.test.status")
	// Install it directly into the root with the same layout the installer would.
	appDir := filepath.Join(root, "io.test.status")
	if err := os.MkdirAll(filepath.Join(appDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	binSrc, _ := os.ReadFile(filepath.Join(bundleDir, "bin", "app"))
	if err := os.WriteFile(filepath.Join(appDir, "bin", "app"), binSrc, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreStatus([]string{"io.test.status"}) })
	var rpt appStatusReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if rpt.ID != "io.test.status" {
		t.Errorf("ID = %q", rpt.ID)
	}
	if !rpt.BinaryPresent {
		t.Errorf("BinaryPresent should be true")
	}
	if !rpt.BinarySHA256OK {
		t.Errorf("sha mismatch despite same bytes: pinned=%s", binSHA)
	}
	if !rpt.ManifestValid {
		t.Errorf("manifest should validate: errors=%v", rpt.ManifestErrors)
	}
	if rpt.BinarySize <= 0 {
		t.Errorf("BinarySize = %d", rpt.BinarySize)
	}
}

func TestCmdAppStoreStatusTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	bundleDir, _ := makeBundle(t, "io.test.statustext")
	appDir := filepath.Join(root, "io.test.statustext")
	if err := os.MkdirAll(filepath.Join(appDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifestRaw, _ := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	binSrc, _ := os.ReadFile(filepath.Join(bundleDir, "bin", "app"))
	if err := os.WriteFile(filepath.Join(appDir, "bin", "app"), binSrc, 0o755); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreStatus([]string{"io.test.statustext"}) })
	for _, frag := range []string{
		"app:",
		"io.test.statustext",
		"version:",
		"binary:",
		"manifest:       valid",
	} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in:\n%s", frag, out)
		}
	}
}

func TestCmdAppStoreUninstallHappyPath(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.gone"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Drop a minimal manifest so the snapshot path runs.
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreUninstall([]string{appID, "--yes"}) })
	var resp map[string]any
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if resp["id"] != appID {
		t.Errorf("id = %v", resp["id"])
	}
	if _, err := os.Stat(appDir); !os.IsNotExist(err) {
		t.Errorf("app dir should be gone: err=%v", err)
	}
	// Audit log written.
	auditPath := filepath.Join(root, pilotctlAuditFileName)
	body, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("audit log not written: %v", err)
	}
	if !strings.Contains(string(body), "uninstalled") {
		t.Errorf("audit missing uninstall event: %s", body)
	}
}

func TestCmdAppStoreCapsNoCapsManifest(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	bundleDir, _ := makeBundle(t, "io.test.nocaps")
	appDir := filepath.Join(root, "io.test.nocaps")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreCaps([]string{"io.test.nocaps"}) })
	out = strings.TrimSpace(out)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty caps: %q", out)
	}
}

// TestCmdAppStoreCallEntrypoint reaches cmdAppStore's dispatch table —
// it doesn't actually connect (no daemon needed). Both "help" and
// "list" with no apps should exit cleanly.
func TestCmdAppStoreInstallTextMode(t *testing.T) {
	isolateAppStoreTest(t) // no daemon: see TestCmdAppStoreInstallHappyPath
	bundleDir, _ := makeBundle(t, "io.test.install.text")
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreInstall([]string{bundleDir, "--local"}) })
	for _, frag := range []string{"installed", "io.test.install.text", "daemon rescans", "SIDELOADED"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreVerifyTextMode(t *testing.T) {
	bundleDir, _ := makeBundle(t, "io.test.verify.text")
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreVerify([]string{bundleDir}) })
	for _, frag := range []string{"bundle:", "io.test.verify.text", "binary:", "VERIFY OK"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreUninstallTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.uninstall.text"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreUninstall([]string{appID, "--yes"}) })
	if !strings.Contains(out, "removed") {
		t.Errorf("expected 'removed' in: %s", out)
	}
}

func TestCmdAppStoreRestartTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.restart.text"
	if err := os.MkdirAll(filepath.Join(root, appID), 0o755); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreRestart([]string{appID}) })
	for _, frag := range []string{"resume marker", ".resume"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreListTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// One installed app.
	appDir := filepath.Join(root, "io.test.listtext")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"),
		minimalManifestJSON("io.test.listtext", []string{"echo"}), 0o600); err != nil {
		t.Fatal(err)
	}

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreList(nil) })
	for _, frag := range []string{"install root", "io.test.listtext", "version:"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreActionsTextWithEntries(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "installed",
		AppID:  "io.text.actions",
		SHA256: "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
		Reason: "test fixture",
	})
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreActions(nil) })
	for _, frag := range []string{"pilotctl action log", "installed", "io.text.actions"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreCapsTextMode(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.captext"
	dir := filepath.Join(root, appID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	mf := `{
		"id": "` + appID + `",
		"app_version": "1.0.0",
		"manifest_version": 1,
		"binary": {"runtime": "go", "path": "bin/app", "sha256": ""},
		"grants": [
			{"cap": "key.sign", "target": "x402-auth",
			 "if": {"kind": "cap", "params": {"asset": "USDC", "per": "hour", "limit": 100}}}
		],
		"store": {"publisher": "ed25519:test", "signature": "sig"}
	}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(mf), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreCaps([]string{appID}) })
	if !strings.Contains(out, "USDC") || !strings.Contains(out, "100") {
		t.Errorf("expected cap details in: %s", out)
	}
}

func TestCmdAppStoreAuditTextWithLog(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	appID := "io.test.audittext"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "supervisor.log"),
		[]byte(`{"at":"2026-05-27T10:00:00Z","app":"io.test.audittext","event":"spawn","pid":42}`+"\n"+
			`{"at":"2026-05-27T10:05:00Z","app":"io.test.audittext","event":"exit","pid":42,"exit_code":0}`+"\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false
	out := captureStdout(t, func() { cmdAppStoreAudit([]string{appID}) })
	for _, frag := range []string{"audit log:", "spawn", "exit"} {
		if !strings.Contains(out, frag) {
			t.Errorf("missing %q in: %s", frag, out)
		}
	}
}

func TestCmdAppStoreDispatcher(t *testing.T) {
	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	// help branch
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	_ = captureStderr(t, func() { cmdAppStore([]string{"help"}) })
	// list branch (delegates to cmdAppStoreList)
	_ = captureStdout(t, func() { cmdAppStore([]string{"list"}) })
	// no-args branch prints help to stderr
	_ = captureStderr(t, func() { cmdAppStore(nil) })
}

// TestCmdAppStoreCatalogueTextOneLinePerApp asserts that text-mode output
// prints exactly one line per app in the form "<id>   <description>" (PILOT-405).
func TestCmdAppStoreCatalogueTextOneLinePerApp(t *testing.T) {
	stageCatalogue(t, `{"version":2,"updated_at":"2026-06-17","apps":[
		{"id":"io.pilot.wallet","version":"1.0.0","description":"Manages x402 payment credentials","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"},
		{"id":"io.pilot.cosift","version":"0.2.0","description":"Web search and answer agent","bundle_url":"https://x/b.tgz","bundle_sha256":"def"}
	]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })

	// Each app must appear as a single line containing both id and description.
	for _, want := range []string{
		"io.pilot.wallet",
		"Manages x402 payment credentials",
		"io.pilot.cosift",
		"Web search and answer agent",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in catalogue output:\n%s", want, out)
		}
	}

	// Both apps must appear on their own lines (one line each, not merged).
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var appLines []string
	for _, l := range lines {
		if strings.Contains(l, "io.pilot.") {
			appLines = append(appLines, l)
		}
	}
	if len(appLines) != 2 {
		t.Errorf("expected 2 app lines, got %d:\n%s", len(appLines), out)
	}
	// Each app line must contain the id and the description on the same line.
	if !strings.Contains(appLines[0], "io.pilot.wallet") || !strings.Contains(appLines[0], "Manages x402") {
		t.Errorf("first app line wrong: %q", appLines[0])
	}
	if !strings.Contains(appLines[1], "io.pilot.cosift") || !strings.Contains(appLines[1], "Web search") {
		t.Errorf("second app line wrong: %q", appLines[1])
	}
}

// TestCmdAppStoreCatalogueTextViewPointerHint asserts the view-pointer hint
// appears at the end of text-mode catalogue output (PILOT-405).
func TestCmdAppStoreCatalogueTextViewPointerHint(t *testing.T) {
	stageCatalogue(t, `{"version":1,"updated_at":"2026-06-17","apps":[
		{"id":"io.pilot.wallet","version":"1.0.0","description":"Manages x402 payment credentials","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"}
	]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })

	const hint = "Run 'pilotctl appstore view <id>' for full details."
	if !strings.Contains(out, hint) {
		t.Errorf("view-pointer hint missing from catalogue output:\n%s", out)
	}
}

// TestCmdAppStoreCatalogueDisplayNameHeadline asserts that text-mode
// output uses the DisplayName (headline) field when present, not the
// full Description. This is the core behaviour change for PILOT-405:
// list shows short headline, `view` shows full detail.
func TestCmdAppStoreCatalogueDisplayNameHeadline(t *testing.T) {
	stageCatalogue(t, `{"version":2,"updated_at":"2026-06-17","apps":[
		{"id":"io.pilot.wallet","version":"1.0.0","display_name":"Pilot Wallet","description":"Manages x402 payment credentials and token allowances for the daemon","metadata_url":"https://x/meta.json","metadata_sha256":"abc","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"}
	]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })

	// The headline (DisplayName) must appear, not the full description.
	if !strings.Contains(out, "Pilot Wallet") {
		t.Errorf("DisplayName missing from catalogue output (should be headline):\n%s", out)
	}
	// The full Description must NOT appear — only the headline.
	if strings.Contains(out, "token allowances") {
		t.Errorf("full Description leaked into catalogue output:\n%s", out)
	}
	// View pointer hint must still be present.
	if !strings.Contains(out, "Run 'pilotctl appstore view <id>' for full details.") {
		t.Errorf("view-pointer hint missing from catalogue output:\n%s", out)
	}
}

// TestCmdAppStoreCatalogueDisplayNameFallback asserts that when
// DisplayName is absent, the Description field is used as the
// headline (back-compat for v1 catalogue entries).
func TestCmdAppStoreCatalogueDisplayNameFallback(t *testing.T) {
	stageCatalogue(t, `{"version":1,"updated_at":"2026-06-17","apps":[
		{"id":"io.pilot.wallet","version":"1.0.0","description":"Manages x402 payment credentials","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"}
	]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })

	// Without DisplayName, Description should still appear.
	if !strings.Contains(out, "Manages x402 payment credentials") {
		t.Errorf("Description missing from catalogue output:\n%s", out)
	}
}

// TestCmdAppStoreCatalogueJSONUnchanged confirms --json output is unchanged:
// it still emits a JSON array of catalogue entries (PILOT-405).
func TestCmdAppStoreCatalogueJSONUnchanged(t *testing.T) {
	stageCatalogue(t, `{"version":1,"updated_at":"2026-06-17","apps":[
		{"id":"io.pilot.wallet","version":"1.0.0","description":"Manages x402 payment credentials","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"}
	]}`)

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })

	var apps []catalogueEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &apps); err != nil {
		t.Fatalf("json output is not a valid array: %v\n%s", err, out)
	}
	if len(apps) != 1 || apps[0].ID != "io.pilot.wallet" {
		t.Errorf("unexpected apps: %+v", apps)
	}
}
