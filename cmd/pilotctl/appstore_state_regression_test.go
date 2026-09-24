// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// Regression tests for the app-store state wipe: `appstore install --force`
// (and `appstore upgrade`, which the hourly updater runs and which reinstalls
// with --force) used to rename the live app dir to <id>.previous, swap in the
// fresh bundle, then RemoveAll the old dir. Everything the app had written into
// $APP (the wallet's EVM key and payment DB, smol's secrets, per-app identities,
// the spend-cap ledger, the audit trail) was deleted. On a checkout without the
// fix, TestAppStoreForceReinstallKeepsAppState fails at the first state file.

// isolateAppStoreTest points every path an install touches at a scratch dir:
// the install root, HOME/PILOT_HOME (consent + identity), the daemon socket (so
// no live daemon is dialled), telemetry (a dead loopback port) and the
// catalogue (a missing file, so target resolution falls through to the local
// bundle without touching the network). Returns the install root; backups land
// in a sibling "app-backups" dir inside the same scratch dir.
func isolateAppStoreTest(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "apps")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home")
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", "")
	t.Setenv("HOME", home)
	t.Setenv("PILOT_HOME", home)
	t.Setenv("PILOT_SOCKET", filepath.Join(base, "no-daemon.sock"))
	t.Setenv("PILOT_TELEMETRY_URL", "http://127.0.0.1:9/telemetry")
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+filepath.Join(base, "no-catalogue.json"))
	prev := jsonOutput
	t.Cleanup(func() { jsonOutput = prev })
	jsonOutput = false
	return root
}

// writeVersionedBundle builds a valid local bundle (manifest.json + bin/app)
// for id at version; binBody varies the binary so two versions differ.
func writeVersionedBundle(t *testing.T, id, version, binBody string) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin", "app")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho "+binBody+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var mf map[string]any
	if err := json.Unmarshal(validManifestJSON(id, sha256File(bin)), &mf); err != nil {
		t.Fatal(err)
	}
	mf["app_version"] = version
	raw, err := json.Marshal(mf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// appStateFixture is what a real install accumulates in $APP at runtime: the
// wallet's keys and DB (with a WAL sidecar), smol's secrets, the spend-cap
// ledger, and a nested app-private file.
var appStateFixture = map[string]string{
	"identity-evm.json":    `{"private_key":"0xthis-wallet-key-must-survive-an-upgrade"}`,
	"identity.json":        `{"ed25519":"per-app identity"}`,
	"data.db":              "SQLite format 3\x00payments ledger",
	"data.db-wal":          "wal frames",
	"secrets.json":         `{"smol_cloud_secret":"s3cr3t"}`,
	"cap-state.jsonl":      `{"window":"24h","spent":"12.50"}` + "\n",
	"data/cache/state.bin": "nested app-private state",
}

// appControlFixture are files in $APP that belong to the bundle, pilotctl or
// the supervisor rather than the app; a reinstall must not carry them over.
var appControlFixture = []string{".suspended", ".resume", "app.sock", "next-steps.json", ".bundle-sha256"}

func seedAppState(t *testing.T, appDir string) {
	t.Helper()
	for rel, body := range appStateFixture {
		p := filepath.Join(appDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range appControlFixture {
		if err := os.WriteFile(filepath.Join(appDir, name), []byte("control"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(filepath.Join(appDir, "supervisor.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"event":"spawn","reason":"prior-history-marker"}` + "\n")
	_ = f.Close()
}

func assertAppStateKept(t *testing.T, appDir, when string) {
	t.Helper()
	// Wallet key first, so a regression reports the headline loss.
	rels := []string{"identity-evm.json"}
	for rel := range appStateFixture {
		if rel != "identity-evm.json" {
			rels = append(rels, rel)
		}
	}
	sort.Strings(rels[1:])
	for _, rel := range rels {
		want := appStateFixture[rel]
		p := filepath.Join(appDir, filepath.FromSlash(rel))
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: app state %s was lost: %v", when, rel, err)
		}
		if string(got) != want {
			t.Fatalf("%s: app state %s changed: got %q want %q", when, rel, got, want)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %s mode = %v, want 0600 (keys must stay private)", when, rel, fi.Mode().Perm())
		}
	}
	log, err := os.ReadFile(filepath.Join(appDir, "supervisor.log"))
	if err != nil || !strings.Contains(string(log), "prior-history-marker") {
		t.Fatalf("%s: supervisor.log audit history was lost (err=%v)", when, err)
	}
}

func TestAppStoreForceReinstallKeepsAppState(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.statefulwallet"
	appDir := filepath.Join(root, id)

	v1 := writeVersionedBundle(t, id, "1.0.0", "v1")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{v1, "--local"}) })
	seedAppState(t, appDir)

	// Same-version reinstall: the docs' generic `install <id> --force` step.
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{v1, "--local", "--force"}) })
	assertAppStateKept(t, appDir, "after install --force")
	for _, name := range appControlFixture {
		if _, err := os.Lstat(filepath.Join(appDir, name)); err == nil {
			t.Errorf("control file %s was carried into the new install", name)
		}
	}
	if _, err := os.Stat(filepath.Join(appDir, manifest.SideloadMarkerName)); err != nil {
		t.Errorf("sideload marker missing after a --local reinstall: %v", err)
	}

	// Version bump: the path `appstore upgrade` (and the hourly updater) takes.
	v2 := writeVersionedBundle(t, id, "1.0.1", "v2")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{v2, "--local", "--force"}) })
	assertAppStateKept(t, appDir, "after a version-bump reinstall")
	raw, err := os.ReadFile(filepath.Join(appDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.AppVersion != "1.0.1" {
		t.Fatalf("installed version = %s, want 1.0.1", m.AppVersion)
	}
	if got := sha256File(filepath.Join(appDir, "bin", "app")); got != m.Binary.SHA256 {
		t.Fatalf("installed binary sha %s does not match the new manifest %s", got, m.Binary.SHA256)
	}

	// Nothing half-done is left where the supervisor scans...
	for _, leftover := range []string{id + ".previous", id + ".staging"} {
		if _, err := os.Lstat(filepath.Join(root, leftover)); err == nil {
			t.Errorf("%s left in the install root, where the supervisor would scan it", leftover)
		}
	}
	// ...and the replaced installs are kept as backups outside it, not deleted.
	backups, err := os.ReadDir(filepath.Join(filepath.Dir(root), "app-backups", id))
	if err != nil {
		t.Fatalf("no backup of the previous install: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("got %d backups, want 2 (one per replaced install)", len(backups))
	}
	newest := filepath.Join(filepath.Dir(root), "app-backups", id, backups[len(backups)-1].Name())
	if got, err := os.ReadFile(filepath.Join(newest, "identity-evm.json")); err != nil || string(got) != appStateFixture["identity-evm.json"] {
		t.Fatalf("backup is missing the wallet key: %q, %v", got, err)
	}
	if !strings.HasSuffix(newest, "-v1.0.0") {
		t.Errorf("backup %s should be tagged with the version it held (1.0.0)", newest)
	}
}
