// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Uninstall deleted the app's dir, and with it the app's state: for the
// wallet, its EVM private key, with the funds at its address out of reach.
// The dir now goes to the app backups (pinned, without the binary), where the
// wallet finds its key again when it is installed again; nothing is deleted.
func TestUninstallKeepsTheAppsStateInABackup(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".pilot", "apps")
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", "")
	appID := "io.pilot.wallet"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(filepath.Join(appDir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "bin", "app"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	key := []byte(`{"secp256k1_seed":"the funds"}`)
	if err := os.WriteFile(filepath.Join(appDir, "identity-evm.json"), key, 0o600); err != nil {
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
	if _, err := os.Stat(appDir); !os.IsNotExist(err) {
		t.Fatalf("app dir still in the install root: %v", err)
	}
	backup, _ := resp["backup"].(string)
	wantParent := filepath.Join(home, ".pilot", "app-backups", appID)
	if !strings.HasPrefix(backup, wantParent+string(filepath.Separator)) {
		t.Fatalf("backup = %q, want it under %s", backup, wantParent)
	}
	got, err := os.ReadFile(filepath.Join(backup, "identity-evm.json"))
	if err != nil || string(got) != string(key) {
		t.Fatalf("key in the backup = %q, %v; want it byte for byte", got, err)
	}
	if _, err := os.Stat(filepath.Join(backup, "bin", "app")); !os.IsNotExist(err) {
		t.Errorf("the binary was kept in the backup: %v", err)
	}
	var meta appBackupMeta
	raw, err := os.ReadFile(filepath.Join(backup, appBackupMetaName))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Kind != backupKindUninstall || !meta.Pinned || meta.FromVersion != "1.0.0" {
		t.Errorf("backup meta = %+v, want kind %q, pinned, from 1.0.0", meta, backupKindUninstall)
	}
}

// When no backup location takes the dir, it is still not deleted: it is kept
// in the install root (renamed, manifest disabled), or the uninstall stops
// with the dir in place. Either way the key survives.
func TestUninstallNeverDeletesTheKeyWhenBackupsFail(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".pilot", "apps")
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", "")
	appID := "io.pilot.wallet"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), minimalManifestJSON(appID, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	key := []byte("the key")
	if err := os.WriteFile(filepath.Join(appDir, "identity-evm.json"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	prevRename := renameForBackup
	renameForBackup = func(string, string) error { return os.ErrPermission }
	t.Cleanup(func() { renameForBackup = prevRename })

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	runTrapped(t, func() { cmdAppStoreUninstall([]string{appID, "--yes"}) })

	var found []string
	_ = filepath.Walk(home, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() && fi.Name() == "identity-evm.json" {
			if b, _ := os.ReadFile(p); string(b) == string(key) {
				found = append(found, p)
			}
		}
		return nil
	})
	if len(found) == 0 {
		t.Fatal("the key is gone after an uninstall whose backup failed")
	}
}
