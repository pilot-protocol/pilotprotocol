// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/pilotprotocol/internal/catalogtrust"
)

func mustWrite(t *testing.T, path, body string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), perm); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s exists, want it absent", path)
	}
}

// ── install without --force on an installed app is a no-op ─────────────────

func TestAppStoreInstallAlreadyInstalledIsNoOp(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.noop"
	appDir := filepath.Join(root, id)
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
	seedAppState(t, appDir)
	before, err := os.Stat(filepath.Join(appDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}

	// By catalogue id: answered before any download, points at `upgrade`.
	out := captureStdout(t, func() { cmdAppStoreInstall([]string{id}) })
	if !strings.Contains(out, "already installed") || !strings.Contains(out, "pilotctl appstore upgrade "+id) {
		t.Fatalf("no-op output should say it is installed and point at upgrade, got:\n%s", out)
	}
	// By local bundle path: answered after reading the bundle's manifest.
	out = captureStdout(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
	if !strings.Contains(out, "already installed") || !strings.Contains(out, "--local --force") {
		t.Fatalf("local no-op output should point at --local --force, got:\n%s", out)
	}
	// JSON: a success-shaped report flagged already_installed, with a hint.
	jsonOutput = true
	out = captureStdout(t, func() { cmdAppStoreInstall([]string{id}) })
	jsonOutput = false
	var rpt installReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !rpt.AlreadyInstalled || rpt.AppVersion != "1.0.0" || !strings.Contains(rpt.Hint, "appstore upgrade") {
		t.Fatalf("JSON no-op report = %+v", rpt)
	}

	after, err := os.Stat(filepath.Join(appDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("a no-op install replaced the installed app")
	}
	assertAppStateKept(t, appDir, "after no-op installs")
	if _, err := os.Stat(filepath.Join(appDir, ".suspended")); err != nil {
		t.Error("a no-op install touched the installed app's control files")
	}
	assertAbsent(t, filepath.Join(filepath.Dir(root), "app-backups"))
}

// ── --reset-state is the explicit, loud, destructive variant ───────────────

func TestAppStoreInstallResetStateStartsEmptyButKeepsBackup(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.reset"
	appDir := filepath.Join(root, id)
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
	seedAppState(t, appDir)

	jsonOutput = true
	var out string
	stderr := captureStderr(t, func() {
		out = captureStdout(t, func() { cmdAppStoreInstall([]string{bundle, "--local", "--reset-state"}) })
	})
	jsonOutput = false
	if !strings.Contains(stderr, "WARNING: --reset-state") || !strings.Contains(stderr, "WITHOUT its saved state") {
		t.Fatalf("--reset-state must warn loudly on stderr, got:\n%s", stderr)
	}
	var rpt installReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !rpt.StateReset || len(rpt.PreservedState) != 0 || rpt.BackupDir == "" {
		t.Fatalf("report = %+v, want state_reset with a backup and nothing preserved", rpt)
	}
	for rel := range appStateFixture {
		assertAbsent(t, filepath.Join(appDir, filepath.FromSlash(rel)))
	}
	if strings.Contains(mustRead(t, filepath.Join(appDir, "supervisor.log")), "prior-history-marker") {
		t.Error("--reset-state carried the old audit log")
	}
	// The discarded state is still recoverable from the backup.
	if got := mustRead(t, filepath.Join(rpt.BackupDir, "identity-evm.json")); got != appStateFixture["identity-evm.json"] {
		t.Fatalf("backup key = %q", got)
	}
	// Uninstall leaves the backups and says where they are.
	out = captureStdout(t, func() { cmdAppStoreUninstall([]string{id, "--yes"}) })
	if !strings.Contains(out, "backup(s) of earlier installs") {
		t.Errorf("uninstall should point at the remaining backups, got:\n%s", out)
	}
}

// ── what counts as app state ────────────────────────────────────────────────

func TestCarryAppStateCarriesOnlyAppState(t *testing.T) {
	oldDir := filepath.Join(t.TempDir(), "old")
	newDir := filepath.Join(t.TempDir(), "new")

	// Old install: bundle files, pilotctl/supervisor control files, and state.
	mustWrite(t, filepath.Join(oldDir, "manifest.json"), "old manifest", 0o644)
	mustWrite(t, filepath.Join(oldDir, "bin", "oldapp"), "old binary", 0o755)
	mustWrite(t, filepath.Join(oldDir, "bin", "helper"), "fetched helper", 0o755)
	mustWrite(t, filepath.Join(oldDir, "install.json"), "old install spec", 0o644)
	for name := range appDirControlFiles {
		if name != "manifest.json" && name != "install.json" {
			mustWrite(t, filepath.Join(oldDir, name), "control", 0o600)
		}
	}
	mustWrite(t, filepath.Join(oldDir, "stale.sock"), "not state", 0o600)
	mustWrite(t, filepath.Join(oldDir, "data.db"), "db", 0o600)
	mustWrite(t, filepath.Join(oldDir, "shipped.txt"), "user-modified copy", 0o600)
	mustWrite(t, filepath.Join(oldDir, "data", "cache", "state.bin"), "nested", 0o600)
	if err := os.Chmod(filepath.Join(oldDir, "data"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("data.db", filepath.Join(oldDir, "current.db")); err != nil {
		t.Fatal(err)
	}
	// A live unix socket (short path: macOS caps sun_path at 104 bytes).
	sockDir, err := os.MkdirTemp("", "cas")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	if ln, err := net.Listen("unix", filepath.Join(sockDir, "s")); err == nil {
		t.Cleanup(func() { _ = ln.Close() })
		if err := os.Rename(filepath.Join(sockDir, "s"), filepath.Join(oldDir, "live-socket")); err != nil {
			t.Fatal(err)
		}
	}

	// New bundle already staged: its own binary and a file it ships.
	mustWrite(t, filepath.Join(newDir, "bin", "newapp"), "new binary", 0o755)
	mustWrite(t, filepath.Join(newDir, "shipped.txt"), "bundle copy", 0o644)

	c, err := carryAppState(oldDir, newDir, "bin/oldapp")
	if err != nil {
		t.Fatalf("carryAppState: %v", err)
	}
	if len(c.Unreadable) != 0 {
		t.Fatalf("nothing here is unreadable, got %q", c.Unreadable)
	}
	carried := c.Carried
	want := []string{
		filepath.Join("bin", "helper"),
		"current.db",
		"data.db",
		filepath.Join("data", "cache", "state.bin"),
	}
	if !reflect.DeepEqual(carried, want) {
		t.Fatalf("carried = %q\nwant      %q", carried, want)
	}
	for name := range appDirControlFiles {
		assertAbsent(t, filepath.Join(newDir, name))
	}
	for _, p := range []string{"bin/oldapp", "stale.sock", "live-socket", "install.json"} {
		assertAbsent(t, filepath.Join(newDir, filepath.FromSlash(p)))
	}
	if got := mustRead(t, filepath.Join(newDir, "shipped.txt")); got != "bundle copy" {
		t.Errorf("a path the new bundle ships was overwritten by the old copy: %q", got)
	}
	// State is hard-linked (same inode as the running app's files) ...
	oldFi, _ := os.Stat(filepath.Join(oldDir, "data.db"))
	newFi, _ := os.Stat(filepath.Join(newDir, "data.db"))
	if !os.SameFile(oldFi, newFi) {
		t.Error("data.db was copied, want a hard link so a running app's writes are not lost")
	}
	// ... symlinks stay symlinks, and dir modes are kept.
	if target, err := os.Readlink(filepath.Join(newDir, "current.db")); err != nil || target != "data.db" {
		t.Errorf("symlink not preserved: %q, %v", target, err)
	}
	if fi, err := os.Stat(filepath.Join(newDir, "data")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Errorf("data/ mode not preserved: %v, %v", fi, err)
	}
	if err := verifyCarriedState(newDir, carried, false); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyCarriedStateToleratesOnlyVolatileFiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "identity.json"), "k", 0o600)
	carried := []string{"identity.json", "data.db-journal"}
	if err := verifyCarriedState(dir, carried, true); err != nil {
		t.Fatalf("a vanished SQLite journal must not fail the post-swap check: %v", err)
	}
	if err := verifyCarriedState(dir, carried, false); err == nil {
		t.Fatal("the pre-swap check must require every carried path")
	}
	if err := verifyCarriedState(dir, []string{"secrets.json"}, true); err == nil {
		t.Fatal("a missing secrets file must fail verification")
	}
}

// ── the swap keeps the previous install until the new one verifies ────────

func TestSwapInAppDirRestoresPreviousWhenVerifyFails(t *testing.T) {
	base := t.TempDir()
	final := filepath.Join(base, "io.test.swap")
	staging := final + appStagingSuffix
	mustWrite(t, filepath.Join(final, "identity-evm.json"), "old key", 0o600)
	mustWrite(t, filepath.Join(staging, "manifest.json"), "new", 0o644)

	prev, err := swapInAppDir(final, staging, func(dir string) error {
		if got := mustRead(t, filepath.Join(dir, "manifest.json")); got != "new" {
			t.Errorf("verify saw %q, want the staged dir", got)
		}
		if _, err := os.Stat(final + appPreviousSuffix); err != nil {
			t.Errorf("previous install not kept while verifying: %v", err)
		}
		return errors.New("binary sha mismatch")
	})
	if err == nil || prev != "" || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("swap = (%q, %v), want a restore error", prev, err)
	}
	if got := mustRead(t, filepath.Join(final, "identity-evm.json")); got != "old key" {
		t.Fatalf("previous install not restored: %q", got)
	}
	assertAbsent(t, final+appPreviousSuffix)
	assertAbsent(t, staging)
}

func TestSwapInAppDirSuccessAndPreviousGuard(t *testing.T) {
	base := t.TempDir()
	final := filepath.Join(base, "io.test.swapok")
	staging := final + appStagingSuffix
	mustWrite(t, filepath.Join(final, "v"), "old", 0o600)
	mustWrite(t, filepath.Join(staging, "v"), "new", 0o600)
	prev, err := swapInAppDir(final, staging, func(string) error { return nil })
	if err != nil || prev != final+appPreviousSuffix {
		t.Fatalf("swap = (%q, %v)", prev, err)
	}
	if mustRead(t, filepath.Join(final, "v")) != "new" || mustRead(t, filepath.Join(prev, "v")) != "old" {
		t.Fatal("swap did not place new and keep old")
	}
	// A second swap must refuse to clobber an unretired previous dir.
	mustWrite(t, filepath.Join(staging, "v"), "newer", 0o600)
	if _, err := swapInAppDir(final, staging, nil); err == nil {
		t.Fatal("swap overwrote an existing .previous dir")
	}
	if mustRead(t, filepath.Join(prev, "v")) != "old" {
		t.Fatal("previous dir changed")
	}
	assertAbsent(t, staging) // a refused swap does not leave staging for the supervisor
	// Fresh install (nothing to replace) returns no previous dir.
	fresh := filepath.Join(base, "io.test.fresh")
	mustWrite(t, filepath.Join(fresh+appStagingSuffix, "v"), "x", 0o600)
	if prev, err := swapInAppDir(fresh, fresh+appStagingSuffix, nil); err != nil || prev != "" {
		t.Fatalf("fresh swap = (%q, %v)", prev, err)
	}
}

// ── crash recovery never deletes state ─────────────────────────────────────

func TestRecoverInterruptedInstall(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.crash"
	final := filepath.Join(root, id)
	prev := final + appPreviousSuffix

	// Died after moving the live install aside: put it back.
	mustWrite(t, filepath.Join(prev, "identity-evm.json"), "key", 0o600)
	notes, err := recoverInterruptedInstall(final, id)
	if err != nil || len(notes) != 1 {
		t.Fatalf("recover = (%v, %v)", notes, err)
	}
	if mustRead(t, filepath.Join(final, "identity-evm.json")) != "key" {
		t.Fatal("interrupted install not restored")
	}
	assertAbsent(t, prev)

	// Died after the swap but before retiring the old dir: back it up.
	mustWrite(t, filepath.Join(prev, "identity-evm.json"), "older key", 0o600)
	if _, err := recoverInterruptedInstall(final, id); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, prev)
	backups, err := os.ReadDir(filepath.Join(appStoreBackupRoot(), id))
	if err != nil || len(backups) != 1 {
		t.Fatalf("leftover previous dir not backed up: %v, %v", backups, err)
	}
	if got := mustRead(t, filepath.Join(appStoreBackupRoot(), id, backups[0].Name(), "identity-evm.json")); got != "older key" {
		t.Fatalf("backup = %q", got)
	}
	if meta, ok := readBackupMeta(filepath.Join(appStoreBackupRoot(), id, backups[0].Name())); !ok || meta.Kind != backupKindRecovered || !meta.Pinned {
		t.Fatalf("a crash leftover must be kept as a pinned backup, meta = %+v (ok=%v)", meta, ok)
	}
	// Died before its swap: a manifest-bearing staging dir the supervisor
	// would adopt as a second copy of the app. Discarded.
	mustWrite(t, filepath.Join(final+appStagingSuffix, "manifest.json"), "{}", 0o644)
	mustWrite(t, filepath.Join(final+appStagingSuffix, "bin", "app"), "new", 0o755)
	if notes, err := recoverInterruptedInstall(final, id); err != nil || len(notes) != 1 {
		t.Fatalf("recover staging = (%v, %v)", notes, err)
	}
	assertAbsent(t, final+appStagingSuffix)
	if mustRead(t, filepath.Join(final, "identity-evm.json")) != "key" {
		t.Fatal("recovery touched the live install")
	}
	// Nothing to do on a clean layout.
	if notes, err := recoverInterruptedInstall(final, id); err != nil || notes != nil {
		t.Fatalf("clean recover = (%v, %v)", notes, err)
	}
}

func TestAppStoreForceInstallAfterCrashKeepsState(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.crashinstall"
	appDir := filepath.Join(root, id)
	v1 := writeVersionedBundle(t, id, "1.0.0", "v1")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{v1, "--local"}) })
	seedAppState(t, appDir)
	// Simulate the old pilotctl dying mid-swap: live dir moved aside, a
	// half-built staging dir next to it, nothing at <id>.
	if err := os.Rename(appDir, appDir+appPreviousSuffix); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(appDir+appStagingSuffix, "bin", "app"), "partial", 0o755)

	v2 := writeVersionedBundle(t, id, "1.1.0", "v2")
	_ = captureStderr(t, func() {
		_ = captureStdout(t, func() { cmdAppStoreInstall([]string{v2, "--local", "--force"}) })
	})
	assertAppStateKept(t, appDir, "after recovering an interrupted install")
	if m, _, err := readInstalledManifest(appDir); err != nil || m.AppVersion != "1.1.0" {
		t.Fatalf("installed manifest = %v, %v", m, err)
	}
	assertAbsent(t, appDir+appPreviousSuffix)
	assertAbsent(t, appDir+appStagingSuffix)
}

// ── backups: out of the install root, detached, pruned, never lost ─────────

func TestRetireAppDirKeepsNewestBackupsDetached(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.retire"
	live := filepath.Join(root, id)
	mustWrite(t, filepath.Join(live, "identity-evm.json"), "key", 0o600)

	var last string
	for i := 0; i < appBackupKeep+2; i++ {
		prev := live + appPreviousSuffix
		mf := validManifestJSON(id, strings.Repeat("a", 64))
		mustWrite(t, filepath.Join(prev, "manifest.json"), string(mf), 0o644)
		mustWrite(t, filepath.Join(prev, "bin", "app"), "old binary", 0o755)
		if err := os.Link(filepath.Join(live, "identity-evm.json"), filepath.Join(prev, "identity-evm.json")); err != nil {
			t.Fatal(err)
		}
		dst, err := retireAppDir(prev, id, appBackupMeta{Kind: backupKindReinstall})
		if err != nil {
			t.Fatalf("retire %d: %v", i, err)
		}
		last = dst
		assertAbsent(t, prev)
	}
	backups, err := os.ReadDir(filepath.Join(appStoreBackupRoot(), id))
	if err != nil || len(backups) != appBackupKeep {
		t.Fatalf("got %d backups (%v), want the newest %d", len(backups), err, appBackupKeep)
	}
	if filepath.Base(last) != backups[len(backups)-1].Name() || !strings.HasSuffix(last, "-v1.0.0") {
		t.Fatalf("newest backup %s not kept (have %v)", last, backups)
	}
	assertAbsent(t, filepath.Join(last, "bin", "app")) // binaries are not state
	liveFi, _ := os.Stat(filepath.Join(live, "identity-evm.json"))
	bakFi, err := os.Stat(filepath.Join(last, "identity-evm.json"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(liveFi, bakFi) {
		t.Error("backup key still shares an inode with the live key")
	}
	if bakFi.Mode().Perm() != 0o600 || mustRead(t, filepath.Join(last, "identity-evm.json")) != "key" {
		t.Errorf("backup key mode/content wrong: %v", bakFi.Mode())
	}
}

// ── end to end through a signed catalogue: install, no-op, upgrade ─────────

func tarGzBundle(t *testing.T, dir string) (path, sha string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, rel := range []string{"manifest.json", "bin/app"} {
		body, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		if err := tw.WriteHeader(&tar.Header{Name: rel, Size: int64(len(body)), Typeflag: tar.TypeReg, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	path = filepath.Join(t.TempDir(), "bundle.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(sum[:])
}

// catalogueTestApp is one entry of a test catalogue.
type catalogueTestApp struct {
	id, version, bundlePath, bundleSHA string
}

// publishSignedCatalogue writes a one-app catalogue signed with an ephemeral
// catalogue key (restored at test end) where loadCatalogue will fetch it.
func publishSignedCatalogue(t *testing.T, catPath, id, version, bundlePath, bundleSHA string) {
	t.Helper()
	publishSignedCatalogueApps(t, catPath, catalogueTestApp{id, version, bundlePath, bundleSHA})
}

// publishSignedCatalogueApps is publishSignedCatalogue for several apps.
func publishSignedCatalogueApps(t *testing.T, catPath string, apps ...catalogueTestApp) {
	t.Helper()
	entries := make([]map[string]any, 0, len(apps))
	for _, a := range apps {
		entries = append(entries, map[string]any{
			"id": a.id, "version": a.version, "description": "stateful test app",
			"bundle_url": "file://" + a.bundlePath, "bundle_sha256": a.bundleSHA,
		})
	}
	body, err := json.Marshal(map[string]any{"version": 2, "apps": entries})
	if err != nil {
		t.Fatal(err)
	}
	sig, restore := catalogtrust.SignWithEphemeralKey(body)
	t.Cleanup(restore)
	mustWrite(t, catPath, string(body), 0o644)
	mustWrite(t, catPath+".sig", base64.StdEncoding.EncodeToString(sig), 0o644)
}

func TestAppStoreUpgradeThroughCatalogueKeepsAppState(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.catalogueupgrade"
	appDir := filepath.Join(root, id)
	catPath := filepath.Join(t.TempDir(), "catalogue.json")
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+catPath)

	v1Tar, v1SHA := tarGzBundle(t, writeVersionedBundle(t, id, "1.0.0", "v1"))
	publishSignedCatalogue(t, catPath, id, "1.0.0", v1Tar, v1SHA)
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{id}) })
	if _, err := os.Stat(filepath.Join(appDir, manifest.SideloadMarkerName)); err == nil {
		t.Fatal("catalogue install was marked sideloaded")
	}
	seedAppState(t, appDir)

	// The docs' generic step, re-run on an installed app: a no-op.
	if out := captureStdout(t, func() { cmdAppStoreInstall([]string{id}) }); !strings.Contains(out, "already installed") {
		t.Fatalf("re-install without --force should be a no-op, got:\n%s", out)
	}

	// A new release lands in the catalogue; the hourly updater runs
	// `pilotctl appstore upgrade --all`.
	v2Tar, v2SHA := tarGzBundle(t, writeVersionedBundle(t, id, "1.1.0", "v2"))
	publishSignedCatalogue(t, catPath, id, "1.1.0", v2Tar, v2SHA)
	out := captureStdout(t, func() { cmdAppStoreUpgrade([]string{"--all"}) })
	if !strings.Contains(out, "state: kept") {
		t.Errorf("upgrade output should report kept state, got:\n%s", out)
	}
	assertAppStateKept(t, appDir, "after appstore upgrade --all")
	if m, _, err := readInstalledManifest(appDir); err != nil || m.AppVersion != "1.1.0" {
		t.Fatalf("upgraded manifest = %v, %v", m, err)
	}
	if got := strings.TrimSpace(mustRead(t, filepath.Join(appDir, bundleSHAMarker))); got != v2SHA {
		t.Errorf("bundle sha marker = %s, want the new bundle's %s", got, v2SHA)
	}
	if outdated, err := findOutdated(); err != nil || len(outdated) != 0 {
		t.Errorf("still outdated after upgrade: %v, %v", outdated, err)
	}
	backups, err := os.ReadDir(filepath.Join(filepath.Dir(root), "app-backups", id))
	if err != nil || len(backups) != 1 || !strings.HasSuffix(backups[0].Name(), "-v1.0.0") {
		t.Fatalf("upgrade backup = %v, %v", backups, err)
	}
}
