// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Tests for the review findings on the app-state preservation change:
// F1 carry of read-only / unreadable state and `upgrade --all` isolation,
// F2 backup retention, F3 the install lock and swap rollback, F4 writes the
// running app makes during the swap, F5 `install --version` on an installed
// app, F6 backup locations and their fallbacks.

// makeTreeRemovable registers a cleanup, run before t.TempDir's own, that
// makes read-only dirs under dir writable again so the temp dir can go.
func makeTreeRemovable(t *testing.T, dir string) {
	t.Helper()
	t.Cleanup(func() { _ = removeAllForce(dir) })
}

// runTrapped runs fn with fatal exits trapped, capturing stdout and stderr.
func runTrapped(t *testing.T, fn func()) (stdout, stderr string, failure *trappedFatal) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { failure = runTrappingFatal(fn) })
	})
	return stdout, stderr, failure
}

// installQuiet runs an install whose output the test does not need, failing
// the test if it ends fatally.
func installQuiet(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	stdout, stderr, f := runTrapped(t, func() { cmdAppStoreInstall(args) })
	if f != nil {
		t.Fatalf("install %v failed: %s: %s\nstderr:\n%s", args, f.Code, f.Message, stderr)
	}
	return stdout, stderr
}

// atomicWrite replaces path the way most apps save state: write a temp file
// beside it, rename it over.
func atomicWrite(t *testing.T, path, body string) {
	t.Helper()
	tmp := path + ".tmp-write"
	mustWrite(t, tmp, body, 0o600)
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

func installedVersion(t *testing.T, appDir string) string {
	t.Helper()
	m, _, err := readInstalledManifest(appDir)
	if err != nil {
		t.Fatalf("read installed manifest in %s: %v", appDir, err)
	}
	return m.AppVersion
}

// backupsByKind reads every backup of an app in dir, keyed by kind.
func backupsByKind(t *testing.T, dir string) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read backups %s: %v", dir, err)
	}
	out := map[string][]string{}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		meta, ok := readBackupMeta(p)
		kind := meta.Kind
		if !ok {
			kind = "(no metadata)"
		}
		out[kind] = append(out[kind], p)
	}
	return out
}

// ── F1: read-only and unreadable state no longer blocks install --force ────

func TestCarryAppStateCarriesReadOnlyDirs(t *testing.T) {
	base := t.TempDir()
	makeTreeRemovable(t, base)
	oldDir, newDir := filepath.Join(base, "old"), filepath.Join(base, "new")
	// A Go module cache: read-only dirs holding read-only files.
	mustWrite(t, filepath.Join(oldDir, "gomodcache", "pkg", "f.go"), "package f", 0o444)
	for _, d := range []string{"gomodcache/pkg", "gomodcache"} {
		if err := os.Chmod(filepath.Join(oldDir, filepath.FromSlash(d)), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(newDir, "bin", "app"), "new binary", 0o755)

	c, err := carryAppState(oldDir, newDir, "")
	if err != nil {
		t.Fatalf("a read-only state dir must carry, got: %v", err)
	}
	if want := []string{filepath.Join("gomodcache", "pkg", "f.go")}; !reflect.DeepEqual(c.Carried, want) || len(c.Unreadable) != 0 {
		t.Fatalf("carried = %q, unreadable = %q", c.Carried, c.Unreadable)
	}
	for _, d := range []string{"gomodcache", "gomodcache/pkg"} {
		fi, err := os.Stat(filepath.Join(newDir, filepath.FromSlash(d)))
		if err != nil || fi.Mode().Perm() != 0o555 {
			t.Errorf("%s mode = %v (%v), want the old dir's 0555 restored", d, fi, err)
		}
	}
	oldFi, _ := os.Stat(filepath.Join(oldDir, "gomodcache", "pkg", "f.go"))
	newFi, err := os.Stat(filepath.Join(newDir, "gomodcache", "pkg", "f.go"))
	if err != nil || !os.SameFile(oldFi, newFi) {
		t.Fatalf("f.go not hard-linked into the new dir: %v", err)
	}
	// A staging dir holding read-only dirs can still be thrown away.
	if err := discardStagingDir(newDir); err != nil {
		t.Fatalf("discard staging with read-only dirs: %v", err)
	}
	assertAbsent(t, newDir)
}

func TestAppStoreReinstallWithReadOnlyStateDirKeepsWorking(t *testing.T) {
	root := isolateAppStoreTest(t)
	makeTreeRemovable(t, filepath.Dir(root))
	const id = "io.test.gomodcache"
	appDir := filepath.Join(root, id)
	v1 := writeVersionedBundle(t, id, "1.0.0", "v1")
	installQuiet(t, v1, "--local")
	seedAppState(t, appDir)
	mustWrite(t, filepath.Join(appDir, "gomodcache", "pkg", "f.go"), "package f", 0o444)
	for _, d := range []string{"gomodcache/pkg", "gomodcache"} {
		if err := os.Chmod(filepath.Join(appDir, filepath.FromSlash(d)), 0o555); err != nil {
			t.Fatal(err)
		}
	}

	// Enough reinstalls that retention has to remove backups holding the
	// read-only tree, and the last carries from a dir the carry created.
	for i := 0; i < appBackupKeep+2; i++ {
		installQuiet(t, v1, "--local", "--force")
	}
	assertAppStateKept(t, appDir, "after reinstalls with a read-only state dir")
	if got := mustRead(t, filepath.Join(appDir, "gomodcache", "pkg", "f.go")); got != "package f" {
		t.Fatalf("f.go = %q", got)
	}
	if fi, err := os.Stat(filepath.Join(appDir, "gomodcache", "pkg")); err != nil || fi.Mode().Perm() != 0o555 {
		t.Errorf("gomodcache/pkg mode = %v (%v), want 0555", fi, err)
	}
	kinds := backupsByKind(t, filepath.Join(filepath.Dir(root), "app-backups", id))
	if len(kinds[backupKindReinstall]) != appBackupKeep || len(kinds) != 1 {
		t.Fatalf("backups = %v, want exactly %d reinstall backups (the older ones removed despite read-only dirs)", kinds, appBackupKeep)
	}
	assertAbsent(t, appDir+appStagingSuffix)
	assertAbsent(t, appDir+appPreviousSuffix)
	// Uninstall removes an app dir holding read-only dirs too.
	if _, stderr, f := runTrapped(t, func() { cmdAppStoreUninstall([]string{id, "--yes"}) }); f != nil {
		t.Fatalf("uninstall with a read-only state dir: %+v\n%s", f, stderr)
	}
	assertAbsent(t, appDir)
}

func TestAppStoreReinstallMovesStateThisUserCannotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read every file")
	}
	root := isolateAppStoreTest(t)
	makeTreeRemovable(t, filepath.Dir(root))
	const id = "io.test.foreignstate"
	appDir := filepath.Join(root, id)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local")
	seedAppState(t, appDir)

	// A root-owned file left by a daemon once run with sudo: with
	// fs.protected_hardlinks this user can neither link nor read it.
	// Simulated with a 0000 file whose link fails with EPERM, plus a dir
	// this user cannot list.
	foreign := filepath.Join(appDir, "supervisor.log.1")
	mustWrite(t, foreign, "root's rotated log", 0o600)
	if err := os.Chmod(foreign, 0); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(appDir, "root-owned", "x.json"), "y", 0o600)
	if err := os.Chmod(filepath.Join(appDir, "root-owned"), 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	origLink := linkFile
	linkFile = func(oldname, newname string) error {
		if filepath.Base(oldname) == "supervisor.log.1" {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EPERM}
		}
		return origLink(oldname, newname)
	}
	t.Cleanup(func() { linkFile = origLink })

	jsonOutput = true
	out, stderr := installQuiet(t, writeVersionedBundle(t, id, "1.1.0", "v2"), "--local", "--force")
	jsonOutput = false
	var rpt installReport
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse report: %v\n%s", err, out)
	}
	if len(rpt.StateNotCarried) != 0 {
		t.Fatalf("state_not_carried = %q, want everything moved across", rpt.StateNotCarried)
	}
	for _, want := range []string{"supervisor.log.1", "root-owned"} {
		found := false
		for _, p := range rpt.PreservedState {
			found = found || p == want
		}
		if !found {
			t.Errorf("preserved_state does not list %s: %q", want, rpt.PreservedState)
		}
	}
	if !strings.Contains(stderr, "cannot be linked or read") {
		t.Errorf("stderr should say some state is moved instead of linked:\n%s", stderr)
	}
	after, err := os.Lstat(foreign)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("the unreadable file was not moved into the new install: %v", err)
	}
	if err := os.Chmod(filepath.Join(appDir, "root-owned"), 0o700); err != nil {
		t.Fatalf("the unreadable dir was not moved into the new install: %v", err)
	}
	if got := mustRead(t, filepath.Join(appDir, "root-owned", "x.json")); got != "y" {
		t.Fatalf("root-owned/x.json = %q", got)
	}
	assertAppStateKept(t, appDir, "after a reinstall with unreadable state")
	if v := installedVersion(t, appDir); v != "1.1.0" {
		t.Fatalf("installed %s, want 1.1.0", v)
	}
	if meta, ok := readBackupMeta(rpt.BackupDir); !ok || meta.Kind != backupKindUpgrade {
		t.Errorf("backup meta = %+v (ok=%v), want a routine upgrade backup: nothing was left behind", meta, ok)
	}
}

func TestReconcileLeftoverMakesTheBackupPinned(t *testing.T) {
	base := t.TempDir()
	oldDir, newDir := filepath.Join(base, "old"), filepath.Join(base, "new")
	mustWrite(t, filepath.Join(oldDir, "secret.key"), "k", 0o600)
	// The path is taken in the new install, so the entry the carry could not
	// link cannot be moved there either: it stays in the old dir.
	mustWrite(t, filepath.Join(newDir, "secret.key"), "bundle file", 0o644)
	r := reconcileAppState(oldDir, newDir, "", &appStateCarry{
		Unreadable: []string{"secret.key"},
		entries:    map[string]carriedEntry{},
		dirs:       map[string]bool{},
	})
	if !reflect.DeepEqual(r.Leftover, []string{"secret.key"}) {
		t.Fatalf("leftover = %q", r.Leftover)
	}
	kind := replacedInstallBackupKind(false, r.Leftover, "1.0.0", "1.1.0")
	if kind != backupKindIncomplete || backupKindRotated(kind) {
		t.Fatalf("kind = %s, want a pinned %s backup", kind, backupKindIncomplete)
	}
}

func TestAppStoreUpgradeAllContinuesPastAFailedApp(t *testing.T) {
	root := isolateAppStoreTest(t)
	catPath := filepath.Join(t.TempDir(), "catalogue.json")
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+catPath)
	const alpha, zulu = "io.test.alpha", "io.test.zulu"

	a1, a1SHA := tarGzBundle(t, writeVersionedBundle(t, alpha, "1.0.0", "a1"))
	z1, z1SHA := tarGzBundle(t, writeVersionedBundle(t, zulu, "1.0.0", "z1"))
	publishSignedCatalogueApps(t, catPath,
		catalogueTestApp{alpha, "1.0.0", a1, a1SHA}, catalogueTestApp{zulu, "1.0.0", z1, z1SHA})
	installQuiet(t, alpha)
	installQuiet(t, zulu)
	seedAppState(t, filepath.Join(root, alpha))

	// Both move to 1.1.0; alpha's (sorted first) cannot be installed.
	a2, _ := tarGzBundle(t, writeVersionedBundle(t, alpha, "1.1.0", "a2"))
	z2, z2SHA := tarGzBundle(t, writeVersionedBundle(t, zulu, "1.1.0", "z2"))
	publishSignedCatalogueApps(t, catPath,
		catalogueTestApp{alpha, "1.1.0", a2, strings.Repeat("0", 64)}, catalogueTestApp{zulu, "1.1.0", z2, z2SHA})

	_, stderr, f := runTrapped(t, func() { cmdAppStoreUpgrade([]string{"--all"}) })
	if f == nil || f.Code != "upgrade_failed" || !strings.Contains(f.Message, alpha) {
		t.Fatalf("upgrade --all = %+v, want upgrade_failed naming %s\nstderr:\n%s", f, alpha, stderr)
	}
	if v := installedVersion(t, filepath.Join(root, zulu)); v != "1.1.0" {
		t.Fatalf("%s is at %s: the failed %s stopped the upgrade of the apps after it", zulu, v, alpha)
	}
	if v := installedVersion(t, filepath.Join(root, alpha)); v != "1.0.0" {
		t.Fatalf("%s is at %s, want it unchanged at 1.0.0", alpha, v)
	}
	assertAppStateKept(t, filepath.Join(root, alpha), "after its failed upgrade")
	if !strings.Contains(stderr, alpha+" was not upgraded") {
		t.Errorf("stderr should say %s was skipped:\n%s", alpha, stderr)
	}
	if fatalTrapDepth != 0 {
		t.Fatalf("fatal trap depth leaked: %d", fatalTrapDepth)
	}
}

// ── F2: retention never removes the only copy of an app's state ────────────

func TestBackupRetentionNeverRemovesTheResetStateBackup(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.wallet"
	appDir := filepath.Join(root, id)
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	installQuiet(t, bundle, "--local")
	mustWrite(t, filepath.Join(appDir, "identity-evm.json"), `{"private_key":"0xORIGINAL"}`, 0o600)

	installQuiet(t, bundle, "--local", "--reset-state")
	// Routine reinstalls afterwards (an agent's install --force, hourly
	// upgrades) must not push the only copy of the key out.
	for i := 0; i < appBackupKeep+1; i++ {
		installQuiet(t, bundle, "--local", "--force")
	}
	backups := filepath.Join(filepath.Dir(root), "app-backups", id)
	kinds := backupsByKind(t, backups)
	if len(kinds[backupKindResetState]) != 1 {
		t.Fatalf("backups = %v: the --reset-state backup was removed", kinds)
	}
	if got := mustRead(t, filepath.Join(kinds[backupKindResetState][0], "identity-evm.json")); !strings.Contains(got, "0xORIGINAL") {
		t.Fatalf("reset-state backup key = %q", got)
	}
	if meta, _ := readBackupMeta(kinds[backupKindResetState][0]); !meta.Pinned {
		t.Error("the reset-state backup is not marked pinned")
	}
	if len(kinds[backupKindReinstall]) != appBackupKeep {
		t.Errorf("reinstall backups = %d, want %d", len(kinds[backupKindReinstall]), appBackupKeep)
	}
}

func TestBackupRetentionKeepsUpgradeBackupsApartFromReinstalls(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.upgradebackup"
	appDir := filepath.Join(root, id)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local")
	seedAppState(t, appDir)
	v2 := writeVersionedBundle(t, id, "1.1.0", "v2")
	installQuiet(t, v2, "--local", "--force") // the pre-upgrade backup
	var stderr string
	for i := 0; i < appBackupKeep+1; i++ {
		_, stderr = installQuiet(t, v2, "--local", "--force")
	}
	kinds := backupsByKind(t, filepath.Join(filepath.Dir(root), "app-backups", id))
	if len(kinds[backupKindUpgrade]) != 1 || !strings.HasSuffix(kinds[backupKindUpgrade][0], "-v1.0.0") {
		t.Fatalf("backups = %v: same-version reinstalls pushed out the pre-upgrade backup", kinds)
	}
	if len(kinds[backupKindReinstall]) != appBackupKeep {
		t.Fatalf("reinstall backups = %d, want %d", len(kinds[backupKindReinstall]), appBackupKeep)
	}
	if !strings.Contains(stderr, "note: removed the older backup") {
		t.Errorf("pruning a backup must say so, stderr:\n%s", stderr)
	}
}

func TestPruneBackupDirsOnlyRotatesRoutineKinds(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string, meta *appBackupMeta) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if meta != nil {
			meta.Pinned = !backupKindRotated(meta.Kind)
			raw, _ := json.Marshal(meta)
			mustWrite(t, filepath.Join(p, appBackupMetaName), string(raw), 0o600)
		}
		return p
	}
	stamp := func(i int) string {
		return "20260101T0000" + string(rune('0'+i/10)) + string(rune('0'+i%10)) + ".000000000Z"
	}
	noMeta := mk(stamp(0)+"-v1", nil)
	r1 := mk(stamp(1)+"-v1", &appBackupMeta{Kind: backupKindReinstall})
	reset := mk(stamp(2)+"-v1", &appBackupMeta{Kind: backupKindResetState})
	r2 := mk(stamp(3)+"-v1", &appBackupMeta{Kind: backupKindReinstall})
	up := mk(stamp(4)+"-v1", &appBackupMeta{Kind: backupKindUpgrade})
	r3 := mk(stamp(5)+"-v2", &appBackupMeta{Kind: backupKindReinstall})
	r4 := mk(stamp(6)+"-v2", &appBackupMeta{Kind: backupKindReinstall})
	inc := mk(stamp(7)+"-v2", &appBackupMeta{Kind: backupKindIncomplete})

	removed := pruneAppBackups(dir, 2)
	if !reflect.DeepEqual(removed, []string{r1, r2}) {
		t.Fatalf("removed = %q, want the two oldest reinstall backups", removed)
	}
	for _, kept := range []string{noMeta, reset, up, r3, r4, inc} {
		if _, err := os.Stat(kept); err != nil {
			t.Errorf("%s was removed: %v", kept, err)
		}
	}
}

// ── F3: one install at a time per app; rollback never lies or leaks ────────

func TestLockAppInstallIsExclusivePerApp(t *testing.T) {
	root := t.TempDir()
	unlock, err := lockAppInstall(root, "io.test.lock")
	if err != nil {
		t.Fatal(err)
	}
	prev := appInstallLockWait
	appInstallLockWait = 200 * time.Millisecond
	t.Cleanup(func() { appInstallLockWait = prev })

	var lockErr error
	stderr := captureStderr(t, func() { _, lockErr = lockAppInstall(root, "io.test.lock") })
	if lockErr == nil || !strings.Contains(lockErr.Error(), "more than") {
		t.Fatalf("second lock = %v, want a timeout while the first is held", lockErr)
	}
	if !strings.Contains(stderr, "waiting for another pilotctl") {
		t.Errorf("a waiting install should say why, stderr:\n%s", stderr)
	}
	other, err := lockAppInstall(root, "io.test.other")
	if err != nil {
		t.Fatalf("another app's lock must not wait: %v", err)
	}
	other()
	unlock()
	unlock() // idempotent
	again, err := lockAppInstall(root, "io.test.lock")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()
	if fi, err := os.Lstat(appInstallLockPath(root, "io.test.lock")); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("lock file = %v, %v; want a plain file the supervisor ignores", fi, err)
	}
}

// startInFlightSwap puts appDir in the state another pilotctl's install is in
// halfway through its swap: the live dir moved to <id>.previous and a
// manifest-bearing staging dir holding the new version, with that install's
// lock held. It returns the lock's release.
func startInFlightSwap(t *testing.T, root, id, newBundle string) func() {
	t.Helper()
	appDir := filepath.Join(root, id)
	unlock, err := lockAppInstall(root, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
	if err := os.Rename(appDir, appDir+appPreviousSuffix); err != nil {
		t.Fatal(err)
	}
	staging := appDir + appStagingSuffix
	mustWrite(t, filepath.Join(staging, "bin", "app"), mustRead(t, filepath.Join(newBundle, "bin", "app")), 0o755)
	mustWrite(t, filepath.Join(staging, "manifest.json"), mustRead(t, filepath.Join(newBundle, "manifest.json")), 0o644)
	return unlock
}

// finishInFlightSwap completes the other install's swap: staging becomes the
// live dir (with the state carried) and the old dir leaves the install root.
func finishInFlightSwap(t *testing.T, root, id string) {
	t.Helper()
	appDir := filepath.Join(root, id)
	staging := appDir + appStagingSuffix
	if _, err := carryAppState(appDir+appPreviousSuffix, staging, "bin/app"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(staging, appDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(appDir+appPreviousSuffix, filepath.Join(t.TempDir(), "retired")); err != nil {
		t.Fatal(err)
	}
}

func TestAppStoreNoOpInstallWaitsForAnInFlightSwap(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.inflight"
	appDir := filepath.Join(root, id)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local")
	seedAppState(t, appDir)
	unlock := startInFlightSwap(t, root, id, writeVersionedBundle(t, id, "1.0.1", "v2"))

	// `install <id>` (the no-op path) while the other install is mid-swap.
	// It used to read the lone <id>.previous as a crash leftover and put it
	// back, breaking the other install's swap.
	type result struct {
		out, errOut string
		f           *trappedFatal
	}
	done := make(chan result, 1)
	go func() {
		var r result
		r.errOut = captureStderr(t, func() {
			r.out = captureStdout(t, func() { r.f = runTrappingFatal(func() { cmdAppStoreInstall([]string{id}) }) })
		})
		done <- r
	}()
	time.Sleep(300 * time.Millisecond)
	select {
	case r := <-done:
		t.Fatalf("install returned while another install held the app's lock: %+v", r)
	default:
	}
	if _, err := os.Stat(filepath.Join(appDir+appPreviousSuffix, "identity-evm.json")); err != nil {
		t.Fatalf("the in-flight install's previous dir was taken over: %v", err)
	}
	assertAbsent(t, appDir)
	if _, err := os.Stat(filepath.Join(appDir+appStagingSuffix, "manifest.json")); err != nil {
		t.Fatalf("the in-flight install's staging dir was touched: %v", err)
	}

	finishInFlightSwap(t, root, id)
	unlock()
	r := <-done
	if r.f != nil {
		t.Fatalf("install failed: %+v\n%s", r.f, r.errOut)
	}
	if !strings.Contains(r.out, "already installed") || !strings.Contains(r.out, "v1.0.1") {
		t.Fatalf("want the no-op answer about the version the other install put in place, got:\n%s", r.out)
	}
	if !strings.Contains(r.errOut, "waiting for another pilotctl") {
		t.Errorf("stderr should say it waited:\n%s", r.errOut)
	}
	assertAppStateKept(t, appDir, "after an install waited for another")
	assertAbsent(t, appDir+appPreviousSuffix)
	assertAbsent(t, appDir+appStagingSuffix)
}

func TestAppStoreInstallWaitsForAnInFlightSwap(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.inflightforce"
	appDir := filepath.Join(root, id)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local")
	seedAppState(t, appDir)
	unlock := startInFlightSwap(t, root, id, writeVersionedBundle(t, id, "1.0.1", "v2"))

	// An install --force of yet another version races the in-flight one.
	v3 := writeVersionedBundle(t, id, "1.0.2", "v3")
	done := make(chan *trappedFatal, 1)
	go func() {
		var f *trappedFatal
		_ = captureStderr(t, func() {
			_ = captureStdout(t, func() { f = runTrappingFatal(func() { cmdAppStoreInstall([]string{v3, "--local", "--force"}) }) })
		})
		done <- f
	}()
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(appDir+appPreviousSuffix, "identity-evm.json")); err != nil {
		t.Fatalf("the in-flight install's previous dir was taken over: %v", err)
	}
	if _, err := os.Stat(filepath.Join(appDir+appStagingSuffix, "manifest.json")); err != nil {
		t.Fatalf("the in-flight install's staging dir was touched: %v", err)
	}
	finishInFlightSwap(t, root, id)
	unlock()
	if f := <-done; f != nil {
		t.Fatalf("install failed: %+v", f)
	}
	if v := installedVersion(t, appDir); v != "1.0.2" {
		t.Fatalf("installed %s, want 1.0.2", v)
	}
	assertAppStateKept(t, appDir, "after two serialized installs")
	assertAbsent(t, appDir+appPreviousSuffix)
	assertAbsent(t, appDir+appStagingSuffix)
}

func TestSwapInAppDirRollbackSaysWhereThePreviousInstallIs(t *testing.T) {
	base := t.TempDir()
	final := filepath.Join(base, "io.test.rollback")
	staging := final + appStagingSuffix
	mustWrite(t, filepath.Join(final, "identity-evm.json"), "old key", 0o600)
	mustWrite(t, filepath.Join(staging, "manifest.json"), "new", 0o644)
	// Another process puts the old dir back right after the swap moved it
	// aside (what an unlocked crash recovery used to do).
	testHookAfterMoveAside = func() {
		if err := os.Rename(final+appPreviousSuffix, final); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { testHookAfterMoveAside = nil })

	prev, err := swapInAppDir(final, staging, nil)
	if err == nil || prev != "" {
		t.Fatalf("swap = (%q, %v), want a failure", prev, err)
	}
	if strings.Contains(err.Error(), "intact at "+final+appPreviousSuffix) {
		t.Fatalf("error claims the previous install is at %s, which does not exist: %v", final+appPreviousSuffix, err)
	}
	if !strings.Contains(err.Error(), "another process put it back") {
		t.Errorf("error should say where the previous install is: %v", err)
	}
	// No manifest-bearing staging dir is left for the supervisor to adopt.
	assertAbsent(t, staging)
	if got := mustRead(t, filepath.Join(final, "identity-evm.json")); got != "old key" {
		t.Fatalf("live install = %q", got)
	}
}

// ── F4: writes the running app makes during the swap are kept ─────────────

func TestReconcileAppStateTakesWhatTheOldProcessChanged(t *testing.T) {
	base := t.TempDir()
	oldDir, newDir := filepath.Join(base, "old"), filepath.Join(base, "new")
	mustWrite(t, filepath.Join(oldDir, "a-state.json"), `{"balance":100}`, 0o600)
	mustWrite(t, filepath.Join(oldDir, "b.json"), "b1", 0o600)
	mustWrite(t, filepath.Join(oldDir, "copied.json"), "c1", 0o600)
	mustWrite(t, filepath.Join(oldDir, "data.db-journal"), "hot journal", 0o600)
	mustWrite(t, filepath.Join(oldDir, "notes.txt"), "n", 0o600)
	mustWrite(t, filepath.Join(oldDir, "sub", "keep.txt"), "k", 0o600)
	mustWrite(t, filepath.Join(newDir, "bin", "app"), "new binary", 0o755)
	origLink := linkFile
	linkFile = func(oldname, newname string) error {
		if filepath.Base(oldname) == "copied.json" {
			return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: syscall.EXDEV}
		}
		return origLink(oldname, newname)
	}
	c, err := carryAppState(oldDir, newDir, "")
	linkFile = origLink
	if err != nil {
		t.Fatal(err)
	}

	// The old process, still running, with $APP naming the old dir:
	atomicWrite(t, filepath.Join(oldDir, "a-state.json"), `{"balance":42}`) // replaced
	mustWrite(t, filepath.Join(oldDir, "created.json"), "created after the carry", 0o600)
	mustWrite(t, filepath.Join(oldDir, "sub2", "nested.json"), "in a new dir", 0o600)
	if err := os.WriteFile(filepath.Join(oldDir, "copied.json"), []byte("c2, rewritten in place"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(oldDir, "data.db-journal")); err != nil { // transaction committed
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(oldDir, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	// b.json changed on both sides: the new install's write wins.
	atomicWrite(t, filepath.Join(oldDir, "b.json"), "b2 in the old dir")
	atomicWrite(t, filepath.Join(newDir, "b.json"), "b2 in the new install")

	r := reconcileAppState(oldDir, newDir, "", c)
	for rel, want := range map[string]string{
		"a-state.json":     `{"balance":42}`,
		"created.json":     "created after the carry",
		"sub2/nested.json": "in a new dir",
		"copied.json":      "c2, rewritten in place",
		"b.json":           "b2 in the new install",
		"sub/keep.txt":     "k",
		"notes.txt":        "n", // a non-volatile deletion is not mirrored
	} {
		if got := mustRead(t, filepath.Join(newDir, filepath.FromSlash(rel))); got != want {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
	// A stale rollback journal would roll back the committed transaction.
	assertAbsent(t, filepath.Join(newDir, "data.db-journal"))
	wantUpdated := []string{"a-state.json", "copied.json", "created.json", filepath.Join("sub2", "nested.json")}
	if !reflect.DeepEqual(r.Updated, wantUpdated) || !reflect.DeepEqual(r.Removed, []string{"data.db-journal"}) || len(r.Leftover) != 0 {
		t.Fatalf("reconcile = %+v, want updated %q, removed [data.db-journal]", r, wantUpdated)
	}
}

func TestAppStoreForceReinstallKeepsWritesMadeDuringTheSwap(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.atomicwrite"
	appDir := filepath.Join(root, id)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local")
	seedAppState(t, appDir)
	mustWrite(t, filepath.Join(appDir, "a-state.json"), `{"balance":100}`, 0o600)

	// Between the carry and the swap the running app saves its state the
	// usual way (temp file + rename) and writes a new file, through $APP.
	testHookBeforeSwap = func(live string) {
		atomicWrite(t, filepath.Join(live, "a-state.json"), `{"balance":42}`)
		mustWrite(t, filepath.Join(live, "receipts", "r1.json"), "receipt", 0o600)
	}
	t.Cleanup(func() { testHookBeforeSwap = nil })
	installQuiet(t, writeVersionedBundle(t, id, "1.1.0", "v2"), "--local", "--force")

	if got := mustRead(t, filepath.Join(appDir, "a-state.json")); got != `{"balance":42}` {
		t.Fatalf("a-state.json = %s: the write made during the swap was reverted", got)
	}
	if got := mustRead(t, filepath.Join(appDir, "receipts", "r1.json")); got != "receipt" {
		t.Fatalf("receipts/r1.json = %q", got)
	}
	assertAppStateKept(t, appDir, "after writes during the swap")
	if v := installedVersion(t, appDir); v != "1.1.0" {
		t.Fatalf("installed %s, want 1.1.0", v)
	}
}

// ── F5: install --version on an installed app does not fake success ────────

func TestAppStoreInstallPinnedVersionOnAnInstalledApp(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.pinned"
	appDir := filepath.Join(root, id)
	catPath := filepath.Join(t.TempDir(), "catalogue.json")
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+catPath)
	v1, v1SHA := tarGzBundle(t, writeVersionedBundle(t, id, "1.0.0", "v1"))
	publishSignedCatalogue(t, catPath, id, "1.0.0", v1, v1SHA)
	installQuiet(t, id)
	seedAppState(t, appDir)
	v2, v2SHA := tarGzBundle(t, writeVersionedBundle(t, id, "2.0.0", "v2"))
	publishSignedCatalogue(t, catPath, id, "2.0.0", v2, v2SHA)

	jsonOutput = true
	_, stderr, f := runTrapped(t, func() { cmdAppStoreInstall([]string{id, "--version", "2.0.0"}) })
	jsonOutput = false
	if f == nil || f.Code != "conflict" {
		t.Fatalf("install --version 2.0.0 over 1.0.0 without --force = %+v, want conflict\n%s", f, stderr)
	}
	if !strings.Contains(stderr, "--force") {
		t.Errorf("the conflict should say how to replace it:\n%s", stderr)
	}
	_, _, f = runTrapped(t, func() { cmdAppStoreInstall([]string{id, "--version", "9.9.9"}) })
	if f == nil || f.Code != "version_unavailable" {
		t.Fatalf("install --version 9.9.9 = %+v, want version_unavailable", f)
	}
	out, _, f := runTrapped(t, func() { cmdAppStoreInstall([]string{id, "--version", "1.0.0"}) })
	if f != nil || !strings.Contains(out, "already installed") {
		t.Fatalf("install --version <installed> = %+v, want the no-op answer, got:\n%s", f, out)
	}
	// A local bundle of another version is a pinned version too.
	_, _, f = runTrapped(t, func() { cmdAppStoreInstall([]string{writeVersionedBundle(t, id, "3.0.0", "v3"), "--local"}) })
	if f == nil || f.Code != "conflict" {
		t.Fatalf("local bundle of another version without --force = %+v, want conflict", f)
	}
	if v := installedVersion(t, appDir); v != "1.0.0" {
		t.Fatalf("installed %s after refused installs, want 1.0.0", v)
	}
	assertAppStateKept(t, appDir, "after refused installs")
	// With --force the pinned version is installed, state kept.
	installQuiet(t, id, "--version", "2.0.0", "--force")
	if v := installedVersion(t, appDir); v != "2.0.0" {
		t.Fatalf("installed %s, want 2.0.0", v)
	}
	assertAppStateKept(t, appDir, "after install --version --force")
}

// ── F6: backup locations and their fallbacks ──────────────────────────────

// writeReplacedInstall creates <root>/<id>.previous as a swap leaves it.
func writeReplacedInstall(t *testing.T, root, id string) string {
	t.Helper()
	prev := filepath.Join(root, id) + appPreviousSuffix
	mustWrite(t, filepath.Join(prev, "manifest.json"), string(validManifestJSON(id, strings.Repeat("a", 64))), 0o644)
	mustWrite(t, filepath.Join(prev, "bin", "app"), "old binary", 0o755)
	mustWrite(t, filepath.Join(prev, "identity-evm.json"), "key", 0o600)
	mustWrite(t, filepath.Join(prev, "data", "cache", "x"), "x", 0o600)
	if err := os.Symlink("identity-evm.json", filepath.Join(prev, "current-key")); err != nil {
		t.Fatal(err)
	}
	return prev
}

func assertStrippedBackup(t *testing.T, dir, kind string) {
	t.Helper()
	if got := mustRead(t, filepath.Join(dir, "identity-evm.json")); got != "key" {
		t.Fatalf("backup %s key = %q", dir, got)
	}
	if fi, err := os.Stat(filepath.Join(dir, "identity-evm.json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("backup key mode = %v, %v", fi, err)
	}
	if target, err := os.Readlink(filepath.Join(dir, "current-key")); err != nil || target != "identity-evm.json" {
		t.Errorf("backup symlink = %q, %v", target, err)
	}
	assertAbsent(t, filepath.Join(dir, "bin", "app"))
	if meta, ok := readBackupMeta(dir); !ok || meta.Kind != kind {
		t.Errorf("backup meta = %+v (ok=%v), want kind %s", meta, ok, kind)
	}
}

func TestRetireAppDirCopiesToABackupRootOnAnotherFilesystem(t *testing.T) {
	root := isolateAppStoreTest(t)
	backupRoot := filepath.Join(t.TempDir(), "other-fs")
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", backupRoot)
	orig := renameForBackup
	renameForBackup = func(oldpath, newpath string) error {
		if strings.HasPrefix(newpath, backupRoot) {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EXDEV}
		}
		return orig(oldpath, newpath)
	}
	t.Cleanup(func() { renameForBackup = orig })
	const id = "io.test.exdev"
	prev := writeReplacedInstall(t, root, id)

	dst, err := retireAppDir(prev, id, appBackupMeta{Kind: backupKindUpgrade})
	if err != nil {
		t.Fatalf("a backup root on another filesystem must work: %v", err)
	}
	if !strings.HasPrefix(dst, filepath.Join(backupRoot, id)+string(filepath.Separator)) {
		t.Fatalf("backup at %s, want it under the configured root %s", dst, backupRoot)
	}
	assertStrippedBackup(t, dst, backupKindUpgrade)
	assertAbsent(t, prev)
}

func TestRetireAppDirFallsBackWithoutGrowingOrHiding(t *testing.T) {
	root := isolateAppStoreTest(t)
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	mustWrite(t, blocker, "x", 0o600)
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", filepath.Join(blocker, "backups"))
	const id = "io.test.fallback"
	defaultLoc := filepath.Join(filepath.Dir(root), "app-backups")

	// 1. The configured root is unusable: the default beside the install
	//    root takes the backup, with a warning naming the problem.
	dst, err := retireAppDir(writeReplacedInstall(t, root, id), id, appBackupMeta{Kind: backupKindReinstall})
	if err == nil || !strings.Contains(err.Error(), "Fix that location") {
		t.Fatalf("want a warning about the configured root, got %v", err)
	}
	if !strings.HasPrefix(dst, filepath.Join(defaultLoc, id)) {
		t.Fatalf("backup at %s, want it in the default location", dst)
	}
	assertStrippedBackup(t, dst, backupKindReinstall)

	// 2. The default is unusable too: a dot-dir inside the install root,
	//    stripped and pruned like any other backup location.
	if err := os.RemoveAll(defaultLoc); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, defaultLoc, "not a dir", 0o600)
	inRoot := filepath.Join(root, inRootBackupDirName, id)
	for i := 0; i < appBackupKeep+2; i++ {
		stderr := captureStderr(t, func() {
			dst, err = retireAppDir(writeReplacedInstall(t, root, id), id, appBackupMeta{Kind: backupKindReinstall})
		})
		if err == nil || !strings.HasPrefix(dst, inRoot) {
			t.Fatalf("retire %d = (%s, %v), want the in-root fallback with a warning", i, dst, err)
		}
		if i == appBackupKeep && !strings.Contains(stderr, "note: removed the older backup") {
			t.Errorf("pruning must say so:\n%s", stderr)
		}
		assertStrippedBackup(t, dst, backupKindReinstall)
	}
	if entries, _ := os.ReadDir(inRoot); len(entries) != appBackupKeep {
		t.Fatalf("in-root fallback holds %d backups, want %d (pruned)", len(entries), appBackupKeep)
	}
	assertAbsent(t, filepath.Join(root, inRootBackupDirName, "manifest.json"))
	if apps, err := scanInstalledApps(); err != nil || len(apps) != 0 {
		t.Fatalf("the fallback dir shows up as an installed app: %v, %v", apps, err)
	}

	// 3. Nothing is usable: parked in the install root with the manifest
	//    disabled, still stripped and pruned.
	if err := os.RemoveAll(filepath.Join(root, inRootBackupDirName)); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, inRootBackupDirName), "not a dir", 0o600)
	for i := 0; i < appBackupKeep+2; i++ {
		_ = captureStderr(t, func() {
			dst, err = retireAppDir(writeReplacedInstall(t, root, id), id, appBackupMeta{Kind: backupKindReinstall})
		})
		if err == nil || !strings.HasPrefix(filepath.Base(dst), id+appPreviousSuffix+"-") {
			t.Fatalf("retire %d = (%s, %v), want a parked dir with a warning", i, dst, err)
		}
		assertAbsent(t, filepath.Join(dst, "manifest.json"))
		assertStrippedBackup(t, dst, backupKindReinstall)
	}
	parked := parkedBackups(root, id)
	if len(parked) != appBackupKeep {
		t.Fatalf("%d parked dirs in the install root, want %d (pruned)", len(parked), appBackupKeep)
	}
	assertAbsent(t, filepath.Join(root, id)+appPreviousSuffix)

	// Uninstall names every backup that is left, parked ones included.
	mustWrite(t, filepath.Join(root, id, "manifest.json"), string(validManifestJSON(id, strings.Repeat("a", 64))), 0o644)
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreUninstall([]string{id, "--yes"}) })
	jsonOutput = false
	var rpt struct {
		Backups []string `json:"backups"`
	}
	if err := json.Unmarshal([]byte(out), &rpt); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(rpt.Backups, parked) {
		t.Fatalf("uninstall lists %q, want the parked backups %q", rpt.Backups, parked)
	}
	for _, p := range parked {
		if _, err := os.Stat(filepath.Join(p, "identity-evm.json")); err != nil {
			t.Errorf("uninstall removed a backup (%s): %v", p, err)
		}
	}
}

func TestUninstallListsBackupsInEveryLocation(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.uninstallbackups"
	appDir := filepath.Join(root, id)
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	installQuiet(t, bundle, "--local")
	seedAppState(t, appDir)
	installQuiet(t, bundle, "--local", "--force") // → default location
	inRoot := filepath.Join(root, inRootBackupDirName, id, "20260101T000000.000000000Z-v0.9.0")
	mustWrite(t, filepath.Join(inRoot, "identity-evm.json"), "older key", 0o600)

	out := captureStdout(t, func() { cmdAppStoreUninstall([]string{id, "--yes"}) })
	if !strings.Contains(out, "2 backup(s) of earlier installs remain") || !strings.Contains(out, inRoot) ||
		!strings.Contains(out, filepath.Join(filepath.Dir(root), "app-backups", id)) {
		t.Fatalf("uninstall should list both backups, got:\n%s", out)
	}
	if errors.Is(func() error { _, err := os.Stat(inRoot); return err }(), fs.ErrNotExist) {
		t.Fatal("uninstall removed a backup")
	}
}
