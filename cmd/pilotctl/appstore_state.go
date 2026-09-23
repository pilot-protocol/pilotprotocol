// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// App state preservation across `appstore install --force` and
// `appstore upgrade` (which the hourly updater runs as `upgrade --all`, and
// which reinstalls through the same --force path).
//
// An installed app keeps its state inside its own directory, <root>/<id>/
// ($APP): the wallet's identity-evm.json and data.db, smol's secrets.json,
// each metered app's identity.json, the cap-state.jsonl spend-cap ledger the
// supervisor passes every app, and the supervisor.log audit trail. The install
// swap used to rename that dir to <id>.previous, move the fresh bundle into
// place and then RemoveAll the old dir, so every reinstall and every upgrade
// silently deleted all of it (for the wallet: the EVM private key).
//
// Every step below runs under the app's install lock (appstore_lock.go), so
// two pilotctl processes (the hourly `upgrade --all` and an agent's
// `install`) never interleave their swaps, and one never mistakes the other's
// in-flight swap for a crash leftover.
//
//  1. The new bundle is staged in <id>.staging (binary + aux files).
//  2. Everything in the live dir that the new bundle does not ship, and that
//     is not a bundle/pilotctl/supervisor control file, is hard-linked into
//     staging (copied when a link is impossible). Directories are created
//     owner-writable while they are filled and get their own mode back
//     afterwards, so a read-only dir (a Go module cache) carries like any
//     other. An entry this user can neither link nor read (a root-owned file
//     left by a daemon once run with sudo) cannot be linked or copied; it is
//     moved across whole after the swap (step 5). The carried set is checked
//     in staging.
//  3. manifest.json is written last, so the supervisor never sees a
//     manifest-bearing staging dir that is still being filled.
//  4. The live dir is renamed to <id>.previous and staging to <id>. The new
//     dir is verified (manifest bytes, binary sha256, carried state). On any
//     failure the previous dir is put back and staging is discarded.
//  5. Reconcile. The old process keeps running until the supervisor restarts
//     it (on its next rescan, up to ~30s later). Hard links carry every write
//     it makes to an existing file in place, but until the swap its $APP
//     still named the old dir, so a file it replaced there (write a temp file,
//     rename it over) or created there after step 2 would otherwise exist only
//     in the old dir. The old dir is walked again: such files are linked into
//     the new dir unless the new dir's copy changed since the carry (then that
//     newer write wins), volatile sidecars the app deleted there (SQLite
//     -journal/-wal, lock and pid files) are dropped from the new dir too, and
//     the entries step 2 could not link are moved across. Writes the old
//     process makes after this through $APP land in the new install; a write
//     through a path relative to its working directory (which still names the
//     old dir) lands in the retired copy until the supervisor restarts it.
//  6. <id>.previous is retired: moved OUT of the install root (the supervisor
//     adopts any dir there that holds a manifest, and a same-version .previous
//     would win over the live dir at daemon start) into
//     <backup root>/<id>/<timestamp>-v<old version>/, without the old binary.
//     retireAppDir says where it goes when that root is unusable, and
//     pruneBackupDirs how long it is kept: routine backups are rotated, a
//     backup holding the only copy of something is never removed.
//
// `install --force --reset-state` is the explicit destructive variant: steps 2
// and 5 are skipped (the new install starts empty) but step 6 still keeps the
// old dir, as a backup retention never removes, and a loud warning names it.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

const (
	appPreviousSuffix = ".previous"
	appStagingSuffix  = ".staging"

	// appBackupKeep is how many routine backups of each kind (see
	// backupKindRotated) are kept per app and backup location.
	appBackupKeep = 3

	// appBackupDetachMax bounds which backup files are turned into
	// independent copies. Carried state is hard-linked, so a retired dir
	// shares inodes with the live one; small files (keys, secrets, config)
	// are copied so an in-place rewrite by a later version cannot reach the
	// backup. Larger files (databases) stay linked: they are protected from
	// deletion and replacement, which is the failure this guards against.
	appBackupDetachMax = 1 << 20

	// appBackupMetaName is written into every backup. It records what kind
	// of backup it is, which decides whether retention may ever remove it.
	appBackupMetaName = ".pilot-backup.json"

	// inRootBackupDirName is the last backup location tried: a dir inside the
	// install root, so a backup is a same-filesystem rename even when every
	// other location is unusable. It holds no manifest.json and starts with a
	// dot, so neither the supervisor nor `list` treats it as an app.
	inRootBackupDirName = ".app-backups"
)

// Backup kinds. Routine ones are rotated; every other kind holds the only
// copy of something and is never removed automatically.
const (
	backupKindUpgrade    = "upgrade"     // replaced by a different version (routine)
	backupKindReinstall  = "reinstall"   // replaced by the same version (routine)
	backupKindResetState = "reset-state" // --reset-state: the only copy of the dropped state
	backupKindIncomplete = "incomplete"  // holds state that could not be carried into the new install
	backupKindRecovered  = "recovered"   // a leftover found by crash recovery; what it holds is unknown
)

// backupKindRotated reports the kinds retention may prune. Anything else,
// including a backup without readable metadata, is kept until a person
// removes it.
func backupKindRotated(kind string) bool {
	return kind == backupKindUpgrade || kind == backupKindReinstall
}

// Test seams. Production code never reassigns them.
var (
	linkFile               = os.Link   // hard-links a carried file
	renameForBackup        = os.Rename // moves a replaced install into a backup location
	testHookBeforeSwap     func(liveDir string)
	testHookAfterMoveAside func()
)

// appDirControlFiles are top-level entries of an installed app dir that belong
// to the bundle, to pilotctl or to the supervisor rather than to the app. They
// are never carried into a new install: the new bundle or the install itself
// recreates the ones that should exist.
var appDirControlFiles = map[string]bool{
	"manifest.json":             true, // bundle: always the new one
	"install.json":              true, // bundle aux (native-delivery spec)
	"install.sh":                true, // bundle aux
	manifest.SideloadMarkerName: true, // set per install source; a catalogue reinstall must drop it
	".suspended":                true, // supervisor crash-loop marker: a new install starts clean
	".resume":                   true, // one-shot restart request
	bundleSHAMarker:             true, // rewritten by every catalogue install
	nextStepsFileName:           true, // catalogue-derived cache, re-fetched at install
	nsCheckedMarker:             true,
	nsRetryMarker:               true,
	"app.sock":                  true, // the running process's socket, recreated at spawn
	appBackupMetaName:           true, // backup bookkeeping, if a backup was restored by hand
}

// appStoreBackupRoot is where retired installs are kept: $PILOT_APPSTORE_BACKUP_ROOT,
// or an "app-backups" dir beside the install root (~/.pilot/app-backups for
// the default ~/.pilot/apps). It must be outside the install root, which the
// supervisor scans for apps.
func appStoreBackupRoot() string {
	if r := os.Getenv("PILOT_APPSTORE_BACKUP_ROOT"); r != "" {
		return r
	}
	return defaultAppStoreBackupRoot()
}

func defaultAppStoreBackupRoot() string {
	return filepath.Join(filepath.Dir(filepath.Clean(appStoreRoot())), "app-backups")
}

// backupLocations lists where retired installs go, in the order they are
// tried: the configured backup root, the default one beside the install root
// (when a different one is configured), and last the in-root fallback.
func backupLocations() []string {
	locs := []string{appStoreBackupRoot()}
	if def := defaultAppStoreBackupRoot(); filepath.Clean(locs[0]) != filepath.Clean(def) {
		locs = append(locs, def)
	}
	return append(locs, filepath.Join(appStoreRoot(), inRootBackupDirName))
}

// readInstalledManifest returns the manifest of the app installed at dir, or an
// error when dir holds no readable, parseable manifest.
func readInstalledManifest(dir string) (*manifest.Manifest, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")) // #nosec G304 -- dir is <install root>/<validated app id>
	if err != nil {
		return nil, nil, err
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	return m, raw, nil
}

// recoverInterruptedInstall repairs what a crashed or killed install can leave
// behind, before anything else touches the app dir. The caller holds the app's
// install lock, so nothing it finds belongs to an install still in progress.
// It never deletes state:
//
//   - <id>.previous without <id>: the swap died after moving the live install
//     aside. The previous install is the only copy of the app's state, so it
//     is put back.
//   - <id>.previous beside <id>: the swap finished but the old dir was never
//     retired. It is moved to the backups like any other replaced install.
//   - <id>.staging: an install died before its swap. Staging only ever holds
//     the new bundle plus links or copies of state whose originals are in the
//     live dir, so it is discarded (a manifest-bearing staging dir would
//     otherwise be adopted by the supervisor as a second copy of the app).
//
// It returns human-readable notes describing what it did.
func recoverInterruptedInstall(finalDir, appID string) ([]string, error) {
	var notes []string
	previousDir := finalDir + appPreviousSuffix
	if _, err := os.Lstat(previousDir); err == nil {
		if _, err := os.Lstat(finalDir); errors.Is(err, fs.ErrNotExist) {
			if err := os.Rename(previousDir, finalDir); err != nil {
				return nil, fmt.Errorf("restore interrupted install %s → %s: %w", previousDir, finalDir, err)
			}
			notes = append(notes, fmt.Sprintf("restored %s from an interrupted install (%s)", appID, previousDir))
		} else {
			backup, err := retireAppDir(previousDir, appID, appBackupMeta{
				Kind:   backupKindRecovered,
				Reason: "left behind by an interrupted install",
			})
			if backup == "" {
				return nil, fmt.Errorf("retire leftover %s: %w", previousDir, err)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "warn: %v\n", err)
			}
			notes = append(notes, fmt.Sprintf("moved a leftover previous install of %s to %s", appID, backup))
		}
	}
	stagingDir := finalDir + appStagingSuffix
	if _, err := os.Lstat(stagingDir); err == nil {
		if err := discardStagingDir(stagingDir); err != nil {
			return notes, fmt.Errorf("remove the unfinished install %s: %w", stagingDir, err)
		}
		notes = append(notes, fmt.Sprintf("removed an unfinished install of %s (%s)", appID, stagingDir))
	}
	return notes, nil
}

// ── carry (step 2) ──────────────────────────────────────────────────────────

// carriedEntry is what one carried file or symlink looked like at carry time,
// in the old dir (src) and in the new one (dst). The post-swap reconcile uses
// it to tell a change the old process made in the old dir (take it) from one
// made in the new dir (keep it).
type carriedEntry struct {
	src, dst fs.FileInfo
	target   string // symlink target
}

// appStateCarry is the result of carryAppState.
type appStateCarry struct {
	// Carried lists the files and symlinks now in the new dir, relative to
	// the app dir, sorted.
	Carried []string
	// Unreadable lists entries this user could neither link nor read. They
	// are moved into the new install after the swap (reconcileAppState).
	Unreadable []string

	entries map[string]carriedEntry
	dirs    map[string]bool // dirs created in, or merged into, the new dir
}

// dirModes remembers the modes of dirs that are made owner-writable while
// they are filled, to restore them afterwards (deepest first).
type dirModes []struct {
	path string
	perm fs.FileMode
}

func (m *dirModes) add(path string, perm fs.FileMode) {
	*m = append(*m, struct {
		path string
		perm fs.FileMode
	}{path, perm})
}

func (m dirModes) restore() {
	for i := len(m) - 1; i >= 0; i-- {
		_ = os.Chmod(m[i].path, m[i].perm)
	}
}

// withWritableDir runs fn with dir temporarily owner-writable and searchable
// when its mode denies that, and restores the mode afterwards.
func withWritableDir(dir string, fn func() error) error {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm()&0o300 == 0o300 {
		return fn()
	}
	if err := os.Chmod(dir, fi.Mode().Perm()|0o700); err != nil {
		return fn()
	}
	defer func() { _ = os.Chmod(dir, fi.Mode().Perm()) }()
	return fn()
}

func cleanRel(rel string) string {
	if rel == "" {
		return ""
	}
	return filepath.Clean(filepath.FromSlash(rel))
}

// skipStateEntry reports entries that are never app state: top-level control
// files and the old manifest's binary (a stale binary is not state).
func skipStateEntry(rel, oldBin string) bool {
	topLevel := !strings.ContainsRune(rel, filepath.Separator)
	return (topLevel && appDirControlFiles[rel]) || (oldBin != "" && rel == oldBin)
}

// carryAppState links (or copies) every piece of app state in oldDir into
// newDir: every file, symlink and directory except
//
//   - top-level control files (appDirControlFiles),
//   - the old manifest's binary (oldBinaryRel),
//   - anything the new bundle already placed in newDir (the bundle wins),
//   - sockets, pipes, devices and *.sock files.
//
// A file that disappears while it is being carried (a transient journal the
// running app just deleted) is skipped. An entry this user can neither link
// nor read is listed in Unreadable instead of failing the install. Any other
// error (disk full, I/O) fails the carry, and nothing has been changed.
func carryAppState(oldDir, newDir, oldBinaryRel string) (*appStateCarry, error) {
	oldBin := cleanRel(oldBinaryRel)
	c := &appStateCarry{entries: map[string]carriedEntry{}, dirs: map[string]bool{}}
	created := map[string]bool{}
	var modes dirModes
	defer func() { modes.restore() }()

	err := filepath.WalkDir(oldDir, func(path string, d fs.DirEntry, walkErr error) error {
		rel, err := filepath.Rel(oldDir, path)
		if err != nil {
			return err
		}
		if walkErr != nil {
			switch {
			case rel == ".":
				return walkErr
			case errors.Is(walkErr, fs.ErrNotExist):
				return nil
			case errors.Is(walkErr, fs.ErrPermission):
				// A dir this user cannot list. Drop the empty copy made on
				// the first visit: the dir is moved across whole after the
				// swap.
				if created[rel] {
					_ = os.Remove(filepath.Join(newDir, rel))
					delete(created, rel)
					delete(c.dirs, rel)
				}
				c.Unreadable = append(c.Unreadable, rel)
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			return walkErr
		}
		if rel == "." {
			return nil
		}
		if skipStateEntry(rel, oldBin) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		dst := filepath.Join(newDir, rel)
		existing, existErr := os.Lstat(dst)
		exists := existErr == nil
		switch typ := d.Type(); {
		case typ.IsDir():
			if exists {
				if existing.IsDir() {
					c.dirs[rel] = true
					return nil // the bundle ships this dir too; merge into it
				}
				fmt.Fprintf(os.Stderr, "warn: not carrying %s/: the new bundle ships a file at that path\n", rel)
				return fs.SkipDir
			}
			info, err := d.Info()
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return fs.SkipDir
				}
				return err
			}
			// Owner-writable while it is filled; its own mode is restored
			// once the walk is done.
			if err := os.Mkdir(dst, 0o700); err != nil {
				return fmt.Errorf("carry %s/: %w", rel, err)
			}
			modes.add(dst, info.Mode().Perm())
			c.dirs[rel] = true
			created[rel] = true
		case typ&fs.ModeSymlink != 0:
			if exists {
				return nil
			}
			src, err := os.Lstat(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			target, err := os.Readlink(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if err := os.Symlink(target, dst); err != nil { // #nosec G122 -- dst is in our staging dir; the walked app dir belongs to the same user, so a path race gains nothing the app could not do itself
				return fmt.Errorf("carry %s: %w", rel, err)
			}
			c.record(rel, src, dst, target)
		case typ.IsRegular():
			if exists || strings.HasSuffix(d.Name(), ".sock") {
				return nil
			}
			// Lstat BEFORE the link: if the app replaces the file in
			// between, the reconcile sees a changed source and relinks.
			src, err := os.Lstat(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if err := linkOrCopy(path, dst); err != nil {
				switch {
				case errors.Is(err, fs.ErrNotExist):
					return nil
				case errors.Is(err, fs.ErrPermission):
					_ = os.Remove(dst) // never leave a partial copy
					c.Unreadable = append(c.Unreadable, rel)
					return nil
				}
				return fmt.Errorf("carry %s: %w", rel, err)
			}
			c.record(rel, src, dst, "")
		}
		// Sockets, named pipes and devices are runtime objects, not state.
		return nil
	})
	sort.Strings(c.Carried)
	sort.Strings(c.Unreadable)
	return c, err
}

func (c *appStateCarry) record(rel string, src fs.FileInfo, dst, target string) {
	c.Carried = append(c.Carried, rel)
	if di, err := os.Lstat(dst); err == nil {
		c.entries[rel] = carriedEntry{src: src, dst: di, target: target}
	}
}

// linkOrCopy hard-links src to dst, falling back to a mode-preserving copy when
// the filesystem refuses the link.
func linkOrCopy(src, dst string) error {
	if err := linkFile(src, dst); err == nil {
		return nil
	} else if errors.Is(err, fs.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	return copyFile(src, dst, info.Mode().Perm())
}

// volatileStateFile reports files whose lifecycle the running app owns and
// that may legitimately vanish between the carry and the post-swap check
// (SQLite sidecars, lock/pid/temp files). They are carried like everything
// else but not required to still exist after the swap, and one the app deleted
// from the old dir during the swap is dropped from the new dir too (a stale
// SQLite rollback journal would otherwise roll back a committed transaction).
func volatileStateFile(rel string) bool {
	name := filepath.Base(rel)
	for _, suffix := range []string{"-journal", "-wal", "-shm", ".lock", ".pid", ".tmp", "~"} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// verifyCarriedState checks that every carried path exists under dir. With
// skipVolatile it tolerates volatile files the app may have removed since.
func verifyCarriedState(dir string, carried []string, skipVolatile bool) error {
	for _, rel := range carried {
		if skipVolatile && volatileStateFile(rel) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(dir, rel)); err != nil {
			return fmt.Errorf("carried state %s is missing: %w", rel, err)
		}
	}
	return nil
}

// verifyInstalledApp is the post-swap check on the new live dir: it holds the
// exact manifest we staged, the binary it pins, and the carried state.
func verifyInstalledApp(dir string, wantManifest []byte, m *manifest.Manifest, carried []string) error {
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json")) // #nosec G304 -- dir is <install root>/<validated app id>
	if err != nil {
		return fmt.Errorf("read installed manifest: %w", err)
	}
	if string(raw) != string(wantManifest) {
		return errors.New("installed manifest does not match the staged one")
	}
	bin, err := resolveUnder(dir, m.Binary.Path)
	if err != nil {
		return fmt.Errorf("binary path: %w", err)
	}
	if got := sha256File(bin); got != m.Binary.SHA256 {
		return fmt.Errorf("installed binary sha256 %s does not match the manifest pin %s", got, m.Binary.SHA256)
	}
	return verifyCarriedState(dir, carried, true)
}

// ── swap (step 4) ───────────────────────────────────────────────────────────

// swapInAppDir moves stagingDir into place at finalDir. A live install at
// finalDir is renamed to finalDir+".previous" first and is left there (never
// deleted) until verify accepts the new dir; on any failure the previous
// install is put back and staging is discarded. It returns the previous dir's
// path when there was one, for the caller to reconcile and retire.
func swapInAppDir(finalDir, stagingDir string, verify func(dir string) error) (string, error) {
	previousDir := finalDir + appPreviousSuffix
	if _, err := os.Lstat(previousDir); err == nil {
		return "", withStagingDiscarded(stagingDir, fmt.Errorf("%s already exists; refusing to overwrite it (it may hold the only copy of the app's state)", previousDir))
	}
	hadOld := false
	if _, err := os.Lstat(finalDir); err == nil {
		if err := os.Rename(finalDir, previousDir); err != nil {
			return "", withStagingDiscarded(stagingDir, fmt.Errorf("move the current install aside: %w (the current install is unchanged)", err))
		}
		hadOld = true
		if testHookAfterMoveAside != nil {
			testHookAfterMoveAside()
		}
	}
	placed := false
	rollback := func(cause error) error {
		if placed {
			// Park the rejected new dir back at the staging path; it only
			// holds the new bundle plus links to state whose originals are
			// in previousDir.
			if err := os.Rename(finalDir, stagingDir); err != nil {
				if hadOld {
					return fmt.Errorf("%w; rollback failed: could not move the rejected new install aside (%v); %s", cause, err, locatePreviousInstall(previousDir, finalDir))
				}
				return fmt.Errorf("%w; could not remove the rejected install at %s: %v", cause, finalDir, err)
			}
		}
		var restoreErr error
		if hadOld {
			restoreErr = os.Rename(previousDir, finalDir)
		}
		// Staging never holds the only copy of anything, and must not stay
		// in the install root with a manifest the supervisor would adopt.
		cause = withStagingDiscarded(stagingDir, cause)
		if !hadOld {
			return cause
		}
		if restoreErr != nil {
			return fmt.Errorf("%w; rollback failed: %v — %s", cause, restoreErr, locatePreviousInstall(previousDir, finalDir))
		}
		return fmt.Errorf("%w (the previous install was restored unchanged)", cause)
	}
	if err := os.Rename(stagingDir, finalDir); err != nil {
		return "", rollback(fmt.Errorf("move the new install into place: %w", err))
	}
	placed = true
	if verify != nil {
		if err := verify(finalDir); err != nil {
			return "", rollback(fmt.Errorf("verify the new install: %w", err))
		}
	}
	if !hadOld {
		return "", nil
	}
	return previousDir, nil
}

// locatePreviousInstall says where the previous install actually is after a
// failed rollback, instead of assuming it is still where the swap left it.
func locatePreviousInstall(previousDir, finalDir string) string {
	if _, err := os.Lstat(previousDir); err == nil {
		return fmt.Sprintf("the previous install is intact at %s; move it back to %s", previousDir, finalDir)
	}
	if _, err := os.Lstat(finalDir); err == nil {
		return fmt.Sprintf("an install is in place at %s (another process put it back); nothing was deleted", finalDir)
	}
	return fmt.Sprintf("neither %s nor %s exists; look for the previous install under %s", previousDir, finalDir, appStoreBackupRoot())
}

// withStagingDiscarded discards stagingDir and folds a failure to do so into
// cause.
func withStagingDiscarded(stagingDir string, cause error) error {
	if err := discardStagingDir(stagingDir); err != nil {
		return fmt.Errorf("%w; %v", cause, err)
	}
	return cause
}

// discardStagingDir removes a staging dir that is not going to be installed.
// Staging only ever holds the new bundle plus links or copies of state whose
// originals are elsewhere, so removing it loses nothing. When it cannot be
// removed whole, its manifest is disabled so the supervisor never adopts it.
func discardStagingDir(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	rmErr := removeAllForce(dir)
	if rmErr == nil {
		return nil
	}
	mf := filepath.Join(dir, "manifest.json")
	if err := os.Rename(mf, mf+".disabled"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("could not remove %s (%v) or disable its manifest (%v); remove it by hand before the daemon rescans", dir, rmErr, err)
	}
	return fmt.Errorf("could not remove %s (%v); its manifest is disabled so the daemon will not load it", dir, rmErr)
}

// removeAllForce is os.RemoveAll for a tree that may contain read-only dirs
// (a carried Go module cache): when the first attempt fails, every dir in the
// tree is made owner-writable and the removal is retried.
func removeAllForce(dir string) error {
	if err := os.RemoveAll(dir); err == nil {
		return nil
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			if info, ierr := d.Info(); ierr == nil && info.Mode().Perm()&0o700 != 0o700 {
				_ = os.Chmod(path, info.Mode().Perm()|0o700) // #nosec G122 -- a staging/backup/app dir of the same user; only adds owner bits so it can be removed
			}
		}
		return nil
	})
	return os.RemoveAll(dir) // #nosec G703 -- callers pass install-root staging/previous dirs or backup dirs we created
}

// ── reconcile (step 5) ──────────────────────────────────────────────────────

// stateReconcile is the result of reconcileAppState.
type stateReconcile struct {
	Updated  []string // entries brought into the new install (new, replaced or moved)
	Removed  []string // volatile files the app deleted from the old dir, dropped from the new one
	Leftover []string // state that stayed only in the old dir (its backup keeps it)
}

// reconcileAppState is step 5 (see the top of this file): after the swap and
// before the old dir is retired, it brings into newDir what the still-running
// old process changed in oldDir since carryAppState, and moves across the
// entries the carry could not link. The new dir's own changes always win.
func reconcileAppState(oldDir, newDir, oldBinaryRel string, c *appStateCarry) stateReconcile {
	var r stateReconcile
	oldBin := cleanRel(oldBinaryRel)

	// Entries this user cannot link or read: move them whole. A rename needs
	// no read access to the entry itself.
	unreadable := make(map[string]bool, len(c.Unreadable))
	for _, rel := range c.Unreadable {
		unreadable[rel] = true
		src := filepath.Join(oldDir, rel)
		if err := moveStateEntry(src, filepath.Join(newDir, rel)); err != nil {
			if _, lerr := os.Lstat(src); errors.Is(lerr, fs.ErrNotExist) {
				continue // the app deleted it since
			}
			r.Leftover = append(r.Leftover, rel)
			continue
		}
		r.Updated = append(r.Updated, rel)
	}

	var modes dirModes
	_ = filepath.WalkDir(oldDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path == oldDir {
				return err
			}
			return nil // vanished, or unreadable: handled above
		}
		rel, rerr := filepath.Rel(oldDir, path)
		if rerr != nil || rel == "." {
			return nil
		}
		if skipStateEntry(rel, oldBin) || unreadable[rel] {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		dst := filepath.Join(newDir, rel)
		live, liveErr := os.Lstat(dst)
		if d.IsDir() {
			if liveErr == nil {
				if live.IsDir() {
					return nil
				}
				return fs.SkipDir // the new bundle ships a file at that path
			}
			if c.dirs[rel] || !errors.Is(liveErr, fs.ErrNotExist) {
				return fs.SkipDir // carried, then removed from the new install by the app: keep it removed
			}
			info, ierr := d.Info()
			if ierr != nil {
				return fs.SkipDir
			}
			// Created in the old dir after the carry.
			if merr := withWritableDir(filepath.Dir(dst), func() error { return os.Mkdir(dst, 0o700) }); merr != nil {
				r.Leftover = append(r.Leftover, rel+string(filepath.Separator))
				return fs.SkipDir
			}
			modes.add(dst, info.Mode().Perm())
			c.dirs[rel] = true
			return nil
		}
		typ := d.Type()
		if !typ.IsRegular() && typ&fs.ModeSymlink == 0 {
			return nil
		}
		if typ.IsRegular() && strings.HasSuffix(d.Name(), ".sock") {
			return nil
		}
		cur, cerr := os.Lstat(path)
		if cerr != nil {
			return nil
		}
		e, wasCarried := c.entries[rel]
		if !wasCarried {
			if !errors.Is(liveErr, fs.ErrNotExist) {
				return nil // the bundle ships it, or the app already wrote it in the new install
			}
			// Created in the old dir after the carry.
			if err := placeStateEntry(path, dst, cur); err != nil {
				r.Leftover = append(r.Leftover, rel)
				return nil
			}
			r.Updated = append(r.Updated, rel)
			return nil
		}
		if liveErr != nil {
			return nil // the app removed it from the new install: keep it removed
		}
		if !sameStateEntry(live, e.dst) {
			return nil // changed in the new install since the carry: that write is newer
		}
		if sameStateEntry(cur, e.src) && (typ&fs.ModeSymlink == 0 || readlinkIs(path, e.target)) {
			return nil // unchanged
		}
		// Replaced (or, for a copied file, rewritten) in the old dir after
		// the carry: take that version.
		if err := replaceStateEntry(path, dst, cur); err != nil {
			r.Leftover = append(r.Leftover, rel)
			return nil
		}
		r.Updated = append(r.Updated, rel)
		return nil
	})
	modes.restore()

	// Volatile sidecars the app deleted from the old dir after the carry.
	for rel, e := range c.entries {
		if !volatileStateFile(rel) {
			continue
		}
		if _, err := os.Lstat(filepath.Join(oldDir, rel)); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		dst := filepath.Join(newDir, rel)
		live, err := os.Lstat(dst)
		if err != nil || !sameStateEntry(live, e.dst) {
			continue
		}
		if withWritableDir(filepath.Dir(dst), func() error { return os.Remove(dst) }) == nil {
			r.Removed = append(r.Removed, rel)
		}
	}
	sort.Strings(r.Updated)
	sort.Strings(r.Removed)
	sort.Strings(r.Leftover)
	return r
}

// sameStateEntry reports whether two Lstat results name the same, unmodified
// file: same inode, size and modification time.
func sameStateEntry(a, b fs.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func readlinkIs(path, target string) bool {
	got, err := os.Readlink(path)
	return err == nil && got == target
}

// placeStateEntry puts the file or symlink at src into dst (which does not
// exist): a hard link, a copy, or, for a file this user cannot read, a move.
func placeStateEntry(src, dst string, info fs.FileInfo) error {
	return withWritableDir(filepath.Dir(dst), func() error {
		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(src)
			if err != nil {
				return err
			}
			return os.Symlink(target, dst)
		}
		err := linkOrCopy(src, dst)
		if errors.Is(err, fs.ErrPermission) {
			_ = os.Remove(dst)
			return moveStateEntry(src, dst)
		}
		return err
	})
}

// replaceStateEntry atomically replaces dst with the file or symlink at src.
func replaceStateEntry(src, dst string, info fs.FileInfo) error {
	dir := filepath.Dir(dst)
	return withWritableDir(dir, func() error {
		tmp := filepath.Join(dir, fmt.Sprintf(".pilot-reconcile-%d-%s", time.Now().UnixNano(), filepath.Base(dst)))
		if err := placeStateEntry(src, tmp, info); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		return nil
	})
}

// moveStateEntry renames src to dst (which must not exist), making the parent
// dirs (and, for a dir moved to a new parent, the dir itself) temporarily
// owner-writable when their modes deny it. Only entries this user owns, or
// whose parents it can write, can move; anything else stays where it is.
func moveStateEntry(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s: %w", dst, fs.ErrExist)
	}
	return withWritableDir(filepath.Dir(src), func() error {
		return withWritableDir(filepath.Dir(dst), func() error {
			err := os.Rename(src, dst)
			if !errors.Is(err, fs.ErrPermission) {
				return err
			}
			// Moving a dir to a new parent rewrites its ".." entry, which
			// needs write access to the dir itself.
			fi, lerr := os.Lstat(src)
			if lerr != nil || !fi.IsDir() || os.Chmod(src, fi.Mode().Perm()|0o700) != nil {
				return err
			}
			err = os.Rename(src, dst)
			if err != nil {
				_ = os.Chmod(src, fi.Mode().Perm())
				return err
			}
			_ = os.Chmod(dst, fi.Mode().Perm())
			return nil
		})
	})
}

// ── backups (step 6) ────────────────────────────────────────────────────────

// appBackupMeta is the .pilot-backup.json written into every backup.
type appBackupMeta struct {
	AppID       string `json:"app_id"`
	Kind        string `json:"kind"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	// Pinned backups are never removed by retention.
	Pinned bool   `json:"pinned"`
	Reason string `json:"reason,omitempty"`
	// NotCarried lists state (relative to the app dir) that is in this
	// backup but could not be carried into the install that replaced it.
	NotCarried []string `json:"not_carried,omitempty"`
	CreatedAt  string   `json:"created_at"`
}

// replacedInstallBackupKind classifies the backup of a replaced install.
func replacedInstallBackupKind(resetState bool, leftover []string, fromVersion, toVersion string) string {
	switch {
	case resetState:
		return backupKindResetState
	case len(leftover) > 0:
		return backupKindIncomplete
	case fromVersion == "":
		return backupKindRecovered // no readable manifest: a broken install we repaired
	case fromVersion != toVersion:
		return backupKindUpgrade
	default:
		return backupKindReinstall
	}
}

var unsafeBackupNameChars = regexp.MustCompile(`[^0-9A-Za-z._+-]`)

// retireAppDir moves a replaced install out of the install root into
// <location>/<id>/<timestamp>[-v<version>]/, strips what is not state (the
// old binary, a dead socket), makes small files independent copies, records
// meta in it, and applies retention to that app's backups there.
//
// The locations are tried in order (backupLocations): the configured backup
// root, the default one beside the install root, and a dot-dir inside the
// install root. A location on another filesystem is written by copying (then
// the original is removed). Only when every location fails does the dir stay
// in the install root, renamed <id>.previous-<timestamp> with its manifest
// disabled so the supervisor can never adopt it; it gets the same stripping,
// metadata and retention.
//
// It returns where the backup is. A non-nil error with a non-empty path is a
// warning (the backup is not where it was configured to go); with an empty
// path, the dir could not be retired at all.
func retireAppDir(previousDir, appID string, meta appBackupMeta) (string, error) {
	oldBinary := ""
	if m, _, err := readInstalledManifest(previousDir); err == nil {
		oldBinary = m.Binary.Path
		if meta.FromVersion == "" {
			meta.FromVersion = m.AppVersion
		}
	}
	now := time.Now().UTC()
	stamp := now.Format("20060102T150405.000000000Z")
	name := stamp
	if meta.FromVersion != "" {
		name += "-v" + unsafeBackupNameChars.ReplaceAllString(meta.FromVersion, "_")
	}
	meta.AppID = appID
	meta.CreatedAt = now.Format(time.RFC3339Nano)
	meta.Pinned = !backupKindRotated(meta.Kind)

	root := filepath.Clean(appStoreRoot())
	inRoot := filepath.Join(root, inRootBackupDirName)
	var failures []string
	for i, loc := range backupLocations() {
		if c := filepath.Clean(loc); c != inRoot && (c == root || strings.HasPrefix(c, root+string(filepath.Separator))) {
			failures = append(failures, fmt.Sprintf("%s: inside the install root", loc))
			continue
		}
		dst, err := moveIntoBackupLocation(previousDir, loc, appID, name, oldBinary)
		if dst == "" {
			failures = append(failures, fmt.Sprintf("%s: %v", loc, err))
			continue
		}
		finishBackup(dst, oldBinary, meta)
		reportPrunedBackups(pruneAppBackups(filepath.Dir(dst), appBackupKeep))
		switch {
		case err != nil:
			return dst, err
		case i > 0:
			return dst, fmt.Errorf("could not keep the replaced install of %s in %s (%s); it is kept at %s instead. Fix that location so later backups go there",
				appID, filepath.Join(appStoreBackupRoot(), appID), strings.Join(failures, "; "), dst)
		}
		return dst, nil
	}

	parked := previousDir + "-" + stamp
	if err := os.Rename(previousDir, parked); err != nil {
		parked = previousDir
	}
	if err := disableManifest(parked); err != nil {
		return parked, fmt.Errorf("could not move the replaced install of %s to any backup location (%s), and disabling its manifest failed (%v); remove or move %s by hand before the daemon restarts",
			appID, strings.Join(failures, "; "), err, parked)
	}
	finishBackup(parked, oldBinary, meta)
	if parked != previousDir {
		reportPrunedBackups(pruneBackupDirs(parkedBackups(root, appID), appBackupKeep))
	}
	return parked, fmt.Errorf("could not move the replaced install of %s to any backup location (%s); it is kept at %s with its manifest disabled",
		appID, strings.Join(failures, "; "), parked)
}

// moveIntoBackupLocation moves previousDir to <loc>/<appID>/<name>. Across
// filesystems it copies (without the old binary), then removes the original;
// if only that removal fails, the copy is returned with a warning and the
// remainder is parked with its manifest disabled.
func moveIntoBackupLocation(previousDir, loc, appID, name, oldBinary string) (string, error) {
	appBackups, err := resolveUnder(loc, appID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(appBackups, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(appBackups, name)
	for i := 1; ; i++ { // same-timestamp collision on a coarse clock
		if _, lerr := os.Lstat(dst); lerr != nil {
			break
		}
		dst = filepath.Join(appBackups, fmt.Sprintf("%s.%d", name, i))
	}
	err = renameForBackup(previousDir, dst)
	if err == nil {
		return dst, nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return "", err
	}
	if err := copyTreeForBackup(previousDir, dst, oldBinary); err != nil {
		_ = removeAllForce(dst)
		return "", fmt.Errorf("copy to another filesystem: %w", err)
	}
	// The copy is complete. Disable the original's manifest first, so a
	// removal that fails halfway can never leave an adoptable dir behind.
	_ = disableManifest(previousDir)
	if err := removeAllForce(previousDir); err != nil {
		rest := previousDir + "-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if rerr := os.Rename(previousDir, rest); rerr != nil {
			rest = previousDir
		}
		return dst, fmt.Errorf("the replaced install was copied to %s but its original could not be removed (%v); what is left of it is at %s with its manifest disabled — remove it by hand", dst, err, rest)
	}
	return dst, nil
}

// copyTreeForBackup copies an install dir to dst (which must not exist):
// regular files with their modes, symlinks and dirs. The old binary, sockets
// and other special files are left out, as stripBackup would remove them.
func copyTreeForBackup(src, dst, oldBinaryRel string) error {
	oldBin := cleanRel(oldBinaryRel)
	var modes dirModes
	defer func() { modes.restore() }()
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		switch typ := d.Type(); {
		case typ.IsDir():
			if err := os.Mkdir(target, 0o700); err != nil {
				return err
			}
			modes.add(target, info.Mode().Perm())
		case rel == oldBin:
			return nil
		case typ&fs.ModeSymlink != 0:
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(link, target) // #nosec G122 -- target is in the backup dir being created; the source tree belongs to the same user
		case typ.IsRegular():
			return copyFile(path, target, info.Mode().Perm())
		}
		return nil
	})
}

func disableManifest(dir string) error {
	mf := filepath.Join(dir, "manifest.json")
	if err := os.Rename(mf, mf+".disabled"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// finishBackup strips a retired dir and records its metadata.
func finishBackup(dir, oldBinary string, meta appBackupMeta) {
	stripBackup(dir, oldBinary)
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, appBackupMetaName), append(raw, '\n'), 0o600) // #nosec G306 G703 -- our own backup dir
	}
	if err != nil {
		// Without metadata retention treats the backup as pinned: it is
		// kept, never pruned.
		fmt.Fprintf(os.Stderr, "warn: could not record backup metadata in %s: %v\n", dir, err)
	}
}

// stripBackup removes what a backup does not need (the old binary, which the
// catalogue re-serves, and any leftover socket) and detaches small files from
// the live install's inodes. Best-effort: a failure leaves a larger backup.
func stripBackup(dir, oldBinaryRel string) {
	if oldBinaryRel != "" {
		if bin, err := resolveUnder(dir, oldBinaryRel); err == nil {
			_ = withWritableDir(filepath.Dir(bin), func() error { return os.Remove(bin) })
		}
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error { // #nosec G703 -- dir is a backup retireAppDir just created
		if err != nil {
			return nil
		}
		typ := d.Type()
		if typ&fs.ModeSocket != 0 {
			_ = withWritableDir(filepath.Dir(path), func() error { return os.Remove(path) })
			return nil
		}
		if !typ.IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > appBackupDetachMax {
			return nil
		}
		if err := withWritableDir(filepath.Dir(path), func() error { return detachFile(path, info.Mode().Perm()) }); err != nil {
			fmt.Fprintf(os.Stderr, "warn: backup %s stays hard-linked to the live file: %v\n", path, err)
		}
		return nil
	})
}

// detachFile replaces path with an independent copy of itself (same bytes, same
// mode), breaking any hard link to the live install.
func detachFile(path string, perm fs.FileMode) error {
	in, err := os.Open(path) // #nosec G304 -- a file inside our own backup dir
	if err != nil {
		return err
	}
	defer in.Close()
	tmp, err := os.CreateTemp(filepath.Dir(path), ".detach-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func readBackupMeta(dir string) (appBackupMeta, bool) {
	var meta appBackupMeta
	raw, err := os.ReadFile(filepath.Join(dir, appBackupMetaName)) // #nosec G304 G703 -- a backup dir we list ourselves
	if err != nil || json.Unmarshal(raw, &meta) != nil {
		return meta, false
	}
	return meta, true
}

// pruneAppBackups applies retention to the backups in one app's backup dir
// (names start with a fixed-width UTC timestamp, so name order is age order).
func pruneAppBackups(dir string, keep int) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if e.IsDir() {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(paths)
	return pruneBackupDirs(paths, keep)
}

// parkedBackups lists the <id>.previous-<timestamp> dirs retireAppDir left in
// the install root, oldest first.
func parkedBackups(root, appID string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	prefix := appID + appPreviousSuffix + "-"
	var paths []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			paths = append(paths, filepath.Join(root, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths
}

// pruneBackupDirs keeps the newest keep backups of each routine kind in paths
// (oldest first) and removes the older ones. Backups that are pinned, of any
// other kind, or without readable metadata are never removed: they may be the
// only copy of an app's keys (a --reset-state, state that could not be
// carried, a crash leftover). It returns what it removed.
func pruneBackupDirs(paths []string, keep int) []string {
	byKind := map[string][]string{}
	for _, p := range paths {
		meta, ok := readBackupMeta(p)
		if !ok || meta.Pinned || !backupKindRotated(meta.Kind) {
			continue
		}
		byKind[meta.Kind] = append(byKind[meta.Kind], p)
	}
	kinds := make([]string, 0, len(byKind))
	for k := range byKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	var removed []string
	for _, kind := range kinds {
		list := byKind[kind]
		for len(list) > keep {
			if removeAllForce(list[0]) == nil {
				removed = append(removed, list[0])
			}
			list = list[1:]
		}
	}
	return removed
}

func reportPrunedBackups(removed []string) {
	for _, p := range removed {
		fmt.Fprintf(os.Stderr, "note: removed the older backup %s (the newest %d routine backups of each kind are kept; backups that hold the only copy of an app's state are never removed)\n", p, appBackupKeep)
	}
}

// listAppBackups returns every backup of appID that exists in any backup
// location, including dirs parked in the install root.
func listAppBackups(root, appID string) []string {
	var out []string
	seen := map[string]bool{}
	for _, loc := range backupLocations() {
		dir, err := resolveUnder(loc, appID)
		if err != nil || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(dir, e.Name()))
			}
		}
	}
	return append(out, parkedBackups(root, appID)...)
}

// ── reporting ───────────────────────────────────────────────────────────────

// reportAlreadyInstalled is the answer to `install` of an app that is already
// installed, without --force: nothing is fetched or changed, and the output
// says how to get a newer version (`upgrade`) or reinstall in place. Both keep
// the app's state. Exit status 0: the app the caller asked for is installed.
func reportAlreadyInstalled(dir string, im *manifest.Manifest, target string, local bool) {
	upgrade := "pilotctl appstore upgrade " + im.ID
	reinstall := "pilotctl appstore install " + im.ID + " --force"
	if local {
		reinstall = "pilotctl appstore install " + target + " --local --force"
	}
	hint := "already installed; nothing changed. "
	if !local {
		hint += "To move to the catalogue's current version (app state is kept): `" + upgrade + "`. "
	}
	hint += "To reinstall in place (app state is kept): `" + reinstall + "`."
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(installReport{
			AppID:            im.ID,
			AppVersion:       im.AppVersion,
			ManifestVersion:  im.ManifestVersion,
			InstalledTo:      dir,
			BinarySHA256:     im.Binary.SHA256,
			AlreadyInstalled: true,
			Hint:             hint,
		})
		return
	}
	fmt.Printf("%s v%s is already installed (%s); nothing changed.\n", im.ID, im.AppVersion, dir)
	if !local {
		fmt.Printf("  newer version from the catalogue (keeps app state): %s\n", upgrade)
	}
	fmt.Printf("  reinstall in place (keeps app state):               %s\n", reinstall)
}

// printInstallNotes surfaces what recoverInterruptedInstall repaired.
func printInstallNotes(notes []string) {
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "note: %s\n", n)
	}
}

// summarizePaths renders up to limit paths for a one-line message.
func summarizePaths(paths []string, limit int) string {
	if len(paths) <= limit {
		return strings.Join(paths, ", ")
	}
	return strings.Join(paths[:limit], ", ") + fmt.Sprintf(", +%d more", len(paths)-limit)
}

// mergeSortedUnique merges two path lists into one sorted list without
// duplicates.
func mergeSortedUnique(a, b []string) []string {
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, p := range list {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}
