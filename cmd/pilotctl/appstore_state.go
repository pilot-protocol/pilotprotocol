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
// The swap now works like this:
//
//  1. The new bundle is staged in <id>.staging (binary + aux files).
//  2. Everything in the live dir that the new bundle does not ship, and that
//     is not a bundle/pilotctl/supervisor control file, is hard-linked into
//     staging (copied when a link is impossible). Hard links keep the carry
//     cheap for large data dirs and consistent while the app is still
//     running: the old process's open descriptors and the new directory
//     entries name the same inodes, so nothing it writes before the
//     supervisor restarts it is lost. The carried set is checked in staging.
//  3. manifest.json is written last, so the supervisor never sees a
//     manifest-bearing staging dir that is still being filled.
//  4. The live dir is renamed to <id>.previous and staging to <id>. The new
//     dir is verified (manifest bytes, binary sha256, carried state). On any
//     failure the previous dir is put back.
//  5. Only then is <id>.previous retired: moved OUT of the install root (the
//     supervisor adopts any dir there that holds a manifest, and a same-version
//     .previous would win over the live dir at daemon start) into
//     <backup root>/<id>/<timestamp>-v<old version>/. The newest
//     appBackupKeep backups per app are kept; nothing is ever RemoveAll'd.
//
// `install --force --reset-state` is the explicit destructive variant: step 2
// is skipped (the new install starts empty) but step 5 still keeps the old dir
// as a backup, and a loud warning names where it went.

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
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

const (
	appPreviousSuffix = ".previous"
	appStagingSuffix  = ".staging"

	// appBackupKeep is how many retired installs are kept per app.
	appBackupKeep = 3

	// appBackupDetachMax bounds which backup files are turned into
	// independent copies. Carried state is hard-linked, so a retired dir
	// shares inodes with the live one; small files (keys, secrets, config)
	// are copied so an in-place rewrite by a later version cannot reach the
	// backup. Larger files (databases) stay linked: they are protected from
	// deletion and replacement, which is the failure this guards against.
	appBackupDetachMax = 1 << 20
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
}

// appStoreBackupRoot is where retired installs are kept: $PILOT_APPSTORE_BACKUP_ROOT,
// or an "app-backups" dir beside the install root (~/.pilot/app-backups for
// the default ~/.pilot/apps). It must be outside the install root, which the
// supervisor scans for apps.
func appStoreBackupRoot() string {
	if r := os.Getenv("PILOT_APPSTORE_BACKUP_ROOT"); r != "" {
		return r
	}
	return filepath.Join(filepath.Dir(filepath.Clean(appStoreRoot())), "app-backups")
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
// behind, before anything else touches the app dir. It never deletes state:
//
//   - <id>.previous without <id>: the swap died after moving the live install
//     aside. The previous install is the only copy of the app's state, so it
//     is put back.
//   - <id>.previous beside <id>: the swap finished but the old dir was never
//     retired. It is moved to the backups like any other replaced install.
//
// It returns human-readable notes describing what it did.
func recoverInterruptedInstall(finalDir, appID string) ([]string, error) {
	previousDir := finalDir + appPreviousSuffix
	if _, err := os.Lstat(previousDir); err != nil {
		return nil, nil
	}
	if _, err := os.Lstat(finalDir); errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(previousDir, finalDir); err != nil {
			return nil, fmt.Errorf("restore interrupted install %s → %s: %w", previousDir, finalDir, err)
		}
		return []string{fmt.Sprintf("restored %s from an interrupted install (%s)", appID, previousDir)}, nil
	}
	backup, err := retireAppDir(previousDir, appID)
	if err != nil {
		return nil, fmt.Errorf("retire leftover %s: %w", previousDir, err)
	}
	return []string{fmt.Sprintf("moved a leftover previous install of %s to %s", appID, backup)}, nil
}

// carryAppState links (or copies) every piece of app state in oldDir into
// newDir: every file, symlink and directory except
//
//   - top-level control files (appDirControlFiles),
//   - the old manifest's binary (oldBinaryRel) — a stale binary is not state,
//   - anything the new bundle already placed in newDir (the bundle wins),
//   - sockets, pipes, devices and *.sock files.
//
// It returns the carried file and symlink paths relative to oldDir, sorted.
// A file that disappears while it is being carried (a transient journal the
// running app just deleted) is skipped rather than failing the install.
func carryAppState(oldDir, newDir, oldBinaryRel string) ([]string, error) {
	oldBin := ""
	if oldBinaryRel != "" {
		oldBin = filepath.Clean(filepath.FromSlash(oldBinaryRel))
	}
	var carried []string
	err := filepath.WalkDir(oldDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) && path != oldDir {
				return nil
			}
			return walkErr
		}
		rel, err := filepath.Rel(oldDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		topLevel := !strings.ContainsRune(rel, filepath.Separator)
		if (topLevel && appDirControlFiles[rel]) || rel == oldBin {
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
			return os.Mkdir(dst, info.Mode().Perm()) // #nosec G301 -- mirrors the app's own dir mode
		case typ&fs.ModeSymlink != 0:
			if exists {
				return nil
			}
			target, err := os.Readlink(path)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if err := os.Symlink(target, dst); err != nil {
				return fmt.Errorf("carry %s: %w", rel, err)
			}
			carried = append(carried, rel)
		case typ.IsRegular():
			if exists || strings.HasSuffix(d.Name(), ".sock") {
				return nil
			}
			if err := linkOrCopy(path, dst); err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return fmt.Errorf("carry %s: %w", rel, err)
			}
			carried = append(carried, rel)
		}
		// Sockets, named pipes and devices are runtime objects, not state.
		return nil
	})
	sort.Strings(carried)
	return carried, err
}

// linkOrCopy hard-links src to dst, falling back to a mode-preserving copy when
// the filesystem refuses the link.
func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
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
// else but not required to still exist after the swap.
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

// swapInAppDir moves stagingDir into place at finalDir. A live install at
// finalDir is renamed to finalDir+".previous" first and is left there (never
// deleted) until verify accepts the new dir; on any failure the previous
// install is put back. It returns the previous dir's path when there was one,
// for the caller to retire.
func swapInAppDir(finalDir, stagingDir string, verify func(dir string) error) (string, error) {
	previousDir := finalDir + appPreviousSuffix
	if _, err := os.Lstat(previousDir); err == nil {
		return "", fmt.Errorf("%s already exists; refusing to overwrite it (it may hold the only copy of the app's state)", previousDir)
	}
	hadOld := false
	if _, err := os.Lstat(finalDir); err == nil {
		if err := os.Rename(finalDir, previousDir); err != nil {
			return "", fmt.Errorf("move the current install aside: %w", err)
		}
		hadOld = true
	}
	placed := false
	rollback := func(cause error) error {
		if placed {
			// Park the rejected new dir back at the staging path; it only
			// holds the new bundle plus links to state whose originals are
			// in previousDir.
			if err := os.Rename(finalDir, stagingDir); err != nil {
				if hadOld {
					return fmt.Errorf("%w; rollback failed: could not move the new install aside (%v) — the previous install is intact at %s", cause, err, previousDir)
				}
				return fmt.Errorf("%w; could not remove the rejected install at %s: %v", cause, finalDir, err)
			}
		}
		if hadOld {
			if err := os.Rename(previousDir, finalDir); err != nil {
				return fmt.Errorf("%w; rollback failed: %v — the previous install is intact at %s, move it back to %s", cause, err, previousDir, finalDir)
			}
		}
		_ = os.RemoveAll(stagingDir) // #nosec G703 -- <install root>/<validated app id>.staging, our own dir
		if hadOld {
			return fmt.Errorf("%w (the previous install was restored unchanged)", cause)
		}
		return cause
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

var unsafeBackupNameChars = regexp.MustCompile(`[^0-9A-Za-z._+-]`)

// retireAppDir moves a replaced install out of the install root into
// <backup root>/<id>/<timestamp>[-v<version>]/, strips what is not state (the
// old binary, the dead socket), makes small files independent copies, and
// prunes the app's backups to the newest appBackupKeep. When the backup root
// is unusable the dir stays in the install root under a unique name with its
// manifest disabled, so the supervisor can never adopt it as the live app; the
// returned error says so and the caller warns.
func retireAppDir(previousDir, appID string) (string, error) {
	oldVersion, oldBinary := "", ""
	if m, _, err := readInstalledManifest(previousDir); err == nil {
		oldVersion, oldBinary = m.AppVersion, m.Binary.Path
	}
	stamp := time.Now().UTC().Format("20060102T150405.000000000Z")
	name := stamp
	if oldVersion != "" {
		name += "-v" + unsafeBackupNameChars.ReplaceAllString(oldVersion, "_")
	}

	backupRoot := appStoreBackupRoot()
	appBackups, err := resolveUnder(backupRoot, appID)
	if err == nil {
		err = os.MkdirAll(appBackups, 0o700)
	}
	if err == nil {
		dst := filepath.Join(appBackups, name)
		for i := 1; ; i++ { // same-timestamp collision on a coarse clock
			if _, lerr := os.Lstat(dst); lerr != nil {
				break
			}
			dst = filepath.Join(appBackups, fmt.Sprintf("%s.%d", name, i))
		}
		if err = os.Rename(previousDir, dst); err == nil {
			stripBackup(dst, oldBinary)
			pruneAppBackups(appBackups, appBackupKeep)
			return dst, nil
		}
	}

	parked := previousDir + "-" + stamp
	if rerr := os.Rename(previousDir, parked); rerr != nil {
		parked = previousDir
	}
	if derr := os.Rename(filepath.Join(parked, "manifest.json"), filepath.Join(parked, "manifest.json.disabled")); derr != nil && !errors.Is(derr, fs.ErrNotExist) {
		return parked, fmt.Errorf("could not move the previous install to %s (%v), and disabling its manifest failed (%v); remove or move %s by hand before the daemon restarts", backupRoot, err, derr, parked)
	}
	return parked, fmt.Errorf("could not move the previous install to %s (%v); it is kept at %s with its manifest disabled", backupRoot, err, parked)
}

// stripBackup removes what a backup does not need (the old binary, which the
// catalogue re-serves, and any leftover socket) and detaches small files from
// the live install's inodes. Best-effort: a failure leaves a larger backup.
func stripBackup(dir, oldBinaryRel string) {
	if oldBinaryRel != "" {
		if bin, err := resolveUnder(dir, oldBinaryRel); err == nil {
			_ = os.Remove(bin)
		}
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		typ := d.Type()
		if typ&fs.ModeSocket != 0 {
			_ = os.Remove(path)
			return nil
		}
		if !typ.IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > appBackupDetachMax {
			return nil
		}
		if err := detachFile(path, info.Mode().Perm()); err != nil {
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

// pruneAppBackups keeps the newest keep backups in dir (names start with a
// fixed-width UTC timestamp, so name order is age order) and removes the rest.
func pruneAppBackups(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for len(names) > keep {
		_ = os.RemoveAll(filepath.Join(dir, names[0])) // #nosec G703 -- an old backup inside our own backup dir
		names = names[1:]
	}
}

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
