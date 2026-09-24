// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// Stale download leftovers in the system temp directory.
//
// `pilotctl appstore install <catalogue id>`, and `appstore upgrade`, which
// appUpgradeLoop runs every hour as `upgrade --all`, download each bundle to
// $TMPDIR/pilot-bundle-<n>.tar.gz and unpack it into
// $TMPDIR/pilot-bundle-unpack-<n>. The unpacked copy is not removed once the
// install has consumed it, and the tarball survives a pilotctl that is
// killed mid-download. The updater's own release download dir,
// $TMPDIR/pilot-update-<n>, is removed when the update returns but not when
// the process is killed mid-download. One laptop's $TMPDIR held 272 of
// these. Nothing else removes them: macOS purges $TMPDIR only after days
// without access, and a Linux /tmp that is not a tmpfs is often never
// cleaned.
//
// sweepStaleTemps removes them once they are clearly abandoned. It only
// touches entries that:
//   - match one of these Pilot-specific names,
//   - are the expected type (a directory for the two dir patterns, a
//     regular file for the tarball; symlinks never match),
//   - are owned by the user the updater runs as, and
//   - were last modified more than staleTempAge ago. An install or update
//     finishes in minutes (pilotctl's download timeout is 60 s, the
//     updater's app-upgrade run is capped at 10 minutes), so a live one is
//     never near that age.

// staleTempAge is how old a leftover must be before it is removed.
const staleTempAge = 24 * time.Hour

// staleTempPattern is one name the sweep removes, and the type of entry it
// must be.
type staleTempPattern struct {
	glob string
	dir  bool
}

// staleTempPatterns are the temp names pilotctl (appstore_catalogue.go,
// fetchAndUnpackBundle) and the updater library (applyUpdate) create with
// os.CreateTemp/os.MkdirTemp in the system temp directory. Keep in step
// with them.
var staleTempPatterns = []staleTempPattern{
	{glob: "pilot-bundle-unpack-*", dir: true},
	{glob: "pilot-bundle-*.tar.gz", dir: false},
	{glob: "pilot-update-*", dir: true},
}

// sweepResult summarises one sweepStaleTemps run.
type sweepResult struct {
	Removed int
	Bytes   int64
	Failed  int
}

// sweepStaleTemps removes the abandoned leftovers in dir (see above) last
// modified before now-maxAge.
func sweepStaleTemps(dir string, now time.Time, maxAge time.Duration) sweepResult {
	var res sweepResult
	cutoff := now.Add(-maxAge)
	for _, p := range staleTempPatterns {
		matches, err := filepath.Glob(filepath.Join(dir, p.glob))
		if err != nil {
			continue // only ErrBadPattern, and the patterns are constant
		}
		for _, path := range matches {
			fi, err := os.Lstat(path)
			if err != nil {
				continue
			}
			if p.dir != fi.IsDir() || (!p.dir && !fi.Mode().IsRegular()) {
				continue
			}
			if !fi.ModTime().Before(cutoff) || !ownedByCurrentUser(fi) {
				continue
			}
			size := treeSize(path)
			// os.RemoveAll does not follow symlinks inside the tree. Every
			// directory in these trees is created owner-writable (0755/0700:
			// pilotctl's untarUnder, the updater's staging), so nothing in
			// them blocks removal.
			if err := os.RemoveAll(path); err != nil {
				res.Failed++
				slog.Warn("temp sweep: could not remove stale download leftover", "path", path, "err", err)
				continue
			}
			res.Removed++
			res.Bytes += size
		}
	}
	return res
}

// treeSize is the total size of the regular files under path (path itself
// when it is a file). Best effort, for the log line only.
func treeSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

// tempSweepLoop runs sweepStaleTemps on the system temp directory now and
// then every interval, until stop is closed. It runs whether or not
// automatic updates are enabled: an interactive `pilotctl appstore install`
// leaves the same leftovers.
func tempSweepLoop(interval time.Duration, stop <-chan struct{}) {
	sweep := func() {
		res := sweepStaleTemps(os.TempDir(), time.Now(), staleTempAge)
		if res.Removed > 0 || res.Failed > 0 {
			slog.Info("temp sweep: removed stale download leftovers",
				"dir", os.TempDir(), "removed", res.Removed, "bytes", res.Bytes, "failed", res.Failed)
		}
	}
	sweep()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			sweep()
		}
	}
}
