// SPDX-License-Identifier: AGPL-3.0-or-later

package logcap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// foreignUID is a uid that is neither this process's nor root's.
var foreignUID = os.Geteuid() + 4242

// fakeForeign makes files and directories with these base names look
// owned by another user; the tests cannot chown without root.
func fakeForeign(t *testing.T, names ...string) {
	t.Helper()
	foreign := map[string]bool{}
	for _, n := range names {
		foreign[filepath.Base(n)] = true
	}
	orig := ownerOf
	ownerOf = func(fi os.FileInfo) (int, bool) {
		if foreign[fi.Name()] {
			return foreignUID, true
		}
		return orig(fi)
	}
	t.Cleanup(func() { ownerOf = orig })
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func isSymlink(path string) bool {
	fi, err := os.Lstat(path)
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

// dirNames lists dir's entries, sorted.
func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// rotateWithoutBackup runs one Check that must truncate the log but keep
// no backup, reporting why.
func rotateWithoutBackup(t *testing.T, r *Rotator, path string) {
	t.Helper()
	rotated, err := r.Check()
	if !rotated {
		t.Fatalf("Check did not truncate an over-limit log (err %v)", err)
	}
	if err == nil {
		t.Fatal("Check kept no backup but reported no error")
	}
	if got := readFile(t, path); got != "" {
		t.Fatalf("log not truncated: %d bytes", len(got))
	}
}

// TestCheckLeavesOtherRotatorsFilesAlone: an operator whose own rotation
// (logrotate with compress + delaycompress, newsyslog, dateext) already
// manages the file keeps every generation it made, even ones owned by
// the daemon's user and sitting at the old .N.gz names.
func TestCheckLeavesOtherRotatorsFilesAlone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pilot-daemon.log")
	f := openLog(t, path)

	foreign := map[string]string{
		path + ".1":           "logrotate delaycompress generation\n",
		path + ".0.gz":        "newsyslog generation\n",
		path + "-20260901.gz": "dateext generation\n",
		path + ".1.gz.tmp":    "someone's temp file\n",
	}
	for gen := 2; gen <= 7; gen++ {
		foreign[fmt.Sprintf("%s.%d.gz", path, gen)] = fmt.Sprintf("logrotate generation %d\n", gen)
	}
	for name, content := range foreign {
		writeFile(t, name, content)
	}

	r := New(f, anywhere(10, 3))
	for i := range 5 {
		write(t, f, fmt.Sprintf("round-%d %s\n", i, strings.Repeat("x", 20)))
		mustRotate(t, r)
	}

	for name, want := range foreign {
		if got := readFile(t, name); got != want {
			t.Fatalf("%s = %q, want it untouched (%q)", name, got, want)
		}
	}
	for gen := 1; gen <= 3; gen++ {
		want := fmt.Sprintf("round-%d ", 5-gen)
		if got := gunzip(t, backupName(path, gen)); !strings.HasPrefix(got, want) {
			t.Fatalf("%s = %q, want the round %d log", backupName(path, gen), got, 5-gen)
		}
	}
	if exists(backupName(path, 4)) {
		t.Fatal("kept more generations than maxBackups")
	}
}

// TestCheckNeverFollowsPlantedSymlinks: links at the names the old
// rotation wrote through (<log>.1, <log>.1.gz.tmp) and at logcap's own
// names are never followed — no file is created or overwritten at their
// targets — and the links themselves are left in place.
func TestCheckNeverFollowsPlantedSymlinks(t *testing.T) {
	for _, tc := range []struct {
		name       string
		link       func(path string) string
		wantBackup bool
	}{
		{"legacy staging name", func(p string) string { return p + ".1" }, true},
		{"legacy temp name", func(p string) string { return p + ".1.gz.tmp" }, true},
		{"staging name", stagingName, false},
		{"temp name", func(p string) string { return backupName(p, 1) + ".tmp" }, false},
		{"generation name", func(p string) string { return backupName(p, 2) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "daemon.log")
			f := openLog(t, path)
			outside := t.TempDir()
			dangling := filepath.Join(outside, "created-through-link")
			victim := filepath.Join(outside, "victim")
			writeFile(t, victim, "victim content\n")

			link := tc.link(path)
			symlink(t, dangling, link)
			// A second link to an existing file, where the name allows one.
			var link2 string
			if tc.name == "generation name" {
				link2 = backupName(path, 1)
				symlink(t, victim, link2)
			}

			content := strings.Repeat("log line\n", 10)
			write(t, f, content)
			r := New(f, anywhere(10, 3))
			if tc.wantBackup {
				mustRotate(t, r)
				if got := gunzip(t, backupName(path, 1)); got != content {
					t.Fatalf("backup = %q, want the log", got)
				}
			} else {
				rotateWithoutBackup(t, r, path)
			}

			if exists(dangling) {
				t.Fatal("a file was created through the planted link")
			}
			if got := readFile(t, victim); got != "victim content\n" {
				t.Fatalf("link target overwritten: %q", got)
			}
			for _, l := range []string{link, link2} {
				if l != "" && !isSymlink(l) {
					t.Fatalf("planted link %s was removed or replaced", l)
				}
			}
		})
	}
}

// TestCheckKeepsStagedCopyWhenTempNameIsTaken: when the temp name is
// occupied by something logcap must not touch, the log is still
// truncated and the staged copy is kept for a later round to finish,
// rather than lost.
func TestCheckKeepsStagedCopyWhenTempNameIsTaken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	symlink(t, filepath.Join(t.TempDir(), "nowhere"), backupName(path, 1)+".tmp")

	content := strings.Repeat("kept\n", 10)
	write(t, f, content)
	rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
	if got := readFile(t, stagingName(path)); got != content {
		t.Fatalf("staged copy = %q, want the log it copied", got)
	}
}

// TestCheckDoesNotConsumeLinkedSecret: a <log>.pilot.1 linking to a file
// the daemon can read (identity.json) is not taken for an interrupted
// rotation's copy: the secret is not gzipped into the backup chain, and
// neither the file nor the link is touched.
func TestCheckDoesNotConsumeLinkedSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	secret := filepath.Join(t.TempDir(), "identity.json")
	writeFile(t, secret, "SECRET-KEY-MATERIAL\n")
	symlink(t, secret, stagingName(path))

	write(t, f, strings.Repeat("s", 50))
	rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)

	if got := readFile(t, secret); got != "SECRET-KEY-MATERIAL\n" {
		t.Fatalf("secret file changed: %q", got)
	}
	if !isSymlink(stagingName(path)) {
		t.Fatal("planted link was removed or replaced")
	}
	gzs, _ := filepath.Glob(filepath.Join(dir, "*.gz"))
	for _, gz := range gzs {
		if strings.Contains(gunzip(t, gz), "SECRET") {
			t.Fatalf("secret gzipped into %s", gz)
		}
	}
}

// TestCheckLeavesOtherUsersFilesAlone: at logcap's own names, a file
// owned by another user is never read, renamed or removed. One in a slot
// the shift would move stops the backup before anything moved.
func TestCheckLeavesOtherUsersFilesAlone(t *testing.T) {
	t.Run("in a kept slot", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "daemon.log")
		f := openLog(t, path)
		writeFile(t, backupName(path, 1), "ours-1")
		writeFile(t, backupName(path, 2), "theirs-2")
		fakeForeign(t, backupName(path, 2))

		write(t, f, strings.Repeat("a", 50))
		rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
		if got := readFile(t, backupName(path, 2)); got != "theirs-2" {
			t.Fatalf("other user's file changed: %q", got)
		}
		if got := readFile(t, backupName(path, 1)); got != "ours-1" {
			t.Fatalf("shift moved generations before stopping: .1 = %q", got)
		}
		if want := []string{"daemon.log", filepath.Base(backupName(path, 1)), filepath.Base(backupName(path, 2))}; !equal(dirNames(t, dir), want) {
			t.Fatalf("dir = %v, want %v", dirNames(t, dir), want)
		}
	})

	t.Run("beyond the kept slots", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "daemon.log")
		f := openLog(t, path)
		writeFile(t, backupName(path, 3), "ours-3")
		writeFile(t, backupName(path, 4), "theirs-4")
		writeFile(t, backupName(path, 5), "ours-5")
		fakeForeign(t, backupName(path, 4))

		write(t, f, strings.Repeat("b", 50))
		mustRotate(t, New(f, anywhere(10, 2)))
		if exists(backupName(path, 3)) {
			t.Fatal("stale generation beyond maxBackups not pruned")
		}
		if got := readFile(t, backupName(path, 4)); got != "theirs-4" {
			t.Fatalf("other user's file changed: %q", got)
		}
		// Pruning stops at the first name that is not ours.
		if !exists(backupName(path, 5)) {
			t.Fatal("pruned past a file that is not ours")
		}
	})

	t.Run("at the staging name", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "daemon.log")
		f := openLog(t, path)
		writeFile(t, stagingName(path), "theirs-staged")
		fakeForeign(t, stagingName(path))

		write(t, f, strings.Repeat("c", 50))
		rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
		if got := readFile(t, stagingName(path)); got != "theirs-staged" {
			t.Fatalf("other user's file changed: %q", got)
		}
		if exists(backupName(path, 1)) {
			t.Fatal("other user's file consumed into a backup")
		}
	})

	t.Run("where an interrupted rotation would finish", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "daemon.log")
		f := openLog(t, path)
		writeFile(t, stagingName(path), "ours-staged")
		writeFile(t, backupName(path, 1), "theirs-1")
		fakeForeign(t, backupName(path, 1))

		write(t, f, strings.Repeat("e", 50))
		rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
		if got := readFile(t, backupName(path, 1)); got != "theirs-1" {
			t.Fatalf("other user's file replaced: %q", got)
		}
		if got := readFile(t, stagingName(path)); got != "ours-staged" {
			t.Fatalf("staged copy lost: %q", got)
		}
	})

	t.Run("at the temp name", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "daemon.log")
		f := openLog(t, path)
		tmp := backupName(path, 1) + ".tmp"
		writeFile(t, tmp, "theirs-tmp")
		fakeForeign(t, tmp)

		write(t, f, strings.Repeat("d", 50))
		rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
		if got := readFile(t, tmp); got != "theirs-tmp" {
			t.Fatalf("other user's file changed: %q", got)
		}
	})
}

// TestCheckReplacesItsOwnStaleTemp: a temp file of ours left by an
// interrupted compress is replaced, not treated as foreign.
func TestCheckReplacesItsOwnStaleTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	writeFile(t, backupName(path, 1)+".tmp", "half-written gzip")

	content := strings.Repeat("e", 50)
	write(t, f, content)
	mustRotate(t, New(f, anywhere(10, 3)))
	if got := gunzip(t, backupName(path, 1)); got != content {
		t.Fatalf("backup = %q, want the log", got)
	}
	if exists(backupName(path, 1) + ".tmp") {
		t.Fatal("temp file left behind")
	}
}

// TestCheckKeepsNoBackupInSharedDirectory: where other users can create
// names — group- or world-writable, sticky /tmp included — or in another
// user's directory, rotation only truncates and creates nothing.
func TestCheckKeepsNoBackupInSharedDirectory(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		foreign bool
	}{
		{"group-writable", 0o770, false},
		{"world-writable sticky", 0o777 | os.ModeSticky, false},
		{"another user's", 0o755, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "logs")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			if tc.foreign {
				fakeForeign(t, dir)
			}
			path := filepath.Join(dir, "daemon.log")
			f := openLog(t, path)
			writeFile(t, backupName(path, 1), "ours-1")
			writeFile(t, stagingName(path), "ours-staged")

			write(t, f, strings.Repeat("f", 50))
			rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
			want := []string{"daemon.log", filepath.Base(stagingName(path)), filepath.Base(backupName(path, 1))}
			sort.Strings(want)
			if got := dirNames(t, dir); !equal(got, want) {
				t.Fatalf("dir = %v, want %v (nothing created, moved or removed)", got, want)
			}
			if got := readFile(t, backupName(path, 1)); got != "ours-1" {
				t.Fatalf("generation changed: %q", got)
			}
		})
	}
}

// TestCheckRealOtherUserFiles repeats the ownership checks with real
// chown'd files and directories, which needs root (the linux container
// run).
func TestCheckRealOtherUserFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown files to another user")
	}
	const other = 4242

	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	names := map[string]string{
		stagingName(path):            "theirs-staged",
		backupName(path, 1) + ".tmp": "theirs-tmp",
		backupName(path, 2):          "theirs-2",
	}
	for name, content := range names {
		writeFile(t, name, content)
		if err := os.Chown(name, other, other); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f, strings.Repeat("g", 50))
	rotateWithoutBackup(t, New(f, anywhere(10, 3)), path)
	for name, want := range names {
		if got := readFile(t, name); got != want {
			t.Fatalf("%s = %q, want it untouched", name, got)
		}
	}

	// A directory owned by another (non-root) user: truncate only.
	sub := filepath.Join(t.TempDir(), "theirs")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(sub, other, other); err != nil {
		t.Fatal(err)
	}
	subPath := filepath.Join(sub, "daemon.log")
	g := openLog(t, subPath)
	write(t, g, strings.Repeat("h", 50))
	rotateWithoutBackup(t, New(g, anywhere(10, 3)), subPath)
	if got := dirNames(t, sub); !equal(got, []string{"daemon.log"}) {
		t.Fatalf("dir = %v, want only the log", got)
	}
}

// TestWatchScopedToWithinDirs: without Anywhere, only a log inside one of
// the Within directories — at any depth, matched by identity so a
// symlinked path works — is watched.
func TestWatchScopedToWithinDirs(t *testing.T) {
	root := t.TempDir()
	pilot := filepath.Join(root, ".pilot")
	logs := filepath.Join(pilot, "logs")
	elsewhere := filepath.Join(root, "var-log")
	for _, d := range []string{logs, elsewhere} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	linkToPilot := filepath.Join(root, "pilot-link")
	symlink(t, pilot, linkToPilot)

	inPilot := openLog(t, filepath.Join(pilot, "daemon.log"))
	nested := openLog(t, filepath.Join(logs, "daemon.log"))
	outside := openLog(t, filepath.Join(elsewhere, "daemon.log"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	scoped := func(within ...string) Options {
		return Options{MaxBytes: 1 << 30, MaxBackups: 1, Within: within}
	}
	for _, tc := range []struct {
		name string
		f    *os.File
		opts Options
		want bool
	}{
		{"inside", inPilot, scoped(pilot), true},
		{"nested inside", nested, scoped(pilot), true},
		{"inside, via a symlinked dir", inPilot, scoped(linkToPilot), true},
		{"outside", outside, scoped(pilot), false},
		{"no dirs", inPilot, scoped(), false},
		{"missing dir", inPilot, scoped(filepath.Join(root, "absent")), false},
		{"outside, explicit", outside, Options{MaxBytes: 1 << 30, MaxBackups: 1, Anywhere: true}, true},
	} {
		if got := Watch(ctx, tc.f, tc.opts, time.Hour); got != tc.want {
			t.Errorf("%s: Watch = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestCheckStopsWhenLogLeavesScope: a watched log moved out of the Within
// directories is no longer the daemon's to rotate: it is neither
// truncated nor backed up.
func TestCheckStopsWhenLogLeavesScope(t *testing.T) {
	root := t.TempDir()
	pilot := filepath.Join(root, ".pilot")
	elsewhere := filepath.Join(root, "elsewhere")
	for _, d := range []string{pilot, elsewhere} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(pilot, "daemon.log")
	f := openLog(t, path)
	content := strings.Repeat("i", 50)
	write(t, f, content)
	r := New(f, Options{MaxBytes: 10, MaxBackups: 3, Within: []string{pilot}})

	moved := filepath.Join(elsewhere, "daemon.log")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	rotated, err := r.Check()
	if rotated || !errors.Is(err, errOutOfScope) {
		t.Fatalf("Check = (%v, %v), want (false, errOutOfScope)", rotated, err)
	}
	if got := readFile(t, moved); got != content {
		t.Fatalf("out-of-scope log changed: %d bytes", len(got))
	}
	if got := dirNames(t, elsewhere); !equal(got, []string{"daemon.log"}) {
		t.Fatalf("files created next to the out-of-scope log: %v", got)
	}

	// Moved back in, it rotates again.
	if err := os.Rename(moved, path); err != nil {
		t.Fatal(err)
	}
	mustRotate(t, r)
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
