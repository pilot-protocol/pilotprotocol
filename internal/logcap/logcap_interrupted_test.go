// SPDX-License-Identifier: AGPL-3.0-or-later

package logcap

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// holdLock opens path and takes the lock a rotation in progress holds on
// its staged copy, from another open file description, as another daemon
// would. The lock is released when the test ends or on release().
func holdLock(t *testing.T, path string) (release func()) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := tryLock(f); err != nil {
		_ = f.Close()
		t.Fatalf("lock %s: %v", path, err)
	}
	var once bool
	release = func() {
		if !once {
			once = true
			_ = f.Close()
		}
	}
	t.Cleanup(release)
	return release
}

// pilotDir returns Options for a log directly in dir, as Pilot's own
// directory: the one `pilotctl daemon start` puts each daemon's log in,
// where a rotation also finishes the other daemons' interrupted ones.
func pilotDir(dir string, maxBytes int64, maxBackups int) Options {
	return Options{MaxBytes: maxBytes, MaxBackups: maxBackups, Within: []string{dir}}
}

// locked reports whether some open file description holds path's lock.
func locked(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = tryLock(f)
	if err != nil && !errors.Is(err, errBusy) {
		t.Fatal(err)
	}
	return errors.Is(err, errBusy)
}

// TestCheckFinishesAnotherLogsInterruptedRotation: `pilotctl daemon
// start` gives each daemon its own pilot-<pid>.log, so the copy a daemon
// staged before it was killed is under a name the next daemon never
// rotates. The next daemon's rotation finishes it into that log's
// generation 1 — and leaves the rest of the dead daemon's files as they
// were.
func TestCheckFinishesAnotherLogsInterruptedRotation(t *testing.T) {
	dir := t.TempDir()
	dead := filepath.Join(dir, "pilot-22.log")
	deadLog := strings.Repeat("pilot-22 line\n", 5)
	writeFile(t, dead, deadLog)
	writeFile(t, stagingName(dead), "staged by pilot-22\n")
	// Its shift had already moved generation 1 up before the copy.
	writeFile(t, backupName(dead, 2), "pilot-22 generation 2")

	path := filepath.Join(dir, "pilot-40.log")
	f := openLog(t, path)
	content := strings.Repeat("pilot-40 line\n", 5)
	write(t, f, content)
	mustRotate(t, New(f, pilotDir(dir, 10, 3)))

	if got := gunzip(t, backupName(dead, 1)); got != "staged by pilot-22\n" {
		t.Fatalf("%s = %q, want the staged copy", backupName(dead, 1), got)
	}
	if exists(stagingName(dead)) {
		t.Fatal("interrupted copy of another log left behind")
	}
	if got := readFile(t, backupName(dead, 2)); got != "pilot-22 generation 2" {
		t.Fatalf("another log's generations were shifted: .2.gz = %q", got)
	}
	if got := readFile(t, dead); got != deadLog {
		t.Fatalf("another log itself changed: %d bytes", len(got))
	}
	if got := gunzip(t, backupName(path, 1)); got != content {
		t.Fatalf("own backup = %q, want the log", got)
	}
	want := []string{
		"pilot-22.log",
		filepath.Base(backupName(dead, 1)),
		filepath.Base(backupName(dead, 2)),
		"pilot-40.log",
		filepath.Base(backupName(path, 1)),
	}
	if got := dirNames(t, dir); !equal(got, want) {
		t.Fatalf("dir = %v, want %v", got, want)
	}
}

// TestCheckLeavesAnotherRotationInProgressAlone: a staged copy another
// live daemon holds locked is still being written or compressed; it is
// not taken for an interrupted one until that lock goes away.
func TestCheckLeavesAnotherRotationInProgressAlone(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "pilot-22.log")
	writeFile(t, stagingName(other), "being copied\n")
	release := holdLock(t, stagingName(other))

	path := filepath.Join(dir, "pilot-40.log")
	f := openLog(t, path)
	r := New(f, pilotDir(dir, 10, 3))
	write(t, f, strings.Repeat("a", 50))
	mustRotate(t, r)
	if got := readFile(t, stagingName(other)); got != "being copied\n" {
		t.Fatalf("staged copy in progress changed: %q", got)
	}
	if exists(backupName(other, 1)) {
		t.Fatal("staged copy in progress was compressed")
	}

	release()
	write(t, f, strings.Repeat("b", 50))
	mustRotate(t, r)
	if got := gunzip(t, backupName(other, 1)); got != "being copied\n" {
		t.Fatalf("%s = %q, want the copy once its rotation is gone", backupName(other, 1), got)
	}
}

// TestCheckLeavesEmptyStagedCopyOfAnotherLogAlone: an empty copy may be
// one another daemon has just created and not yet locked, so it is left
// alone; there is nothing in it to keep either way.
func TestCheckLeavesEmptyStagedCopyOfAnotherLogAlone(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "pilot-22.log")
	writeFile(t, stagingName(other), "")

	path := filepath.Join(dir, "pilot-40.log")
	f := openLog(t, path)
	write(t, f, strings.Repeat("c", 50))
	mustRotate(t, New(f, pilotDir(dir, 10, 3)))
	if !exists(stagingName(other)) {
		t.Fatal("empty staged copy removed")
	}
	if exists(backupName(other, 1)) {
		t.Fatal("empty staged copy compressed")
	}
}

// TestCheckOnlyFinishesStagedCopiesOfOurs: the search for other logs'
// interrupted rotations touches only regular files of this user at the
// staging names of `pilotctl daemon start`'s logs, pilot-<pid>.log.pilot.1;
// everything else in the directory — a link, a directory, another user's
// file at such a name, a bare ".pilot.1", other rotators' names, the
// staging name of any other log — is left as it was, and so is anything
// outside the directory.
func TestCheckOnlyFinishesStagedCopiesOfOurs(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "logs")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// What a bare ".pilot.1" would name, taken as the directory's own
	// staged copy: in the parent, which rotation never vetted.
	outside := stagingName(dir)
	writeFile(t, outside, "outside the log directory\n")
	secret := filepath.Join(t.TempDir(), "identity.json")
	writeFile(t, secret, "SECRET-KEY-MATERIAL\n")
	link := stagingName(filepath.Join(dir, "pilot-1.log"))
	symlink(t, secret, link)
	if err := os.Mkdir(stagingName(filepath.Join(dir, "pilot-2.log")), 0o700); err != nil {
		t.Fatal(err)
	}
	theirs := stagingName(filepath.Join(dir, "pilot-3.log"))
	writeFile(t, theirs, "another user's file\n")
	fakeForeign(t, theirs)
	untouched := map[string]string{
		theirs:                                  "another user's file\n",
		filepath.Join(dir, ".pilot.1"):          "no log name\n",
		filepath.Join(dir, "x.log.pilot.2"):     "not a staging name\n",
		filepath.Join(dir, "x.log.pilot.1.gz"):  "not a staging name\n",
		filepath.Join(dir, "x.log.1"):           "logrotate's\n",
		filepath.Join(dir, "x.log.pilot.1.bak"): "not a staging name\n",
	}
	// Staging names of logs that are not `pilotctl daemon start`'s.
	for _, log := range []string{
		"x.log", "app", "pilot-daemon.log", "pilot-starting.log",
		"pilot-.log", "pilot-12a.log", "pilot-12.log.1", "pilot-12",
	} {
		untouched[stagingName(filepath.Join(dir, log))] = "the staging name of " + log + "\n"
	}
	for name, content := range untouched {
		writeFile(t, name, content)
	}
	// One that is: the scan did run.
	orphan := filepath.Join(dir, "pilot-9.log")
	writeFile(t, stagingName(orphan), "pilot-9's copy\n")
	before := dirNames(t, dir)

	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	write(t, f, strings.Repeat("d", 50))
	mustRotate(t, New(f, pilotDir(dir, 10, 3)))

	for name, want := range untouched {
		if got := readFile(t, name); got != want {
			t.Fatalf("%s = %q, want it untouched", name, got)
		}
	}
	if !isSymlink(link) {
		t.Fatal("planted link was removed or replaced")
	}
	if got := readFile(t, secret); got != "SECRET-KEY-MATERIAL\n" {
		t.Fatalf("link target changed: %q", got)
	}
	if got := gunzip(t, backupName(orphan, 1)); got != "pilot-9's copy\n" {
		t.Fatalf("%s = %q, want pilot-9's copy finished", backupName(orphan, 1), got)
	}
	var want []string
	for _, name := range before {
		if name != filepath.Base(stagingName(orphan)) {
			want = append(want, name)
		}
	}
	want = append(want, "daemon.log", filepath.Base(backupName(path, 1)), filepath.Base(backupName(orphan, 1)))
	sort.Strings(want)
	if got := dirNames(t, dir); !equal(got, want) {
		t.Fatalf("dir = %v, want %v", got, want)
	}
	if got := readFile(t, outside); got != "outside the log directory\n" {
		t.Fatalf("%s = %q, want it untouched", outside, got)
	}
	if got := dirNames(t, parent); !equal(got, []string{"logs", filepath.Base(outside)}) {
		t.Fatalf("parent dir = %v, want nothing created or removed there", got)
	}
}

// TestCheckFinishesOrphansOnlyInPilotDirectory: other daemons' copies
// are finished only where `pilotctl daemon start` puts its logs, a
// Within directory itself. A log rotated anywhere else — explicitly, in a
// shared /var/log; as the brew service log, in brew's var/log; in a
// directory below ~/.pilot — leaves the other files in its directory
// alone, even at a pilot-<pid>.log.pilot.1 name.
func TestCheckFinishesOrphansOnlyInPilotDirectory(t *testing.T) {
	for _, tc := range []struct {
		name string
		// opts for a log in dir, with pilot as ~/.pilot.
		opts func(pilot, dir string) Options
		dir  func(root string) string
	}{
		{
			"explicit, outside Within",
			func(pilot, _ string) Options {
				return Options{MaxBytes: 10, MaxBackups: 3, Anywhere: true, Within: []string{pilot}}
			},
			func(root string) string { return filepath.Join(root, "var", "log") },
		},
		{
			"explicit, no Within",
			func(string, string) Options { return anywhere(10, 3) },
			func(root string) string { return filepath.Join(root, "var", "log") },
		},
		{
			"brew service log",
			func(pilot, dir string) Options {
				return Options{MaxBytes: 10, MaxBackups: 3, Within: []string{pilot}, Files: []string{filepath.Join(dir, "pilot-daemon.log")}}
			},
			func(root string) string { return filepath.Join(root, "var", "log") },
		},
		{
			"below Within",
			func(pilot, _ string) Options { return Options{MaxBytes: 10, MaxBackups: 3, Within: []string{pilot}} },
			func(root string) string { return filepath.Join(root, ".pilot", "logs") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			pilot := filepath.Join(root, ".pilot")
			dir := tc.dir(root)
			for _, d := range []string{pilot, dir} {
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			others := map[string]string{
				stagingName(filepath.Join(dir, "pilot-22.log")): "a pilot-<pid>.log copy\n",
				filepath.Join(dir, "app.pilot.1"):               "logrotate's delaycompress generation\n",
			}
			for name, content := range others {
				writeFile(t, name, content)
			}
			path := filepath.Join(dir, "pilot-daemon.log")
			f := openLog(t, path)
			content := strings.Repeat("o", 50)
			write(t, f, content)
			mustRotate(t, New(f, tc.opts(pilot, dir)))

			if got := gunzip(t, backupName(path, 1)); got != content {
				t.Fatalf("own backup = %q, want the log", got)
			}
			for name, want := range others {
				if got := readFile(t, name); got != want {
					t.Fatalf("%s = %q, want it untouched", name, got)
				}
			}
			want := []string{"app.pilot.1", "pilot-22.log.pilot.1", "pilot-daemon.log", filepath.Base(backupName(path, 1))}
			sort.Strings(want)
			if got := dirNames(t, dir); !equal(got, want) {
				t.Fatalf("dir = %v, want %v", got, want)
			}
		})
	}
}

// TestCheckOwnRotationInProgressStopsTheShift: when this log's own staged
// copy is held by a rotation in progress (another process writing the
// same log), this round keeps no backup and moves nothing, instead of
// shifting generations under that rotation; once the lock is gone the
// copy is finished as an interrupted one.
func TestCheckOwnRotationInProgressStopsTheShift(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	// The other rotation has shifted (.1.gz is free) and staged its copy.
	writeFile(t, backupName(path, 2), "generation 2")
	writeFile(t, stagingName(path), "the other rotation's copy\n")
	release := holdLock(t, stagingName(path))

	r := New(f, anywhere(10, 3))
	write(t, f, strings.Repeat("e", 50))
	rotated, err := r.Check()
	if !rotated || !errors.Is(err, errBusy) {
		t.Fatalf("Check = (%v, %v), want (true, errBusy)", rotated, err)
	}
	if got := readFile(t, path); got != "" {
		t.Fatalf("log not truncated: %d bytes", len(got))
	}
	want := []string{"daemon.log", filepath.Base(stagingName(path)), filepath.Base(backupName(path, 2))}
	sort.Strings(want)
	if got := dirNames(t, dir); !equal(got, want) {
		t.Fatalf("dir = %v, want %v (nothing moved)", got, want)
	}

	release()
	write(t, f, strings.Repeat("g", 50))
	mustRotate(t, r)
	for gen, want := range map[int]string{1: strings.Repeat("g", 50), 2: "the other rotation's copy\n"} {
		if got := gunzip(t, backupName(path, gen)); got != want {
			t.Fatalf("%s = %q, want %q", backupName(path, gen), got, want)
		}
	}
	if got := readFile(t, backupName(path, 3)); got != "generation 2" {
		t.Fatalf(".3.gz = %q, want the old generation 2", got)
	}
}

// TestCheckReleasesItsLockEachRound: a copy kept after a failed compress
// is not left locked, or the next round would take it for a rotation in
// progress and never finish it.
func TestCheckReleasesItsLockEachRound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	tmp := backupName(path, 1) + ".tmp"
	symlink(t, filepath.Join(t.TempDir(), "nowhere"), tmp)

	r := New(f, anywhere(10, 3))
	first := strings.Repeat("1", 50)
	write(t, f, first)
	rotateWithoutBackup(t, r, path)
	if locked(t, stagingName(path)) {
		t.Fatal("kept staged copy still locked after the round")
	}

	if err := os.Remove(tmp); err != nil {
		t.Fatal(err)
	}
	second := strings.Repeat("2", 50)
	write(t, f, second)
	mustRotate(t, r)
	if got := gunzip(t, backupName(path, 2)); got != first {
		t.Fatalf(".2.gz = %q, want the kept copy", got)
	}
	if got := gunzip(t, backupName(path, 1)); got != second {
		t.Fatalf(".1.gz = %q, want the log", got)
	}
}

// TestCreateStagedHoldsTheLock: the copy is locked from creation until
// the rotation closes it, and its content is the log.
func TestCreateStagedHoldsTheLock(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "daemon.log")
	writeFile(t, src, "log content\n")
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	dst := stagingName(src)
	held, err := createStaged(in, dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dst); got != "log content\n" {
		t.Fatalf("staged copy = %q", got)
	}
	if !locked(t, dst) {
		t.Fatal("staged copy not locked while held")
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if locked(t, dst) {
		t.Fatal("staged copy still locked after close")
	}
}

// TestHoldStagedYieldsToAnotherRotation: if another rotation of the same
// log takes the new copy between its creation and its lock — locking it,
// or finishing and replacing it — this one gives the copy up rather than
// write into or remove a file that is no longer its own.
func TestHoldStagedYieldsToAnotherRotation(t *testing.T) {
	create := func(t *testing.T) (string, *os.File) {
		t.Helper()
		dst := stagingName(filepath.Join(t.TempDir(), "daemon.log"))
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = out.Close() })
		return dst, out
	}

	t.Run("locked by the other", func(t *testing.T) {
		dst, out := create(t)
		holdLock(t, dst)
		if held, err := holdStaged(dst, out); err == nil {
			held.Close()
			t.Fatal("holdStaged took a copy another rotation holds")
		} else if !errors.Is(err, errBusy) {
			t.Fatalf("err = %v, want errBusy", err)
		}
		if !exists(dst) {
			t.Fatal("copy removed")
		}
	})

	t.Run("finished and replaced by the other", func(t *testing.T) {
		dst, out := create(t)
		if err := os.Remove(dst); err != nil {
			t.Fatal(err)
		}
		writeFile(t, dst, "the other rotation's new copy\n")
		if held, err := holdStaged(dst, out); err == nil {
			held.Close()
			t.Fatal("holdStaged took a copy that is no longer its own")
		}
		if got := readFile(t, dst); got != "the other rotation's new copy\n" {
			t.Fatalf("other rotation's copy changed: %q", got)
		}
	})
}

// TestHelperStagedCopy is not a test: TestCheckFinishesCopyOfKilledDaemon
// runs the test binary as another daemon that stages a copy, holds it as
// a rotation does, and waits to be killed.
func TestHelperStagedCopy(t *testing.T) {
	dst := os.Getenv("LOGCAP_HELPER_STAGED")
	if dst == "" {
		t.Skip("helper process for TestCheckFinishesCopyOfKilledDaemon")
	}
	in, err := os.Open(os.Getenv("LOGCAP_HELPER_LOG"))
	if err != nil {
		t.Fatal(err)
	}
	held, err := createStaged(in, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if _, err := os.Stdout.WriteString("staged\n"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
	t.Fatal("helper was not killed")
}

// TestCheckFinishesCopyOfKilledDaemon: across processes, as in the field.
// A daemon killed (SIGKILL, OOM) mid-rotation leaves its copy; while it
// is alive another daemon leaves the copy alone, and once it is dead its
// lock is gone and the next rotation finishes the copy.
func TestCheckFinishesCopyOfKilledDaemon(t *testing.T) {
	dir := t.TempDir()
	dead := filepath.Join(dir, "pilot-22.log")
	deadLog := strings.Repeat("pilot-22 line\n", 20)
	writeFile(t, dead, deadLog)

	helper := exec.Command(os.Args[0], "-test.run=^TestHelperStagedCopy$", "-test.v")
	helper.Env = append(os.Environ(),
		"LOGCAP_HELPER_LOG="+dead,
		"LOGCAP_HELPER_STAGED="+stagingName(dead))
	out, err := helper.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	helper.Stderr = os.Stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	ready := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if sc.Text() == "staged" {
				ready <- true
				break
			}
		}
		close(ready)
		// Drain -test.v output until the helper exits.
		for sc.Scan() {
		}
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("helper exited before staging its copy")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("helper never staged its copy")
	}

	path := filepath.Join(dir, "pilot-40.log")
	f := openLog(t, path)
	r := New(f, pilotDir(dir, 10, 3))
	write(t, f, strings.Repeat("h", 50))
	mustRotate(t, r)
	if exists(backupName(dead, 1)) {
		t.Fatal("copy of a live daemon's rotation was compressed")
	}

	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = helper.Wait()

	write(t, f, strings.Repeat("i", 50))
	mustRotate(t, r)
	if got := gunzip(t, backupName(dead, 1)); got != deadLog {
		t.Fatalf("%s = %d bytes, want the killed daemon's copy (%d)", backupName(dead, 1), len(got), len(deadLog))
	}
	if exists(stagingName(dead)) {
		t.Fatal("killed daemon's copy left behind")
	}
}

// TestCheckWithoutFileLocking: on a filesystem that cannot flock, a log
// is still rotated with backups and its own interrupted copy finished,
// as before locking existed; another log's copy, which might belong to a
// live rotation there is no telling apart, is left alone.
func TestCheckWithoutFileLocking(t *testing.T) {
	orig := tryLock
	tryLock = func(*os.File) error { return errors.New("operation not supported") }
	t.Cleanup(func() { tryLock = orig })

	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	writeFile(t, stagingName(path), "own interrupted copy\n")
	other := filepath.Join(dir, "pilot-22.log")
	writeFile(t, stagingName(other), "another log's copy\n")

	content := strings.Repeat("k", 50)
	write(t, f, content)
	mustRotate(t, New(f, pilotDir(dir, 10, 3)))
	if got := gunzip(t, backupName(path, 1)); got != content {
		t.Fatalf(".1.gz = %q, want the log", got)
	}
	if got := gunzip(t, backupName(path, 2)); got != "own interrupted copy\n" {
		t.Fatalf(".2.gz = %q, want the interrupted copy", got)
	}
	if got := readFile(t, stagingName(other)); got != "another log's copy\n" {
		t.Fatalf("another log's copy changed: %q", got)
	}
	if exists(backupName(other, 1)) {
		t.Fatal("another log's copy compressed without a lock to go by")
	}
}
