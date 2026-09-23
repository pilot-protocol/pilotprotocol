// SPDX-License-Identifier: AGPL-3.0-or-later

package logcap

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// openLog opens path the way launchd opens StandardErrorPath: write-only,
// append, create.
func openLog(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func write(t *testing.T, f *os.File, s string) {
	t.Helper()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func gunzip(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func mustRotate(t *testing.T, r *Rotator) {
	t.Helper()
	rotated, err := r.Check()
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !rotated {
		t.Fatal("Check did not rotate an over-limit log")
	}
}

func TestCheckBelowLimitIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	write(t, f, strings.Repeat("x", 100))

	r := New(f, 100, 3) // exactly at the limit: not over it
	rotated, err := r.Check()
	if err != nil || rotated {
		t.Fatalf("Check = (%v, %v), want (false, nil)", rotated, err)
	}
	if got := readFile(t, path); len(got) != 100 {
		t.Fatalf("log size = %d, want 100 (untouched)", len(got))
	}
	if exists(path + ".1.gz") {
		t.Fatal("backup written for a log under the limit")
	}
}

func TestCheckRotatesTruncatesAndGzips(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	first := strings.Repeat("first line\n", 20)
	write(t, f, first)

	r := New(f, 100, 3)
	mustRotate(t, r)

	if got := readFile(t, path); got != "" {
		t.Fatalf("log after rotation = %d bytes, want empty", len(got))
	}
	if got := gunzip(t, path+".1.gz"); got != first {
		t.Fatalf("backup content mismatch: got %d bytes, want %d", len(got), len(first))
	}
	if exists(path + ".1") {
		t.Fatal("uncompressed staging copy left behind")
	}
	fi, err := os.Stat(path + ".1.gz")
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode = %v, want 0600", fi.Mode().Perm())
	}

	// The O_APPEND writer carries on at the new end of file: no sparse
	// hole, no stale bytes.
	write(t, f, "after\n")
	if got := readFile(t, path); got != "after\n" {
		t.Fatalf("log after post-rotation write = %q, want %q", got, "after\n")
	}
}

func TestCheckShiftsGenerationsAndDropsOldest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	r := New(f, 10, 3)

	contents := []string{"generation-A\n", "generation-B\n", "generation-C\n", "generation-D\n"}
	for _, c := range contents {
		write(t, f, c)
		mustRotate(t, r)
	}

	// Newest in .1, oldest kept in .3; generation-A fell off the end.
	for gen, want := range map[int]string{1: contents[3], 2: contents[2], 3: contents[1]} {
		if got := gunzip(t, backupName(path, gen)); got != want {
			t.Fatalf("%s = %q, want %q", backupName(path, gen), got, want)
		}
	}
	if exists(backupName(path, 4)) {
		t.Fatal("kept more generations than maxBackups")
	}
}

func TestCheckRemovesGenerationsBeyondLoweredLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	// Leftovers from a run with a larger -log-max-backups.
	for gen := 1; gen <= 5; gen++ {
		if err := os.WriteFile(backupName(path, gen), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(t, f, strings.Repeat("y", 50))
	mustRotate(t, New(f, 10, 2))

	if !exists(backupName(path, 1)) || !exists(backupName(path, 2)) {
		t.Fatal("expected .1.gz and .2.gz")
	}
	for gen := 3; gen <= 5; gen++ {
		if exists(backupName(path, gen)) {
			t.Fatalf("%s survived with maxBackups=2", backupName(path, gen))
		}
	}
}

func TestCheckZeroBackupsJustTruncates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	write(t, f, strings.Repeat("z", 50))

	mustRotate(t, New(f, 10, 0))
	if got := readFile(t, path); got != "" {
		t.Fatalf("log not truncated: %d bytes", len(got))
	}
	matches, _ := filepath.Glob(path + ".*")
	if len(matches) != 0 {
		t.Fatalf("backups written with maxBackups=0: %v", matches)
	}
}

func TestCheckFinishesInterruptedRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	// A previous rotation copied to .1 and died before compressing it;
	// its shift had already moved the older backup to .2.gz.
	if err := os.WriteFile(path+".1", []byte("interrupted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write(t, f, strings.Repeat("n", 50))
	mustRotate(t, New(f, 10, 3))

	if got := gunzip(t, backupName(path, 2)); got != "interrupted\n" {
		t.Fatalf(".2.gz = %q, want the interrupted generation", got)
	}
	if got := gunzip(t, backupName(path, 1)); got != strings.Repeat("n", 50) {
		t.Fatalf(".1.gz = %q, want the current log", got)
	}
	if exists(path + ".1") {
		t.Fatal("staging copy left behind")
	}
}

// TestCheckNonAppendWriterRewinds: a writer that did not open the file
// O_APPEND (a shell's `2>file`) shares the descriptor offset; rotation
// must rewind it or the next write re-creates the old size as a hole.
func TestCheckNonAppendWriterRewinds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	write(t, f, strings.Repeat("w", 50))

	mustRotate(t, New(f, 10, 1))
	write(t, f, "next\n")
	if got := readFile(t, path); got != "next\n" {
		t.Fatalf("log = %q (%d bytes), want %q — offset not rewound", got, len(got), "next\n")
	}
}

// TestCheckTruncatesWithoutBackupWhenPathIsGone: an unlinked log still
// fills the disk through the open descriptor, so it is truncated even
// though no backup can be made.
func TestCheckTruncatesWithoutBackupWhenPathIsGone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	write(t, f, strings.Repeat("d", 50))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	rotated, err := New(f, 10, 3).Check()
	if !rotated {
		t.Fatalf("Check did not truncate an unlinked over-limit log (err %v)", err)
	}
	if err == nil {
		t.Fatal("expected an error reporting the missing backup")
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 {
		t.Fatalf("unlinked log size = %d, want 0", fi.Size())
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.gz")); len(matches) != 0 {
		t.Fatalf("backup written for an unlinked log: %v", matches)
	}
}

// TestCheckFollowsRenamedLog: fdPath resolves the file's current name,
// so backups land next to wherever the open log now lives.
func TestCheckFollowsRenamedLog(t *testing.T) {
	dir := t.TempDir()
	orig := filepath.Join(dir, "daemon.log")
	f := openLog(t, orig)
	write(t, f, strings.Repeat("r", 50))
	moved := filepath.Join(dir, "moved.log")
	if err := os.Rename(orig, moved); err != nil {
		t.Fatal(err)
	}

	mustRotate(t, New(f, 10, 1))
	if !exists(moved + ".1.gz") {
		t.Fatal("backup not written next to the renamed log")
	}
}

func TestWatchNoopForNonRegularFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()
	defer pw.Close()
	if Watch(ctx, pw, 1, 3, time.Minute) {
		t.Fatal("Watch started on a pipe (journald/systemd case)")
	}

	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devnull.Close()
	if Watch(ctx, devnull, 1, 3, time.Minute) {
		t.Fatal("Watch started on a character device (terminal case)")
	}
}

func TestWatchDisabledByZeroLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	if Watch(context.Background(), f, 0, 3, time.Minute) {
		t.Fatal("Watch started with maxBytes=0 (disabled)")
	}
}

func TestWatchRotatesInBackground(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.log")
	f := openLog(t, path)
	content := strings.Repeat("background\n", 10)
	write(t, f, content)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !Watch(ctx, f, 20, 1, 10*time.Millisecond) {
		t.Fatal("Watch did not start on a regular file")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !exists(path + ".1.gz") {
		if time.Now().After(deadline) {
			t.Fatal("background watcher never rotated the log")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if got := gunzip(t, path+".1.gz"); got != content {
		t.Fatalf("backup = %d bytes, want %d", len(got), len(content))
	}
}
