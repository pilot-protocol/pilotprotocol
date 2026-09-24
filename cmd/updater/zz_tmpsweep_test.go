// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// mkTree creates path as a dir holding a file of size bytes and a
// read-only subdir with another file, the shape an unpacked bundle can
// have, then backdates it.
func mkTree(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(path, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "manifest.json"), make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "bin", "app"), []byte("x"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(path, "bin"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(path, "bin"), 0o700) })
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func mkFile(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// TestSweepRemovesOnlyAbandonedPilotDownloads: abandoned bundle downloads
// and update dirs go; anything fresh, of the wrong type, a symlink, or not
// named like ours stays.
func TestSweepRemovesOnlyAbandonedPilotDownloads(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := now.Add(-2 * staleTempAge)
	fresh := now.Add(-time.Minute)

	// Removed.
	mkTree(t, filepath.Join(dir, "pilot-bundle-unpack-111"), 1000, old)
	mkFile(t, filepath.Join(dir, "pilot-bundle-222.tar.gz"), 500, old)
	mkTree(t, filepath.Join(dir, "pilot-update-333"), 200, old)

	// Kept: an install or update still in progress.
	mkTree(t, filepath.Join(dir, "pilot-bundle-unpack-444"), 10, fresh)
	mkFile(t, filepath.Join(dir, "pilot-bundle-555.tar.gz"), 10, fresh)
	// Kept: not our names.
	mkTree(t, filepath.Join(dir, "other-unpack-666"), 10, old)
	mkFile(t, filepath.Join(dir, "pilot-bundle-notes.txt"), 10, old)
	// Kept: our names, wrong type.
	mkFile(t, filepath.Join(dir, "pilot-bundle-unpack-777"), 10, old)
	mkTree(t, filepath.Join(dir, "pilot-bundle-888.tar.gz"), 10, old)
	// Kept: a symlink with our name, and what it points at.
	target := filepath.Join(t.TempDir(), "precious")
	mkTree(t, target, 10, old)
	link := filepath.Join(dir, "pilot-bundle-unpack-999")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	// Backdate the link itself (os.Chtimes would follow it), so only its
	// type keeps it.
	tv := []unix.Timeval{unix.NsecToTimeval(old.UnixNano()), unix.NsecToTimeval(old.UnixNano())}
	if err := unix.Lutimes(link, tv); err != nil {
		t.Fatal(err)
	}

	res := sweepStaleTemps(dir, now, staleTempAge)

	for _, gone := range []string{"pilot-bundle-unpack-111", "pilot-bundle-222.tar.gz", "pilot-update-333"} {
		if exists(filepath.Join(dir, gone)) {
			t.Errorf("%s was not removed", gone)
		}
	}
	for _, kept := range []string{
		"pilot-bundle-unpack-444", "pilot-bundle-555.tar.gz",
		"other-unpack-666", "pilot-bundle-notes.txt",
		"pilot-bundle-unpack-777", "pilot-bundle-888.tar.gz",
		"pilot-bundle-unpack-999",
	} {
		if !exists(filepath.Join(dir, kept)) {
			t.Errorf("%s was removed", kept)
		}
	}
	if !exists(filepath.Join(target, "manifest.json")) {
		t.Error("the symlink's target was touched")
	}
	if res.Removed != 3 || res.Failed != 0 {
		t.Errorf("result = %+v, want 3 removed, 0 failed", res)
	}
	if want := int64(1000 + 1 + 500 + 200 + 1); res.Bytes != want {
		t.Errorf("bytes = %d, want %d", res.Bytes, want)
	}
}

// TestSweepEmptyDir is a no-op.
func TestSweepEmptyDir(t *testing.T) {
	if res := sweepStaleTemps(t.TempDir(), time.Now(), staleTempAge); res != (sweepResult{}) {
		t.Fatalf("result = %+v, want zero", res)
	}
}

// TestTempSweepLoopSweepsTempDirAndStops: the loop sweeps $TMPDIR right
// away and returns once stopped.
func TestTempSweepLoopSweepsTempDirAndStops(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	stale := filepath.Join(dir, "pilot-bundle-unpack-1")
	mkTree(t, stale, 10, time.Now().Add(-2*staleTempAge))

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		tempSweepLoop(time.Hour, stop)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for exists(stale) {
		if time.Now().After(deadline) {
			t.Fatal("stale leftover not swept")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tempSweepLoop did not return after stop")
	}
}

func TestOwnedByCurrentUser(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	mkFile(t, p, 1, time.Now())
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !ownedByCurrentUser(fi) {
		t.Fatal("a file this process created is not reported as its own")
	}
}

// TestSweepKeepsOtherUsersLeftovers: on a shared /tmp another user's
// downloads are not ours to remove. Needs root to create them.
func TestSweepKeepsOtherUsersLeftovers(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to create a file owned by another user")
	}
	dir := t.TempDir()
	old := time.Now().Add(-2 * staleTempAge)
	theirs := filepath.Join(dir, "pilot-bundle-unpack-1")
	mkTree(t, theirs, 10, old)
	if err := os.Lchown(theirs, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(theirs, old, old)
	if res := sweepStaleTemps(dir, time.Now(), staleTempAge); res.Removed != 0 || !exists(theirs) {
		t.Fatalf("another user's leftover was removed (result %+v)", res)
	}
}
