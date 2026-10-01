// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Uninstall deletes <install root>/.<id>.lock: there used to be one left for
// every app ever installed. The app can be installed again afterwards.
func TestAppStoreUninstallRemovesLockFile(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.lockleft"
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	installQuiet(t, bundle, "--local")
	if _, err := os.Lstat(appInstallLockPath(root, id)); err != nil {
		t.Fatalf("install should have left its lock file: %v", err)
	}
	if _, stderr, f := runTrapped(t, func() { cmdAppStoreUninstall([]string{id, "--yes"}) }); f != nil {
		t.Fatalf("uninstall: %+v\n%s", f, stderr)
	}
	assertAbsent(t, filepath.Join(root, id))
	if _, err := os.Lstat(appInstallLockPath(root, id)); err == nil {
		t.Fatalf("%s is still there after uninstall", appInstallLockPath(root, id))
	}
	installQuiet(t, bundle, "--local")
	if _, err := os.Stat(filepath.Join(root, id, "manifest.json")); err != nil {
		t.Fatalf("install after uninstall: %v", err)
	}
}

// shortLockWait makes a lock attempt that has to wait give up quickly.
func shortLockWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := appInstallLockWait
	appInstallLockWait = d
	t.Cleanup(func() { appInstallLockWait = prev })
}

// lockIsHeld reports whether the lock file now at the path is locked.
func lockIsHeld(t *testing.T, root, id string) bool {
	t.Helper()
	prev := appInstallLockWait
	appInstallLockWait = 150 * time.Millisecond
	defer func() { appInstallLockWait = prev }()
	var (
		unlock func()
		err    error
	)
	_ = captureStderr(t, func() { unlock, err = lockAppInstall(root, id) })
	if err != nil {
		if !strings.Contains(err.Error(), "more than") {
			t.Fatalf("lock probe: %v", err)
		}
		return true
	}
	unlock()
	return false
}

// An install that was waiting for the lock while an uninstall deleted the lock
// file must not go ahead on the deleted file: the next install would create a
// new file, lock that, and both would run. The waiter ends up holding the
// lock on the file that is at the path.
func TestLockAppInstallWaiterSurvivesLockFileRemoval(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.lockwaiter"
	_, uninstallDone, err := lockAppInstallRemovable(root, id)
	if err != nil {
		t.Fatal(err)
	}
	old, err := os.Lstat(appInstallLockPath(root, id))
	if err != nil {
		t.Fatal(err)
	}

	type got struct {
		unlock func()
		err    error
	}
	waiter := make(chan got, 1)
	var stderr string
	go func() {
		var g got
		stderr = captureStderr(t, func() { g.unlock, g.err = lockAppInstall(root, id) })
		waiter <- g
	}()
	select {
	case g := <-waiter:
		t.Fatalf("second locker did not wait: %+v", g)
	case <-time.After(300 * time.Millisecond): // it is polling the held lock
	}

	uninstallDone()

	var w got
	select {
	case w = <-waiter:
	case <-time.After(10 * time.Second):
		t.Fatal("waiter never got the lock after the uninstall released it")
	}
	if w.err != nil {
		t.Fatalf("waiter: %v\n%s", w.err, stderr)
	}
	now, err := os.Lstat(appInstallLockPath(root, id))
	if err != nil {
		t.Fatalf("the waiter holds a lock but no lock file is at the path: %v", err)
	}
	if os.SameFile(old, now) {
		t.Fatal("the deleted lock file is still at the path")
	}
	if !lockIsHeld(t, root, id) {
		t.Fatal("a third locker got the lock while the waiter holds it: the waiter is on the deleted file")
	}
	w.unlock()
	if lockIsHeld(t, root, id) {
		t.Fatal("lock still held after the waiter released it")
	}
}

// After the lock file was deleted, the next two lockers still exclude each
// other.
func TestLockAppInstallExclusiveAfterLockFileRemoval(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.lockagain"
	_, firstDone, err := lockAppInstallRemovable(root, id)
	if err != nil {
		t.Fatal(err)
	}
	firstDone()
	if _, err := os.Lstat(appInstallLockPath(root, id)); err == nil {
		t.Fatal("unlockAndRemove left the lock file")
	}

	second, err := lockAppInstall(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if !lockIsHeld(t, root, id) {
		t.Fatal("two lockers hold the lock after the lock file was deleted")
	}
	second()
}

// Many installs and uninstalls of one app at once: whoever holds the lock is
// alone, although about half the holders delete the lock file as they
// release it, like an uninstall does.
func TestLockAppInstallStressWithRemoval(t *testing.T) {
	root := t.TempDir()
	const id = "io.test.lockstress"
	shortLockWait(t, 2*time.Minute)
	workers, rounds := 12, 150
	if testing.Short() {
		rounds = 40
	}
	var (
		holders  atomic.Int32
		doubles  atomic.Int32
		removals atomic.Int32
		wg       sync.WaitGroup
	)
	errs := make(chan error, workers)
	// The "waiting for another pilotctl" notes go to stderr; keep them out of
	// the test output.
	_ = captureStderr(t, func() {
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(seed int64) {
				defer wg.Done()
				rng := rand.New(rand.NewSource(seed))
				for i := 0; i < rounds; i++ {
					unlock, unlockAndRemove, err := lockAppInstallRemovable(root, id)
					if err != nil {
						errs <- err
						return
					}
					if holders.Add(1) != 1 {
						doubles.Add(1)
					}
					time.Sleep(time.Duration(rng.Intn(300)) * time.Microsecond)
					holders.Add(-1)
					if rng.Intn(2) == 0 {
						removals.Add(1)
						unlockAndRemove()
					} else {
						unlock()
					}
				}
			}(int64(w + 1))
		}
		wg.Wait()
	})
	close(errs)
	for err := range errs {
		t.Fatalf("lock: %v", err)
	}
	if n := doubles.Load(); n != 0 {
		t.Fatalf("%d time(s) two holders had the lock at once (%d lock-file removals in %d locks)", n, removals.Load(), workers*rounds)
	}
	t.Logf("%d locks, %d lock-file removals, never two holders", workers*rounds, removals.Load())
}
