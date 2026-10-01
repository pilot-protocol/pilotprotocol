// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Per-app install lock.
//
// Installing, upgrading and uninstalling an app rename dirs in the install
// root (<id> → <id>.previous, <id>.staging → <id>), and crash recovery
// (recoverInterruptedInstall) reads a lone <id>.previous as the leftover of a
// dead install and puts it back. Without a lock, recovery run by one pilotctl
// (the hourly `upgrade --all`, or an agent's `install <id>`) could take over
// another pilotctl's swap halfway through it. Every step that looks at or
// changes those dirs therefore runs under an exclusive flock on
// <install root>/.<id>.lock. The lock file is a plain file: the supervisor and
// `list` only look at dirs.
//
// Uninstall deletes the lock file as it releases the lock
// (lockAppInstallRemovable). Deleting a lock file normally races with the
// next locker: one that had already opened the file gets the lock on a file
// that is no longer at the path, and the one after it creates a new file and
// holds a lock too. So a locker checks, once it has the lock, that the file
// it locked is still the one at the path, and starts over if it is not.
//
// From the moment the file is deleted the lock excludes nobody: the next
// locker creates a new file and goes ahead. Deleting is therefore only ever
// done together with the release, as the last thing the holder does.
//
// A pilotctl older than this check that is waiting for the lock at the moment
// of an uninstall can still end up on the deleted file; like the pilotctls
// that take no lock at all, that is tolerated, not prevented.
//
// flock is released by the kernel when the process exits, so a pilotctl that
// dies or exits through fatalHint never leaves the app locked.

// appInstallLockWait bounds how long an install waits for another one of the
// same app to finish. Linking tens of thousands of carried files can take a
// minute on a slow filesystem; the fleet installer gives a whole pilotctl run
// 10 minutes. A var so tests can shorten it.
var appInstallLockWait = 5 * time.Minute

func appInstallLockPath(root, appID string) string {
	return filepath.Join(root, "."+appID+".lock")
}

// lockAppInstall takes the app's install lock, waiting up to
// appInstallLockWait for another holder. It returns the function that
// releases it (safe to call more than once).
func lockAppInstall(root, appID string) (func(), error) {
	unlock, _, err := lockAppInstallRemovable(root, appID)
	return unlock, err
}

// lockAppInstallRemovable is lockAppInstall for uninstall: it also returns
// unlockAndRemove, which deletes the lock file and releases the lock in one
// step. The caller must be done with the app's dirs before calling it (see the
// top of this file). Whichever of the two functions is called first wins; the
// other then does nothing.
func lockAppInstallRemovable(root, appID string) (unlock, unlockAndRemove func(), err error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create install root %s: %w", root, err)
	}
	path := appInstallLockPath(root, appID)
	deadline := time.Now().Add(appInstallLockWait)
	waiting := false
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- <install root>/.<validated app id>.lock
		if err != nil {
			return nil, nil, fmt.Errorf("open lock %s: %w", path, err)
		}
		fd := int(f.Fd()) // #nosec G115 -- a file descriptor always fits an int
		for {
			err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
			if err == nil {
				break
			}
			if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
				_ = f.Close()
				return nil, nil, fmt.Errorf("lock %s: %w", path, err)
			}
			if time.Now().After(deadline) {
				_ = f.Close()
				return nil, nil, fmt.Errorf("another pilotctl has been installing, upgrading or removing %s for more than %s (lock %s is held)", appID, appInstallLockWait, path)
			}
			if !waiting {
				fmt.Fprintf(os.Stderr, "note: waiting for another pilotctl to finish installing, upgrading or removing %s\n", appID)
				waiting = true
			}
			time.Sleep(50 * time.Millisecond)
		}
		// An uninstall that held the lock may have deleted the file while we
		// waited on it. The lock only counts on the file that is at the path
		// now; closing f drops the one we got.
		current, err := lockFileIsCurrent(f, path)
		if err != nil {
			_ = f.Close()
			return nil, nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if !current {
			_ = f.Close()
			continue
		}
		var once sync.Once
		release := func(remove bool) {
			once.Do(func() {
				if remove {
					_ = os.Remove(path)
				}
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = f.Close()
			})
		}
		return func() { release(false) }, func() { release(true) }, nil
	}
}

// lockFileIsCurrent reports whether the open lock file f is the file at path.
func lockFileIsCurrent(f *os.File, path string) (bool, error) {
	held, err := f.Stat()
	if err != nil {
		return false, err
	}
	at, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return os.SameFile(held, at), nil
}
