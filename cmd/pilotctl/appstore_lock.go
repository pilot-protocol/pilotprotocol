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
// `list` only look at dirs. It is never deleted (deleting a lock file races
// with the next locker); it is empty and harmless.
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
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create install root %s: %w", root, err)
	}
	path := appInstallLockPath(root, appID)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- <install root>/.<validated app id>.lock
	if err != nil {
		return nil, fmt.Errorf("open lock %s: %w", path, err)
	}
	fd := int(f.Fd()) // #nosec G115 -- a file descriptor always fits an int
	deadline := time.Now().Add(appInstallLockWait)
	waiting := false
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("another pilotctl has been installing, upgrading or removing %s for more than %s (lock %s is held)", appID, appInstallLockWait, path)
		}
		if !waiting {
			fmt.Fprintf(os.Stderr, "note: waiting for another pilotctl to finish installing, upgrading or removing %s\n", appID)
			waiting = true
		}
		time.Sleep(50 * time.Millisecond)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(fd, syscall.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}
