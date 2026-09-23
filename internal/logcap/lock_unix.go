// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin || linux

package logcap

import (
	"errors"
	"os"
	"syscall"
)

// flock takes an exclusive flock(2) on f without waiting. The lock
// belongs to f's open file description and goes away when it is closed,
// including when the process dies, so a copy left locked by a crash is
// free again. It returns errBusy when another open file description
// holds the lock, and another error when the filesystem cannot lock.
func flock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var lockErr error
	if err := rc.Control(func(fd uintptr) {
		for {
			lockErr = syscall.Flock(int(fd), syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(lockErr, syscall.EINTR) {
				return
			}
		}
	}); err != nil {
		return err
	}
	if errors.Is(lockErr, syscall.EWOULDBLOCK) {
		return errBusy
	}
	return lockErr
}
