// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package proxyconf

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ownProcessGroup makes cmd the leader of a new process group and has its
// context's cancellation SIGKILL that whole group, so nothing a timed-out
// refresh command started outlives it.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
}

// killProcessGroup SIGKILLs the process group cmd leads.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
