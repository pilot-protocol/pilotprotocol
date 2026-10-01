// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package main

import (
	"bytes"
	"errors"

	"golang.org/x/sys/unix"
)

// listProcessIDs returns every pid in the process table.
func listProcessIDs() []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(procs))
	for _, p := range procs {
		pids = append(pids, int(p.Proc.P_pid))
	}
	return pids
}

// processExecutable returns the path pid was exec'd from, read from
// kern.procargs2: a 32-bit argc, then the exec path, NUL-terminated. The
// kernel copies the path at exec time, so it is still there after the file
// was deleted or its dir removed. Fails for another user's process and for a
// zombie (no address space left to read).
func processExecutable(pid int) (string, error) {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}
	if len(buf) < 5 {
		return "", errors.New("short kern.procargs2")
	}
	rest := buf[4:] // skip argc
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) == 0 {
		return "", errors.New("empty exec path")
	}
	return string(rest), nil
}

// processCodeUnder: the executable path above is authoritative here.
func processCodeUnder(int, []string) (string, bool) { return "", false }
