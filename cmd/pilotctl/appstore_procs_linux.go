// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package main

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// listProcessIDs returns every pid in /proc.
func listProcessIDs() []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// processExecutable returns the resolved path of pid's executable. The kernel
// appends " (deleted)" once the file is unlinked; that suffix is dropped so a
// process whose app dir was already removed is still recognised. Fails for
// another user's process and for a zombie.
func processExecutable(pid int) (string, error) {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(exe, " (deleted)"), nil
}

// processCodeUnder returns the first file under roots that pid has mapped
// executable (an "x" in /proc/<pid>/maps). Under binfmt emulation the kernel's
// executable is the translator (/run/rosetta/rosetta, qemu-*), but the guest
// binary is still mapped r-x at its load address. Unreadable for another
// user's process.
func processCodeUnder(pid int, roots []string) (string, bool) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/maps") // #nosec G304 -- /proc/<pid>/maps for an integer pid
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		// address perms offset dev inode pathname
		fields := strings.Fields(sc.Text())
		if len(fields) < 6 || !strings.Contains(fields[1], "x") {
			continue
		}
		p := strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)")
		if pathUnder(p, roots) {
			return p, true
		}
	}
	return "", false
}
