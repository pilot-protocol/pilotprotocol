// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Stopping what an app leaves running when it is uninstalled.
//
// The supervisor stops an app by signalling the app's own process (and, with
// newer app-store releases, its process group). Anything the app started that
// detached into its own session or group survives that: a smolvm microVM
// (`smolvm-bin _boot-vm`, measured at ~311 MiB RSS), a `redis-server
// --daemonize`, a postmaster, a mysqld. They are reparented to init/launchd.
// So is an app instance orphaned by a daemon that died hard (macOS has no
// parent-death signal). Once the app's directory is deleted nothing can
// manage them any more: no app answers for them, `reapStale` matches only the
// app binary + socket argv, and they keep running until the machine reboots.
//
// Every one of those processes runs a binary that lives inside the app's
// directory (the app binary itself, or a native tool the app staged under
// $APP), so that is how uninstall finds them: by the path of the executable,
// not by process tree, group or session, which the processes are free to
// leave.

// appDirStopGrace is how long processes running from an app dir get to exit
// on SIGTERM before they are SIGKILLed. smolvm stops a VM in ~60 ms and a
// postmaster's fast paths finish well inside this.
const appDirStopGrace = 5 * time.Second

// appDirProcess is a running process whose executable lives under an app dir.
type appDirProcess struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
}

// appDirRoots returns the forms of dir a kernel may report an executable
// under: the cleaned absolute path and, when it differs, the path with
// symlinks resolved (/tmp → /private/tmp on macOS; /proc/<pid>/exe is always
// resolved). Call it while dir still exists.
func appDirRoots(dir string) []string {
	var roots []string
	add := func(p string) {
		if p == "" || p == string(filepath.Separator) {
			return // never treat the filesystem root as an app dir
		}
		for _, r := range roots {
			if r == p {
				return
			}
		}
		roots = append(roots, p)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = filepath.Clean(dir)
	}
	add(abs)
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		add(real)
	}
	return roots
}

// pathUnder reports whether p is strictly inside one of roots.
func pathUnder(p string, roots []string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	for _, r := range roots {
		if strings.HasPrefix(p, r+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// processesRunningFrom returns every process whose executable lives under
// roots. It skips pid 1, this process and its parent (an app that runs
// `pilotctl appstore uninstall` on itself is stopped by the supervisor, not
// by the pilotctl it is waiting on).
func processesRunningFrom(roots []string) []appDirProcess {
	if len(roots) == 0 {
		return nil
	}
	self, parent := os.Getpid(), os.Getppid()
	var out []appDirProcess
	for _, pid := range listProcessIDs() {
		if pid <= 1 || pid == self || pid == parent {
			continue
		}
		exe, ok := runningFrom(pid, roots)
		if !ok {
			continue
		}
		out = append(out, appDirProcess{PID: pid, Exe: exe})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

// runningFrom reports whether pid runs code from under roots, and which file:
// its executable, or else (Linux) an executable mapping of a file there. The
// mapping catches a binary run under binfmt emulation (Rosetta for Linux,
// qemu-user), where the kernel reports the translator as the executable.
func runningFrom(pid int, roots []string) (string, bool) {
	if exe, err := processExecutable(pid); err == nil && pathUnder(exe, roots) {
		return exe, true
	}
	return processCodeUnder(pid, roots)
}

// stillRunningFrom reports whether pid is alive and still runs code from
// under roots. A pid that exited, turned into a zombie (no executable any
// more) or was reused by an unrelated program is not.
func stillRunningFrom(pid int, roots []string) bool {
	_, ok := runningFrom(pid, roots)
	return ok
}

// stopProcessesRunningFrom SIGTERMs every process running from roots, gives
// them grace to exit, then SIGKILLs whatever is left. Each pid is re-checked
// against roots immediately before it is signalled, so a pid that exited and
// was reused in between is never touched. It returns the processes it found
// and those that were still running afterwards (signal refused, or stuck in
// the kernel).
func stopProcessesRunningFrom(roots []string, grace time.Duration) (found, left []appDirProcess) {
	found = processesRunningFrom(roots)
	if len(found) == 0 {
		return nil, nil
	}
	signal := func(p appDirProcess, sig syscall.Signal) {
		if !stillRunningFrom(p.PID, roots) {
			return
		}
		if proc, err := os.FindProcess(p.PID); err == nil {
			_ = proc.Signal(sig)
		}
	}
	for _, p := range found {
		signal(p, syscall.SIGTERM)
	}
	alive := func() []appDirProcess {
		var out []appDirProcess
		for _, p := range found {
			if stillRunningFrom(p.PID, roots) {
				out = append(out, p)
			}
		}
		return out
	}
	deadline := time.Now().Add(grace)
	for len(alive()) > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	for _, p := range alive() {
		signal(p, syscall.SIGKILL)
	}
	killDeadline := time.Now().Add(2 * time.Second)
	for len(alive()) > 0 && time.Now().Before(killDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	return found, alive()
}

// describeAppDirProcesses renders "name (pid N), …" for messages.
func describeAppDirProcesses(ps []appDirProcess) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, filepath.Base(p.Exe)+" (pid "+strconv.Itoa(p.PID)+")")
	}
	return strings.Join(parts, ", ")
}
