// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux || darwin

package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A copy of this test binary started with PILOTCTL_TEST_APPDIR_PROC set plays
// a process an app left running (a VM, a daemonized server): it optionally
// ignores SIGTERM, reports that it is ready, and sleeps. init runs before
// TestMain, so the copy never runs any test.
func init() {
	mode := os.Getenv("PILOTCTL_TEST_APPDIR_PROC")
	if mode == "" {
		return
	}
	if mode == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	}
	if ready := os.Getenv("PILOTCTL_TEST_APPDIR_READY"); ready != "" {
		_ = os.WriteFile(ready, nil, 0o600)
	}
	time.Sleep(time.Hour)
	os.Exit(0)
}

// placeTestBinary puts this test binary at dst (hard link, else a copy).
func placeTestBinary(t *testing.T, dst string) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if os.Link(self, dst) == nil {
		return
	}
	in, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

// startDetached runs bin as a sleeper in its own session, the way smolvm
// starts a VM and redis-server --daemonize detaches, and waits until it is
// up. The process is reaped in the background so a stopped one never lingers
// as a zombie of the test.
func startDetached(t *testing.T, bin, mode string) (pid int, exited <-chan struct{}) {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "PILOTCTL_TEST_APPDIR_PROC="+mode, "PILOTCTL_TEST_APPDIR_READY="+ready)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-done
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper %s never became ready", bin)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cmd.Process.Pid, done
}

func requireProcessTable(t *testing.T) {
	t.Helper()
	if _, err := processExecutable(os.Getpid()); err != nil {
		t.Skipf("process executables are not readable here (%v); a sandbox may block it", err)
	}
}

func waitExited(t *testing.T, what string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("%s is still running", what)
	}
}

func pidsOf(ps []appDirProcess) map[int]bool {
	out := map[int]bool{}
	for _, p := range ps {
		out[p.PID] = true
	}
	return out
}

func TestPathUnder(t *testing.T) {
	roots := []string{"/srv/apps/io.x", "/private/srv/apps/io.x"}
	for p, want := range map[string]bool{
		"/srv/apps/io.x/bin/app":            true,
		"/private/srv/apps/io.x/smolvm-bin": true,
		"/srv/apps/io.x":                    false, // the dir itself is not a binary in it
		"/srv/apps/io.xy/bin/app":           false, // sibling app with a common prefix
		"/srv/apps/io.x/../io.y/bin/app":    false,
		"bin/app":                           false, // relative exec paths are never matched
		"":                                  false,
	} {
		if got := pathUnder(p, roots); got != want {
			t.Errorf("pathUnder(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestAppDirRootsResolvesSymlinks(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	roots := appDirRoots(link)
	resolved, _ := filepath.EvalSymlinks(real)
	if !pathUnder(filepath.Join(link, "bin", "x"), roots) || !pathUnder(filepath.Join(resolved, "bin", "x"), roots) {
		t.Fatalf("roots %v must cover both the link and its target", roots)
	}
	if got := appDirRoots("/"); len(got) != 0 {
		t.Fatalf("the filesystem root must never be an app dir: %v", got)
	}
}

// A detached process running from the app dir is stopped; one running the
// same program from elsewhere is left alone.
func TestStopProcessesRunningFromStopsOnlyTheAppsOwn(t *testing.T) {
	requireProcessTable(t)
	appDir := filepath.Join(t.TempDir(), "io.test.vm")
	inside := filepath.Join(appDir, "tool-1.0-os-arch", "tool-bin")
	placeTestBinary(t, inside)
	outside := filepath.Join(t.TempDir(), "elsewhere", "tool-bin")
	placeTestBinary(t, outside)

	inPID, inDone := startDetached(t, inside, "sleep")
	outPID, outDone := startDetached(t, outside, "sleep")

	roots := appDirRoots(appDir)
	found, left := stopProcessesRunningFrom(roots, 5*time.Second)
	if !pidsOf(found)[inPID] {
		t.Fatalf("found %+v, want pid %d (running %s)", found, inPID, inside)
	}
	if pidsOf(found)[outPID] {
		t.Fatalf("pid %d runs from outside the app dir and must not be touched: %+v", outPID, found)
	}
	if len(left) != 0 {
		t.Fatalf("left running: %+v", left)
	}
	waitExited(t, "the app dir's process", inDone)
	select {
	case <-outDone:
		t.Fatal("the process running from outside the app dir was stopped")
	default:
	}
}

// A process that ignores SIGTERM is SIGKILLed once the grace runs out.
func TestStopProcessesRunningFromKillsAfterGrace(t *testing.T) {
	requireProcessTable(t)
	appDir := filepath.Join(t.TempDir(), "io.test.stubborn")
	bin := filepath.Join(appDir, "bin", "server")
	placeTestBinary(t, bin)
	pid, done := startDetached(t, bin, "ignore-term")

	start := time.Now()
	found, left := stopProcessesRunningFrom(appDirRoots(appDir), 300*time.Millisecond)
	if !pidsOf(found)[pid] || len(left) != 0 {
		t.Fatalf("found=%+v left=%+v, want pid %d stopped", found, left, pid)
	}
	waitExited(t, "the SIGTERM-ignoring process", done)
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("stopped in %s: SIGTERM should have been ignored until the grace ran out", took)
	}
}

// The app dir may already be gone (a supervisor respawned the app between
// the stop and the delete): the process still counts as the app's.
func TestStopProcessesRunningFromDeletedDir(t *testing.T) {
	requireProcessTable(t)
	appDir := filepath.Join(t.TempDir(), "io.test.gone")
	bin := filepath.Join(appDir, "bin", "app")
	placeTestBinary(t, bin)
	pid, done := startDetached(t, bin, "sleep")

	roots := appDirRoots(appDir)
	if err := os.RemoveAll(appDir); err != nil {
		t.Fatal(err)
	}
	found, left := stopProcessesRunningFrom(roots, 5*time.Second)
	if !pidsOf(found)[pid] || len(left) != 0 {
		t.Fatalf("found=%+v left=%+v, want pid %d stopped", found, left, pid)
	}
	waitExited(t, "the process of the deleted app dir", done)
}

// `appstore uninstall` stops what the app left running — from the app dir
// and from a backup of an earlier install — before deleting the dir, and
// reports it.
func TestCmdAppStoreUninstallStopsLeftoverProcesses(t *testing.T) {
	requireProcessTable(t)
	base := t.TempDir()
	root := filepath.Join(base, "apps")
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	t.Setenv("PILOT_APPSTORE_BACKUP_ROOT", "")
	appID := "io.test.leftover"
	appDir := filepath.Join(root, appID)
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mf := `{"id":"` + appID + `","app_version":"1.0.0","manifest_version":1,` +
		`"binary":{"path":"bin/app","sha256":"` + hex64 + `"},"exposes":["leftover.help"]}`
	if err := os.WriteFile(filepath.Join(appDir, "manifest.json"), []byte(mf), 0o644); err != nil {
		t.Fatal(err)
	}
	vm := filepath.Join(appDir, "tool-1.0", "tool-bin")
	placeTestBinary(t, vm)
	vmPID, vmDone := startDetached(t, vm, "sleep")

	backup := filepath.Join(base, "app-backups", appID, "20260101T000000Z-upgrade")
	old := filepath.Join(backup, "tool-0.9", "tool-bin")
	placeTestBinary(t, old)
	oldPID, oldDone := startDetached(t, old, "sleep")

	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = true
	out := captureStdout(t, func() { cmdAppStoreUninstall([]string{appID, "--yes"}) })
	var resp struct {
		Stopped      []appDirProcess `json:"stopped_processes"`
		StillRunning []appDirProcess `json:"still_running"`
		Backups      []string        `json:"backups"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	got := pidsOf(resp.Stopped)
	if !got[vmPID] || !got[oldPID] {
		t.Fatalf("stopped_processes = %+v, want pids %d and %d", resp.Stopped, vmPID, oldPID)
	}
	if len(resp.StillRunning) != 0 {
		t.Fatalf("still_running = %+v", resp.StillRunning)
	}
	waitExited(t, "the process running from the app dir", vmDone)
	waitExited(t, "the process running from the backup", oldDone)
	if _, err := os.Stat(appDir); !os.IsNotExist(err) {
		t.Fatalf("app dir should be gone: %v", err)
	}
	if _, err := os.Stat(backup); err != nil {
		t.Fatalf("the backup must be kept: %v", err)
	}
	audit, _ := os.ReadFile(filepath.Join(root, pilotctlAuditFileName))
	if !strings.Contains(string(audit), "stopped=") {
		t.Fatalf("audit record does not name the stopped processes: %s", audit)
	}
}
