// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/app-store/plugin/appstore"
)

// startRealSupervisor isolates the install root and runs the daemon's real
// app supervisor (the app-store module, with the daemon's 2s rescan
// shortened to rescan) on it. Unlike the tests in
// zz_appstore_startwait_test.go, nothing here writes supervisor.log by hand:
// what install reads is what the supervisor wrote.
func startRealSupervisor(t *testing.T, rescan time.Duration) (root string) {
	t.Helper()
	root = isolateAppStoreTest(t)
	svc := appstore.NewService(appstore.Config{
		InstallRoot:    root,
		RescanInterval: rescan,
		Logger:         log.New(io.Discard, "", 0),
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.Start(ctx, appstore.Deps{}); err != nil {
		cancel()
		t.Fatalf("start supervisor: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		// A healthy test app runs for as long as its socket file exists.
		socks, _ := filepath.Glob(filepath.Join(root, "*", "app.sock"))
		for _, s := range socks {
			_ = os.Remove(s)
		}
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		_ = svc.Stop(stopCtx)
	})
	return root
}

// realBundle writes a local bundle whose binary is the given shell script.
// writeVersionedBundle writes "#!/bin/sh\necho <body>\n". The supervisor runs
// in this process and hands the app this process's stderr, which is the pipe
// runTrapped captures while an install runs; the app lets go of it at once,
// or the capture would wait for the app to exit. tag makes the binary, and
// so its sha256, differ between versions.
func realBundle(t *testing.T, id, version, tag, script string) string {
	t.Helper()
	return writeVersionedBundle(t, id, version, tag+" >/dev/null\nexec >/dev/null 2>&1\n"+script)
}

// installUnderDaemon runs a JSON-mode install with a daemon socket
// listening (the fake daemon serves one connection, so each install gets
// its own).
func installUnderDaemon(t *testing.T, args ...string) (report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
	var stdout string
	withJSON(func() {
		stdout, stderr, failure = runTrapped(t, func() { cmdAppStoreInstall(args) })
	})
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("install report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return report, stderr, failure
}

func logSupervisor(t *testing.T, appDir string) {
	t.Helper()
	log, _ := os.ReadFile(filepath.Join(appDir, "supervisor.log"))
	t.Logf("supervisor.log:\n%s", log)
}

// healthyScript opens its "socket" (the supervisor and pilotctl only look for
// the path) and keeps running, like an app does, until the file is removed.
const healthyScript = `while [ $# -gt 0 ]; do if [ "$1" = "--socket" ]; then sock="$2"; fi; shift; done
: > "$sock"
while [ -e "$sock" ]; do sleep 0.2; done`

// installUnderRealSupervisor installs a local bundle whose binary is the
// given shell script under the real supervisor.
func installUnderRealSupervisor(t *testing.T, id, script string) (report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	root := startRealSupervisor(t, 100*time.Millisecond)
	report, stderr, failure = installUnderDaemon(t, realBundle(t, id, "1.0.0", "starting", script), "--local")
	logSupervisor(t, filepath.Join(root, id))
	return report, stderr, failure
}

func TestAppStoreInstallUnderRealSupervisorCrashingApp(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out the supervisor's 1s restart delay")
	}
	const id = "io.test.realcrash"
	report, stderr, f := installUnderRealSupervisor(t, id, "exit 7")
	if f == nil || f.Code != "app_start_failed" {
		t.Fatalf("install = %+v, want app_start_failed\nreport: %v\nstderr: %s", f, report, stderr)
	}
	if !strings.Contains(f.Message, "exited 2 times at start (last exit code 7)") {
		t.Errorf("message = %q", f.Message)
	}
	if report["start_state"] != appStartFailed {
		t.Errorf("report = %v", report)
	}
	if ms, _ := report["start_waited_ms"].(float64); ms > 15000 {
		t.Errorf("took %vms to see two exits", ms)
	}
}

func TestAppStoreInstallUnderRealSupervisorHealthyApp(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real process")
	}
	report, stderr, f := installUnderRealSupervisor(t, "io.test.realhealthy", healthyScript)
	if f != nil {
		t.Fatalf("install of a healthy app failed: %+v\n%s", f, stderr)
	}
	if report["start_state"] != appStartStarted {
		t.Fatalf("report = %v", report)
	}
}

// An upgrade of a running app: the replaced instance exits after the swap
// (its socket went with the old dir) and is stopped by the rescan. None of
// that is the new install's.
func TestAppStoreUpgradeUnderRealSupervisor(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real processes")
	}
	shortStartWait(t, 10*time.Second)
	const id = "io.test.realupgrade"
	// A rescan slower than the old app's 0.2s socket check, so the old
	// instance has exited (and is waiting out its restart delay) when the
	// rescan replaces it.
	root := startRealSupervisor(t, 500*time.Millisecond)
	appDir := filepath.Join(root, id)
	if report, stderr, f := installUnderDaemon(t, realBundle(t, id, "1.0.0", "v1", healthyScript), "--local"); f != nil || report["start_state"] != appStartStarted {
		t.Fatalf("install v1: %+v %v\n%s", f, report, stderr)
	}
	report, stderr, f := installUnderDaemon(t, realBundle(t, id, "2.0.0", "v2", healthyScript), "--local", "--force")
	logSupervisor(t, appDir)
	if f != nil {
		t.Fatalf("upgrade failed: %+v\n%s", f, stderr)
	}
	if report["start_state"] != appStartStarted {
		t.Fatalf("report = %v", report)
	}
	if _, has := report["start_exits"]; has {
		t.Errorf("the replaced instance's exit was counted: %v", report)
	}
}

// The supervisor compares an install with the version it runs, which can be
// newer than the one on disk: here it runs v2.0.0 and refused the v1.0.0
// installed over it, so it refuses v1.5.0 as well. install reports that at
// once instead of waiting for a start that will not come.
func TestAppStoreInstallUnderRealSupervisorDowngradeRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a real process")
	}
	shortStartWait(t, 10*time.Second)
	const id = "io.test.realrefused"
	root := startRealSupervisor(t, 100*time.Millisecond)
	appDir := filepath.Join(root, id)
	if report, stderr, f := installUnderDaemon(t, realBundle(t, id, "2.0.0", "v2", healthyScript), "--local"); f != nil || report["start_state"] != appStartStarted {
		t.Fatalf("install v2: %+v %v\n%s", f, report, stderr)
	}
	if report, stderr, f := installUnderDaemon(t, realBundle(t, id, "1.0.0", "v1", healthyScript), "--local", "--force"); f != nil {
		t.Fatalf("install v1: %+v %v\n%s", f, report, stderr)
	}
	begin := time.Now()
	report, stderr, f := installUnderDaemon(t, realBundle(t, id, "1.5.0", "v1.5", healthyScript), "--local", "--force")
	logSupervisor(t, appDir)
	if f == nil || f.Code != "app_start_failed" {
		t.Fatalf("install v1.5 = %+v, want app_start_failed\nreport: %v\nstderr: %s", f, report, stderr)
	}
	if !strings.Contains(f.Message, "refusing 1.5.0 (existing 2.0.0)") {
		t.Errorf("message = %q", f.Message)
	}
	if took := time.Since(begin); took > 5*time.Second {
		t.Errorf("took %s to see the refusal", took)
	}
}

// install waits exactly when the supervisor will act: it orders a
// prerelease below its release, as the supervisor does.
func TestAppStoreInstallUnderRealSupervisorPrereleaseOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("starts real processes")
	}
	shortStartWait(t, 10*time.Second)
	const id = "io.test.realprerelease"
	root := startRealSupervisor(t, 100*time.Millisecond)
	appDir := filepath.Join(root, id)
	if report, stderr, f := installUnderDaemon(t, realBundle(t, id, "1.0.0-beta.1", "beta1", healthyScript), "--local"); f != nil || report["start_state"] != appStartStarted {
		t.Fatalf("install 1.0.0-beta.1: %+v %v\n%s", f, report, stderr)
	}
	// The release is newer than its prerelease: the supervisor switches to it.
	report, stderr, f := installUnderDaemon(t, realBundle(t, id, "1.0.0", "release", healthyScript), "--local", "--force")
	if f != nil || report["start_state"] != appStartStarted {
		logSupervisor(t, appDir)
		t.Fatalf("1.0.0-beta.1 → 1.0.0: %+v %v\n%s", f, report, stderr)
	}
	// A prerelease of the running release is older: no wait, and the
	// supervisor does refuse it.
	begin := time.Now()
	report, stderr, f = installUnderDaemon(t, realBundle(t, id, "1.0.0-beta.2", "beta2", healthyScript), "--local", "--force")
	if f != nil {
		t.Fatalf("1.0.0 → 1.0.0-beta.2: %+v\n%s", f, stderr)
	}
	if _, has := report["start_state"]; has || time.Since(begin) > 5*time.Second {
		t.Errorf("waited for a start the supervisor refuses: %v", report)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		log, _ := os.ReadFile(filepath.Join(appDir, "supervisor.log"))
		if strings.Contains(string(log), "refusing 1.0.0-beta.2 (existing 1.0.0)") {
			break
		}
		if time.Now().After(deadline) {
			logSupervisor(t, appDir)
			t.Fatal("the supervisor did not refuse 1.0.0-beta.2, so install should have waited for it")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
