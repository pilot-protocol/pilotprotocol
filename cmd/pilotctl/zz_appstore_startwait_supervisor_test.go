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

// installUnderRealSupervisor installs a local bundle whose binary is the
// given shell script while the daemon's real app supervisor (the app-store
// module, with the daemon's 2s rescan shortened) watches the install root.
// Unlike the tests in zz_appstore_startwait_test.go, nothing here writes
// supervisor.log by hand: what install reads is what the supervisor wrote.
func installUnderRealSupervisor(t *testing.T, id, script string) (report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	root := isolateAppStoreTest(t)
	t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)

	svc := appstore.NewService(appstore.Config{
		InstallRoot:    root,
		RescanInterval: 100 * time.Millisecond,
		Logger:         log.New(io.Discard, "", 0),
	})
	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.Start(ctx, appstore.Deps{}); err != nil {
		cancel()
		t.Fatalf("start supervisor: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		// The healthy test app runs for as long as its socket file exists.
		_ = os.Remove(filepath.Join(root, id, "app.sock"))
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer stopCancel()
		_ = svc.Stop(stopCtx)
	})

	// writeVersionedBundle writes "#!/bin/sh\necho <body>\n". The supervisor
	// runs in this process and hands the app this process's stderr, which is
	// the pipe runTrapped captures while the install runs; the app lets go of
	// it at once, or the capture would wait for the app to exit.
	bundle := writeVersionedBundle(t, id, "1.0.0", "starting >/dev/null\nexec >/dev/null 2>&1\n"+script)
	var stdout string
	withJSON(func() {
		stdout, stderr, failure = runTrapped(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
	})
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("install report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	log, _ := os.ReadFile(filepath.Join(root, id, "supervisor.log"))
	t.Logf("supervisor.log:\n%s", log)
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
	// Opens its "socket" (the supervisor and pilotctl only look for the
	// path) and keeps running, like an app does, until the file is removed.
	script := `while [ $# -gt 0 ]; do if [ "$1" = "--socket" ]; then sock="$2"; fi; shift; done
: > "$sock"
while [ -e "$sock" ]; do sleep 0.2; done`
	report, stderr, f := installUnderRealSupervisor(t, "io.test.realhealthy", script)
	if f != nil {
		t.Fatalf("install of a healthy app failed: %+v\n%s", f, stderr)
	}
	if report["start_state"] != appStartStarted {
		t.Fatalf("report = %v", report)
	}
}
