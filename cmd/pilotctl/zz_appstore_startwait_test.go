// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// supLog appends supervisor.log lines the way the daemon's supervisor writes
// them.
func supLog(t *testing.T, appDir string, at time.Time, events ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(appDir, "supervisor.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, ev := range events {
		name, extra, _ := strings.Cut(ev, " ")
		line := fmt.Sprintf(`{"at":%q,"app":"io.test.app","event":%q`, at.UTC().Format(time.RFC3339Nano), name)
		if extra != "" {
			line += "," + extra
		}
		if _, err := f.WriteString(line + "}\n"); err != nil {
			t.Fatal(err)
		}
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadAppStart(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	before, after := since.Add(-time.Hour), since.Add(time.Second)
	const exit1 = `exit "exit_code":1`

	for _, tc := range []struct {
		name     string
		replaced bool
		setup    func(t *testing.T, dir string)
		want     string
		check    func(t *testing.T, st appStartStatus)
	}{
		{name: "nothing yet", setup: func(*testing.T, string) {}, want: appStartStarting,
			check: func(t *testing.T, st appStartStatus) {
				if st.Picked {
					t.Error("Picked with no supervisor event")
				}
			}},
		{name: "only pilotctl's own install line", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "installed")
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Picked || st.LastEvent != "" {
				t.Errorf("pilotctl's install line counted as a supervisor event: %+v", st)
			}
		}},
		{name: "spawned, socket not there yet", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", "spawn")
		}, want: appStartStarting},
		{name: "spawned and socket there", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", "spawn")
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted},
		{name: "socket without a spawn since the install is a leftover", setup: func(t *testing.T, dir string) {
			supLog(t, dir, before, "supervise-start", "spawn")
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarting},
		{name: "one exit is not a failure", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", "spawn", exit1)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 1 || st.ExitCode != 1 {
				t.Errorf("exits=%d code=%d", st.Exits, st.ExitCode)
			}
		}},
		{name: "two exits and no socket", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", "spawn", exit1, "spawn", `exit "exit_code":3`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 2 || st.ExitCode != 3 || !strings.Contains(st.LastEvent, `"exit_code":3`) {
				t.Errorf("%+v", st)
			}
		}},
		{name: "exited once, then came up", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", "spawn", exit1, "spawn")
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted},
		{name: "exits of the previous install do not count", setup: func(t *testing.T, dir string) {
			supLog(t, dir, before, "spawn", exit1, "spawn", exit1, "spawn", exit1, "suspend")
			supLog(t, dir, after, "supervise-start", "spawn")
		}, want: appStartStarting},
		{name: "replaced install: the stopped old instance logs an exit too", replaced: true, setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "upgrade-applied", "exit", "supervise-start", "spawn", exit1)
		}, want: appStartStarting},
		{name: "replaced install: three exits", replaced: true, setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "upgrade-applied", "exit", "supervise-start", "spawn", exit1, "spawn", exit1)
		}, want: appStartFailed},
		{name: "suspend event", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, "supervise-start", `verify-fail "reason":"sha256 mismatch"`, `suspend "reason":">=10 consecutive verify failures"`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if !st.Suspended {
				t.Error("not marked suspended")
			}
		}},
		{name: "suspended marker written since the install", setup: func(t *testing.T, dir string) {
			touch(t, filepath.Join(dir, ".suspended"))
		}, want: appStartFailed},
		{name: "suspended marker carried from the previous install", setup: func(t *testing.T, dir string) {
			marker := filepath.Join(dir, ".suspended")
			touch(t, marker)
			if err := os.Chtimes(marker, before, before); err != nil {
				t.Fatal(err)
			}
		}, want: appStartStarting},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			st := readAppStart(dir, since, tc.replaced)
			if st.State != tc.want {
				t.Fatalf("state = %q, want %q (%+v)", st.State, tc.want, st)
			}
			if tc.check != nil {
				tc.check(t, st)
			}
		})
	}
}

func shortStartWait(t *testing.T, wait time.Duration) {
	t.Helper()
	prevWait, prevPoll := appStartWait, appStartPoll
	appStartWait, appStartPoll = wait, 20*time.Millisecond
	t.Cleanup(func() { appStartWait, appStartPoll = prevWait, prevPoll })
}

// The wait ends as soon as the start is decided, and at the deadline
// otherwise: an app that is merely slow is "starting", never "failed".
func TestWaitForAppStart(t *testing.T) {
	shortStartWait(t, 0)
	t.Run("returns when the socket appears", func(t *testing.T) {
		dir := t.TempDir()
		since := time.Now()
		go func() {
			time.Sleep(200 * time.Millisecond)
			supLog(t, dir, time.Now(), "supervise-start", "spawn")
			touch(t, filepath.Join(dir, "app.sock"))
		}()
		st := waitForAppStart(dir, since, false, 10*time.Second)
		if st.State != appStartStarted || st.Waited > 5*time.Second {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("returns on the second exit", func(t *testing.T) {
		dir := t.TempDir()
		since := time.Now()
		go func() {
			time.Sleep(100 * time.Millisecond)
			supLog(t, dir, time.Now(), "supervise-start", "spawn", `exit "exit_code":1`)
			time.Sleep(100 * time.Millisecond)
			supLog(t, dir, time.Now(), "spawn", `exit "exit_code":1`)
		}()
		st := waitForAppStart(dir, since, false, 10*time.Second)
		if st.State != appStartFailed || st.Waited > 5*time.Second {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("a slow app is still starting at the deadline", func(t *testing.T) {
		dir := t.TempDir()
		supLog(t, dir, time.Now(), "supervise-start", "spawn")
		st := waitForAppStart(dir, time.Now().Add(-time.Second), false, 300*time.Millisecond)
		if st.State != appStartStarting || st.Waited < 300*time.Millisecond {
			t.Fatalf("%+v", st)
		}
	})
}

// installWithSupervisor installs a local bundle with a daemon socket
// listening, while supervise plays the daemon's supervisor on the app dir
// once the install has put the manifest there.
func installWithSupervisor(t *testing.T, id string, supervise func(appDir string), args ...string) (root string, report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	root = isolateAppStoreTest(t)
	sd := newStreamDaemon(t)
	t.Setenv("PILOT_SOCKET", sd.path)
	appDir := filepath.Join(root, id)
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if _, err := os.Stat(filepath.Join(appDir, "manifest.json")); err == nil {
				break
			}
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		if supervise != nil {
			supervise(appDir)
		}
	}()
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	var stdout string
	withJSON(func() {
		stdout, stderr, failure = runTrapped(t, func() { cmdAppStoreInstall(append([]string{bundle, "--local"}, args...)) })
	})
	close(stop)
	<-done
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("install report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return root, report, stderr, failure
}

func TestAppStoreInstallReportsStartedApp(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	const id = "io.test.starts"
	_, report, stderr, f := installWithSupervisor(t, id, func(appDir string) {
		time.Sleep(150 * time.Millisecond) // the rescan
		supLog(t, appDir, time.Now(), "supervise-start", "spawn")
		touch(t, filepath.Join(appDir, "app.sock"))
	})
	if f != nil {
		t.Fatalf("install failed: %+v\n%s", f, stderr)
	}
	if report["start_state"] != appStartStarted || report["id"] != id {
		t.Fatalf("report = %v", report)
	}
}

// The lab case: the app exits at every start. install used to exit 0 and
// say nothing.
func TestAppStoreInstallFailsForAppThatCrashesAtStart(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	const id = "io.test.crashes"
	root, report, stderr, f := installWithSupervisor(t, id, func(appDir string) {
		supLog(t, appDir, time.Now(), "supervise-start", "spawn", `exit "exit_code":1`)
		time.Sleep(100 * time.Millisecond) // the supervisor's restart delay
		supLog(t, appDir, time.Now(), "spawn", `exit "exit_code":1`)
	})
	if f == nil || f.Code != "app_start_failed" {
		t.Fatalf("install = %+v, want app_start_failed\nstderr: %s", f, stderr)
	}
	if !strings.Contains(f.Message, "exited 2 times at start (last exit code 1)") {
		t.Errorf("message = %q", f.Message)
	}
	// (stderr is the JSON error document, so the quoted log line is escaped.)
	for _, part := range []string{"Last supervisor event", "exit_code", "pilotctl appstore audit " + id, "daemon's log", "pilotctl appstore uninstall " + id} {
		if !strings.Contains(stderr, part) {
			t.Errorf("error output does not mention %q:\n%s", part, stderr)
		}
	}
	// The report is still printed, and the files are installed.
	if report["start_state"] != appStartFailed || report["start_exits"] != float64(2) || !strings.Contains(fmt.Sprint(report["start_detail"]), `"exit_code":1`) {
		t.Errorf("report = %v", report)
	}
	if _, err := os.Stat(filepath.Join(root, id, "manifest.json")); err != nil {
		t.Errorf("the app is not installed: %v", err)
	}
}

func TestAppStoreInstallFailsForSuspendedApp(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	const id = "io.test.suspended"
	_, report, stderr, f := installWithSupervisor(t, id, func(appDir string) {
		supLog(t, appDir, time.Now(), "supervise-start", `suspend "reason":">5 crashes in 1m0s"`)
		touch(t, filepath.Join(appDir, ".suspended"))
	})
	if f == nil || f.Code != "app_start_failed" || !strings.Contains(f.Message, "suspended it after repeated crashes") {
		t.Fatalf("install = %+v\nstderr: %s", f, stderr)
	}
	if !strings.Contains(stderr, "pilotctl appstore restart "+id) || report["start_state"] != appStartFailed {
		t.Errorf("report = %v\nstderr: %s", report, stderr)
	}
}

// A healthy app that needs longer than the wait (mysql took 16s to be
// ready) is a successful install.
func TestAppStoreInstallSlowAppIsNotAFailure(t *testing.T) {
	shortStartWait(t, 400*time.Millisecond)
	_, report, stderr, f := installWithSupervisor(t, "io.test.slow", func(appDir string) {
		supLog(t, appDir, time.Now(), "supervise-start", "spawn")
	})
	if f != nil {
		t.Fatalf("install of a slow app failed: %+v\n%s", f, stderr)
	}
	if report["start_state"] != appStartStarting {
		t.Fatalf("report = %v", report)
	}
	if ms, _ := report["start_waited_ms"].(float64); ms < 400 || ms > 5000 {
		t.Errorf("waited %vms for a 400ms wait", report["start_waited_ms"])
	}
}

// No wait, and no start_state in the report, when it would be pointless.
func TestAppStoreInstallDoesNotWaitWhenNothingWillStartTheApp(t *testing.T) {
	shortStartWait(t, 30*time.Second) // any wait would be obvious
	fast := func(t *testing.T, report map[string]any, took time.Duration) {
		t.Helper()
		if _, has := report["start_state"]; has || took > 10*time.Second {
			t.Fatalf("install waited (%s): %v", took, report)
		}
	}
	t.Run("--no-wait", func(t *testing.T) {
		begin := time.Now()
		_, report, stderr, f := installWithSupervisor(t, "io.test.nowait", nil, "--no-wait")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		fast(t, report, time.Since(begin))
	})
	t.Run("no daemon", func(t *testing.T) {
		isolateAppStoreTest(t) // points PILOT_SOCKET at a path nothing listens on
		bundle := writeVersionedBundle(t, "io.test.nodaemon", "1.0.0", "v1")
		begin := time.Now()
		var stdout string
		withJSON(func() { stdout, _ = installQuiet(t, bundle, "--local") })
		var report map[string]any
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("%v\n%s", err, stdout)
		}
		fast(t, report, time.Since(begin))
	})
	t.Run("reinstall of the same version and binary", func(t *testing.T) {
		const id = "io.test.samebinary"
		_, _, stderr, f := installWithSupervisor(t, id, nil, "--no-wait")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		// Same bundle again, with --force and without --no-wait: the
		// supervisor leaves the running app alone, so there is no start to see.
		// (The fake daemon serves one connection; give this install its own.)
		t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
		bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
		begin := time.Now()
		var stdout string
		withJSON(func() { stdout, _ = installQuiet(t, bundle, "--local", "--force") })
		var report map[string]any
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("%v\n%s", err, stdout)
		}
		fast(t, report, time.Since(begin))
	})
}

// Human output: the start is reported in place of "will be picked up within
// ~30s", and a failed start still prints what was installed first.
func TestAppStoreInstallTextOutputReportsStart(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	run := func(t *testing.T, id string, events ...string) (stdout, stderr string, f *trappedFatal) {
		root := isolateAppStoreTest(t)
		t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
		appDir := filepath.Join(root, id)
		go func() {
			for i := 0; i < 500; i++ {
				if _, err := os.Stat(filepath.Join(appDir, "manifest.json")); err == nil {
					supLog(t, appDir, time.Now(), events...)
					if events[len(events)-1] == "spawn" {
						touch(t, filepath.Join(appDir, "app.sock"))
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
		return runTrapped(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
	}
	t.Run("started", func(t *testing.T) {
		stdout, stderr, f := run(t, "io.test.textok", "supervise-start", "spawn")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		if !strings.Contains(stdout, "started: the daemon is running io.test.textok") || strings.Contains(stdout, "within ~30s") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if !strings.Contains(stderr, "waiting up to") || !strings.Contains(stderr, "--no-wait") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})
	t.Run("failed", func(t *testing.T) {
		stdout, stderr, f := run(t, "io.test.textbad", "supervise-start", "spawn", `exit "exit_code":1`, "spawn", `exit "exit_code":1`)
		if f == nil || f.Code != "app_start_failed" {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		if !strings.Contains(stdout, "installed io.test.textbad v1.0.0") || strings.Contains(stdout, "started:") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if !strings.Contains(stderr, `Last supervisor event: {"at":`) || !strings.Contains(stderr, "pilotctl appstore audit io.test.textbad") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})
}
