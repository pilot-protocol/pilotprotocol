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
// them. Tests call it from goroutines that play the supervisor, so failures
// are reported with t.Error: t.Fatal must not be called off the test's own
// goroutine.
func supLog(t *testing.T, appDir string, at time.Time, events ...string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(appDir, "supervisor.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Error(err)
		return
	}
	defer f.Close()
	for _, ev := range events {
		name, extra, _ := strings.Cut(ev, " ")
		line := fmt.Sprintf(`{"at":%q,"app":"io.test.app","event":%q`, at.UTC().Format(time.RFC3339Nano), name)
		if extra != "" {
			line += "," + extra
		}
		if _, err := f.WriteString(line + "}\n"); err != nil {
			t.Error(err)
			return
		}
	}
}

// touch creates an empty file; like supLog, it is called from goroutines.
func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Error(err)
	}
}

// ofBinary returns a supervisor.log event as the instance running the binary
// with this sha256 writes it: supervise-start and spawn carry the sha.
func ofBinary(sha, event string) string {
	if strings.Contains(event, " ") { // already has fields
		return event + `,"sha256":"` + sha + `"`
	}
	return event + ` "sha256":"` + sha + `"`
}

const (
	testNewSHA = "1111111111111111111111111111111111111111111111111111111111111111"
	testOldSHA = "2222222222222222222222222222222222222222222222222222222222222222"
)

func TestReadAppStart(t *testing.T) {
	since := time.Now().Add(-time.Minute)
	before, after := since.Add(-time.Hour), since.Add(time.Second)
	const exit1 = `exit "exit_code":1`
	var (
		start    = ofBinary(testNewSHA, "supervise-start")
		spawn    = ofBinary(testNewSHA, "spawn")
		upgraded = ofBinary(testNewSHA, "upgrade-applied")
		oldSpawn = ofBinary(testOldSHA, "spawn")
	)

	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
		check func(t *testing.T, st appStartStatus)
	}{
		{name: "nothing yet", setup: func(*testing.T, string) {}, want: appStartStarting,
			check: func(t *testing.T, st appStartStatus) {
				if st.Picked {
					t.Error("Picked with no supervisor event")
				}
			}},
		{name: "only pilotctl's own install line", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, ofBinary(testNewSHA, "installed"))
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Picked || st.LastEvent != "" {
				t.Errorf("pilotctl's install line counted as a supervisor event: %+v", st)
			}
		}},
		{name: "spawned, socket not there yet", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn)
		}, want: appStartStarting},
		{name: "spawned and socket there", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted},
		{name: "socket without a spawn since the install is a leftover", setup: func(t *testing.T, dir string) {
			supLog(t, dir, before, start, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarting},
		{name: "one exit is not a failure", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 1 || st.ExitCode != 1 {
				t.Errorf("exits=%d code=%d", st.Exits, st.ExitCode)
			}
		}},
		{name: "two exits and no socket", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1, spawn, `exit "exit_code":3`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 2 || st.ExitCode != 3 || !strings.Contains(st.LastEvent, `"exit_code":3`) {
				t.Errorf("%+v", st)
			}
		}},
		{name: "exited once, then came up", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted},
		{name: "exits of the previous install do not count", setup: func(t *testing.T, dir string) {
			supLog(t, dir, before, oldSpawn, exit1, oldSpawn, exit1, oldSpawn, exit1, "suspend")
			supLog(t, dir, after, start, spawn)
		}, want: appStartStarting},

		// The old instance runs until the supervisor's rescan replaces it, and
		// writes to the same log after the swap.
		{name: "upgrade: the old instance's crash loop is suspended after the swap", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, oldSpawn, exit1, `suspend "reason":">5 crashes in 1m0s"`)
			touch(t, filepath.Join(dir, ".suspended"))
			supLog(t, dir, after, upgraded, start, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 0 || st.Suspended || st.Spawns != 1 {
				t.Errorf("the old instance's events were counted: %+v", st)
			}
		}},
		{name: "upgrade: the old instance's suspend, the new one not up yet", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, exit1, `suspend "reason":">5 crashes in 1m0s"`, upgraded, start, spawn)
		}, want: appStartStarting},
		{name: "upgrade: the old instance's events before the rescan are not the new install's", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, exit1, oldSpawn, exit1, `suspend "reason":">5 crashes in 1m0s"`)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Picked || st.LastEvent != "" {
				t.Errorf("%+v", st)
			}
		}},
		{name: "upgrade: the old instance's exit when the rescan stops it, after the new supervise-start", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, upgraded, start, `exit "exit_code":-1`, `supervise-stop "reason":"context canceled"`, spawn, exit1)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 1 || st.ExitCode != 1 {
				t.Errorf("exits=%d code=%d, want only the new instance's one", st.Exits, st.ExitCode)
			}
		}},
		{name: "upgrade: the new instance exits twice", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, upgraded, `exit "exit_code":-1`, start, spawn, exit1, spawn, exit1)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 2 {
				t.Errorf("exits=%d, want 2", st.Exits)
			}
		}},
		{name: "a .suspended marker alone is the old instance's", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn)
			touch(t, filepath.Join(dir, ".suspended"))
		}, want: appStartStarting},

		{name: "the new instance's crash loop is suspended", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1, `suspend "reason":">5 crashes in 1m0s"`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if !st.Suspended || !strings.Contains(st.LastEvent, `"suspend"`) {
				t.Errorf("%+v", st)
			}
		}},
		{name: "suspended after verify failures", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, ofBinary(testNewSHA, `verify-fail "reason":"sha256 mismatch"`), `suspend "reason":">=10 consecutive verify failures"`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if !st.Suspended {
				t.Error("not marked suspended")
			}
		}},
		{name: "resumed by the operator", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1, `suspend "reason":">5 crashes in 1m0s"`, "resume", start, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}, want: appStartStarted},
		{name: "spawn-fail: the failure, not the exit -1 after it, is the last event", setup: func(t *testing.T, dir string) {
			fail := `spawn-fail "reason":"fork/exec bin/app: exec format error"`
			supLog(t, dir, after, start, fail, `exit "exit_code":-1`, fail, `exit "exit_code":-1`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 2 || !strings.Contains(st.StartError, "exec format error") || !strings.Contains(st.LastEvent, `"spawn-fail"`) {
				t.Errorf("%+v", st)
			}
			what, _ := st.startFailure("io.test.app")
			if !strings.Contains(what, "could not run it") || !strings.Contains(what, "exec format error") {
				t.Errorf("failure = %q", what)
			}
		}},
		{name: "spawn-time verify failure", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, ofBinary(testNewSHA, `verify-fail "reason":"spawn-time: sha256 mismatch"`), `exit "exit_code":-1`)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Exits != 1 || !strings.Contains(st.LastEvent, "spawn-time") {
				t.Errorf("%+v", st)
			}
		}},
		{name: "the old instance's verify failures are not the new install's", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, ofBinary(testOldSHA, `verify-fail "reason":"sha256 mismatch"`), `suspend "reason":">=10 consecutive verify failures"`)
		}, want: appStartStarting},
		{name: "refused as a downgrade", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, `downgrade-refused "reason":"rescan: refusing 1.5.0 (existing 2.0.0)"`)
		}, want: appStartFailed, check: func(t *testing.T, st appStartStatus) {
			if st.Refusal != "rescan: refusing 1.5.0 (existing 2.0.0)" || !st.Picked {
				t.Errorf("%+v", st)
			}
		}},
		{name: "another version's refusal is not this install's", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, `downgrade-refused "reason":"rescan: refusing 1.0.0 (existing 2.0.0)"`)
		}, want: appStartStarting, check: func(t *testing.T, st appStartStatus) {
			if st.Picked {
				t.Errorf("%+v", st)
			}
		}},
		{name: "the log rotated during the wait", setup: func(t *testing.T, dir string) {
			supLog(t, dir, after, start, spawn, exit1)
			if err := os.Rename(filepath.Join(dir, "supervisor.log"), filepath.Join(dir, "supervisor.log.1")); err != nil {
				t.Fatal(err)
			}
			supLog(t, dir, after, spawn, exit1)
		}, want: appStartFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			st := readAppStart(appStartTarget{Dir: dir, Since: since, Version: "1.5.0", BinarySHA256: testNewSHA})
			if st.State != tc.want {
				t.Fatalf("state = %q, want %q (%+v)", st.State, tc.want, st)
			}
			if tc.check != nil {
				tc.check(t, st)
			}
		})
	}
}

// Must order versions exactly as compareVersions in the app-store module's
// plugin/appstore (the daemon's supervisor) does.
func TestSupervisorVersionCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.1", "1.0.0", 1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"1.2", "1.2.0", 0},     // a missing part is 0
		{"1.0.0-beta.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-beta.1", 1},
		{"1.0.0-beta.2", "1.0.0-beta.1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta.10", "1.0.0-beta.9", -1}, // prereleases compare as plain strings
		{"2.0.0-rc.1", "1.9.9", 1},
	} {
		if got := supervisorVersionCompare(c.a, c.b); got != c.want {
			t.Errorf("supervisorVersionCompare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
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
	target := func(dir string, since time.Time) appStartTarget {
		return appStartTarget{Dir: dir, Since: since, Version: "1.0.0", BinarySHA256: testNewSHA}
	}
	start, spawn := ofBinary(testNewSHA, "supervise-start"), ofBinary(testNewSHA, "spawn")
	t.Run("returns when the socket appears", func(t *testing.T) {
		dir := t.TempDir()
		since := time.Now()
		go func() {
			time.Sleep(200 * time.Millisecond)
			supLog(t, dir, time.Now(), start, spawn)
			touch(t, filepath.Join(dir, "app.sock"))
		}()
		st := waitForAppStart(target(dir, since), 10*time.Second)
		if st.State != appStartStarted || st.Waited > 5*time.Second {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("returns on the second exit", func(t *testing.T) {
		dir := t.TempDir()
		since := time.Now()
		go func() {
			time.Sleep(100 * time.Millisecond)
			supLog(t, dir, time.Now(), start, spawn, `exit "exit_code":1`)
			time.Sleep(100 * time.Millisecond)
			supLog(t, dir, time.Now(), spawn, `exit "exit_code":1`)
		}()
		st := waitForAppStart(target(dir, since), 10*time.Second)
		if st.State != appStartFailed || st.Waited > 5*time.Second {
			t.Fatalf("%+v", st)
		}
	})
	t.Run("a slow app is still starting at the deadline", func(t *testing.T) {
		dir := t.TempDir()
		supLog(t, dir, time.Now(), start, spawn)
		st := waitForAppStart(target(dir, time.Now().Add(-time.Second)), 300*time.Millisecond)
		if st.State != appStartStarting || st.Waited < 300*time.Millisecond {
			t.Fatalf("%+v", st)
		}
	})
}

// installWithSupervisor installs a local bundle with a daemon socket
// listening, while supervise plays the daemon's supervisor on the app dir
// once the install has put the manifest there. sha is the bundle's binary
// sha256, which the supervisor logs on supervise-start and spawn.
func installWithSupervisor(t *testing.T, id string, supervise func(appDir, sha string), args ...string) (root string, report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	root = isolateAppStoreTest(t)
	sd := newStreamDaemon(t)
	t.Setenv("PILOT_SOCKET", sd.path)
	bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
	sha := sha256File(filepath.Join(bundle, "bin", "app"))
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
			supervise(appDir, sha)
		}
	}()
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
	_, report, stderr, f := installWithSupervisor(t, id, func(appDir, sha string) {
		time.Sleep(150 * time.Millisecond) // the rescan
		supLog(t, appDir, time.Now(), ofBinary(sha, "supervise-start"), ofBinary(sha, "spawn"))
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
	root, report, stderr, f := installWithSupervisor(t, id, func(appDir, sha string) {
		supLog(t, appDir, time.Now(), ofBinary(sha, "supervise-start"), ofBinary(sha, "spawn"), `exit "exit_code":1`)
		time.Sleep(100 * time.Millisecond) // the supervisor's restart delay
		supLog(t, appDir, time.Now(), ofBinary(sha, "spawn"), `exit "exit_code":1`)
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
	_, report, stderr, f := installWithSupervisor(t, id, func(appDir, sha string) {
		// A crash record carried over from an earlier instance can suspend
		// the app at its first exit.
		supLog(t, appDir, time.Now(), ofBinary(sha, "supervise-start"), ofBinary(sha, "spawn"), `exit "exit_code":1`, `suspend "reason":">5 crashes in 1m0s"`)
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
	_, report, stderr, f := installWithSupervisor(t, "io.test.slow", func(appDir, sha string) {
		supLog(t, appDir, time.Now(), ofBinary(sha, "supervise-start"), ofBinary(sha, "spawn"))
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
	// The supervisor orders a prerelease below its release, and refuses it.
	t.Run("--force to a prerelease of the installed version", func(t *testing.T) {
		const id = "io.test.prerelease"
		isolateAppStoreTest(t)
		installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local", "--no-wait")
		t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
		bundle := writeVersionedBundle(t, id, "1.0.0-beta.1", "beta")
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

// upgradeWithSupervisor installs v1.0.0 of id without waiting, then installs
// toVersion over it with --force and a daemon socket listening, while
// supervise plays the daemon's supervisor on the app dir once the new
// install is swapped in. sha is the new binary's sha256, which the
// supervisor logs on the new instance's supervise-start and spawn.
func upgradeWithSupervisor(t *testing.T, id, toVersion string, supervise func(appDir, sha string)) (report map[string]any, stderr string, failure *trappedFatal) {
	t.Helper()
	root := isolateAppStoreTest(t)
	installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local", "--no-wait")
	t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
	bundle := writeVersionedBundle(t, id, toVersion, "v2 "+toVersion)
	sha := sha256File(filepath.Join(bundle, "bin", "app"))
	appDir := filepath.Join(root, id)
	done := make(chan struct{})
	stop := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if m, _, err := readInstalledManifest(appDir); err == nil && m.Binary.SHA256 == sha {
				break
			}
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
		supervise(appDir, sha)
	}()
	var stdout string
	withJSON(func() {
		stdout, stderr, failure = runTrapped(t, func() { cmdAppStoreInstall([]string{bundle, "--local", "--force"}) })
	})
	close(stop)
	<-done
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("install report: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}
	return report, stderr, failure
}

// After the swap, the supervisor keeps running the replaced instance until
// its next rescan. What that instance logs in the meantime (its crash loop
// ending in a suspend, or the exit it logs when the rescan stops it) is not
// the new install's.
func TestAppStoreUpgradeIgnoresTheReplacedInstance(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	t.Run("old instance's crash loop is suspended after the swap", func(t *testing.T) {
		report, stderr, f := upgradeWithSupervisor(t, "io.test.oldcrashloop", "2.0.0", func(appDir, sha string) {
			// The old instance's sixth exit in a minute, after the swap.
			supLog(t, appDir, time.Now(), ofBinary(testOldSHA, "spawn"), `exit "exit_code":1`, `suspend "reason":">5 crashes in 1m0s"`)
			touch(t, filepath.Join(appDir, ".suspended"))
			time.Sleep(50 * time.Millisecond) // the rescan
			supLog(t, appDir, time.Now(), ofBinary(sha, "upgrade-applied"), ofBinary(sha, "supervise-start"))
			_ = os.Remove(filepath.Join(appDir, ".suspended")) // supervise-start clears it
			supLog(t, appDir, time.Now(), ofBinary(sha, "spawn"))
			touch(t, filepath.Join(appDir, "app.sock"))
		})
		if f != nil {
			t.Fatalf("a good upgrade failed: %+v\nstderr: %s", f, stderr)
		}
		if report["start_state"] != appStartStarted {
			t.Fatalf("report = %v", report)
		}
		if _, has := report["start_exits"]; has {
			t.Errorf("the old instance's exit was counted: %v", report)
		}
	})
	t.Run("old instance stopped by the rescan", func(t *testing.T) {
		report, stderr, f := upgradeWithSupervisor(t, "io.test.oldstopped", "2.0.0", func(appDir, sha string) {
			// The new instance's supervise-start is logged before the old
			// instance has exited: the old one gets up to 3s to shut down.
			supLog(t, appDir, time.Now(), ofBinary(sha, "upgrade-applied"), ofBinary(sha, "supervise-start"),
				`exit "exit_code":-1`, `supervise-stop "reason":"context canceled"`, ofBinary(sha, "spawn"))
			touch(t, filepath.Join(appDir, "app.sock"))
		})
		if f != nil {
			t.Fatalf("%+v\nstderr: %s", f, stderr)
		}
		if report["start_state"] != appStartStarted {
			t.Fatalf("report = %v", report)
		}
		if _, has := report["start_exits"]; has {
			t.Errorf("the old instance's exit was counted: %v", report)
		}
	})
	t.Run("new instance crashes after the old one is stopped", func(t *testing.T) {
		report, stderr, f := upgradeWithSupervisor(t, "io.test.newcrashes", "2.0.0", func(appDir, sha string) {
			supLog(t, appDir, time.Now(), ofBinary(sha, "upgrade-applied"), `exit "exit_code":-1`, ofBinary(sha, "supervise-start"),
				ofBinary(sha, "spawn"), `exit "exit_code":4`)
			time.Sleep(100 * time.Millisecond) // the supervisor's restart delay
			supLog(t, appDir, time.Now(), ofBinary(sha, "spawn"), `exit "exit_code":4`)
		})
		if f == nil || f.Code != "app_start_failed" {
			t.Fatalf("install = %+v, want app_start_failed\nstderr: %s", f, stderr)
		}
		if report["start_exits"] != float64(2) || !strings.Contains(f.Message, "exited 2 times at start (last exit code 4)") {
			t.Errorf("exits miscounted: %v\n%s", report, f.Message)
		}
	})
}

// The supervisor refuses an install it orders below the version it runs,
// and logs downgrade-refused on every rescan. That is the outcome: the new
// version will not start, so install says so at once instead of waiting.
func TestAppStoreInstallReportsDowngradeRefusal(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	begin := time.Now()
	// v1.0.0 is on disk, but the daemon runs v2.0.0 (it refused v1.0.0
	// earlier), so it refuses v1.5.0 too.
	report, stderr, f := upgradeWithSupervisor(t, "io.test.refused", "1.5.0", func(appDir, _ string) {
		supLog(t, appDir, time.Now(), `downgrade-refused "reason":"rescan: refusing 1.5.0 (existing 2.0.0)"`)
	})
	if took := time.Since(begin); took > 5*time.Second {
		t.Errorf("install waited %s for an app the daemon refused", took)
	}
	if f == nil || f.Code != "app_start_failed" {
		t.Fatalf("install = %+v, want app_start_failed\nreport: %v\nstderr: %s", f, report, stderr)
	}
	if !strings.Contains(f.Message, "refusing 1.5.0 (existing 2.0.0)") || !strings.Contains(f.Message, "older") {
		t.Errorf("message = %q", f.Message)
	}
	if !strings.Contains(stderr, "restart") || report["start_state"] != appStartFailed {
		t.Errorf("report = %v\nstderr: %s", report, stderr)
	}
}

// Human output: the start is reported in place of "will be picked up within
// ~30s", and a failed start still prints what was installed first.
func TestAppStoreInstallTextOutputReportsStart(t *testing.T) {
	shortStartWait(t, 10*time.Second)
	// events are logged once the install is there; supervise-start and spawn
	// as the new install's, and a final spawn opens the app's socket.
	run := func(t *testing.T, id string, events ...string) (stdout, stderr string, f *trappedFatal) {
		root := isolateAppStoreTest(t)
		t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
		bundle := writeVersionedBundle(t, id, "1.0.0", "v1")
		sha := sha256File(filepath.Join(bundle, "bin", "app"))
		appDir := filepath.Join(root, id)
		done := make(chan struct{})
		go func() {
			defer close(done)
			if len(events) == 0 {
				return
			}
			for i := 0; i < 500; i++ {
				if _, err := os.Stat(filepath.Join(appDir, "manifest.json")); err == nil {
					var lines []string
					for _, ev := range events {
						if ev == "supervise-start" || ev == "spawn" {
							ev = ofBinary(sha, ev)
						}
						lines = append(lines, ev)
					}
					supLog(t, appDir, time.Now(), lines...)
					if events[len(events)-1] == "spawn" {
						touch(t, filepath.Join(appDir, "app.sock"))
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}()
		stdout, stderr, f = runTrapped(t, func() { cmdAppStoreInstall([]string{bundle, "--local"}) })
		<-done
		return stdout, stderr, f
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
	// One note, not "has not started after 300ms" and "will be picked up
	// within ~30s" both.
	t.Run("not picked up by the end of the wait", func(t *testing.T) {
		shortStartWait(t, 300*time.Millisecond)
		stdout, stderr, f := run(t, "io.test.textnotyet")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		if !strings.Contains(stdout, "has not started io.test.textnotyet") || strings.Contains(stdout, "within ~30s") {
			t.Errorf("stdout:\n%s", stdout)
		}
	})
	t.Run("an older version is not waited for, and says so", func(t *testing.T) {
		const id = "io.test.textolder"
		isolateAppStoreTest(t)
		installQuiet(t, writeVersionedBundle(t, id, "1.0.0", "v1"), "--local", "--no-wait")
		t.Setenv("PILOT_SOCKET", newStreamDaemon(t).path)
		stdout, stderr := installQuiet(t, writeVersionedBundle(t, id, "1.0.0-rc.1", "rc"), "--local", "--force")
		if !strings.Contains(stdout, "v1.0.0-rc.1 is older than the v1.0.0 it replaced") || strings.Contains(stdout, "within ~30s") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if strings.Contains(stderr, "waiting up to") {
			t.Errorf("stderr:\n%s", stderr)
		}
	})
}

// --wait <duration> replaces the default wait; 0 does not wait.
func TestAppStoreInstallWaitFlag(t *testing.T) {
	shortStartWait(t, 30*time.Second) // the default, which --wait replaces
	slow := func(appDir, sha string) {
		supLog(t, appDir, time.Now(), ofBinary(sha, "supervise-start"), ofBinary(sha, "spawn"))
	}
	t.Run("--wait 300ms", func(t *testing.T) {
		_, report, stderr, f := installWithSupervisor(t, "io.test.waitshort", slow, "--wait", "300ms")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		if ms, _ := report["start_waited_ms"].(float64); report["start_state"] != appStartStarting || ms < 300 || ms > 5000 {
			t.Errorf("report = %v", report)
		}
	})
	t.Run("--wait 0", func(t *testing.T) {
		_, report, stderr, f := installWithSupervisor(t, "io.test.waitzero", slow, "--wait", "0")
		if f != nil {
			t.Fatalf("%+v\n%s", f, stderr)
		}
		if _, has := report["start_state"]; has {
			t.Errorf("waited: %v", report)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		isolateAppStoreTest(t)
		for _, bad := range [][]string{{"--wait"}, {"--wait", "soon"}, {"--wait", "-1s"}} {
			_, _, f := runTrapped(t, func() {
				cmdAppStoreInstall(append([]string{writeVersionedBundle(t, "io.test.waitbad", "1.0.0", "v1"), "--local"}, bad...))
			})
			if f == nil || f.Code != "invalid_argument" {
				t.Errorf("%v: %+v", bad, f)
			}
		}
	})
}
