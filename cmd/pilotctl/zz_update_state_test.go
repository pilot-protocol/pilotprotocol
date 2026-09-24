// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pilot-protocol/updater"
)

// fakeUpdateRunner stands in for *updater.Updater in `pilotctl update` tests:
// no GitHub, no binary replacement, no daemon restart.
type fakeUpdateRunner struct {
	cfg    updater.Config
	err    error
	status updater.Status
	// record mimics the real updater: write status to cfg.StatusPath when
	// RunOnce finishes, so `update status` can read it back.
	record bool
	// check, when set, is a successful check recorded the way updater
	// v0.2.5 records it: merged into the record already at cfg.StatusPath,
	// and the merged record is what LastStatus returns. It replaces status.
	check *fakeCheck
}

func (f *fakeUpdateRunner) RunOnce() error {
	if f.check != nil {
		base, _ := updater.ReadStatus(f.cfg.StatusPath)
		f.check.record(&base)
		f.status = base
		f.record = true
	}
	if f.record && f.cfg.StatusPath != "" {
		b, _ := json.Marshal(f.status)
		_ = os.MkdirAll(filepath.Dir(f.cfg.StatusPath), 0o755)
		_ = os.WriteFile(f.cfg.StatusPath, b, 0o644)
	}
	return f.err
}

func (f *fakeUpdateRunner) LastStatus() updater.Status { return f.status }

// fakeCheck is one successful manual check. record applies it to the record
// on disk as updater v0.2.5's recordCheck (status.go) does, including what
// it leaves alone: restart_error is cleared only when this check installed
// a release, restarted the daemon without error and did not replace
// pilot-updater. Every real release replaces pilot-updater, so a
// restart_error from an earlier run survives a successful restart, and an
// up-to-date check off Linux never clears it.
type fakeCheck struct {
	current, latest, installed string
	updaterReplaced            bool
	restartErr                 error
}

func (c *fakeCheck) record(s *updater.Status) {
	now := time.Now().UTC()
	s.LastCheckAt = now
	s.LastCheckTrigger = updater.TriggerManual
	if c.latest != "" {
		s.LatestVersion = c.latest
	}
	switch {
	case c.installed != "":
		s.CurrentVersion = c.installed
	case c.current != "":
		s.CurrentVersion = c.current
	}
	s.LastError = ""
	s.ConsecutiveFailures = 0
	s.LastSuccessAt = now
	if c.installed == "" {
		s.LastResult = updater.ResultUpToDate
		return
	}
	s.LastResult = updater.ResultUpdated
	s.LastUpdateAt = now
	s.LastUpdateVersion = c.installed
	if c.restartErr != nil {
		s.RestartError = c.restartErr.Error()
	} else if !c.updaterReplaced {
		s.RestartError = ""
	}
}

// withDaemonProbe swaps daemonVersionProbe for probe, so no test reaches a
// real daemon, and shortens the restart wait. It returns the probe count.
func withDaemonProbe(t *testing.T, probe func() (string, bool)) *int {
	t.Helper()
	calls := new(int)
	prevProbe, prevWait, prevInterval := daemonVersionProbe, restartSettleWait, daemonProbeInterval
	daemonVersionProbe = func() (string, bool) {
		*calls++
		return probe()
	}
	restartSettleWait = 2 * time.Second
	daemonProbeInterval = time.Millisecond
	t.Cleanup(func() {
		daemonVersionProbe, restartSettleWait, daemonProbeInterval = prevProbe, prevWait, prevInterval
	})
	return calls
}

// daemonAt is a probe for a daemon that answers with ver.
func daemonAt(ver string) func() (string, bool) {
	return func() (string, bool) { return ver, true }
}

// noDaemon is a probe for a host where nothing answers on the socket.
func noDaemon() (string, bool) { return "", false }

// withFakeUpdater isolates HOME, points PILOT_UPDATER_BIN at a temp install
// dir, swaps newUpdateRunner for fake and fakes a host with no daemon
// running (tests that need one call withDaemonProbe again). Returns the
// temp HOME.
func withFakeUpdater(t *testing.T, fake *fakeUpdateRunner) string {
	t.Helper()
	home := withTempHomeFull(t)
	t.Setenv("PILOT_UPDATER_BIN", filepath.Join(home, "bin", "pilot-updater"))
	t.Setenv("PILOT_SOCKET", filepath.Join(home, "no-daemon.sock"))
	withDaemonProbe(t, noDaemon)
	prev := newUpdateRunner
	newUpdateRunner = func(cfg updater.Config) updateRunner {
		fake.cfg = cfg
		return fake
	}
	t.Cleanup(func() { newUpdateRunner = prev })
	return home
}

func withJSONOutput(t *testing.T, on bool) {
	t.Helper()
	prev := jsonOutput
	jsonOutput = on
	t.Cleanup(func() { jsonOutput = prev })
}

// TestCmdUpdate_PassesStatusPath pins the updater#49 follow-up: the one-shot
// updater records into the same ~/.pilot/update-state.json the pilot-updater
// loop writes, so manual runs show up in `pilotctl update status`.
func TestCmdUpdate_PassesStatusPath(t *testing.T) {
	fake := &fakeUpdateRunner{status: updater.Status{LastResult: updater.ResultUpToDate, CurrentVersion: "v1.2.3"}}
	home := withFakeUpdater(t, fake)
	withJSONOutput(t, true)

	_ = captureStdout(t, func() { cmdUpdate([]string{"--pin", "v1.2.3"}) })

	if want := filepath.Join(home, ".pilot", "update-state.json"); fake.cfg.StatusPath != want {
		t.Errorf("StatusPath = %q, want %q", fake.cfg.StatusPath, want)
	}
	if want := filepath.Join(home, "bin"); fake.cfg.InstallDir != want {
		t.Errorf("InstallDir = %q, want %q", fake.cfg.InstallDir, want)
	}
	if fake.cfg.PinnedVersion != "v1.2.3" {
		t.Errorf("PinnedVersion = %q, want v1.2.3", fake.cfg.PinnedVersion)
	}
}

// TestCmdUpdate_RunOnceErrorExitsNonZero: a failed check used to print
// "Update check complete" / {"status":"ok"} and exit 0. It must now fail with
// code update_failed and the updater's error.
func TestCmdUpdate_RunOnceErrorExitsNonZero(t *testing.T) {
	cause := errors.New("fetch latest release: GitHub API returned 403 (rate limit exceeded)")

	t.Run("text", func(t *testing.T) {
		withFakeUpdater(t, &fakeUpdateRunner{err: cause})
		withJSONOutput(t, false)
		var failure *trappedFatal
		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				failure = runTrappingFatal(func() { cmdUpdate(nil) })
			})
		})
		if failure == nil {
			t.Fatal("cmdUpdate returned normally after RunOnce failed; want a fatal exit")
		}
		if failure.Code != "update_failed" {
			t.Errorf("code = %q, want update_failed", failure.Code)
		}
		if !strings.Contains(failure.Message, "update failed") || !strings.Contains(failure.Message, "rate limit exceeded") {
			t.Errorf("message = %q, want it to name the failure and its cause", failure.Message)
		}
		if !strings.Contains(stderr, "error: update failed: fetch latest release") {
			t.Errorf("stderr missing the error:\n%s", stderr)
		}
		if !strings.Contains(stderr, "pilotctl update status") {
			t.Errorf("stderr missing the hint:\n%s", stderr)
		}
		if strings.Contains(stdout, "Update check complete") {
			t.Errorf("failed update still printed success:\n%s", stdout)
		}
	})

	t.Run("json", func(t *testing.T) {
		withFakeUpdater(t, &fakeUpdateRunner{err: cause})
		withJSONOutput(t, true)
		var failure *trappedFatal
		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				failure = runTrappingFatal(func() { cmdUpdate(nil) })
			})
		})
		if failure == nil {
			t.Fatal("cmdUpdate returned normally after RunOnce failed; want a fatal exit")
		}
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("stdout must be empty on failure, got:\n%s", stdout)
		}
		var env map[string]interface{}
		if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &env); err != nil {
			t.Fatalf("stderr is not one JSON error envelope: %v\n%s", err, stderr)
		}
		if env["status"] != "error" || env["code"] != "update_failed" {
			t.Errorf("envelope = %v, want status=error code=update_failed", env)
		}
		if msg, _ := env["message"].(string); !strings.Contains(msg, "rate limit exceeded") {
			t.Errorf("message = %q, want the updater error", msg)
		}
	})
}

// TestCmdUpdate_JSONReportsResultAndRestartError: a successful install whose
// daemon restart failed is still exit 0, but --json carries the result and
// restart_error.
func TestCmdUpdate_JSONReportsResultAndRestartError(t *testing.T) {
	const restartErr = "restart daemon: pilot-daemon.service has Restart=on-failure; run: sudo systemctl restart pilot-daemon"
	fake := &fakeUpdateRunner{status: updater.Status{
		LastResult:     updater.ResultUpdated,
		CurrentVersion: "v1.14.0",
		LatestVersion:  "v1.14.0",
		RestartError:   restartErr,
	}}
	home := withFakeUpdater(t, fake)
	withDaemonProbe(t, daemonAt("v1.13.9"))
	withJSONOutput(t, true)

	out := captureStdout(t, func() { cmdUpdate(nil) })
	var env struct {
		Status string                 `json:"status"`
		Data   map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if env.Status != "ok" {
		t.Errorf("status = %q, want ok", env.Status)
	}
	want := map[string]interface{}{
		"result":          "updated",
		"updated":         true,
		"current_version": "v1.14.0",
		"latest_version":  "v1.14.0",
		"restart_error":   restartErr,
		"restart_needed":  true,
		"daemon_running":  true,
		"daemon_version":  "v1.13.9",
		"status_file":     filepath.Join(home, ".pilot", "update-state.json"),
	}
	for k, v := range want {
		if env.Data[k] != v {
			t.Errorf("data[%q] = %v, want %v", k, env.Data[k], v)
		}
	}
}

const (
	// macRestartErr is what updater v0.2.5 records when launchctl kickstart
	// fails, e.g. after `pilotctl daemon stop` booted the agent out.
	macRestartErr = "restart daemon (launchctl kickstart -k gui/501/network.pilotprotocol.pilot-daemon): exit status 113 Could not find service"
	// linuxRestartErr is a Linux restart_error; it names its own command.
	linuxRestartErr = "restart daemon: daemon (pid 42) left running the old version: pilot-daemon.service has Restart=on-failure, so systemd would not start the daemon again after it stops cleanly; restart it with: sudo systemctl restart pilot-daemon"
)

// printedUpdateResult runs printUpdateResult for st with the daemon
// answering as probe does, and returns what it wrote.
func printedUpdateResult(t *testing.T, st updater.Status, probe func() (string, bool)) (stdout, stderr string) {
	t.Helper()
	withDaemonProbe(t, probe)
	restart := checkDaemonRestart(st, 0)
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { printUpdateResult(st, restart) })
	})
	return stdout, stderr
}

// TestPrintUpdateResult covers the text report of a successful run.
func TestPrintUpdateResult(t *testing.T) {
	t.Run("daemon still on the old version", func(t *testing.T) {
		stdout, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.14.0", RestartError: macRestartErr},
			daemonAt("v1.13.9"))
		if !strings.Contains(stdout, "Updated to v1.14.0.") {
			t.Errorf("stdout = %q", stdout)
		}
		for _, want := range []string{
			"daemon is not running them (it runs v1.13.9, installed is v1.14.0)",
			macRestartErr,
			// The macOS message names only the launchctl call that failed.
			"restart it with: pilotctl daemon stop && pilotctl daemon start",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr missing %q:\n%s", want, stderr)
			}
		}
	})
	t.Run("linux message keeps its own command", func(t *testing.T) {
		_, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.14.0", RestartError: linuxRestartErr},
			daemonAt("v1.13.9"))
		if !strings.Contains(stderr, linuxRestartErr) {
			t.Errorf("stderr = %q", stderr)
		}
		if strings.Contains(stderr, "pilotctl daemon stop") {
			t.Errorf("a second restart command must not be added to one that names its own:\n%s", stderr)
		}
	})
	t.Run("daemon already on the installed version", func(t *testing.T) {
		stdout, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.14.0", RestartError: macRestartErr},
			daemonAt("v1.14.0"))
		if !strings.Contains(stdout, "Updated to v1.14.0.") {
			t.Errorf("stdout = %q", stdout)
		}
		if stderr != "" {
			t.Errorf("an out-of-date restart_error must not warn, got %q", stderr)
		}
	})
	t.Run("installed but no daemon running", func(t *testing.T) {
		_, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.14.0", RestartError: macRestartErr},
			noDaemon)
		for _, want := range []string{
			"warning: the daemon is not running; v1.14.0 runs when it starts.",
			"last restart attempt: " + macRestartErr,
			"start it with: pilotctl daemon start",
		} {
			if !strings.Contains(stderr, want) {
				t.Errorf("stderr missing %q:\n%s", want, stderr)
			}
		}
		if strings.Contains(stderr, "not running them") {
			t.Errorf("no daemon runs the old binaries:\n%s", stderr)
		}
	})
	t.Run("up to date", func(t *testing.T) {
		stdout, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpToDate, CurrentVersion: "v1.13.9"},
			daemonAt("v1.13.9"))
		if !strings.Contains(stdout, "Already up to date (v1.13.9).") {
			t.Errorf("stdout = %q", stdout)
		}
		if stderr != "" {
			t.Errorf("no warning expected, got %q", stderr)
		}
	})
	t.Run("up to date, restart error recorded, no daemon running", func(t *testing.T) {
		// Nothing was installed and nothing runs the old binaries.
		_, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpToDate, CurrentVersion: "v1.13.9", RestartError: macRestartErr},
			noDaemon)
		if stderr != "" {
			t.Errorf("no warning expected, got %q", stderr)
		}
	})
	t.Run("up to date, daemon still on the old version", func(t *testing.T) {
		// The restart an earlier run could not do is still needed.
		_, stderr := printedUpdateResult(t,
			updater.Status{LastResult: updater.ResultUpToDate, CurrentVersion: "v1.13.9", RestartError: linuxRestartErr},
			daemonAt("v1.13.8"))
		if !strings.Contains(stderr, "(it runs v1.13.8, installed is v1.13.9)") {
			t.Errorf("stderr = %q", stderr)
		}
	})
}

// writeUpdateState writes st where `pilotctl update status` reads it.
func writeUpdateState(t *testing.T, st updater.Status) {
	t.Helper()
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(updateStatusPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func updateStatusJSON(t *testing.T) map[string]interface{} {
	t.Helper()
	withJSONOutput(t, true)
	out := captureStdout(t, cmdAutoUpdateStatus)
	var env struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	return env.Data
}

func updateStatusText(t *testing.T) string {
	t.Helper()
	withJSONOutput(t, false)
	return captureStdout(t, cmdAutoUpdateStatus)
}

func TestCmdUpdateStatus_NothingRecorded(t *testing.T) {
	home := withTempHomeFull(t)
	withDaemonProbe(t, noDaemon)

	data := updateStatusJSON(t)
	if data["update_state"] != nil {
		t.Errorf("update_state = %v, want null when no check was recorded", data["update_state"])
	}
	if data["restart_error"] != "" {
		t.Errorf("restart_error = %v, want empty", data["restart_error"])
	}
	if want := filepath.Join(home, ".pilot", "update-state.json"); data["status_file"] != want {
		t.Errorf("status_file = %v, want %s", data["status_file"], want)
	}
	if _, ok := data["status_error"]; ok {
		t.Errorf("status_error must be absent for a missing file: %v", data["status_error"])
	}

	if out := updateStatusText(t); !strings.Contains(out, "Last check:        none recorded yet") {
		t.Errorf("text output:\n%s", out)
	}
}

// TestCmdUpdateStatus_ShowsRecordedFailureAndRestartError pins what `update
// status` surfaces from the updater's record: the failing check and the
// restart_error that says the daemon still runs the old binaries.
func TestCmdUpdateStatus_ShowsRecordedFailureAndRestartError(t *testing.T) {
	withTempHomeFull(t)
	withDaemonProbe(t, daemonAt("v1.13.8"))
	const restartErr = "restart daemon: pilot-daemon.service has Restart=on-failure; run: sudo systemctl restart pilot-daemon"
	const lastErr = "fetch latest release: GitHub API returned 403 (rate limit exceeded)"
	now := time.Now().UTC().Truncate(time.Second)
	writeUpdateState(t, updater.Status{
		LastCheckAt:         now,
		LastCheckTrigger:    updater.TriggerAuto,
		LastResult:          updater.ResultFailed,
		LastError:           lastErr,
		ConsecutiveFailures: 3,
		LastSuccessAt:       now.Add(-3 * time.Hour),
		CurrentVersion:      "v1.13.9",
		LatestVersion:       "v1.14.0",
		LastUpdateAt:        now.Add(-72 * time.Hour),
		LastUpdateVersion:   "v1.13.9",
		RestartError:        restartErr,
	})

	data := updateStatusJSON(t)
	if data["restart_error"] != restartErr {
		t.Errorf("restart_error = %v, want %q", data["restart_error"], restartErr)
	}
	if data["restart_needed"] != true || data["daemon_running"] != true || data["daemon_version"] != "v1.13.8" {
		t.Errorf("restart_needed/daemon_running/daemon_version = %v / %v / %v, want true / true / v1.13.8",
			data["restart_needed"], data["daemon_running"], data["daemon_version"])
	}
	if data["last_result"] != "failed" || data["last_error"] != lastErr {
		t.Errorf("last_result/last_error = %v / %v", data["last_result"], data["last_error"])
	}
	rec, ok := data["update_state"].(map[string]interface{})
	if !ok {
		t.Fatalf("update_state = %T %v, want the recorded object", data["update_state"], data["update_state"])
	}
	if rec["restart_error"] != restartErr || rec["consecutive_failures"] != float64(3) || rec["latest_version"] != "v1.14.0" {
		t.Errorf("update_state = %v", rec)
	}

	out := updateStatusText(t)
	for _, want := range []string{
		"(auto) — failed",
		"Last error:        " + lastErr,
		"Failures in a row: 3",
		"Last success:",
		"Installed/latest:  v1.13.9 / v1.14.0",
		"Last update:       v1.13.9 at ",
		"Daemon restart:    NEEDED — the daemon runs v1.13.8, installed is v1.13.9",
		restartErr,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdUpdateStatus_HealthyRecordHasNoWarnings(t *testing.T) {
	withTempHomeFull(t)
	withDaemonProbe(t, daemonAt("v1.14.0"))
	writeUpdateState(t, updater.Status{
		LastCheckAt:      time.Now().UTC(),
		LastCheckTrigger: updater.TriggerManual,
		LastResult:       updater.ResultUpToDate,
		CurrentVersion:   "v1.14.0",
		LatestVersion:    "v1.14.0",
		PinnedVersion:    "v1.14.0",
	})
	out := updateStatusText(t)
	if !strings.Contains(out, "(manual) — up to date") || !strings.Contains(out, "Installed/pinned:  v1.14.0 / v1.14.0") {
		t.Errorf("text output:\n%s", out)
	}
	for _, unwanted := range []string{"Last error", "Failures in a row", "Daemon restart"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("healthy record must not print %q:\n%s", unwanted, out)
		}
	}
}

func TestCmdUpdateStatus_UnreadableStatusFile(t *testing.T) {
	withTempHomeFull(t)
	withDaemonProbe(t, noDaemon)
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(updateStatusPath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	data := updateStatusJSON(t)
	if s, _ := data["status_error"].(string); !strings.Contains(s, "parse") {
		t.Errorf("status_error = %v, want a parse error", data["status_error"])
	}
	if data["update_state"] != nil {
		t.Errorf("update_state = %v, want null", data["update_state"])
	}
	if out := updateStatusText(t); !strings.Contains(out, "status file unreadable") {
		t.Errorf("text output:\n%s", out)
	}
}

// TestCmdUpdate_FailureIsVisibleInUpdateStatus is the end-to-end shape of the
// fix: a failed manual update exits non-zero, and `update status` then shows
// the failure the updater recorded at StatusPath.
func TestCmdUpdate_FailureIsVisibleInUpdateStatus(t *testing.T) {
	const lastErr = "apply update: download pilot-v1.14.0-linux-amd64.tar.gz: no data for 60s"
	fake := &fakeUpdateRunner{
		err:    errors.New(lastErr),
		record: true,
		status: updater.Status{
			LastCheckAt:         time.Now().UTC(),
			LastCheckTrigger:    updater.TriggerManual,
			LastResult:          updater.ResultFailed,
			LastError:           lastErr,
			ConsecutiveFailures: 1,
		},
	}
	withFakeUpdater(t, fake)
	withJSONOutput(t, false)

	var failure *trappedFatal
	_ = captureStderr(t, func() {
		failure = runTrappingFatal(func() { cmdUpdate(nil) })
	})
	if failure == nil || failure.Code != "update_failed" {
		t.Fatalf("failure = %+v, want update_failed", failure)
	}

	out := updateStatusText(t)
	if !strings.Contains(out, "(manual) — failed") || !strings.Contains(out, lastErr) {
		t.Errorf("update status does not show the recorded failure:\n%s", out)
	}
}

// updateJSON runs `pilotctl --json update` and returns the data object.
func updateJSON(t *testing.T) map[string]interface{} {
	t.Helper()
	withJSONOutput(t, true)
	out := captureStdout(t, func() { cmdUpdate(nil) })
	var env struct {
		Data map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	return env.Data
}

// updateText runs `pilotctl update` in text mode and returns stdout and
// stderr. The daemon probe must report a running daemon, or cmdUpdate would
// re-run skill install against the network.
func updateText(t *testing.T) (stdout, stderr string) {
	t.Helper()
	withJSONOutput(t, false)
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() { cmdUpdate(nil) })
	})
	return stdout, stderr
}

// staleRestartRecord is update-state.json after an update whose daemon
// restart failed: v1.13.9 installed, restart_error set.
func staleRestartRecord(restartErr string) updater.Status {
	now := time.Now().UTC().Add(-time.Hour)
	return updater.Status{
		LastCheckAt:       now,
		LastCheckTrigger:  updater.TriggerManual,
		LastResult:        updater.ResultUpdated,
		LastSuccessAt:     now,
		CurrentVersion:    "v1.13.9",
		LatestVersion:     "v1.13.9",
		LastUpdateAt:      now,
		LastUpdateVersion: "v1.13.9",
		RestartError:      restartErr,
	}
}

// TestCmdUpdate_SuccessfulRestartAfterFailedOne is F1: an update whose
// launchctl kickstart failed, then another update whose kickstart worked.
// updater v0.2.5 keeps the first restart_error (the release replaced
// pilot-updater), so LastStatus still carries it. pilotctl must not warn
// that the daemon is not running the new binaries once the daemon reports
// the installed version, and must wait for the restarted daemon to answer.
func TestCmdUpdate_SuccessfulRestartAfterFailedOne(t *testing.T) {
	const firstRestartErr = "restart daemon (launchctl kickstart -k gui/501/network.pilotprotocol.pilot-daemon): exit status 1 "
	newFake := func() *fakeUpdateRunner {
		return &fakeUpdateRunner{check: &fakeCheck{
			current: "v1.13.8", latest: "v1.13.9", installed: "v1.13.9", updaterReplaced: true,
		}}
	}
	// restartingDaemon answers only from the fourth probe on, like a
	// daemon launchd has just started again.
	restartingDaemon := func() func() (string, bool) {
		n := 0
		return func() (string, bool) {
			n++
			if n < 4 {
				return "", false
			}
			return "v1.13.9", true
		}
	}

	t.Run("text", func(t *testing.T) {
		fake := newFake()
		withFakeUpdater(t, fake)
		writeUpdateState(t, staleRestartRecord(firstRestartErr))
		calls := withDaemonProbe(t, restartingDaemon())

		stdout, stderr := updateText(t)
		if got := fake.LastStatus().RestartError; got != firstRestartErr {
			t.Fatalf("precondition: the merged record should still carry the first restart_error, got %q", got)
		}
		if !strings.Contains(stdout, "Updated to v1.13.9.") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if stderr != "" {
			t.Errorf("the daemon runs v1.13.9; no warning expected, got:\n%s", stderr)
		}
		if *calls < 4 {
			t.Errorf("probed the daemon %d times; want it to wait for the restarted daemon", *calls)
		}
	})

	t.Run("json", func(t *testing.T) {
		fake := newFake()
		withFakeUpdater(t, fake)
		writeUpdateState(t, staleRestartRecord(firstRestartErr))
		withDaemonProbe(t, restartingDaemon())

		data := updateJSON(t)
		if data["result"] != "updated" || data["restart_error"] != "" || data["restart_needed"] != false {
			t.Errorf("result/restart_error/restart_needed = %v / %q / %v, want updated / \"\" / false",
				data["result"], data["restart_error"], data["restart_needed"])
		}
		if data["daemon_running"] != true || data["daemon_version"] != "v1.13.9" {
			t.Errorf("daemon_running/daemon_version = %v / %v", data["daemon_running"], data["daemon_version"])
		}
	})

	t.Run("daemon never reports the new version", func(t *testing.T) {
		fake := newFake()
		withFakeUpdater(t, fake)
		writeUpdateState(t, staleRestartRecord(firstRestartErr))
		calls := withDaemonProbe(t, daemonAt("v1.13.8"))
		restartSettleWait = 20 * time.Millisecond

		data := updateJSON(t)
		if data["restart_needed"] != true || data["restart_error"] != firstRestartErr || data["daemon_version"] != "v1.13.8" {
			t.Errorf("restart_needed/restart_error/daemon_version = %v / %q / %v", data["restart_needed"], data["restart_error"], data["daemon_version"])
		}
		if *calls < 2 {
			t.Errorf("probed %d times; a possibly out-of-date restart_error should be re-checked until the wait ends", *calls)
		}
	})
}

// TestCmdUpdate_RestartErrorFromThisRunIsCheckedOnce: a restart_error this
// run recorded is current, so pilotctl checks the daemon once instead of
// waiting for it.
func TestCmdUpdate_RestartErrorFromThisRunIsCheckedOnce(t *testing.T) {
	fake := &fakeUpdateRunner{check: &fakeCheck{
		current: "v1.13.9", latest: "v1.14.0", installed: "v1.14.0", updaterReplaced: true,
		restartErr: errors.New(macRestartErr),
	}}
	withFakeUpdater(t, fake)
	calls := withDaemonProbe(t, noDaemon)

	data := updateJSON(t)
	if *calls != 1 {
		t.Errorf("probed the daemon %d times, want 1", *calls)
	}
	if data["restart_error"] != macRestartErr || data["restart_needed"] != false || data["daemon_running"] != false {
		t.Errorf("restart_error/restart_needed/daemon_running = %q / %v / %v", data["restart_error"], data["restart_needed"], data["daemon_running"])
	}
}

// TestCmdUpdate_UpToDateAfterManualRestart is F2: after an update whose
// kickstart failed, the user restarts the daemon as told. updater v0.2.5
// never clears restart_error on an up-to-date check off Linux, so the
// record keeps it. `pilotctl update` must not warn, and `update status`
// must not say the restart is still needed.
func TestCmdUpdate_UpToDateAfterManualRestart(t *testing.T) {
	setup := func(t *testing.T) *fakeUpdateRunner {
		fake := &fakeUpdateRunner{check: &fakeCheck{current: "v1.13.9", latest: "v1.13.9"}}
		withFakeUpdater(t, fake)
		writeUpdateState(t, staleRestartRecord(macRestartErr))
		return fake
	}

	t.Run("text", func(t *testing.T) {
		fake := setup(t)
		calls := withDaemonProbe(t, daemonAt("v1.13.9"))
		stdout, stderr := updateText(t)
		if got := fake.LastStatus(); got.LastResult != updater.ResultUpToDate || got.RestartError != macRestartErr {
			t.Fatalf("precondition: want an up_to_date record that still carries the restart_error, got %+v", got)
		}
		if !strings.Contains(stdout, "Already up to date (v1.13.9).") {
			t.Errorf("stdout:\n%s", stdout)
		}
		if stderr != "" {
			t.Errorf("the daemon runs v1.13.9; no warning expected, got:\n%s", stderr)
		}
		if *calls != 1 {
			t.Errorf("probed %d times; an up-to-date run should not wait", *calls)
		}

		out := updateStatusText(t)
		if strings.Contains(out, "NEEDED") {
			t.Errorf("update status still says the restart is needed:\n%s", out)
		}
		if !strings.Contains(out, "Daemon restart:    not needed — the daemon runs the installed v1.13.9") {
			t.Errorf("update status text:\n%s", out)
		}
	})

	t.Run("json", func(t *testing.T) {
		setup(t)
		withDaemonProbe(t, daemonAt("v1.13.9"))
		data := updateJSON(t)
		if data["result"] != "up_to_date" || data["restart_error"] != "" || data["restart_needed"] != false {
			t.Errorf("result/restart_error/restart_needed = %v / %q / %v, want up_to_date / \"\" / false",
				data["result"], data["restart_error"], data["restart_needed"])
		}

		st := updateStatusJSON(t)
		if st["restart_error"] != "" || st["restart_needed"] != false {
			t.Errorf("update status restart_error/restart_needed = %q / %v", st["restart_error"], st["restart_needed"])
		}
		// The record itself is the updater's and is shown as written.
		if rec, _ := st["update_state"].(map[string]interface{}); rec["restart_error"] != macRestartErr {
			t.Errorf("update_state.restart_error = %v, want the recorded %q", rec["restart_error"], macRestartErr)
		}
	})
}

// TestCmdUpdate_UpToDateWithDaemonStopped: `pilotctl daemon stop` booted
// the launchd agent out, so the kickstart of the next update failed and the
// daemon is still stopped. Nothing runs the old binaries: the up-to-date run
// reports no restart as needed, and `update status` says the daemon is not
// running and how to start it (not the kickstart that failed).
func TestCmdUpdate_UpToDateWithDaemonStopped(t *testing.T) {
	fake := &fakeUpdateRunner{check: &fakeCheck{current: "v1.13.9", latest: "v1.13.9"}}
	withFakeUpdater(t, fake)
	writeUpdateState(t, staleRestartRecord(macRestartErr))
	withDaemonProbe(t, noDaemon)

	data := updateJSON(t)
	if data["result"] != "up_to_date" || data["restart_needed"] != false || data["daemon_running"] != false {
		t.Errorf("result/restart_needed/daemon_running = %v / %v / %v", data["result"], data["restart_needed"], data["daemon_running"])
	}

	out := updateStatusText(t)
	for _, want := range []string{
		"Daemon restart:    daemon not running — v1.13.9 runs when it starts",
		"last restart attempt: " + macRestartErr,
		"start it with: pilotctl daemon start",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("update status missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "NEEDED") {
		t.Errorf("no daemon runs the old binaries:\n%s", out)
	}
}

func TestSameRelease(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"v1.13.9", "v1.13.9", true},
		{"1.13.9", "v1.13.9", true},
		{"v1.13.8", "v1.13.9", false},
		{"v1.14.0-rc1", "v1.14.0", false},
		{"dev", "v1.13.9", false},
		{"", "v1.13.9", false},
		{"v1.13.9", "", false},
	} {
		if got := sameRelease(c.a, c.b); got != c.want {
			t.Errorf("sameRelease(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
