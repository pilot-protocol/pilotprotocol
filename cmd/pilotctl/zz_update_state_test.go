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
}

func (f *fakeUpdateRunner) RunOnce() error {
	if f.record && f.cfg.StatusPath != "" {
		b, _ := json.Marshal(f.status)
		_ = os.MkdirAll(filepath.Dir(f.cfg.StatusPath), 0o755)
		_ = os.WriteFile(f.cfg.StatusPath, b, 0o644)
	}
	return f.err
}

func (f *fakeUpdateRunner) LastStatus() updater.Status { return f.status }

// withFakeUpdater isolates HOME, points PILOT_UPDATER_BIN at a temp install
// dir and swaps newUpdateRunner for fake. Returns the temp HOME.
func withFakeUpdater(t *testing.T, fake *fakeUpdateRunner) string {
	t.Helper()
	home := withTempHomeFull(t)
	t.Setenv("PILOT_UPDATER_BIN", filepath.Join(home, "bin", "pilot-updater"))
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
		"status_file":     filepath.Join(home, ".pilot", "update-state.json"),
	}
	for k, v := range want {
		if env.Data[k] != v {
			t.Errorf("data[%q] = %v, want %v", k, env.Data[k], v)
		}
	}
}

// TestPrintUpdateResult covers the text report of a successful run.
func TestPrintUpdateResult(t *testing.T) {
	t.Run("updated with restart error", func(t *testing.T) {
		const restartErr = "restart daemon (launchctl kickstart -k gui/501/network.pilotprotocol.pilot-daemon): exit status 113"
		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				printUpdateResult(updater.Status{LastResult: updater.ResultUpdated, CurrentVersion: "v1.14.0", RestartError: restartErr})
			})
		})
		if !strings.Contains(stdout, "Updated to v1.14.0.") {
			t.Errorf("stdout = %q", stdout)
		}
		if !strings.Contains(stderr, "daemon is not running them") || !strings.Contains(stderr, restartErr) {
			t.Errorf("stderr must warn with the restart error, got %q", stderr)
		}
	})
	t.Run("up to date", func(t *testing.T) {
		var stdout string
		stderr := captureStderr(t, func() {
			stdout = captureStdout(t, func() {
				printUpdateResult(updater.Status{LastResult: updater.ResultUpToDate, CurrentVersion: "v1.13.9"})
			})
		})
		if !strings.Contains(stdout, "Already up to date (v1.13.9).") {
			t.Errorf("stdout = %q", stdout)
		}
		if stderr != "" {
			t.Errorf("no warning expected, got %q", stderr)
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
		"Daemon restart:    NEEDED",
		restartErr,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdUpdateStatus_HealthyRecordHasNoWarnings(t *testing.T) {
	withTempHomeFull(t)
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
