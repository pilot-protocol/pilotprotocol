// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain lets us re-exec the test binary as if it were `pilotctl`.
// When PILOTCTL_TEST_REEXEC=1 we strip the test-runner argv0 and call
// main() directly with PILOTCTL_TEST_ARGV as the new os.Args. This is
// the standard Go pattern for testing os.Exit code paths without
// taking down the test process.
//
// Tests that need fatal-path coverage spawn a child via runCLI() below.
func TestMain(m *testing.M) {
	if os.Getenv("PILOTCTL_TEST_REEXEC") == "1" {
		// argv is passed as a newline-joined list of base64 encoded
		// strings — works around exec's NUL ban while preserving any
		// raw bytes (newlines, spaces, etc.) inside individual args.
		raw := os.Getenv("PILOTCTL_TEST_ARGV")
		var argv []string
		if raw != "" {
			for _, b64 := range strings.Split(raw, "\n") {
				dec, err := base64.StdEncoding.DecodeString(b64)
				if err != nil {
					panic("test argv decode: " + err.Error())
				}
				argv = append(argv, string(dec))
			}
		}
		os.Args = append([]string{"pilotctl"}, argv...)
		if os.Getenv("PILOTCTL_TEST_SANDBOX") == "1" {
			// A Linux container without systemd, with bash (see
			// sandboxProxyCmdFor), whatever host runs the test.
			hostGOOS = "linux"
			systemdRunning = func() bool { return false }
			bashAvailable = func() bool { return true }
		}
		main()
		return
	}
	os.Exit(m.Run())
}

// runCLI re-execs the test binary with the given pilotctl argv and
// returns (stdout, stderr, exitCode). Stdin is /dev/null. HOME is
// pointed at a tmp dir per-call so config writes are isolated.
func runCLI(t *testing.T, args []string, env map[string]string) (string, string, int) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	encoded := make([]string, len(args))
	for i, a := range args {
		encoded[i] = base64.StdEncoding.EncodeToString([]byte(a))
	}
	// Pass -test.gocoverdir so the child writes coverage data to the
	// same dir the parent test binary already uses (Go 1.20+ collect).
	// Without this, every re-exec runs blind from coverage's POV and
	// our subprocess tests look like dead weight.
	childArgs := []string{"-test.run=TestMain"}
	if dir := os.Getenv("GOCOVERDIR"); dir != "" {
		childArgs = append(childArgs, "-test.gocoverdir="+dir)
	}
	cmd := exec.Command(exe, childArgs...)
	cmd.Env = append(os.Environ(),
		"PILOTCTL_TEST_REEXEC=1",
		"PILOTCTL_TEST_ARGV="+strings.Join(encoded, "\n"),
	)
	// Isolate HOME so the test never touches the real ~/.pilot.
	tmp := t.TempDir()
	cmd.Env = append(cmd.Env, "HOME="+tmp)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatalf("run: %v", err)
		}
	}
	return stdout.String(), stderr.String(), code
}

func TestCLIVersion(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"version"}, nil)
	if code != 0 {
		t.Errorf("exit=%d, want 0", code)
	}
	// version prints whatever the linker stamped in (default "dev" in tests).
	got := strings.TrimSpace(stdout)
	if got == "" {
		t.Errorf("expected non-empty version, got %q", got)
	}
}

// TestCLIVersionFlagIgnored confirms that --json (a global flag) doesn't
// change `version` output — the command prints a bare string regardless.
// Pinning this prevents accidental wrapping in a future refactor.
func TestCLIVersionFlagIgnored(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "version"}, nil)
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	if strings.Contains(stdout, "{") {
		t.Errorf("version should not be JSON-wrapped: %q", stdout)
	}
}

func TestCLINoArgsPrintsUsage(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{}, nil)
	if code == 0 {
		t.Errorf("expected non-zero exit for no args, got 0")
	}
	full := stdout + stderr
	if !strings.Contains(full, "pilotctl") || !strings.Contains(full, "Usage") && !strings.Contains(full, "daemon") {
		t.Errorf("usage banner missing: %s", full[:min2(800, len(full))])
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"this-does-not-exist"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit")
	}
	if !strings.Contains(stderr, "this-does-not-exist") && !strings.Contains(stderr, "unknown") && !strings.Contains(stderr, "Unknown") {
		t.Errorf("expected error mentioning unknown command, got: %s", stderr)
	}
}

func TestCLIHelpFlag(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{"send-message", "--help"}, nil)
	if code != 0 {
		t.Errorf("help should exit 0, got %d", code)
	}
	full := stdout + stderr
	if !strings.Contains(full, "send-message") {
		t.Errorf("help text missing 'send-message': %s", full)
	}
	if !strings.Contains(full, "--data") {
		t.Errorf("help text missing flag listing: %s", full)
	}
}

func TestCLIInit(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{
		"--json", "init",
		"--registry", "r.example:9000",
		"--hostname", "subproc-host",
	}, nil)
	if code != 0 {
		t.Errorf("init exit=%d", code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	if env["status"] != "ok" {
		t.Errorf("status = %v", env["status"])
	}
	data := env["data"].(map[string]interface{})
	if data["registry"] != "r.example:9000" {
		t.Errorf("registry = %v", data["registry"])
	}
}

func TestCLIContext(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "context"}, nil)
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	data := env["data"].(map[string]interface{})
	if data["commands"] == nil {
		t.Errorf("commands missing")
	}
}

func TestCLITrustedListEmpty(t *testing.T) {
	t.Parallel()
	// With no env overrides the trustedagents list may be empty in test
	// builds; either way the command should exit zero with some output.
	stdout, stderr, code := runCLI(t, []string{"trusted", "list"}, nil)
	if code != 0 {
		t.Errorf("exit=%d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
}

func TestCLIExtrasHelp(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"extras"}, nil)
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	if !strings.Contains(stdout, "network") || !strings.Contains(stdout, "policy") {
		t.Errorf("extras help missing core sections: %s", stdout)
	}
}

func TestCLIAppStoreList(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "appstore", "list"}, map[string]string{
		"PILOT_APPSTORE_ROOT": filepath.Join(t.TempDir(), "apps-root"),
	})
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	out := strings.TrimSpace(stdout)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty list, got %q", out)
	}
}

func TestCLIAppStoreHelp(t *testing.T) {
	t.Parallel()
	stdout, stderr, code := runCLI(t, []string{"appstore"}, nil)
	if code != 0 {
		t.Errorf("appstore (no args) exit=%d", code)
	}
	full := stdout + stderr
	if !strings.Contains(full, "appstore") {
		t.Errorf("help text missing 'appstore': %s", full)
	}
}

func TestCLIAppStoreUnknownSub(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"appstore", "noop-subcmd"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for unknown subcmd")
	}
	if !strings.Contains(stderr, "noop-subcmd") && !strings.Contains(stderr, "unknown") {
		t.Errorf("expected error mention, got: %s", stderr)
	}
}

func TestCLIAppStoreUninstallRequiresYes(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "apps-root")
	if err := os.MkdirAll(filepath.Join(root, "victim"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, stderr, code := runCLI(t, []string{"appstore", "uninstall", "victim"}, map[string]string{
		"PILOT_APPSTORE_ROOT": root,
	})
	if code == 0 {
		t.Error("expected non-zero exit without --yes")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Errorf("expected --yes hint: %s", stderr)
	}
	// Dir should still exist — destructive op refused.
	if _, err := os.Stat(filepath.Join(root, "victim")); err != nil {
		t.Errorf("victim dir should still exist: %v", err)
	}
}

func TestCLIAppStoreVerifyMissingBundle(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"appstore", "verify", "/no/such/bundle"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for missing bundle")
	}
	if !strings.Contains(stderr, "does not exist") && !strings.Contains(stderr, "bundle") {
		t.Errorf("expected missing-bundle error: %s", stderr)
	}
}

func TestCLIAppStoreInstallBadBundle(t *testing.T) {
	t.Parallel()
	// Empty dir → no manifest.json → fatalHint
	_, stderr, code := runCLI(t, []string{
		"appstore", "install", t.TempDir(),
	}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for bad bundle")
	}
	if !strings.Contains(stderr, "manifest") {
		t.Errorf("expected manifest error: %s", stderr)
	}
}

func TestCLIAppStoreRestartUnknownApp(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"appstore", "restart", "no.such.app"}, map[string]string{
		"PILOT_APPSTORE_ROOT": filepath.Join(t.TempDir(), "apps-root"),
	})
	if code == 0 {
		t.Error("expected non-zero exit for unknown app")
	}
	if !strings.Contains(stderr, "no.such.app") && !strings.Contains(stderr, "not installed") {
		t.Errorf("expected error mention: %s", stderr)
	}
}

func TestCLIAppStoreActionsEmpty(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "appstore", "actions"}, map[string]string{
		"PILOT_APPSTORE_ROOT": filepath.Join(t.TempDir(), "apps-root"),
	})
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	out := strings.TrimSpace(stdout)
	if out != "[]" && out != "null" {
		t.Errorf("expected empty array: %q", out)
	}
}

func TestCLIConfigShowDefaults(t *testing.T) {
	t.Parallel()
	stdout, _, code := runCLI(t, []string{"--json", "config"}, nil)
	if code != 0 {
		t.Errorf("exit=%d", code)
	}
	var env map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("json: %v", err)
	}
	data := env["data"].(map[string]interface{})
	// Defaults filled in by cmdConfig when keys absent.
	if data["registry"] == nil {
		t.Errorf("registry default missing")
	}
	if data["socket"] == nil {
		t.Errorf("socket default missing")
	}
}

// TestCLIConfigSetMalformed pins the fatalCode path: --set without `=`.
func TestCLIConfigSetMalformed(t *testing.T) {
	t.Parallel()
	_, stderr, code := runCLI(t, []string{"config", "--set", "nokey"}, nil)
	if code == 0 {
		t.Error("expected non-zero exit for malformed --set")
	}
	if !strings.Contains(stderr, "--set") && !strings.Contains(stderr, "key=value") {
		t.Errorf("expected usage hint, got: %s", stderr)
	}
}

// TestCLIDaemonStatusCheckNoDaemon exercises the --check fast path with
// no daemon running. Must exit non-zero, silently.
func TestCLIDaemonStatusCheckNoDaemon(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	_, _, code := runCLI(t, []string{"daemon", "status", "--check"}, map[string]string{
		"PILOT_SOCKET": filepath.Join(tmp, "nope.sock"),
	})
	if code == 0 {
		t.Error("expected non-zero exit when daemon socket absent")
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
