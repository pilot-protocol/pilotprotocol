package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func installerSection(t *testing.T, start, end string) string {
	t.Helper()
	b, err := os.ReadFile("../../install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	a := strings.Index(s, start)
	if a < 0 {
		t.Fatal("missing", start)
	}
	s = s[a:]
	bidx := strings.Index(s, end)
	if bidx < 0 {
		t.Fatal("missing", end)
	}
	return s[:bidx]
}

func TestIssue475LegacyLaunchdMigration(t *testing.T) {
	section := installerSection(t, "if [ \"$OS\" = \"darwin\" ]; then\n    for _label in network.pilotprotocol.pilot-daemon", "# install_bin")
	for _, tc := range []struct {
		name         string
		loaded, fail bool
	}{{"loaded", true, false}, {"unloaded", false, false}, {"bootout fails", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			dir := filepath.Join(home, "Library", "LaunchAgents")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(dir, "com.vulturelabs.pilot-daemon.plist")
			original := "legacy operator flags"
			os.WriteFile(old, []byte(original), 0600)
			script := `set -eu
OS=darwin
PILOT_MANAGED_MODE=0
PILOT_MANAGED_NO_START=0
RESTART_LAUNCHD=""
launchctl() {
 case "$1:$2" in
  print:*/com.vulturelabs.pilot-daemon) [ "$LOADED" = 1 ] ;;
  print:*) return 1 ;;
  bootout:*) [ "$FAIL_BOOTOUT" != 1 ] ;;
  *) return 99 ;;
 esac
}
` + section + `printf 'RESTART=%s\n' "$RESTART_LAUNCHD"`
			cmd := exec.Command("sh", "-c", script)
			cmd.Env = append(os.Environ(), "HOME="+home, "LOADED=0", "FAIL_BOOTOUT=0")
			if tc.loaded {
				cmd.Env = append(cmd.Env, "LOADED=1")
			}
			if tc.fail {
				cmd.Env = append(cmd.Env, "FAIL_BOOTOUT=1")
			}
			out, err := cmd.CombinedOutput()
			if tc.fail {
				if err == nil {
					t.Fatal("must abort")
				}
				if _, err := os.Stat(old); err != nil {
					t.Fatal("legacy plist removed on failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if _, err := os.Stat(old); !os.IsNotExist(err) {
				t.Fatal("legacy plist still active")
			}
			b, err := os.ReadFile(filepath.Join(dir, "network.pilotprotocol.pilot-daemon.plist"))
			if err != nil || string(b) != original {
				t.Fatalf("lost operator settings: %s %v", b, err)
			}
			want := "RESTART=\n"
			if tc.loaded {
				want = "RESTART=network.pilotprotocol.pilot-daemon\n"
			}
			if !strings.Contains(string(out), want) {
				t.Fatalf("want %q: %s", want, out)
			}
		})
	}
}

func TestIssue476UpgradeAutoUpdateState(t *testing.T) {
	section := installerSection(t, "# Enable background auto-updates by default", "# --- Set up system service ---")
	for _, existing := range []string{"", `{"enabled":false}`, `{"enabled":true}`} {
		t.Run(existing, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "auto-update.json")
			if existing != "" {
				os.WriteFile(path, []byte(existing), 0600)
			}
			cmd := exec.Command("sh", "-c", "set -eu\n"+section)
			cmd.Env = append(os.Environ(), "PILOT_DIR="+dir, "PILOT_MANAGED_MODE=0", "UPDATING=true")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if existing != "" && string(b) != existing {
				t.Fatalf("operator setting changed: %s", b)
			}
			if existing == "" && !strings.Contains(string(b), `"enabled": true`) {
				t.Fatalf("upgrade not enabled: %s", b)
			}
		})
	}
}
