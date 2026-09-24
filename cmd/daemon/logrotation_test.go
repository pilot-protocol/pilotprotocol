// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestFlagExplicit: -log-max-size counts as explicit — rotating a log
// outside ~/.pilot — when given on the command line or in the config
// file, under either key spelling and only with a value ApplyToFlags
// would apply; the flag's default alone does not.
func TestFlagExplicit(t *testing.T) {
	saved := flag.CommandLine
	t.Cleanup(func() { flag.CommandLine = saved })
	parse := func(args ...string) {
		t.Helper()
		flag.CommandLine = flag.NewFlagSet("pilot-daemon", flag.ContinueOnError)
		flag.Int("log-max-size", 50, "")
		flag.Int("log-max-backups", 3, "")
		if err := flag.CommandLine.Parse(args); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name string
		args []string
		cfg  map[string]interface{}
		want bool
	}{
		{"default", nil, nil, false},
		{"other flag set", []string{"-log-max-backups", "5"}, map[string]interface{}{"log_max_backups": float64(5)}, false},
		{"command line", []string{"-log-max-size", "50"}, nil, true},
		{"command line 0", []string{"-log-max-size=0"}, nil, true},
		{"config underscore", nil, map[string]interface{}{"log_max_size": float64(20)}, true},
		{"config hyphen", nil, map[string]interface{}{"log-max-size": "20"}, true},
		{"config null", nil, map[string]interface{}{"log_max_size": nil}, false},
		{"config object", nil, map[string]interface{}{"log_max_size": map[string]interface{}{}}, false},
		// ApplyToFlags reads the hyphenated key when present, even when
		// its value is one it ignores.
		{"config hyphen null shadows underscore", nil, map[string]interface{}{"log-max-size": nil, "log_max_size": float64(20)}, false},
	} {
		parse(tc.args...)
		if got := flagExplicit("log-max-size", tc.cfg); got != tc.want {
			t.Errorf("%s: flagExplicit = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPilotDirs: the default rotation scope is ~/.pilot, plus
// $PILOT_HOME/.pilot where `pilotctl daemon start` keeps its logs when
// PILOT_HOME is set.
func TestPilotDirs(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_HOME", "")
	if got, want := pilotDirs(), []string{filepath.Join(home, ".pilot")}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pilotDirs = %v, want %v", got, want)
	}

	alt := t.TempDir()
	t.Setenv("PILOT_HOME", alt)
	want := []string{filepath.Join(home, ".pilot"), filepath.Join(alt, ".pilot")}
	if got := pilotDirs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("pilotDirs = %v, want %v", got, want)
	}
}

// TestHomebrewServiceLog: the pilot-daemon Pilot's Homebrew formula
// installed maps to the log its `brew services` block sets,
// <prefix>/var/log/pilot-daemon.log — however it was started: through
// <prefix>/opt/pilotprotocol (the service's run path), the linked
// <prefix>/bin, or the Cellar itself. Any other binary maps to nothing.
func TestHomebrewServiceLog(t *testing.T) {
	prefix := t.TempDir()
	// macOS's temp dir is under the /var -> /private/var link; the
	// result is built from the resolved executable path.
	realPrefix, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		t.Fatal(err)
	}
	file := func(rel string) string {
		t.Helper()
		p := filepath.Join(prefix, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, rel string) string {
		t.Helper()
		p := filepath.Join(prefix, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cellar := file("Cellar/pilotprotocol/1.13.9/bin/pilot-daemon")
	opt := filepath.Join(link("../Cellar/pilotprotocol/1.13.9", "opt/pilotprotocol"), "bin", "pilot-daemon")
	linked := link("../Cellar/pilotprotocol/1.13.9/bin/pilot-daemon", "bin/pilot-daemon")
	want := filepath.Join(realPrefix, "var", "log", "pilot-daemon.log")
	for _, exe := range []string{cellar, opt, linked} {
		if got, ok := homebrewServiceLog(exe); !ok || got != want {
			t.Errorf("homebrewServiceLog(%s) = (%q, %v), want (%q, true)", exe, got, ok, want)
		}
	}

	for _, exe := range []string{
		file(".pilot/bin/pilot-daemon"),                                      // install.sh
		file("usr/local/bin/pilot-daemon"),                                   // a manual install
		file("Cellar/otherformula/1.0/bin/pilot-daemon"),                     // another formula
		file("Cellar/pilotprotocol/1.13.9/bin/pilotctl"),                     // another binary
		file("Cellar/pilotprotocol/1.13.9/libexec/pilot-daemon"),             // not the formula's bin
		filepath.Join(prefix, "Cellar/pilotprotocol/9.9.9/bin/pilot-daemon"), // missing
	} {
		if got, ok := homebrewServiceLog(exe); ok {
			t.Errorf("homebrewServiceLog(%s) = %q, want no Homebrew service log", exe, got)
		}
	}
}
