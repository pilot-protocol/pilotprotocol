// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
)

// pilotDirs returns the directories the daemon's log is in when Pilot
// itself set it up, which is where -log-max-size applies by default:
// launchd's StandardErrorPath (~/.pilot/daemon.log, from install.sh) and
// `pilotctl daemon start` (~/.pilot/pilot-<pid>.log, under $PILOT_HOME
// when that is set). pilotLogFiles adds the Homebrew service's log. A log
// an operator redirected anywhere else may already be rotated by other
// means, so it is left alone unless -log-max-size is set explicitly
// (flagExplicit).
func pilotDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".pilot"))
	}
	if h := os.Getenv("PILOT_HOME"); h != "" {
		dirs = append(dirs, filepath.Join(h, ".pilot"))
	}
	return dirs
}

// pilotLogFiles returns the logs outside pilotDirs that Pilot itself set
// up, where -log-max-size also applies by default: the `brew services`
// log when this daemon is the one Pilot's Homebrew formula installed.
func pilotLogFiles() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if log, ok := homebrewServiceLog(exe); ok {
		return []string{log}
	}
	return nil
}

// homebrewServiceLog returns the file `brew services` sends the daemon's
// stdout and stderr to when exe is the pilot-daemon of Pilot's Homebrew
// formula (TeoSlayer/homebrew-pilot, Formula/pilotprotocol.rb):
// <prefix>/Cellar/pilotprotocol/<version>/bin/pilot-daemon, which the
// service runs through the <prefix>/opt/pilotprotocol link. The formula's
// service block sets log_path and error_log_path to
// var/"log/pilot-daemon.log", which launchd (StandardOutPath,
// StandardErrorPath) or systemd (StandardOutput=append:) opens and
// nothing rotates. Only that one file is in scope, not the rest of
// <prefix>/var/log, which belongs to other formulae. Keep the names here
// in step with the formula.
func homebrewServiceLog(exe string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", false
	}
	bin := filepath.Dir(resolved)
	formula := filepath.Dir(filepath.Dir(bin))
	cellar := filepath.Dir(formula)
	if filepath.Base(resolved) != "pilot-daemon" ||
		filepath.Base(bin) != "bin" ||
		filepath.Base(formula) != "pilotprotocol" ||
		filepath.Base(cellar) != "Cellar" {
		return "", false
	}
	return filepath.Join(filepath.Dir(cellar), "var", "log", "pilot-daemon.log"), true
}

// flagExplicit reports whether flag name was set on the command line or
// in the config file. config.ApplyToFlags sets config values without
// marking the flag as set, so the config map is checked directly, the
// way ApplyToFlags reads it: the hyphenated key, else the underscored
// one, and only the value types it applies.
func flagExplicit(name string, fileConfig map[string]interface{}) bool {
	explicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			explicit = true
		}
	})
	if explicit {
		return true
	}
	val, ok := fileConfig[name]
	if !ok {
		val = fileConfig[strings.ReplaceAll(name, "-", "_")]
	}
	switch val.(type) {
	case string, float64, bool:
		return true
	}
	return false
}
