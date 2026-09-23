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
// when that is set). A log an operator redirected anywhere else may
// already be rotated by other means, so it is left alone unless
// -log-max-size is set explicitly (flagExplicit).
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
