// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/logcap"
)

// install.sh's launchd job points the updater's stdout and stderr at
// ~/.pilot/updater.log (StandardOutPath/StandardErrorPath). launchd opens
// that file and never rotates it, and nothing else does either: one
// laptop's updater.log held every line since the June install (2,205
// lines, 310 KB), and each failed GitHub check adds a ~400-byte line an
// hour. The daemon caps its own daemon.log from the inside
// (cmd/daemon/logrotation.go); the updater now does the same with the same
// package, keeping gzipped <log>.pilot.N.gz generations. Under systemd the
// updater logs to journald and this is a no-op: stderr is not a regular
// file there.

const (
	// defaultUpdaterLogMaxMB is -log-max-size's default. The updater writes
	// a few lines an hour, so this is years of history.
	defaultUpdaterLogMaxMB = 10
	// defaultUpdaterLogBackups is -log-max-backups's default, the same as
	// the daemon's.
	defaultUpdaterLogBackups = 3
	// updaterLogCheckInterval is how often the log's size is checked.
	updaterLogCheckInterval = 5 * time.Minute
)

// updaterLogDirs returns the directories the updater's log is in when
// Pilot set it up, where the cap applies by default: ~/.pilot (install.sh's
// launchd updater.log), and $PILOT_HOME/.pilot when that is set. A log an
// operator redirected elsewhere may be rotated by other means, so it is
// left alone unless -log-max-size is set explicitly.
func updaterLogDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".pilot"))
	}
	if h := os.Getenv("PILOT_HOME"); h != "" {
		dirs = append(dirs, filepath.Join(h, ".pilot"))
	}
	return dirs
}

// capUpdaterLog starts capping the log f writes to (the updater's
// stderr) at maxMB megabytes, keeping backups gzipped generations, until
// ctx is done. anywhere lifts the ~/.pilot scope. It reports whether
// capping started: false when maxMB <= 0, f is not a regular file, or the
// log is out of scope.
func capUpdaterLog(ctx context.Context, f *os.File, maxMB, backups int, anywhere bool, interval time.Duration) bool {
	return logcap.Watch(ctx, f, logcap.Options{
		MaxBytes:   int64(maxMB) << 20,
		MaxBackups: backups,
		Anywhere:   anywhere,
		Within:     updaterLogDirs(),
	}, interval)
}

// flagSetOnCommandLine reports whether flag name was given on the command
// line.
func flagSetOnCommandLine(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
