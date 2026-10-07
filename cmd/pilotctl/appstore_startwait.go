// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Did the app start? (`appstore install`)
//
// install only writes files; the daemon's supervisor starts the app on its
// next rescan (2s). So install used to report success for an app that then
// exited at every start: on an image without tar, io.pilot.sqlite's adapter
// failed while staging its assets, was restarted five times and suspended,
// and the install output said nothing.
//
// After a successful install, with a daemon to start the app, install now
// watches the app dir for up to appStartWait (--wait) and reports one of:
//
//   - started: the supervisor spawned the app and its socket is there.
//   - failed: the supervisor suspended it, it exited at least twice without
//     its socket being there, or the supervisor refused it as a downgrade.
//     install exits non-zero.
//   - starting: none of these, by the deadline. Not a failure: an app that
//     takes longer than the wait to open its socket is healthy.
//
// Everything is read from the app dir (supervisor.log, app.sock), like `list`
// and `status` do: pilotctl has no channel to the supervisor. The supervisor
// only suspends an app after more than five exits in a minute, 31s at the
// earliest, so waiting for a suspend alone would either miss the failure or
// cost every install half a minute; two exits are there after about 3s.
//
// Which lines are the new install's. supervisor.log is carried into the new
// install, and when an install is replaced the supervisor keeps running the
// old instance until its next rescan, with the same log. So lines written
// after the swap can still be the old instance's: the end of its crash loop
// (exits, then a suspend and its .suspended marker), and the exit it logs
// when the rescan stops it, often after the new instance's supervise-start
// because it gets up to 3s to shut down. Lines name no instance, but the new
// instance's supervise-start and spawn carry the sha256 of the binary it
// runs, which is the installed manifest's. So nothing counts before one of
// those; an exit counts only when it ends a start attempt of the new
// instance; and a suspend only when it follows one of its exits. When the
// binary is identical across versions the old instance's restarts carry the
// same sha, so the counts start again at the new instance's supervise-start.

// appStartWait is how long install waits for the app's first start unless
// --wait says otherwise. appStartPoll is how often it looks. Vars so tests
// can shorten them.
var (
	appStartWait = 20 * time.Second
	appStartPoll = 200 * time.Millisecond
)

const (
	appStartStarted  = "started"
	appStartFailed   = "failed"
	appStartStarting = "starting"
)

// appStartExitsForFailure is how many exits without a socket make a failed
// start. One could be anything; a second, after the supervisor's 1s restart
// delay, means the app does not come up on its own.
const appStartExitsForFailure = 2

// appStartTarget is the install whose first start is watched.
type appStartTarget struct {
	Dir          string    // the app dir
	Since        time.Time // when the install was swapped in
	Version      string    // the installed manifest's app_version
	BinarySHA256 string    // the installed manifest's binary sha256
}

// appStartStatus is what install saw of the app's first start.
type appStartStatus struct {
	State      string // appStartStarted, appStartFailed or appStartStarting
	Waited     time.Duration
	Picked     bool   // the supervisor has started (or refused) this install
	Spawns     int    // spawns of this install
	Exits      int    // exits of this install
	ExitCode   int    // exit code of the last of them
	StartError string // why the daemon could not run the binary at its last attempt (spawn-fail, verify-fail)
	Suspended  bool   // the supervisor gave up on the app
	Refusal    string // the supervisor's reason for refusing this install as a downgrade
	LastEvent  string // last supervisor.log line of this install, as written
}

// supervisorEvent is the part of a supervisor.log line install looks at.
type supervisorEvent struct {
	At       time.Time `json:"at"`
	Event    string    `json:"event"`
	ExitCode int       `json:"exit_code"`
	Reason   string    `json:"reason"`
	SHA256   string    `json:"sha256"`
}

// supervisorLogLines returns the lines of the app's supervisor.log, oldest
// first. The supervisor rotates the log to supervisor.log.1 once it is 10MB;
// when that happened during the wait, the start of it is there.
func supervisorLogLines(appDir string, since time.Time) []string {
	var lines []string
	for _, name := range []string{"supervisor.log.1", "supervisor.log"} {
		path := filepath.Join(appDir, name)
		if name != "supervisor.log" {
			if fi, err := os.Stat(path); err != nil || fi.ModTime().Before(since) {
				continue
			}
		}
		f, err := os.Open(path) // #nosec G304 -- <install root>/<validated app id>/supervisor.log[.1]
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				lines = append(lines, line)
			}
		}
		_ = f.Close()
	}
	return lines
}

// readAppStart reads the app dir once.
func readAppStart(tg appStartTarget) appStartStatus {
	var st appStartStatus
	var (
		ours      bool // the new instance's supervise loop has started
		attempt   bool // a start attempt of the new instance has not exited yet
		ended     bool // its last attempt has ended (exit, verify-fail): a suspend now is its own
		noProcess bool // the open attempt failed before a process ran
	)
	for _, line := range supervisorLogLines(tg.Dir, tg.Since) {
		var ev supervisorEvent
		if json.Unmarshal([]byte(line), &ev) != nil || ev.At.Before(tg.Since) {
			continue
		}
		thisBinary := ev.SHA256 == tg.BinarySHA256
		switch ev.Event {
		case "downgrade-refused":
			// Written on every rescan that finds a manifest older than the
			// version the supervisor runs, which can be newer than the one
			// this install replaced. It names no binary; the reason names
			// the refused version.
			if !refusesVersion(ev.Reason, tg.Version) {
				continue
			}
			st.Refusal = ev.Reason
		case "supervise-start":
			if !thisBinary {
				continue
			}
			// The new instance starts here: anything counted so far was
			// the old instance's (a manifest-only bump runs an identical
			// binary, so its restarts log this sha too).
			ours, attempt, ended, noProcess = true, false, false, false
			st.Refusal = ""
			st.Spawns, st.Exits, st.ExitCode, st.StartError, st.Suspended = 0, 0, 0, "", false
		case "spawn":
			if !thisBinary {
				continue // the old instance, restarting before the rescan replaced it
			}
			ours, attempt, ended, noProcess = true, true, false, false
			st.Spawns++
			st.StartError = ""
		case "spawn-fail":
			if !ours {
				continue
			}
			// The exec failed; an exit -1 follows.
			attempt, noProcess = true, true
			st.StartError = ev.Reason
		case "verify-fail":
			if !ours || !thisBinary {
				continue
			}
			if strings.HasPrefix(ev.Reason, "spawn-time:") {
				// The check just before exec; an exit -1 follows.
				attempt, noProcess = true, true
			} else {
				// Retried after a backoff; suspended after 10 in a row.
				ended = true
			}
			st.StartError = ev.Reason
		case "exit":
			if !attempt {
				continue // the old instance: stopped by the rescan, or crashing before it
			}
			st.Exits++
			st.ExitCode = ev.ExitCode
			afterNoProcess := noProcess
			attempt, ended, noProcess = false, true, false
			if afterNoProcess {
				// The exit -1 after a spawn-fail or verify-fail says nothing
				// that line did not; keep that one as the last event.
				st.Picked = true
				continue
			}
		case "suspend":
			if !ended {
				continue // the end of the old instance's crash loop
			}
			st.Suspended = true
		case "resume":
			if !ours {
				continue
			}
			st.Suspended, ended = false, false
		default:
			continue
		}
		st.Picked = true
		st.LastEvent = line
	}
	// The .suspended marker is not read: it names no instance either, and
	// the old instance writes it into the new install's dir when its crash
	// loop ends after the swap. The supervisor logs the suspend before it
	// writes the marker, so the log has everything the marker would say.
	_, sockErr := os.Stat(filepath.Join(tg.Dir, "app.sock"))
	switch {
	case st.Refusal != "":
		st.State = appStartFailed
	case st.Suspended:
		st.State = appStartFailed
	case sockErr == nil && st.Spawns > 0:
		st.State = appStartStarted
	case sockErr != nil && st.Exits >= appStartExitsForFailure:
		st.State = appStartFailed
	default:
		st.State = appStartStarting
	}
	return st
}

// refusesVersion reports whether a downgrade-refused reason is about
// version. The supervisor words it "refusing <new> (existing <running>)",
// after "rescan: " when the rescan refused it.
func refusesVersion(reason, version string) bool {
	return strings.Contains(reason, "refusing "+version+" (")
}

// waitForAppStart polls the app dir until the start is decided either way,
// or wait has passed.
func waitForAppStart(tg appStartTarget, wait time.Duration) appStartStatus {
	begin := time.Now()
	for {
		st := readAppStart(tg)
		st.Waited = time.Since(begin)
		if st.State != appStartStarting || st.Waited >= wait {
			return st
		}
		time.Sleep(appStartPoll)
	}
}

// daemonSocketReachable reports whether a daemon is listening on the control
// socket. Without one nothing starts the app, and there is nothing to wait
// for.
func daemonSocketReachable() bool {
	c, err := net.DialTimeout("unix", getSocket(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// supervisorVersionCompare orders app versions the way the daemon's
// supervisor does when it decides whether an install on disk replaces the
// app it runs (compareVersions in the app-store module's plugin/appstore,
// which is not exported): MAJOR.MINOR.PATCH numerically, then a release
// above its prereleases, then prereleases as plain strings. semverCompare
// ignores prereleases, which is fine for "does the catalogue have a newer
// version", but not here: 1.0.0 → 1.0.0-beta.1 is equal there and a
// downgrade the supervisor refuses, so install would wait for a start that
// cannot come.
func supervisorVersionCompare(a, b string) int {
	if a == b {
		return 0
	}
	aNum, aPre, _ := strings.Cut(a, "-")
	bNum, bPre, _ := strings.Cut(b, "-")
	aParts, bParts := strings.Split(aNum, "."), strings.Split(bNum, ".")
	part := func(parts []string, i int) int {
		if i >= len(parts) {
			return 0
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return 0
		}
		return n
	}
	for i := 0; i < 3; i++ {
		if av, bv := part(aParts, i), part(bParts, i); av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	switch {
	case aPre == "" && bPre != "":
		return 1
	case aPre != "" && bPre == "":
		return -1
	}
	return strings.Compare(aPre, bPre)
}

// startFailure words a failed start: what happened, and where to look.
func (st appStartStatus) startFailure(appID string) (what, hint string) {
	if st.Refusal != "" {
		what = "the daemon runs a newer version and refuses to replace it with an older one (" + st.Refusal + ")"
		hint = "the files are installed, but the daemon keeps the version it was running (which it cannot restart from these files) " +
			"and starts this one only when the daemon itself restarts (`pilotctl daemon stop`, then `pilotctl daemon start`). " +
			"To stay on the newer version instead, install a version at least as new as the one the daemon runs, with --force. " +
			"To remove it: `pilotctl appstore uninstall " + appID + " --yes`."
		return what, hint
	}
	switch {
	case st.Suspended:
		what = "the daemon suspended it after repeated crashes"
	case st.StartError != "":
		what = fmt.Sprintf("the daemon could not run it (%d attempts; last: %s)", st.Exits, st.StartError)
	default:
		what = fmt.Sprintf("it exited %d times at start (last exit code %d)", st.Exits, st.ExitCode)
	}
	hint = "the files are installed, the app is not running. "
	if st.LastEvent != "" {
		hint += "Last supervisor event: " + st.LastEvent + ". "
	}
	hint += "`pilotctl appstore audit " + appID + "` shows the supervisor's events; the app's own error output is in the daemon's log. "
	if st.Suspended {
		hint += "After fixing the cause: `pilotctl appstore restart " + appID + "`."
	} else {
		hint += "The daemon keeps restarting it and suspends it after more than 5 exits in a minute; once it is suspended, `pilotctl appstore restart " + appID + "` retries it."
	}
	hint += " To remove it: `pilotctl appstore uninstall " + appID + " --yes`."
	return what, hint
}

// startNote is the one line install prints for a start that did not fail.
func (st appStartStatus) startNote(appID string) string {
	waited := st.Waited.Round(100 * time.Millisecond)
	switch {
	case st.State == appStartStarted:
		return fmt.Sprintf("started: the daemon is running %s (socket ready after %s)", appID, waited)
	case !st.Picked:
		return fmt.Sprintf("note: the daemon has not started %s after %s; it picks new apps up on its rescan. Check with `pilotctl appstore status %s`", appID, waited, appID)
	case st.StartError != "":
		return fmt.Sprintf("note: the daemon could not run %s yet (%s); it keeps retrying. Check with `pilotctl appstore status %s` and `pilotctl appstore audit %s`", appID, st.StartError, appID, appID)
	case st.Exits > 0:
		return fmt.Sprintf("note: %s is not ready after %s and has exited %d time(s) (last exit code %d); the daemon is restarting it. Check with `pilotctl appstore status %s` and `pilotctl appstore audit %s`", appID, waited, st.Exits, st.ExitCode, appID, appID)
	default:
		return fmt.Sprintf("note: %s is still starting after %s (no socket yet); check with `pilotctl appstore status %s`", appID, waited, appID)
	}
}
