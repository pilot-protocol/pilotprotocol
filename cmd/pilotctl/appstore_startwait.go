// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
// watches the app dir for up to appStartWait and reports one of:
//
//   - started: the supervisor spawned the app and its socket is there.
//   - failed: the supervisor suspended it, or it exited at least twice
//     without its socket being there. install exits non-zero.
//   - starting: neither, by the deadline. Not a failure: an app that takes
//     longer than the wait to open its socket is healthy.
//
// Everything is read from the app dir (supervisor.log, .suspended,
// app.sock), like `list` and `status` do: pilotctl has no channel to the
// supervisor. The supervisor only suspends an app after more than five exits
// in a minute, 31s at the earliest, so waiting for .suspended alone would
// either miss the failure or cost every install half a minute; two exits are
// there after about 3s.

// appStartWait bounds how long install waits for the app's first start.
// appStartPoll is how often it looks. Vars so tests can shorten them.
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

// appStartStatus is what install saw of the app's first start.
type appStartStatus struct {
	State     string // appStartStarted, appStartFailed or appStartStarting
	Waited    time.Duration
	Picked    bool   // the supervisor has logged something for this install
	Spawns    int    // spawn events since the install
	Exits     int    // exit events since the install
	ExitCode  int    // exit code of the last of them
	Suspended bool   // the supervisor gave up on the app
	LastEvent string // last supervisor.log line since the install, as written
}

// supervisorEvent is the part of a supervisor.log line install looks at.
type supervisorEvent struct {
	At       time.Time `json:"at"`
	Event    string    `json:"event"`
	ExitCode int       `json:"exit_code"`
	Reason   string    `json:"reason"`
}

// readAppStart reads the app dir once. since is when the new install was
// swapped in: older log lines belong to a previous install, whose log is
// carried over. replaced is true when an install was replaced: the instance
// the supervisor stops for it logs one exit of its own.
func readAppStart(appDir string, since time.Time, replaced bool) appStartStatus {
	var st appStartStatus
	if f, err := os.Open(filepath.Join(appDir, "supervisor.log")); err == nil { // #nosec G304 -- <install root>/<validated app id>/supervisor.log
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			var ev supervisorEvent
			if line == "" || json.Unmarshal([]byte(line), &ev) != nil || ev.At.Before(since) {
				continue
			}
			if ev.Event == "installed" {
				continue // written by pilotctl itself
			}
			st.Picked = true
			st.LastEvent = line
			switch ev.Event {
			case "spawn":
				st.Spawns++
			case "exit":
				st.Exits++
				st.ExitCode = ev.ExitCode
			case "suspend":
				st.Suspended = true
			case "resume":
				st.Suspended = false
			}
		}
		_ = f.Close()
	}
	// The marker of a previous install can be carried into this one before
	// the supervisor clears it, so only one written since the swap counts.
	if fi, err := os.Stat(filepath.Join(appDir, ".suspended")); err == nil && !fi.ModTime().Before(since) {
		st.Suspended = true
	}
	_, sockErr := os.Stat(filepath.Join(appDir, "app.sock"))
	needExits := appStartExitsForFailure
	if replaced {
		needExits++
	}
	switch {
	case st.Suspended:
		st.State = appStartFailed
	case sockErr == nil && st.Spawns > 0:
		st.State = appStartStarted
	case sockErr != nil && st.Exits >= needExits:
		st.State = appStartFailed
	default:
		st.State = appStartStarting
	}
	return st
}

// waitForAppStart polls the app dir until the start is decided either way,
// or wait has passed.
func waitForAppStart(appDir string, since time.Time, replaced bool, wait time.Duration) appStartStatus {
	begin := time.Now()
	for {
		st := readAppStart(appDir, since, replaced)
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

// startFailure words a failed start: what happened, and where to look.
func (st appStartStatus) startFailure(appID string) (what, hint string) {
	if st.Suspended {
		what = "the daemon suspended it after repeated crashes"
	} else {
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
	case st.Exits > 0:
		return fmt.Sprintf("note: %s is not ready after %s and has exited %d time(s) (last exit code %d); the daemon is restarting it. Check with `pilotctl appstore status %s` and `pilotctl appstore audit %s`", appID, waited, st.Exits, st.ExitCode, appID, appID)
	default:
		return fmt.Sprintf("note: %s is still starting after %s (no socket yet); check with `pilotctl appstore status %s`", appID, waited, appID)
	}
}
