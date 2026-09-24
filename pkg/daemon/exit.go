// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Supervisor-respawn exits.
//
// Some failure modes are only cured by a fresh process — the rx watchdog's
// hard escalation (rxwatchdog.go) exits non-zero so launchd (KeepAlive
// SuccessfulExit=false) / systemd (Restart=always) respawn the daemon.
//
// That exit used to be a direct os.Exit, which skipped the composition
// root's graceful shutdown (cmd/daemon: Daemon.Stop + runtime.StopPlugins).
// StopPlugins is what stops the app-store supervisor and terminates its
// child app processes; apps run in their own process group, so every
// watchdog exit orphaned all of them. One laptop accumulated 94 copies of
// each of 12 apps (~2.8 GB RSS) in a week.
//
// requestSupervisorExit now hands the exit to the host process instead:
// the handler installed with SetExitHandler (cmd/daemon's shutdown loop)
// runs the normal teardown and then exits with the requested code, so the
// supervisor still sees a non-zero status and respawns. The teardown can
// itself hang when the transport is wedged, so a hard deadline is armed
// before the handler runs: when it expires the process exits with the same
// code regardless. With no handler installed (embedders, bare test
// daemons) the request exits immediately — the pre-existing behavior.

// supervisorExitDeadline bounds the graceful path of a supervisor-respawn
// exit. Long enough for Daemon.Stop (its own 5s background-goroutine
// wait) plus StopPlugins (5s); short enough that a wedged teardown still
// respawns promptly.
const supervisorExitDeadline = 15 * time.Second

// ExitRequest is a deliberate self-exit the daemon asks its host process
// to perform after a graceful shutdown.
type ExitRequest struct {
	// Code is the process exit status. Non-zero so the supervisor
	// respawns (rxWedgeExitCode for the rx watchdog).
	Code int
	// Reason is a short machine-readable cause for logs, e.g. "rx-wedge".
	Reason string
}

var (
	exitHandler   atomic.Pointer[func(ExitRequest)]
	exitRequested atomic.Bool

	// exitSeamMu guards the test seams below. Production never writes
	// them; tests swap them (see zz_exit_request_test.go).
	exitSeamMu sync.Mutex
	// hardExit terminates the process.
	hardExit = os.Exit
	// exitDeadline is supervisorExitDeadline outside tests.
	exitDeadline = supervisorExitDeadline
)

// SetExitHandler installs fn as the receiver of supervisor-respawn exit
// requests. fn must not block: it should hand the request to the
// goroutine that owns shutdown (cmd/daemon forwards it into its shutdown
// loop) and return. That goroutine runs the graceful teardown and exits
// the process with req.Code. nil uninstalls the handler, restoring the
// immediate os.Exit.
func SetExitHandler(fn func(ExitRequest)) {
	if fn == nil {
		exitHandler.Store(nil)
		return
	}
	exitHandler.Store(&fn)
}

// requestSupervisorExit asks the host process to shut down gracefully and
// exit with req.Code, forcing the exit after exitDeadline. Only the first
// request per process takes effect: later ones (another subsystem, or a
// tick racing the teardown) are dropped so the code and the deadline stay
// those of the first.
func requestSupervisorExit(req ExitRequest) {
	if !exitRequested.CompareAndSwap(false, true) {
		return
	}
	exitSeamMu.Lock()
	exit, deadline := hardExit, exitDeadline
	exitSeamMu.Unlock()

	h := exitHandler.Load()
	if h == nil {
		exit(req.Code)
		return
	}
	// Arm the deadline BEFORE handing off: if the handler or the teardown
	// it triggers wedges, the process still exits for respawn.
	time.AfterFunc(deadline, func() {
		slog.Error("graceful shutdown did not finish before the exit deadline — forcing exit",
			"reason", req.Reason,
			"exit_code", req.Code,
			"deadline", deadline.String())
		exit(req.Code)
	})
	slog.Info("requesting graceful shutdown for supervisor respawn",
		"reason", req.Reason,
		"exit_code", req.Code,
		"deadline", deadline.String())
	(*h)(req)
}
