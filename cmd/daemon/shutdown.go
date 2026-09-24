// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"syscall"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// supervisorExitRequests carries daemon-initiated exits for supervisor
// respawn (the rx watchdog's hard escalation) into main's shutdown loop,
// so they run the same graceful teardown as a signal — above all
// StopPlugins, which terminates the app-store's child apps — before the
// process exits with the requested code. See pkg/daemon/exit.go.
var supervisorExitRequests = make(chan daemon.ExitRequest, 1)

// forwardExitRequest is the daemon.SetExitHandler hook. Non-blocking, as
// the handler contract requires: a request already pending means the
// shutdown it triggers covers this one too.
func forwardExitRequest(req daemon.ExitRequest) {
	select {
	case supervisorExitRequests <- req:
	default:
	}
}

// shutdownCause records what ended the shutdown loop.
type shutdownCause struct {
	// restart: a signed fleet lifecycle command asked for a re-exec.
	restart bool
	// exit: the daemon asked to exit for supervisor respawn. nil for
	// signals and fleet lifecycle requests.
	exit *daemon.ExitRequest
}

// awaitShutdown blocks until something asks the daemon to stop: SIGINT/
// SIGTERM, a fleet lifecycle request, or a daemon exit request. SIGHUP
// runs onReload and keeps waiting.
func awaitShutdown(sig <-chan os.Signal, lifecycle <-chan string, exits <-chan daemon.ExitRequest, onReload func()) shutdownCause {
	for {
		select {
		case received := <-sig:
			if received == syscall.SIGHUP {
				onReload()
				continue
			}
			return shutdownCause{}
		case l := <-lifecycle:
			return shutdownCause{restart: l == "restart"}
		case req := <-exits:
			return shutdownCause{exit: &req}
		}
	}
}

var (
	// daemonStopBudget is how long teardown waits for Daemon.Stop before
	// stopping the plugins anyway. Daemon.Stop can hang when the
	// transport is wedged — exactly when the rx watchdog asks for an
	// exit — and the plugins must still be stopped so the app-store
	// reaps its children before the process goes away.
	daemonStopBudget = 8 * time.Second
	// pluginStopTimeout bounds runtime.StopPlugins.
	pluginStopTimeout = 5 * time.Second
)

// teardown runs the graceful shutdown sequence.
//
// Order matters: Daemon.Stop publishes daemon.shutting_down to the bus
// before tearing down ports/IPC/tunnels. Plugins (notably webhook) are
// still subscribed at that point, so the event flows through.
// StopPlugins then drains each plugin's queue. Reversing this order
// would lose the shutdown event because the webhook's bus subscription
// would be cancelled before doStop publishes.
//
// If Daemon.Stop overruns daemonStopBudget the plugins are stopped
// regardless, then teardown still waits for Daemon.Stop to finish (its
// identity flush runs last). For a supervisor-respawn exit that wait is
// capped by the deadline pkg/daemon armed with the request; for a signal
// it is capped by the supervisor's stop timeout, as before.
func teardown(stopDaemon func(), stopPlugins func(context.Context) error) {
	daemonDone := make(chan struct{})
	go func() {
		defer close(daemonDone)
		stopDaemon()
	}()
	select {
	case <-daemonDone:
	case <-time.After(daemonStopBudget):
		slog.Warn("daemon stop still running — stopping plugins anyway",
			"budget", daemonStopBudget.String())
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), pluginStopTimeout)
	if err := stopPlugins(stopCtx); err != nil {
		slog.Warn("plugin shutdown error", "err", err)
	}
	stopCancel()
	<-daemonDone
}

// shutdown tears the daemon down and, when the daemon itself asked for
// the exit, exits with its code so launchd (SuccessfulExit=false) and
// systemd (Restart=always) respawn it. Returns for every other cause.
func shutdown(cause shutdownCause, stopDaemon func(), stopPlugins func(context.Context) error, exit func(int)) {
	slog.Info("shutting down")
	teardown(stopDaemon, stopPlugins)
	if cause.exit != nil {
		slog.Info("graceful shutdown complete — exiting for supervisor respawn",
			"reason", cause.exit.Reason,
			"exit_code", cause.exit.Code)
		exit(cause.exit.Code)
	}
}

// fatalAfterPluginStart replaces log.Fatalf for failures once plugins are
// running: it stops them before exiting 1. log.Fatalf would skip
// StopPlugins and orphan any app the app-store supervisor had already
// spawned — and since the supervisor respawns on the non-zero exit, a
// persistent startup failure would leak a fresh set on every attempt.
func fatalAfterPluginStart(stopPlugins func(context.Context) error, format string, args ...any) {
	log.Printf(format, args...)
	stopCtx, stopCancel := context.WithTimeout(context.Background(), pluginStopTimeout)
	if err := stopPlugins(stopCtx); err != nil {
		log.Printf("plugin shutdown error: %v", err)
	}
	stopCancel()
	os.Exit(1)
}
