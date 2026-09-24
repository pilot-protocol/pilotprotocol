// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pilot-protocol/pilotprotocol/pkg/daemon"
)

// stepRecorder records teardown steps in the order they ran.
type stepRecorder struct {
	mu    sync.Mutex
	steps []string
}

func (r *stepRecorder) add(step string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.steps = append(r.steps, step)
}

func (r *stepRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.steps...)
}

func equalSteps(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestExitRequestRunsGracefulShutdownThenExits: a daemon exit request
// (the rx watchdog's hard escalation) ends the shutdown loop like a
// signal, runs Daemon.Stop then StopPlugins — which reaps the app-store's
// child apps — and only then exits with the requested code.
func TestExitRequestRunsGracefulShutdownThenExits(t *testing.T) {
	// Drain anything a previous test left in the package-level channel.
	select {
	case <-supervisorExitRequests:
	default:
	}
	forwardExitRequest(daemon.ExitRequest{Code: 86, Reason: "rx-wedge"})
	// A second request while one is pending must not block the caller
	// (the handler runs on the watchdog goroutine).
	forwardExitRequest(daemon.ExitRequest{Code: 1, Reason: "dup"})

	cause := awaitShutdown(make(chan os.Signal), make(chan string), supervisorExitRequests, func() {
		t.Error("reload called without SIGHUP")
	})
	if cause.exit == nil || cause.exit.Code != 86 {
		t.Fatalf("cause = %+v, want exit request with code 86", cause)
	}
	if cause.restart {
		t.Fatal("exit request must not re-exec")
	}

	var rec stepRecorder
	exitCode := -1
	shutdown(cause,
		func() { rec.add("daemon.Stop") },
		func(context.Context) error { rec.add("StopPlugins"); return nil },
		func(code int) { rec.add("exit"); exitCode = code })

	if want := []string{"daemon.Stop", "StopPlugins", "exit"}; !equalSteps(rec.snapshot(), want) {
		t.Fatalf("teardown steps = %v, want %v", rec.snapshot(), want)
	}
	if exitCode != 86 {
		t.Fatalf("exit code = %d, want 86 (non-zero so the supervisor respawns)", exitCode)
	}
}

// TestSignalShutdownDoesNotExit: SIGTERM keeps the old behavior — tear
// down and return from main (status 0), no forced exit code.
func TestSignalShutdownDoesNotExit(t *testing.T) {
	sig := make(chan os.Signal, 2)
	sig <- syscall.SIGHUP
	sig <- syscall.SIGTERM
	reloads := 0
	cause := awaitShutdown(sig, make(chan string), make(chan daemon.ExitRequest), func() { reloads++ })
	if reloads != 1 {
		t.Fatalf("SIGHUP reloads = %d, want 1", reloads)
	}
	if cause.exit != nil || cause.restart {
		t.Fatalf("SIGTERM cause = %+v, want plain shutdown", cause)
	}

	var rec stepRecorder
	shutdown(cause,
		func() { rec.add("daemon.Stop") },
		func(context.Context) error { rec.add("StopPlugins"); return nil },
		func(code int) { t.Fatalf("signal shutdown called exit(%d)", code) })
	if want := []string{"daemon.Stop", "StopPlugins"}; !equalSteps(rec.snapshot(), want) {
		t.Fatalf("teardown steps = %v, want %v", rec.snapshot(), want)
	}
}

// TestLifecycleRestartCause: the signed fleet restart still maps to a
// re-exec, not an exit.
func TestLifecycleRestartCause(t *testing.T) {
	lifecycle := make(chan string, 1)
	lifecycle <- "restart"
	cause := awaitShutdown(make(chan os.Signal), lifecycle, make(chan daemon.ExitRequest), func() {})
	if !cause.restart || cause.exit != nil {
		t.Fatalf("cause = %+v, want restart", cause)
	}
}

// TestTeardownStopsPluginsWhenDaemonStopHangs: a wedged transport can
// hang Daemon.Stop. The plugins must still be stopped once the budget
// runs out, or the app-store's children are orphaned when the exit
// deadline kills the process.
func TestTeardownStopsPluginsWhenDaemonStopHangs(t *testing.T) {
	prev := daemonStopBudget
	daemonStopBudget = 20 * time.Millisecond
	t.Cleanup(func() { daemonStopBudget = prev })

	release := make(chan struct{})
	pluginsStopped := make(chan struct{})
	done := make(chan struct{})
	var rec stepRecorder
	go func() {
		defer close(done)
		teardown(
			func() { <-release; rec.add("daemon.Stop") },
			func(context.Context) error { rec.add("StopPlugins"); close(pluginsStopped); return nil })
	}()

	select {
	case <-pluginsStopped:
	case <-time.After(5 * time.Second):
		t.Fatal("plugins were not stopped while Daemon.Stop hung")
	}
	select {
	case <-done:
		t.Fatal("teardown returned before Daemon.Stop finished")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("teardown did not return after Daemon.Stop finished")
	}
	if want := []string{"StopPlugins", "daemon.Stop"}; !equalSteps(rec.snapshot(), want) {
		t.Fatalf("teardown steps = %v, want %v", rec.snapshot(), want)
	}
}
