// SPDX-License-Identifier: AGPL-3.0-or-later

package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

// swapExitSeamsForTest stubs the process-exit seams behind
// requestSupervisorExit and resets the once-per-process latch. The
// returned channel receives every code passed to hardExit. Like
// swapExitForTest, callers must NOT use t.Parallel(): the seams and the
// installed handler are package-global.
func swapExitSeamsForTest(t *testing.T, deadline time.Duration) <-chan int {
	t.Helper()
	exited := make(chan int, 4)
	exitSeamMu.Lock()
	prevExit, prevDeadline := hardExit, exitDeadline
	hardExit = func(code int) {
		select {
		case exited <- code:
		default:
		}
	}
	exitDeadline = deadline
	exitSeamMu.Unlock()
	prevHandler := exitHandler.Load()
	exitRequested.Store(false)
	t.Cleanup(func() {
		exitSeamMu.Lock()
		hardExit, exitDeadline = prevExit, prevDeadline
		exitSeamMu.Unlock()
		exitHandler.Store(prevHandler)
		exitRequested.Store(false)
	})
	return exited
}

// captureExitRequests installs a handler that records requests, standing
// in for cmd/daemon's shutdown loop.
func captureExitRequests(t *testing.T) <-chan ExitRequest {
	t.Helper()
	got := make(chan ExitRequest, 4)
	SetExitHandler(func(req ExitRequest) { got <- req })
	return got
}

// TestRequestSupervisorExitHandsOffToHandler: with a handler installed the
// request goes to the host's graceful shutdown path — the process is NOT
// exited on the spot (that was what orphaned the app-store's children).
func TestRequestSupervisorExitHandsOffToHandler(t *testing.T) {
	exited := swapExitSeamsForTest(t, time.Hour)
	got := captureExitRequests(t)

	requestSupervisorExit(ExitRequest{Code: rxWedgeExitCode, Reason: "rx-wedge"})

	select {
	case req := <-got:
		if req.Code != rxWedgeExitCode || req.Reason != "rx-wedge" {
			t.Fatalf("handler got %+v, want code %d reason rx-wedge", req, rxWedgeExitCode)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exit request never reached the handler")
	}
	select {
	case code := <-exited:
		t.Fatalf("process exited immediately (code %d) instead of via graceful shutdown", code)
	default:
	}
}

// TestRequestSupervisorExitDeadlineForcesExit: if the graceful shutdown
// hangs (wedged transport), the armed deadline exits anyway with the
// requested code so the supervisor still respawns.
func TestRequestSupervisorExitDeadlineForcesExit(t *testing.T) {
	exited := swapExitSeamsForTest(t, 20*time.Millisecond)
	// A handler that accepts the request and then never exits — the
	// teardown it would have triggered is stuck.
	SetExitHandler(func(ExitRequest) {})

	requestSupervisorExit(ExitRequest{Code: rxWedgeExitCode, Reason: "rx-wedge"})

	select {
	case code := <-exited:
		if code != rxWedgeExitCode {
			t.Fatalf("forced exit code = %d, want %d", code, rxWedgeExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deadline never forced the exit")
	}
}

// TestRequestSupervisorExitWithoutHandlerExitsImmediately: embedders that
// never install a handler keep the old direct-exit behavior.
func TestRequestSupervisorExitWithoutHandlerExitsImmediately(t *testing.T) {
	exited := swapExitSeamsForTest(t, time.Hour)
	SetExitHandler(nil)

	requestSupervisorExit(ExitRequest{Code: rxWedgeExitCode, Reason: "rx-wedge"})

	select {
	case code := <-exited:
		if code != rxWedgeExitCode {
			t.Fatalf("exit code = %d, want %d", code, rxWedgeExitCode)
		}
	default:
		t.Fatal("no handler installed but the process was not exited")
	}
}

// TestRequestSupervisorExitFirstRequestWins: a second request (another
// subsystem, or a tick racing the teardown) must not re-arm the deadline
// or change the exit code.
func TestRequestSupervisorExitFirstRequestWins(t *testing.T) {
	swapExitSeamsForTest(t, time.Hour)
	got := captureExitRequests(t)

	requestSupervisorExit(ExitRequest{Code: rxWedgeExitCode, Reason: "first"})
	requestSupervisorExit(ExitRequest{Code: 1, Reason: "second"})

	if req := <-got; req.Reason != "first" {
		t.Fatalf("first request = %+v, want reason first", req)
	}
	select {
	case req := <-got:
		t.Fatalf("second request reached the handler: %+v", req)
	default:
	}
}

// TestRxWatchdogHardExitRequestsGracefulShutdown drives the real
// (unswapped) rxWatchdogExit: the hard escalation records the exit for the
// restart-loop breaker, then hands exit code 86 to the host's shutdown
// path instead of calling os.Exit.
func TestRxWatchdogHardExitRequestsGracefulShutdown(t *testing.T) {
	exited := swapExitSeamsForTest(t, time.Hour)
	got := captureExitRequests(t)

	d := newRxWatchdogTestDaemon(t)
	now := time.Now()
	d.config.IdentityPath = filepath.Join(t.TempDir(), "id")
	d.lastRegistryOKNano.Store(now.UnixNano())

	st := wedgeState(d, now)
	if action := d.rxWatchdogTick(st, now); action != rxActionExit {
		t.Fatalf("action = %q, want %q", action, rxActionExit)
	}
	select {
	case req := <-got:
		if req.Code != rxWedgeExitCode {
			t.Fatalf("requested exit code = %d, want %d", req.Code, rxWedgeExitCode)
		}
	default:
		t.Fatal("hard escalation did not request a graceful shutdown")
	}
	select {
	case code := <-exited:
		t.Fatalf("watchdog exited directly (code %d), skipping plugin shutdown", code)
	default:
	}
	path := rxWedgeExitLogPath(d.config.IdentityPath)
	if n := len(recentRxWedgeExits(path, now, rxWedgeLoopWindow)); n != 1 {
		t.Fatalf("recorded exits = %d, want 1 (recorded before the request)", n)
	}
}
