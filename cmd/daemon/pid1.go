// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"
	"os"
	"runtime"
)

// A daemon that is PID 1 (the entrypoint of a container started without an
// init) inherits every orphaned process in the container. Apps start servers
// that daemonize (redis-server, postgres); when one of those exits, it stays
// a zombie until PID 1 waits for it, and Go only waits for the children it
// started itself. The daemon does not reap them: a wait for "any child" also
// takes the exit status of the apps the supervisor is waiting on (os/exec
// then fails with "waitid: no child processes"). Reaping is the job of an
// init process, so the daemon only says so, once, at startup.

// pid1Warning returns the startup warning for a daemon running as PID 1 on
// Linux, and "" for any other process.
func pid1Warning(goos string, pid int) string {
	if goos != "linux" || pid != 1 {
		return ""
	}
	return "the daemon is PID 1: processes that its apps start and leave behind (database servers that daemonize) " +
		"will not be reaped and stay as zombies after they exit. Run the daemon under an init process: " +
		"`docker run --init`, or tini as the container's entrypoint"
}

// warnIfPID1 logs pid1Warning for this process.
func warnIfPID1(logger *slog.Logger) {
	logPID1Warning(logger, runtime.GOOS, os.Getpid())
}

func logPID1Warning(logger *slog.Logger, goos string, pid int) {
	if msg := pid1Warning(goos, pid); msg != "" {
		logger.Warn(msg)
	}
}
