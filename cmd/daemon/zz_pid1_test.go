// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// The PID 1 warning is for a Linux daemon that is the container's init, and
// for nothing else.
func TestPID1WarningOnlyForLinuxPID1(t *testing.T) {
	for _, tc := range []struct {
		goos string
		pid  int
		want bool
	}{
		{"linux", 1, true},
		{"linux", 2, false},
		{"linux", 7, false}, // what `docker run --init` gives the daemon
		{"linux", 0, false},
		{"darwin", 1, false},
		{"windows", 1, false},
	} {
		var buf bytes.Buffer
		logPID1Warning(slog.New(slog.NewTextHandler(&buf, nil)), tc.goos, tc.pid)
		got := buf.String()
		if tc.want {
			if strings.Count(got, "level=WARN") != 1 {
				t.Errorf("%s pid %d: want exactly one warning, got %q", tc.goos, tc.pid, got)
			}
			for _, part := range []string{"PID 1", "not be reaped", "docker run --init", "tini"} {
				if !strings.Contains(got, part) {
					t.Errorf("%s pid %d: warning does not mention %q: %q", tc.goos, tc.pid, part, got)
				}
			}
		} else if got != "" {
			t.Errorf("%s pid %d: want no warning, got %q", tc.goos, tc.pid, got)
		}
	}
}

// The test process is never PID 1 outside a container that runs `go test` as
// its entrypoint, so the real check stays silent here.
func TestWarnIfPID1SilentForOrdinaryProcess(t *testing.T) {
	if os.Getpid() == 1 {
		t.Skip("running as PID 1")
	}
	var buf bytes.Buffer
	warnIfPID1(slog.New(slog.NewTextHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Fatalf("pid %d logged %q", os.Getpid(), buf.String())
	}
}
