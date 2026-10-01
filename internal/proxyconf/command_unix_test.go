// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build unix

package proxyconf

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A refresh command that outlives the deadline is killed with everything
// it started, and the refresh fails promptly.
func TestCommandSourceTimeoutKillsTheGroup(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := CommandSource("sleep 30 & echo $! > '"+pidFile+"'; wait", env)(ctx)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("hung command: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("hung command took %v to fail", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			t.Fatalf("the command's background child %d outlived the timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
