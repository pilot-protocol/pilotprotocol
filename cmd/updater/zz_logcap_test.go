// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// openLog creates the log at path the way launchd does (O_APPEND) and
// fills it with size bytes.
func openLog(t *testing.T, path string, size int) (*os.File, []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	data := bytes.Repeat([]byte("time=x level=ERROR msg=\"failed to fetch latest release\"\n"), size/56+1)[:size]
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
	return f, data
}

// TestUpdaterLogIsCappedInsidePilotDir: install.sh's launchd job writes the
// updater's stderr to ~/.pilot/updater.log, which nothing rotated. Past the
// cap it is truncated and its content kept as updater.log.pilot.1.gz.
func TestUpdaterLogIsCappedInsidePilotDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_HOME", "")
	logPath := filepath.Join(home, ".pilot", "updater.log")
	f, data := openLog(t, logPath, 1<<20+4096)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !capUpdaterLog(ctx, f, 1, defaultUpdaterLogBackups, false, time.Hour) {
		t.Fatal("capping did not start for ~/.pilot/updater.log")
	}

	backup := logPath + ".pilot.1.gz"
	deadline := time.Now().Add(10 * time.Second)
	for {
		fi, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(backup); err == nil && fi.Size() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("log not rotated: size=%d", fi.Size())
		}
		time.Sleep(20 * time.Millisecond)
	}

	gz, err := os.Open(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	zr, err := gzip.NewReader(gz)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("backup holds %d bytes, want the %d the log had", len(got), len(data))
	}
}

// TestUpdaterLogElsewhereIsLeftAlone: a log an operator redirected outside
// ~/.pilot is rotated only when -log-max-size is set explicitly.
func TestUpdaterLogElsewhereIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_HOME", "")
	if err := os.MkdirAll(filepath.Join(home, ".pilot"), 0o700); err != nil {
		t.Fatal(err)
	}
	f, _ := openLog(t, filepath.Join(t.TempDir(), "var", "updater.log"), 16)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if capUpdaterLog(ctx, f, 1, 3, false, time.Hour) {
		t.Fatal("capping started for a log outside ~/.pilot without an explicit -log-max-size")
	}
	if !capUpdaterLog(ctx, f, 1, 3, true, time.Hour) {
		t.Fatal("capping did not start for an explicitly capped log")
	}
}

// TestUpdaterLogCapDisabled: -log-max-size=0 turns the cap off.
func TestUpdaterLogCapDisabled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	f, _ := openLog(t, filepath.Join(home, ".pilot", "updater.log"), 16)
	if capUpdaterLog(context.Background(), f, 0, 3, true, time.Hour) {
		t.Fatal("capping started with -log-max-size=0")
	}
}

// TestUpdaterLogDirs follows HOME and PILOT_HOME.
func TestUpdaterLogDirs(t *testing.T) {
	t.Setenv("HOME", "/h")
	t.Setenv("PILOT_HOME", "/p")
	got := updaterLogDirs()
	want := []string{filepath.Join("/h", ".pilot"), filepath.Join("/p", ".pilot")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("updaterLogDirs() = %v, want %v", got, want)
	}
}
