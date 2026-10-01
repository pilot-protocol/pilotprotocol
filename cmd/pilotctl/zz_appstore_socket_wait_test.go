// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// `appstore call` right after `appstore install` used to fail: the daemon had
// not started the app yet. It now waits for the socket — but only for an app
// that is installed and not suspended, so a call that cannot succeed still
// fails at once.
func TestWaitForAppSocket(t *testing.T) {
	t.Run("not installed fails at once", func(t *testing.T) {
		dir := t.TempDir()
		start := time.Now()
		if err := waitForAppSocket(dir, filepath.Join(dir, "app.sock"), 5*time.Second); err == nil {
			t.Fatal("want an error for an app with no manifest")
		}
		if time.Since(start) > time.Second {
			t.Errorf("waited %v for an app that is not installed", time.Since(start))
		}
	})

	t.Run("suspended fails at once", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"manifest.json", ".suspended"} {
			if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		start := time.Now()
		if err := waitForAppSocket(dir, filepath.Join(dir, "app.sock"), 5*time.Second); err == nil {
			t.Fatal("want an error for a suspended app")
		}
		if time.Since(start) > time.Second {
			t.Errorf("waited %v for a suspended app", time.Since(start))
		}
	})

	t.Run("installed app is waited for", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(dir, "app.sock")
		go func() {
			time.Sleep(400 * time.Millisecond)
			_ = os.WriteFile(sock, nil, 0o600)
		}()
		if err := waitForAppSocket(dir, sock, 5*time.Second); err != nil {
			t.Fatalf("socket appeared but wait failed: %v", err)
		}
	})

	t.Run("gives up after the wait", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := waitForAppSocket(dir, filepath.Join(dir, "app.sock"), 300*time.Millisecond); err == nil {
			t.Fatal("want an error when the socket never appears")
		}
	})
}
