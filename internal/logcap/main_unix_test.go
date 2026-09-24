// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin || linux

package logcap

import (
	"os"
	"syscall"
	"testing"
)

// TestMain runs the tests under umask 022, whatever the caller's. Under
// umask 002 t.TempDir's directories are group-writable, and on macOS their
// group is staff, which every local account is in, so rotation there
// (rightly) keeps no backup. The tests about directory permissions set
// them explicitly.
func TestMain(m *testing.M) {
	syscall.Umask(0o022)
	os.Exit(m.Run())
}
