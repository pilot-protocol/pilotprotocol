// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package logcap

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestCheckKeepsGenerationsOfAppendOnlyLog: an operator makes the log
// append-only for tamper resistance (chflags uappnd; chattr +a on
// Linux). The daemon's O_APPEND writes go on, but it can no longer
// truncate the log: its backups are kept rather than shifted out one per
// round, and no copy is left behind.
func TestCheckKeepsGenerationsOfAppendOnlyLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	for gen := 1; gen <= 3; gen++ {
		writeFile(t, backupName(path, gen), fmt.Sprintf("generation %d", gen))
	}
	f := openLog(t, path)
	content := strings.Repeat("a", 50)
	write(t, f, content)
	if err := unix.Chflags(path, unix.UF_APPEND); err != nil {
		t.Skipf("chflags uappnd: %v", err)
	}
	t.Cleanup(func() { _ = unix.Chflags(path, 0) })
	before := dirNames(t, dir)

	r := New(f, anywhere(10, 3))
	for round := range 3 {
		rotated, err := r.Check()
		if rotated || !errors.Is(err, errTruncate) || !errors.Is(err, unix.EPERM) {
			t.Fatalf("round %d: Check = (%v, %v), want (false, errTruncate: EPERM)", round, rotated, err)
		}
		if got := dirNames(t, dir); !equal(got, before) {
			t.Fatalf("round %d: dir = %v, want %v", round, got, before)
		}
	}
	for gen := 1; gen <= 3; gen++ {
		if got := readFile(t, backupName(path, gen)); got != fmt.Sprintf("generation %d", gen) {
			t.Fatalf("%s = %q", backupName(path, gen), got)
		}
	}

	if err := unix.Chflags(path, 0); err != nil {
		t.Fatal(err)
	}
	mustRotate(t, r)
	if got := gunzip(t, backupName(path, 1)); got != content {
		t.Fatalf(".1.gz = %q, want the log", got)
	}
	for gen, want := range map[int]string{2: "generation 1", 3: "generation 2"} {
		if got := readFile(t, backupName(path, gen)); got != want {
			t.Fatalf("%s = %q, want %q", backupName(path, gen), got, want)
		}
	}
}
