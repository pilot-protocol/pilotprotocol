// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package logcap

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// umask002Dir makes a directory the way `mkdir -p ~/.pilot/bin` does in
// install.sh under umask 002 — group-writable, with the process's group —
// and skips the test unless that group is this user's private group in
// /etc/passwd and /etc/group (the linux container run creates such a
// user).
func umask002Dir(t *testing.T) string {
	t.Helper()
	passwd, perr := os.ReadFile("/etc/passwd")
	group, gerr := os.ReadFile("/etc/group")
	if perr != nil || gerr != nil || !userPrivateGroup(os.Geteuid(), os.Getegid(), passwd, group) {
		t.Skip("this user's primary group is not a user private group")
	}
	dir := filepath.Join(t.TempDir(), ".pilot")
	old := syscall.Umask(0o002)
	err := os.Mkdir(dir, 0o777)
	syscall.Umask(old)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o775 {
		t.Fatalf("mode %v, want 0775", fi.Mode().Perm())
	}
	if gid := fi.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getegid() {
		t.Skipf("directory got group %d, not the process's (setgid parent)", gid)
	}
	return dir
}

// TestCheckRealPrivateGroupDirectory: with the real account files, a log
// in a directory made under umask 002 by a user with a private group is
// rotated with backups.
func TestCheckRealPrivateGroupDirectory(t *testing.T) {
	dir := umask002Dir(t)
	path := filepath.Join(dir, "daemon.log")
	f := openLog(t, path)
	content := strings.Repeat("u", 50)
	write(t, f, content)
	mustRotate(t, New(f, Options{MaxBytes: 10, MaxBackups: 3, Within: []string{dir}}))
	if got := gunzip(t, backupName(path, 1)); got != content {
		t.Fatalf("backup = %q, want the log", got)
	}
}

// TestPrivateGroupDirWithACL: a POSIX ACL entry can give another user the
// write the group bits (then the ACL mask) show, so a directory with one
// is not taken as private.
func TestPrivateGroupDirWithACL(t *testing.T) {
	dir := umask002Dir(t)
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !privateGroupDir(dir, fi) {
		t.Fatal("private group directory without an ACL was not accepted")
	}

	// user::rwx user:4242:rwx group::rwx mask::rwx other::r-x, in the
	// kernel's system.posix_acl_access format.
	const undefined = 0xffffffff
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range []struct {
		tag, perm uint16
		id        uint32
	}{
		{0x01, 7, undefined},
		{0x02, 7, uint32(foreignUID)},
		{0x04, 7, undefined},
		{0x10, 7, undefined},
		{0x20, 5, undefined},
	} {
		acl = binary.LittleEndian.AppendUint16(acl, e.tag)
		acl = binary.LittleEndian.AppendUint16(acl, e.perm)
		acl = binary.LittleEndian.AppendUint32(acl, e.id)
	}
	if err := syscall.Setxattr(dir, "system.posix_acl_access", acl, 0); err != nil {
		if errors.Is(err, syscall.ENOTSUP) {
			t.Skip("filesystem has no POSIX ACLs")
		}
		t.Fatal(err)
	}
	fi, err = os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if privateGroupDir(dir, fi) {
		t.Fatal("directory with an ACL granting another user write was taken as private")
	}
	if err := checkDir(dir); err == nil {
		t.Fatal("checkDir accepted a directory another user can write through an ACL")
	}
}

// TestPrivateGroupDirOtherGroup: a group-writable directory whose group
// is not the user's is not private (needs root to chgrp).
func TestPrivateGroupDirOtherGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the directory another group")
	}
	dir := umask002Dir(t)
	if err := os.Chown(dir, -1, foreignUID); err != nil {
		t.Fatal(err)
	}
	if err := checkDir(dir); err == nil {
		t.Fatal("checkDir accepted a directory writable by another group")
	}
}
