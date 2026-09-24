// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package logcap

import (
	"errors"
	"os"
	"syscall"
)

// privateGroupDir reports whether only this user can write to dir (whose
// Lstat is fi) through its group permission: the directory's group is
// the user's private group (userPrivateGroup) and it has no POSIX ACL.
// With an ACL the group bits are the ACL's mask, and a named user or
// group entry may hold the write they show.
func privateGroupDir(dir string, fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if acl, err := hasAccessACL(dir); err != nil || acl {
		return false
	}
	passwd, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false
	}
	group, err := os.ReadFile("/etc/group")
	if err != nil {
		return false
	}
	return userPrivateGroup(os.Geteuid(), int(st.Gid), passwd, group)
}

// hasAccessACL reports whether dir carries a POSIX access ACL. The kernel
// stores none for an ACL the mode bits already express.
func hasAccessACL(dir string) (bool, error) {
	_, err := syscall.Getxattr(dir, "system.posix_acl_access", nil)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, syscall.ENODATA), errors.Is(err, syscall.ENOTSUP):
		return false, nil
	}
	return false, err
}
