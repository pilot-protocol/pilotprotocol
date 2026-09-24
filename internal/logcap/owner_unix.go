// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin || linux

package logcap

import (
	"os"
	"syscall"
)

// oNoFollow makes opening a symlink fail (ELOOP) instead of opening its
// target.
const oNoFollow = syscall.O_NOFOLLOW

// fileOwner returns the uid that owns fi.
func fileOwner(fi os.FileInfo) (int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
