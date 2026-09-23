// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build linux

package logcap

import (
	"os"
	"strconv"
)

const fdPathSupported = true

// fdPath returns the current path of the file open on f via
// /proc/self/fd. A deleted file reads back as "<path> (deleted)", which
// the caller's same-file check then rejects.
func fdPath(f *os.File) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(f.Fd()), 10))
}
