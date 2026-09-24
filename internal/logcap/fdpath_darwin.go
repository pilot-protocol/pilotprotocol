// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build darwin

package logcap

import (
	"bytes"
	"os"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const fdPathSupported = true

// getpathBuf receives F_GETPATH's result. The buffer's address reaches
// fcntl as a plain integer, which the runtime neither tracks nor fixes up
// if a stack-allocated buffer moved, so it lives in static storage.
var (
	getpathMu  sync.Mutex
	getpathBuf [unix.PathMax]byte
)

// fdPath returns the current path of the file open on f (fcntl F_GETPATH).
// It follows renames of the open file.
func fdPath(f *os.File) (string, error) {
	getpathMu.Lock()
	defer getpathMu.Unlock()
	// #nosec G103 -- F_GETPATH takes a MAXPATHLEN output buffer by address.
	if _, err := unix.FcntlInt(f.Fd(), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&getpathBuf[0])))); err != nil {
		return "", err
	}
	n := bytes.IndexByte(getpathBuf[:], 0)
	if n < 0 {
		n = len(getpathBuf)
	}
	return string(getpathBuf[:n]), nil
}
