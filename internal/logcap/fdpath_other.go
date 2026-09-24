// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin && !linux

package logcap

import (
	"errors"
	"os"
)

// fdPathSupported is false here: without a path there is no backup, so
// Watch leaves the log alone rather than truncate it blind.
const fdPathSupported = false

func fdPath(*os.File) (string, error) {
	return "", errors.New("logcap: mapping a descriptor to its path is unsupported on this platform")
}
