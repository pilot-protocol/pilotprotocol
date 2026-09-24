// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin && !linux

package logcap

import (
	"errors"
	"os"
)

// Rotation never runs here (fdPathSupported is false); this only keeps
// the package building.
func flock(*os.File) error {
	return errors.New("logcap: file locking is unsupported on this platform")
}
