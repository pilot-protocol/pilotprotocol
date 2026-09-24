// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !darwin && !linux

package logcap

import "os"

// Rotation never runs here (fdPathSupported is false); these only keep
// the package building.

const oNoFollow = 0

func fileOwner(os.FileInfo) (int, bool) { return 0, false }
