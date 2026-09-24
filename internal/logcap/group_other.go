// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux

package logcap

import "os"

// privateGroupDir is false: a group-writable log directory keeps no
// backups. macOS has no user private groups — a user's primary group is
// staff, shared by every local account — and its /etc/passwd and
// /etc/group are not where its accounts live. Rotation does not run on
// the other platforms (fdPathSupported is false).
func privateGroupDir(string, os.FileInfo) bool { return false }
