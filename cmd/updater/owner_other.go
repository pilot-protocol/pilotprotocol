// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import "os"

// ownedByCurrentUser cannot tell the owner here, so the temp sweep removes
// nothing.
func ownedByCurrentUser(os.FileInfo) bool { return false }
