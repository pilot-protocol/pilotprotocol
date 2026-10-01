// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !linux && !darwin

package main

import "errors"

// No process table access here: uninstall finds nothing to stop.
func listProcessIDs() []int { return nil }

func processExecutable(int) (string, error) {
	return "", errors.New("process executables are not readable on this platform")
}

// processCodeUnder: the executable path above is authoritative here.
func processCodeUnder(int, []string) (string, bool) { return "", false }
