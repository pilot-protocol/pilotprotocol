// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package proxyconf

import "os/exec"

// ownProcessGroup leaves cmd as it is: without Unix process groups, a
// timed-out refresh command is killed on its own (exec.Cmd's default).
func ownProcessGroup(*exec.Cmd) {}

// killProcessGroup is a no-op without Unix process groups.
func killProcessGroup(*exec.Cmd) error { return nil }
