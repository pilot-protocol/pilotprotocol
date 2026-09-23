// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "os"

// A fatal error ends the process: fatalCode and fatalHint print it and exit 1.
// runTrappingFatal lets a command run another command's code path, which may
// end that way, and carry on afterwards. `appstore upgrade --all` uses it so
// one app that cannot be upgraded does not stop the upgrade of every app
// sorted after it (the hourly updater runs `upgrade --all`).

// trappedFatal is the error a trapped fatalCode/fatalHint call ended with. The
// message and hint have already been printed.
type trappedFatal struct {
	Code    string
	Message string
}

// fatalTrapDepth > 0 while runTrappingFatal is running.
var fatalTrapDepth int

// exitAfterFatal ends the process after fatalCode/fatalHint printed an
// error, or, inside runTrappingFatal, unwinds to it (running deferred calls,
// such as releasing an app's install lock, on the way).
func exitAfterFatal(code, msg string) {
	if fatalTrapDepth > 0 {
		panic(trappedFatal{Code: code, Message: msg})
	}
	os.Exit(1)
}

// runTrappingFatal runs fn and returns the fatal error it ended with, or nil
// when it returned normally. Any other panic propagates.
func runTrappingFatal(fn func()) (failure *trappedFatal) {
	fatalTrapDepth++
	defer func() {
		fatalTrapDepth--
		if r := recover(); r != nil {
			tf, ok := r.(trappedFatal)
			if !ok {
				panic(r)
			}
			failure = &tf
		}
	}()
	fn()
	return nil
}
