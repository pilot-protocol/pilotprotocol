// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"context"
	"os"
	"strings"
	"testing"
)

// CommandSource runs the command in the environment it was given, not in
// this process's current one: the daemon points its own HTTPS_PROXY at its
// app relay, and the refresh command must keep seeing the launch
// environment (and never print the relay).
func TestCommandSourceUsesGivenEnvironment(t *testing.T) {
	t.Setenv("PROBE_PROXY", "http://pilot-relay:tok@127.0.0.1:1") // what the daemon exports later
	launch := []string{"PATH=" + os.Getenv("PATH"), "PROBE_PROXY=http://muse:launch@egress.test:3128"}
	const cmd = `printf %s "$PROBE_PROXY"`
	src := CommandSource(cmd, launch)
	launch[1] = "PROBE_PROXY=changed" // CommandSource keeps its own copy
	out, err := src(context.Background())
	if err != nil || out != "http://muse:launch@egress.test:3128" {
		t.Fatalf("with the launch environment = (%q, %v)", out, err)
	}
	out, err = CommandSource(cmd, nil)(context.Background())
	if err != nil || out != "http://pilot-relay:tok@127.0.0.1:1" {
		t.Fatalf("nil environment = (%q, %v), want this process's", out, err)
	}
	out, err = CommandSource(cmd, []string{})(context.Background())
	if err != nil || out != "" {
		t.Fatalf("empty environment = (%q, %v), want nothing inherited", out, err)
	}
}

// Failures never carry the command's output (it would hold credentials),
// and a command that outlives the deadline is killed with everything it
// started.
func TestCommandSourceFailures(t *testing.T) {
	env := []string{"PATH=" + os.Getenv("PATH")}
	_, err := CommandSource("echo http://muse:s3cret@proxy.test; echo oops >&2; exit 3", env)(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit status 3") || strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "oops") {
		t.Fatalf("failing command: %v", err)
	}
	_, err = CommandSource("head -c 70000 /dev/zero", env)(context.Background())
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("oversized output: %v", err)
	}
}
