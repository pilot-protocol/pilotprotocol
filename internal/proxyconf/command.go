// SPDX-License-Identifier: AGPL-3.0-or-later

package proxyconf

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// maxCommandOutput caps what a refresh command may print (as netproxy's).
const maxCommandOutput = 64 << 10

// CommandSource returns a refresh source for netproxy.WithRefreshFunc that
// runs command the way netproxy.WithRefreshCommand does — "sh -c", stdin
// and stderr discarded (stderr could echo credentials, e.g. under set -x),
// at most 64 KiB of output, and on Unix in a process group of its own that
// is killed as a whole when the refresh deadline passes — except that it
// runs in env instead of this process's current environment.
//
// The daemon needs that because it points its own HTTPS_PROXY at its app
// Relay (so the apps it starts inherit the Relay, see Relay) once it is
// running. A refresh command such as bash -c 'printf %s "$https_proxy"'
// must still see what the daemon was launched with — in Meta Muse a fresh
// bash then reads the rotated credentials — and never the Relay, which
// would make the daemon's proxy its own Relay. A nil env runs the command
// in this process's environment, as netproxy does.
//
// The output is never part of an error.
func CommandSource(command string, env []string) func(ctx context.Context) (string, error) {
	if env != nil {
		env = append(make([]string, 0, len(env)), env...)
	}
	return func(ctx context.Context) (string, error) {
		// #nosec G204 -- running the operator's proxy command (-proxy-cmd,
		// $PILOT_PROXY_CMD, config.json proxy_cmd) with sh -c is this function's
		// purpose; it is set by whoever starts the daemon, never by a peer.
		cmd := exec.CommandContext(ctx, "sh", "-c", command)
		if env != nil {
			cmd.Env = env
		}
		var out cappedOutput
		cmd.Stdout = &out
		cmd.WaitDelay = time.Second // a child left holding stdout cannot hang Wait
		ownProcessGroup(cmd)
		err := cmd.Run()
		switch {
		case ctx.Err() != nil:
			return "", errors.New("refresh command timed out")
		case err != nil:
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return "", fmt.Errorf("refresh command failed: %s", ee.ProcessState)
			}
			if errors.Is(err, exec.ErrWaitDelay) {
				// sh has exited, but a process it started held stdout
				// open until now: end the group.
				_ = killProcessGroup(cmd)
				return "", errors.New("refresh command left a process holding its output open")
			}
			return "", fmt.Errorf("refresh command failed to run: %v", err)
		case out.overflow:
			return "", fmt.Errorf("refresh command printed more than %d bytes", maxCommandOutput)
		}
		return string(out.buf), nil
	}
}

// cappedOutput keeps the first maxCommandOutput bytes written to it and
// notes whether there were more.
type cappedOutput struct {
	buf      []byte
	overflow bool
}

func (b *cappedOutput) Write(p []byte) (int, error) {
	if room := maxCommandOutput - len(b.buf); len(p) > room {
		b.buf = append(b.buf, p[:room]...)
		b.overflow = true
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}
