// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// startLogTail is how much of the end of a daemon log `daemon start` reads
// to explain a failed start.
const startLogTail = 256 << 10

// readLogTail returns the last startLogTail bytes of the log at path, split
// into lines ("" when it cannot be read). The first, possibly partial,
// line of a truncated read is dropped.
func readLogTail(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- the daemon log daemon start itself created under the config dir
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil
	}
	off := int64(0)
	if st.Size() > startLogTail {
		off = st.Size() - startLogTail
	}
	b, err := io.ReadAll(io.NewSectionReader(f, off, st.Size()-off))
	if err != nil {
		return nil
	}
	lines := strings.Split(string(b), "\n")
	if off > 0 && len(lines) > 0 {
		lines = lines[1:]
	}
	return lines
}

// logLevelAtLeastWarn reports whether a slog line (text or JSON) is at
// level WARN or ERROR.
func logLevelAtLeastWarn(line string) bool {
	for _, l := range []string{"level=WARN", "level=ERROR", `"level":"WARN"`, `"level":"ERROR"`} {
		if strings.Contains(line, l) {
			return true
		}
	}
	return false
}

// lastProxyErrorFromLog returns the most recent proxy error pilot-daemon
// logged — "proxy CONNECT <target>: 407 Proxy Authentication Required",
// "proxy CONNECT <target>: dial proxy ...", as netproxy words them — or ""
// when there is none. WARN and ERROR lines win over INFO ones (a plugin's
// failed fetch, say). netproxy never puts credentials or proxy-supplied
// text in these errors, so they are safe to show.
func lastProxyErrorFromLog(path string) string {
	lines := readLogTail(path)
	var anyLevel string
	for i := len(lines) - 1; i >= 0; i-- {
		e := extractProxyError(lines[i])
		if e == "" {
			continue
		}
		if logLevelAtLeastWarn(lines[i]) {
			return e
		}
		if anyLevel == "" {
			anyLevel = e
		}
	}
	return anyLevel
}

// extractProxyError cuts the netproxy error out of one log line: from
// "proxy CONNECT " to the end of the quoted slog value it sits in, an
// unbalanced ")" (an error quoted inside a message) or a "; " (the hint
// pilot-daemon appends). Escaped characters are unescaped.
func extractProxyError(line string) string {
	i := strings.Index(line, "proxy CONNECT ")
	if i < 0 {
		return ""
	}
	rest := line[i:]
	var b strings.Builder
	depth := 0
scan:
	for j := 0; j < len(rest); j++ {
		c := rest[j]
		switch {
		case c == '\\' && j+1 < len(rest):
			j++
			b.WriteByte(rest[j])
			continue
		case c == '"':
			break scan
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				break scan
			}
			depth--
		case c == ';' && j+1 < len(rest) && rest[j+1] == ' ':
			break scan
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// lastErrorFromLog returns the message of the last ERROR line (pilot-daemon
// logs its fatal startup error there), else the last non-empty line, cut to
// a readable length. "" for an empty or unreadable log.
func lastErrorFromLog(path string) string {
	lines := readLogTail(path)
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if last == "" {
			last = line
		}
		if strings.Contains(line, "level=ERROR") || strings.Contains(line, `"level":"ERROR"`) {
			if msg := slogMessage(line); msg != "" {
				return msg
			}
			return clip(line)
		}
	}
	return clip(last)
}

// slogMessage returns the msg of a slog text or JSON line, "" if none.
func slogMessage(line string) string {
	if strings.HasPrefix(line, "{") {
		var rec map[string]any
		if json.Unmarshal([]byte(line), &rec) == nil {
			if m, ok := rec["msg"].(string); ok {
				return clip(m)
			}
		}
		return ""
	}
	i := strings.Index(line, "msg=")
	if i < 0 {
		return ""
	}
	rest := line[i+len("msg="):]
	if !strings.HasPrefix(rest, `"`) {
		if j := strings.IndexByte(rest, ' '); j >= 0 {
			rest = rest[:j]
		}
		return clip(rest)
	}
	var b strings.Builder
	for j := 1; j < len(rest); j++ {
		c := rest[j]
		if c == '\\' && j+1 < len(rest) {
			j++
			b.WriteByte(rest[j])
			continue
		}
		if c == '"' {
			break
		}
		b.WriteByte(c)
	}
	return clip(b.String())
}

// clip bounds a log excerpt quoted in an error message.
func clip(s string) string {
	const max = 600
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// daemonExitStatus renders how the daemon process ended.
func daemonExitStatus(err error) string {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ProcessState.String()
	}
	if err != nil {
		return err.Error()
	}
	return "exit status 0"
}

// rotateHint is the second half of the credential hints: how to hand the
// daemon rotating credentials.
const rotateHint = "if the proxy rotates its credentials, give the daemon a command that prints the current proxy URL: --proxy-cmd, or pilotctl config --set proxy_cmd=\"bash -c 'printf %s \\\"\\$https_proxy\\\"'\""

// refreshingHint replaces rotateHint when the daemon already re-reads its
// credentials with a proxy command (src names it, see proxyCmdSource):
// telling the user to set one would send them after the wrong fix. The
// command itself printed credentials the proxy refused.
func refreshingHint(src string) string {
	return "the daemon already re-reads them with " + src + " (every 60s and on each rejection), so that command printed credentials the proxy refused: run it from a fresh shell and check that it prints a proxy URL with the current credentials"
}

// proxyErrorHint says what to do about a proxy error the daemon logged.
// refreshSrc is the proxy command the daemon re-reads its credentials
// with (proxyCmdSource), "" when it has none.
func proxyErrorHint(proxyErr, refreshSrc string) string {
	credentials := rotateHint
	if refreshSrc != "" {
		credentials = refreshingHint(refreshSrc)
	}
	switch {
	case strings.Contains(proxyErr, " 407 "):
		return "the proxy rejected the credentials (407): check HTTPS_PROXY (or --proxy / PILOT_PROXY); " + credentials
	case strings.Contains(proxyErr, "read CONNECT response: ") && strings.Contains(proxyErr, "(response text withheld)"):
		// netproxy's report of a CONNECT answer it could not parse — how
		// Meta Muse's proxy rejects wrong or expired credentials.
		return "the proxy's answer to CONNECT could not be parsed (\"malformed HTTP status code\"), which is how some egress proxies (Meta Muse's) reject wrong or expired credentials: check the credentials in HTTPS_PROXY (or --proxy / PILOT_PROXY); " + credentials
	case strings.Contains(proxyErr, ": dial proxy "):
		return "the proxy could not be reached: check HTTPS_PROXY (or --proxy / PILOT_PROXY)"
	default:
		return "the proxy refused the connection: it must allow CONNECT to " + compatRegistryAddr + " and beacon.pilotprotocol.network:443"
	}
}

// reportDaemonStartFailure ends a `daemon start` whose daemon never became
// ready: it exited (exitStatus != "") or the wait ran out. It shows what
// the daemon's log says went wrong — above all its last proxy error, which
// behind an egress proxy is nearly always the cause — instead of only "did
// not become ready". refreshSrc is as for proxyErrorHint.
func reportDaemonStartFailure(pid int, logPath, exitStatus string, waited time.Duration, refreshSrc string) {
	proxyErr := lastProxyErrorFromLog(logPath)
	hint := fmt.Sprintf("check logs: tail -f %s", logPath)
	if proxyErr != "" {
		hint = proxyErrorHint(proxyErr, refreshSrc) + "; full log: " + logPath
	}
	if exitStatus != "" {
		msg := fmt.Sprintf("daemon (pid %d) exited during startup (%s)", pid, exitStatus)
		if last := lastErrorFromLog(logPath); last != "" {
			msg += ": " + last
		}
		if proxyErr != "" && !strings.Contains(msg, proxyErr) {
			msg += "; last proxy error: " + proxyErr
		}
		code := "internal"
		if proxyErr != "" {
			code = "connection_failed"
		}
		fatalHint(code, hint, "%s", msg)
	}
	msg := fmt.Sprintf("daemon started (pid %d) but did not become ready within %s", pid, waited)
	if proxyErr != "" {
		msg += "; last proxy error: " + proxyErr
	}
	fatalHint("timeout", hint, "%s", msg)
}

// proxyCmdSource says where the running daemon's proxy refresh command
// comes from, "" when it uses none: pilot-daemon reports one on its
// "outbound network" line ("credentials refreshed by command"), and only
// then does this name the source — the built-in sandbox command, else
// --proxy-cmd, $PILOT_PROXY_CMD or config.json proxy_cmd. A configured
// command is not echoed: it may embed secrets.
func proxyCmdSource(plan daemonLaunchPlan, flags map[string]string, logPath string, sandbox bool) string {
	used := false
	for _, line := range readLogTail(logPath) {
		if strings.Contains(line, "outbound network") && strings.Contains(line, "credentials refreshed by command") {
			used = true
		}
	}
	if !used {
		return ""
	}
	switch {
	case sandbox:
		return sandboxProxyCmd
	case plan.ProxyCmd != "":
		return "--proxy-cmd"
	case strings.TrimSpace(os.Getenv(proxyconf.EnvRefreshCommand)) != "":
		return "$" + proxyconf.EnvRefreshCommand
	default:
		return "config.json proxy_cmd"
	}
}
