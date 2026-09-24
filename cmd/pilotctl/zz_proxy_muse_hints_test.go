// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/netproxy"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
)

// web4-470-muse-rejection-diagnostics-misdirect: Meta Muse's proxy answers
// wrong or expired credentials with a status line net/http cannot parse,
// which netproxy reports as "read CONNECT response: malformed HTTP status
// code (response text withheld)". `daemon start` must call that a
// credential problem and point at proxy_cmd, not tell the operator that
// the proxy must allow CONNECT to the registry.
func TestCLIDaemonStartGarbledProxyAnswerHint(t *testing.T) {
	const garbled = "proxy CONNECT registry.pilotprotocol.network:443 via http://***@127.0.0.1:3151: read CONNECT response: malformed HTTP status code (response text withheld)"
	hint := proxyErrorHint(garbled, "")
	if !strings.Contains(hint, "could not be parsed") || !strings.Contains(hint, "proxy_cmd") || strings.Contains(hint, "must allow CONNECT") {
		t.Errorf("proxyErrorHint(garbled) = %q", hint)
	}
	if got := extractProxyError(`time=x level=WARN msg="registry dial failed, retrying" attempt=1 max=10 backoff=500ms error="dial registry TLS pinned: ` + garbled + `"`); got != garbled {
		t.Errorf("extractProxyError = %q, want %q", got, garbled)
	}
	for _, other := range []string{
		"proxy CONNECT registry.pilotprotocol.network:443: 403 Forbidden",
		"proxy CONNECT registry.pilotprotocol.network:443 via http://***@p:1: read CONNECT response: EOF",
	} {
		if h := proxyErrorHint(other, ""); strings.Contains(h, "could not be parsed") {
			t.Errorf("proxyErrorHint(%q) = %q, not a garbled answer", other, h)
		}
	}

	home := t.TempDir()
	bin := writeStartFailDaemon(t, []string{
		`time=2026-09-24T06:12:45Z level=WARN msg="transport auto-selected" transport=compat reason="no UDP answer from beacon b, and the proxy http://***@127.0.0.1:3151 refused the compat beacon check (proxy CONNECT beacon.pilotprotocol.network:443 via http://***@127.0.0.1:3151: read CONNECT response: malformed HTTP status code (response text withheld)); staying on compat"`,
		`time=2026-09-24T06:12:46Z level=WARN msg="registry dial failed, retrying" attempt=1 max=10 backoff=500ms error="dial registry TLS pinned: ` + garbled + `"`,
		`time=2026-09-24T06:13:30Z level=ERROR msg="daemon start: registry dial (after 10 attempts): dial registry TLS pinned: ` + garbled + `; the proxy's answer to CONNECT could not be parsed"`,
	}, 1)
	env := cliEnvCleared(map[string]string{
		"PILOT_DAEMON_BIN": bin,
		"PILOT_SOCKET":     filepath.Join(t.TempDir(), "pilot.sock"),
		"PILOT_HOME":       home,
	})
	_, stderr, code := runCLI(t, []string{"--json", "daemon", "start", "--wait", "20s"}, env)
	if code == 0 {
		t.Fatal("daemon start succeeded against a daemon that exited")
	}
	var res struct{ Code, Message, Hint string }
	if err := json.Unmarshal([]byte(strings.TrimSpace(stderr)), &res); err != nil {
		t.Fatalf("stderr is not one JSON error: %v\n%s", err, stderr)
	}
	if !strings.Contains(res.Message, garbled) {
		t.Errorf("message lacks the proxy error: %q", res.Message)
	}
	if !strings.Contains(res.Hint, "could not be parsed") || !strings.Contains(res.Hint, "proxy_cmd") || strings.Contains(res.Hint, "must allow CONNECT") {
		t.Errorf("hint = %q, want the credential hint", res.Hint)
	}
}

// web4-470-sandbox-cmd-variable-precedence: the refresh command pilotctl
// hands the daemon in a sandbox (and install.sh saves) must never trade a
// proxy URL with credentials for one without: whichever of $https_proxy
// and $HTTPS_PROXY carries credentials wins, $https_proxy when both do
// (Meta Muse's guidance reads that one from a fresh shell), and the
// daemon's own order when neither does. Run for real through bash, the
// way the daemon's resolver runs it.
func TestSandboxProxyCmdKeepsTheCredentialedProxy(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("no bash")
	}
	const (
		upper     = "http://corp:s3cret@egress.test:3128"
		upperBare = "http://egress.test:3128"
		lower     = "http://muse:rotated@muse-proxy.test:3128"
		lowerBare = "http://other.test:3128"
	)
	for _, tc := range []struct {
		name, upper, lower, want string
	}{
		{"HTTPS_PROXY has credentials, https_proxy names the proxy without", upper, upperBare, upper},
		{"HTTPS_PROXY has credentials, https_proxy another proxy without", upper, lowerBare, upper},
		{"HTTPS_PROXY only", upper, "", upper},
		{"https_proxy has credentials, HTTPS_PROXY without", upperBare, lower, lower},
		{"https_proxy only (Meta Muse)", "", lower, lower},
		{"both with credentials: the fresh shell's https_proxy", upper, lower, lower},
		{"neither with credentials: the daemon's order", upperBare, lowerBare, upperBare},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("sh", "-c", sandboxProxyCmd)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HTTPS_PROXY=" + tc.upper, "https_proxy=" + tc.lower}
			out, err := cmd.Output()
			if err != nil || string(out) != tc.want {
				t.Fatalf("sandboxProxyCmd printed (%q, %v), want %q", out, err, tc.want)
			}
		})
	}

	// What the daemon's resolver makes of it, in the reviewer's case.
	withTransportEnvCleared(t)
	t.Setenv("HTTPS_PROXY", upper)
	t.Setenv("https_proxy", upperBare)
	r, err := proxyconf.Resolve("auto", netproxy.WithRefreshCommand(sandboxProxyCmd))
	if err != nil {
		t.Fatal(err)
	}
	if got := proxyconf.ProxyFor(r, "registry.pilotprotocol.network:443"); got != "http://***@egress.test:3128" {
		t.Fatalf("daemon proxy with the sandbox command = %q, want the credentialed http://***@egress.test:3128", got)
	}
}

// When the daemon already re-reads its credentials with a proxy command,
// a rejected credential means that command printed stale or wrong ones:
// the hint must say so and not tell the operator to set one (E2E scenario
// 3: a 407 with config.json proxy_cmd in place was answered with "give the
// daemon a command that prints the current proxy URL").
func TestProxyErrorHintWithProxyCommandInUse(t *testing.T) {
	for _, proxyErr := range []string{
		"proxy CONNECT registry.pilotprotocol.network:443: 407 Proxy Authentication Required",
		"proxy CONNECT registry.pilotprotocol.network:443 via http://***@127.0.0.1:3151: read CONNECT response: malformed HTTP status code (response text withheld)",
	} {
		without := proxyErrorHint(proxyErr, "")
		if !strings.Contains(without, rotateHint) {
			t.Errorf("no proxy command: hint %q lacks the proxy_cmd advice", without)
		}
		with := proxyErrorHint(proxyErr, "config.json proxy_cmd")
		if strings.Contains(with, rotateHint) || strings.Contains(with, "give the daemon a command") {
			t.Errorf("proxy command in use: hint %q still says to set one", with)
		}
		if !strings.Contains(with, "already re-reads them with config.json proxy_cmd") || !strings.Contains(with, "fresh shell") {
			t.Errorf("proxy command in use: hint %q does not name it or say how to check it", with)
		}
	}
	if h := proxyErrorHint("proxy CONNECT registry.pilotprotocol.network:443: 403 Forbidden", "config.json proxy_cmd"); strings.Contains(h, "re-reads") {
		t.Errorf("a 403 is not a credential problem: %q", h)
	}
}

// install.sh saves SANDBOX_PROXY_CMD as config.json proxy_cmd on sandbox
// hosts, and a saved proxy_cmd turns off the one `daemon start` would hand
// the daemon (sandboxProxyCmdFor). The two must be the same command, or a
// node the installer set up runs an older one (web4-470 review: the
// installer kept `printf %s "${https_proxy:-$HTTPS_PROXY}"`, which drops
// credentials that only HTTPS_PROXY carries).
func TestInstallerSavesTheSandboxProxyCmd(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var assign string
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(line, "SANDBOX_PROXY_CMD=") {
			if assign != "" {
				t.Fatal("install.sh assigns SANDBOX_PROXY_CMD more than once")
			}
			assign = line
		}
	}
	if assign == "" {
		t.Fatal("install.sh has no SANDBOX_PROXY_CMD= line")
	}
	out, err := exec.Command(sh, "-c", assign+`; printf %s "$SANDBOX_PROXY_CMD"`).Output()
	if err != nil {
		t.Fatalf("evaluating %q: %v", assign, err)
	}
	if string(out) != sandboxProxyCmd {
		t.Errorf("install.sh SANDBOX_PROXY_CMD = %q\npilotctl sandboxProxyCmd  = %q", out, sandboxProxyCmd)
	}
}
