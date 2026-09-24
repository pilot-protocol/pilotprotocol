package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIssue477RejectInvalidConfig(t *testing.T) {
	for _, kv := range []string{"transport=bogus", "proxy=notaurl", "encrypt=maybe", "encrypt=", "socket=", "registry=notanaddr", "registry=host:99999", "beacon=:9001", "nonsense_key=1", "log_max_size=-1"} {
		t.Run(kv, func(t *testing.T) {
			home := t.TempDir()
			out, errOut, code := runCLI(t, []string{"--json", "config", "--set", kv}, map[string]string{"HOME": home, "PILOT_HOME": home})
			if code == 0 || !strings.Contains(out+errOut, "invalid_argument") {
				t.Fatalf("exit %d: %s %s", code, out, errOut)
			}
			if _, err := os.Stat(filepath.Join(home, ".pilot", "config.json")); !os.IsNotExist(err) {
				t.Fatalf("invalid setting wrote config: %v", err)
			}
		})
	}
}

func TestIssue477EncryptBooleanAndLaunch(t *testing.T) {
	withTempHomeFull(t)
	for _, val := range []string{"false", "true"} {
		captureStdout(t, func() { cmdConfig([]string{"--set", "encrypt=" + val}) })
		cfg := loadConfig()
		if got, ok := cfg["encrypt"].(bool); !ok || got != (val == "true") {
			t.Fatalf("encrypt not a JSON boolean: %#v", cfg["encrypt"])
		}
		args, _, _ := buildDaemonArgs(nil)
		if got := strings.Contains(strings.Join(args, " "), "--encrypt=false"); got != (val == "false") {
			t.Fatalf("encrypt %s: %v", val, args)
		}
	}
	args, _, _ := buildDaemonArgs([]string{"--no-encrypt"})
	if !strings.Contains(strings.Join(args, " "), "--encrypt=false") {
		t.Fatal(args)
	}
}

func TestIssue481HelpAndVersion(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"-h"}, {"--version"}, {"version"}} {
		out, stderr, code := runCLI(t, args, nil)
		if code != 0 || out == "" || strings.Contains(stderr, "unknown command") {
			t.Fatalf("%v: exit=%d out=%q err=%q", args, code, out, stderr)
		}
	}
}

func TestIssue481EmptyAppList(t *testing.T) {
	for _, exists := range []bool{true, false} {
		root := filepath.Join(t.TempDir(), "apps")
		if exists {
			if err := os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
		}
		for _, jsonMode := range []bool{true, false} {
			args := []string{"appstore", "list"}
			if jsonMode {
				args = append([]string{"--json"}, args...)
			}
			out, stderr, code := runCLI(t, args, map[string]string{"PILOT_APPSTORE_ROOT": root})
			if code != 0 || stderr != "" {
				t.Fatalf("exit=%d out=%s err=%s", code, out, stderr)
			}
			if jsonMode && strings.TrimSpace(out) != "[]" {
				t.Fatalf("want [], got %s", out)
			}
		}
	}
}

func TestIssue480RejectUnknownAndInvalidFlags(t *testing.T) {
	for _, flags := range [][]string{{"--bogusflag"}, {"--timeout", "nonsense"}, {"--timeout", "0s"}, {"--wait", "-1s"}} {
		args := append([]string{"--json", "send-message", "0:0000.0000.002A", "--data", "hi"}, flags...)
		out, stderr, code := runCLI(t, args, map[string]string{"PILOT_SOCKET": "/tmp/nonexistent-issue480.sock"})
		if code == 0 || !strings.Contains(out+stderr, "invalid_argument") {
			t.Fatalf("%v: %d %s %s", flags, code, out, stderr)
		}
	}
}

func TestIssue480TotalTimeout(t *testing.T) {
	for _, phase := range []string{"resolve", "handshake", "dial", "ack", "reply"} {
		t.Run(phase, func(t *testing.T) {
			d := newStreamDaemon(t)
			target := "0:0000.0000.002A"
			switch phase {
			case "resolve":
				target = "dead-peer"
				d.on(tdCmdResolveHostname, func([]byte) [][]byte { return nil })
			case "handshake":
				d.on(tdCmdHandshake, func([]byte) [][]byte { return nil })
			case "dial":
				d.on(tdCmdDial, func([]byte) [][]byte { return nil })
			case "ack":
				d.on(tdCmdSend, func([]byte) [][]byte { return nil })
			}
			start := time.Now()
			out, stderr, code := runCLI(t, []string{"--json", "send-message", target, "--data", "hi", "--wait", "5s", "--timeout", "200ms"}, map[string]string{"PILOT_SOCKET": d.path})
			elapsed := time.Since(start)
			var result map[string]interface{}
			if err := json.Unmarshal([]byte(stderr), &result); err != nil {
				t.Fatalf("invalid JSON %q: %v; stderr=%s", out, err, stderr)
			}
			if code == 0 || !strings.Contains(stderr, "exceeded total timeout") || elapsed > 2*time.Second {
				t.Fatalf("exit=%d elapsed=%v out=%s stderr=%s", code, elapsed, out, stderr)
			}
		})
	}
}
