// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pilot-protocol/common/protocol"
)

// withTempHomeFull isolates HOME so config/socket/registry helpers don't
// touch the developer's real ~/.pilot during tests. Returns the path.
func withTempHomeFull(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	// Clear env overrides so the test exercises the loadConfig fallback path.
	t.Setenv("PILOT_HOME", "")
	t.Setenv("PILOT_SOCKET", "")
	t.Setenv("PILOT_REGISTRY", "")
	t.Setenv("PILOT_BEACON", "")
	t.Setenv("PILOT_ADMIN_TOKEN", "")
	// A developer or CI shell exporting PILOT_TRANSPORT=compat or a proxy
	// must not change what daemon start / registry dials plan.
	for _, k := range daemonForwardEnv {
		t.Setenv(k, "")
	}
	return tmp
}

func TestConfigDirAndPaths(t *testing.T) {
	tmp := withTempHomeFull(t)
	if got := configDir(); got != filepath.Join(tmp, ".pilot") {
		t.Errorf("configDir = %s", got)
	}
	if got := configPath(); got != filepath.Join(tmp, ".pilot", defaultConfigFile) {
		t.Errorf("configPath = %s", got)
	}
	if got := pidFilePath(); got != filepath.Join(tmp, ".pilot", defaultPIDFile) {
		t.Errorf("pidFilePath = %s", got)
	}
	if got := logFilePath(); got != filepath.Join(tmp, ".pilot", defaultLogFile) {
		t.Errorf("logFilePath = %s", got)
	}
	if got := featureFlagsPath(); got != filepath.Join(tmp, ".pilot", "feature-flags.json") {
		t.Errorf("featureFlagsPath = %s", got)
	}
}

func TestGetSocketEnvPrecedence(t *testing.T) {
	withTempHomeFull(t)
	t.Setenv("PILOT_SOCKET", "/var/run/custom.sock")
	if got := getSocket(); got != "/var/run/custom.sock" {
		t.Errorf("env override = %s", got)
	}
}

func TestGetSocketDefault(t *testing.T) {
	withTempHomeFull(t)
	if got := getSocket(); got != defaultSocket() {
		t.Errorf("default = %s, want %s", got, defaultSocket())
	}
}

func TestGetSocketFromConfigFile(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cfg := map[string]interface{}{"socket": "/tmp/from-config.sock"}
	body, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultConfigFile), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := getSocket(); got != "/tmp/from-config.sock" {
		t.Errorf("config-file path = %s", got)
	}
}

func TestGetRegistryEnvPrecedence(t *testing.T) {
	withTempHomeFull(t)
	t.Setenv("PILOT_REGISTRY", "registry.example:9000")
	if got := getRegistry(); got != "registry.example:9000" {
		t.Errorf("env override = %s", got)
	}
}

func TestGetRegistryDefault(t *testing.T) {
	withTempHomeFull(t)
	if got := getRegistry(); got != "34.71.57.205:9000" {
		t.Errorf("default = %s", got)
	}
}

func TestGetAdminTokenEnv(t *testing.T) {
	withTempHomeFull(t)
	t.Setenv("PILOT_ADMIN_TOKEN", "secret-tok")
	if got := getAdminToken(); got != "secret-tok" {
		t.Errorf("got %q", got)
	}
}

func TestGetAdminTokenEmpty(t *testing.T) {
	withTempHomeFull(t)
	if got := getAdminToken(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestLoadConfigMissingReturnsEmpty(t *testing.T) {
	withTempHomeFull(t)
	cfg := loadConfig()
	if len(cfg) != 0 {
		t.Errorf("missing config should return empty map, got %v", cfg)
	}
}

func TestLoadConfigParsesJSON(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := []byte(`{"hostname":"my-agent","registry":"r.example:9000"}`)
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultConfigFile), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := loadConfig()
	if cfg["hostname"] != "my-agent" {
		t.Errorf("hostname = %v", cfg["hostname"])
	}
	if cfg["registry"] != "r.example:9000" {
		t.Errorf("registry = %v", cfg["registry"])
	}
}

func TestLoadConfigCorruptReturnsEmpty(t *testing.T) {
	tmp := withTempHomeFull(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pilot"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, ".pilot", defaultConfigFile), []byte("not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg := loadConfig()
	if len(cfg) != 0 {
		t.Errorf("corrupt config should return empty, got %v", cfg)
	}
}

func TestSaveConfigRoundtrip(t *testing.T) {
	withTempHomeFull(t)
	cfg := map[string]interface{}{
		"hostname": "round-trip",
		"socket":   "/tmp/rt.sock",
	}
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	got := loadConfig()
	if got["hostname"] != "round-trip" {
		t.Errorf("hostname = %v", got["hostname"])
	}
	if got["socket"] != "/tmp/rt.sock" {
		t.Errorf("socket = %v", got["socket"])
	}
}

// TestFeatureEnabledEnvOverride verifies the precedence rule documented
// in featureEnabled: env var > feature-flags.json > false.
func TestFeatureEnabledEnvOverride(t *testing.T) {
	withTempHomeFull(t)
	featureFlags = map[string]bool{"ping.reuse_conn": false}
	t.Setenv("PILOT_FLAG_PING_REUSE_CONN", "1")
	if !featureEnabled("ping.reuse_conn") {
		t.Error("env=1 should beat config=false")
	}
	t.Setenv("PILOT_FLAG_PING_REUSE_CONN", "0")
	if featureEnabled("ping.reuse_conn") {
		t.Error("env=0 should be off")
	}
	t.Setenv("PILOT_FLAG_PING_REUSE_CONN", "false")
	if featureEnabled("ping.reuse_conn") {
		t.Error("env='false' should be off")
	}
}

func TestFeatureEnabledFromFlagsFile(t *testing.T) {
	withTempHomeFull(t)
	t.Setenv("PILOT_FLAG_HANDSHAKE_BATCH", "")
	// Bypass env var by clearing it; only the in-memory map governs.
	featureFlags = map[string]bool{"handshake.batch": true}
	if !featureEnabled("handshake.batch") {
		t.Error("config=true should be on")
	}
	featureFlags = map[string]bool{}
	if featureEnabled("handshake.batch") {
		t.Error("absent flag should default to false")
	}
}

func TestLoadFeatureFlagsParsesAllTypes(t *testing.T) {
	tmp := withTempHomeFull(t)
	dir := filepath.Join(tmp, ".pilot")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	body := []byte(`{
		"on_bool": true,
		"off_bool": false,
		"on_int": 1,
		"off_int": 0,
		"on_str": "true",
		"on_one": "1",
		"off_str": "no"
	}`)
	if err := os.WriteFile(filepath.Join(dir, "feature-flags.json"), body, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	loadFeatureFlags()
	want := map[string]bool{
		"on_bool":  true,
		"off_bool": false,
		"on_int":   true,
		"off_int":  false,
		"on_str":   true,
		"on_one":   true,
		"off_str":  false,
	}
	for k, w := range want {
		if got := featureFlags[k]; got != w {
			t.Errorf("featureFlags[%q] = %v, want %v", k, got, w)
		}
	}
}

func TestLoadFeatureFlagsMissingIsSilent(t *testing.T) {
	withTempHomeFull(t)
	loadFeatureFlags()
	if featureFlags == nil {
		t.Error("missing file should initialize empty map, not nil")
	}
	if len(featureFlags) != 0 {
		t.Errorf("missing file should give empty flags, got %v", featureFlags)
	}
}

func TestSkillsHomeRel(t *testing.T) {
	tmp := withTempHomeFull(t)
	in := filepath.Join(tmp, ".claude", "skills", "pilotctl", "SKILL.md")
	got := skillsHomeRel(in)
	if !strings.HasPrefix(got, "~/") {
		t.Errorf("expected ~/-prefixed path, got %q", got)
	}
	if !strings.HasSuffix(got, "SKILL.md") {
		t.Errorf("expected SKILL.md suffix, got %q", got)
	}
	// Out-of-home paths should return verbatim.
	out := skillsHomeRel("/etc/passwd")
	if out != "/etc/passwd" {
		t.Errorf("out-of-home should be unchanged, got %q", out)
	}
}

// TestBuildDaemonArgsDefaults exercises the no-flag baseline of
// buildDaemonArgs — every required daemon flag must be present with a
// sensible default and no admin/email/public bits added.
func TestBuildDaemonArgsDefaults(t *testing.T) {
	withTempHomeFull(t)
	args, sock, _ := buildDaemonArgs([]string{})
	if sock == "" {
		t.Fatal("socket path should be set")
	}
	required := []string{"--registry", "--beacon", "--listen", "--socket", "--identity", "--log-level", "--log-format"}
	got := strings.Join(args, " ")
	for _, k := range required {
		if !strings.Contains(got, k) {
			t.Errorf("expected %s in %v", k, args)
		}
	}
	// Optional bits MUST NOT be present without their flags.
	// --admin-token is no longer passed via argv (PILOT-290).
	for _, k := range []string{"--public", "--webhook", "--networks", "--trust-auto-approve"} {
		if strings.Contains(got, k) {
			t.Errorf("unexpected default flag %s in %v", k, args)
		}
	}
}

func TestBuildDaemonArgsHonorsFlags(t *testing.T) {
	withTempHomeFull(t)
	args, _, adminTok := buildDaemonArgs([]string{
		"--registry", "r.x:9000",
		"--beacon", "b.x:9001",
		"--listen", "1.2.3.4:4000",
		"--socket", "/tmp/t.sock",
		"--email", "test@example.com",
		"--hostname", "my-host",
		"--public",
		"--webhook", "https://hook.example",
		"--admin-token", "tok",
		"--networks", "1,2,3",
		"--trust-auto-approve",
		"--log-level", "debug",
		"--no-encrypt",
	})
	got := strings.Join(args, " ")
	checks := map[string]string{
		"--registry r.x:9000":            "registry flag",
		"--beacon b.x:9001":              "beacon flag",
		"--listen 1.2.3.4:4000":          "listen flag",
		"--socket /tmp/t.sock":           "socket flag",
		"--email test@example.com":       "email flag",
		"--hostname my-host":             "hostname flag",
		"--public":                       "public flag",
		"--webhook https://hook.example": "webhook flag",
		"--networks 1,2,3":               "networks flag",
		"--trust-auto-approve":           "trust auto-approve flag",
		"--log-level debug":              "log-level flag",
		"--encrypt=false":                "no-encrypt → --encrypt=false",
	}
	for fragment, label := range checks {
		if !strings.Contains(got, fragment) {
			t.Errorf("%s: expected %q in %v", label, fragment, args)
		}
	}
	// Admin token is now returned separately, not passed via argv (PILOT-290).
	if adminTok != "tok" {
		t.Errorf("admin-token flag: expected %q, got %q", "tok", adminTok)
	}
}

// TestBuildDaemonArgsOwnerAlias verifies the legacy `-owner` flag is
// honored as an alias for `--email` when no email is given explicitly.
func TestBuildDaemonArgsOwnerAlias(t *testing.T) {
	withTempHomeFull(t)
	args, _, _ := buildDaemonArgs([]string{"-owner", "legacy@example.com"})
	if !strings.Contains(strings.Join(args, " "), "--email legacy@example.com") {
		t.Errorf("expected --email passthrough from -owner: %v", args)
	}
}

// TestBuildDaemonArgsConfigFallback confirms loadConfig values feed
// through buildDaemonArgs when flags are unset.
func TestBuildDaemonArgsConfigFallback(t *testing.T) {
	withTempHomeFull(t)
	cfg := map[string]interface{}{
		"registry": "cfg.example:9000",
		"beacon":   "cfg.example:9001",
		"hostname": "cfg-host",
		"webhook":  "https://cfg-webhook",
		"networks": "9,10",
	}
	if err := saveConfig(cfg); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	args, _, _ := buildDaemonArgs([]string{})
	got := strings.Join(args, " ")
	for _, want := range []string{
		"--registry cfg.example:9000",
		"--beacon cfg.example:9001",
		"--hostname cfg-host",
		"--webhook https://cfg-webhook",
		"--networks 9,10",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in %v", want, args)
		}
	}
}

// TestParseAddrOrHostnameNumeric exercises the two non-daemon branches
// of parseAddrOrHostname: full pilot address and bare node ID.
func TestParseAddrOrHostnameNumeric(t *testing.T) {
	t.Parallel()
	addr, err := parseAddrOrHostname(nil, "0:0000.0000.000B")
	if err != nil {
		t.Fatalf("address parse: %v", err)
	}
	if addr.Node != 0xB {
		t.Errorf("node = %d, want 11", addr.Node)
	}

	addr, err = parseAddrOrHostname(nil, "42")
	if err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if addr.Node != 42 || addr.Network != 0 {
		t.Errorf("got %+v", addr)
	}
}

// TestResolveToNodeIDNumericAndAddress exercises the two non-daemon
// branches of resolveToNodeID.
func TestResolveToNodeIDNumericAndAddress(t *testing.T) {
	t.Parallel()
	if got := resolveToNodeID(nil, "0"); got != 0 {
		t.Errorf("zero numeric = %d", got)
	}
	if got := resolveToNodeID(nil, "12345"); got != 12345 {
		t.Errorf("numeric = %d", got)
	}
	if got := resolveToNodeID(nil, "0:0000.0000.000F"); got != 0xF {
		t.Errorf("address = %d, want 15", got)
	}
}

// TestProtocolAddrRoundtrip confirms our address-printer/parser round-trip,
// proving the test fixtures above (e.g. "0:0000.0000.000B") aren't ad-hoc.
func TestProtocolAddrRoundtrip(t *testing.T) {
	t.Parallel()
	original := protocol.Addr{Network: 0, Node: 0xB}
	parsed, err := protocol.ParseAddr(original.String())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed != original {
		t.Errorf("roundtrip lost data: %v vs %v", parsed, original)
	}
}
