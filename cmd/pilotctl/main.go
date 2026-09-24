// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pilot-protocol/common/consent"
	"github.com/pilot-protocol/common/decision"
	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/common/protocol"
	registry "github.com/pilot-protocol/common/registry/client"
	"github.com/pilot-protocol/dataexchange"
	"github.com/pilot-protocol/eventstream"
	"github.com/pilot-protocol/pilotprotocol/internal/proxyconf"
	"github.com/pilot-protocol/policy/policylang"
	"github.com/pilot-protocol/trustedagents"
)

var version = "dev"

// Global flags
var jsonOutput bool
var verbose bool

// Config paths
const (
	defaultConfigDir  = ".pilot"
	defaultConfigFile = "config.json"
	defaultPIDFile    = "pilot.pid"
	defaultLogFile    = "pilot.log"
)

func defaultSocket() string {
	return driver.DefaultSocketPath()
}

func configDir() string {
	// PILOT_HOME, when set, overrides the location of the .pilot config
	// directory — matching the override the other components honor and
	// letting callers (tests, sandboxes, multi-identity setups) relocate
	// state without rewriting $HOME.
	if h := os.Getenv("PILOT_HOME"); h != "" {
		return filepath.Join(h, defaultConfigDir)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, defaultConfigDir)
}

func configPath() string       { return configDir() + "/" + defaultConfigFile }
func pidFilePath() string      { return configDir() + "/" + defaultPIDFile }
func logFilePath() string      { return configDir() + "/" + defaultLogFile }
func featureFlagsPath() string { return configDir() + "/feature-flags.json" }

// featureFlags is the in-process cache of ~/.pilot/feature-flags.json.
// Loaded once at startup via loadFeatureFlags(); never mutated after that.
var featureFlags map[string]bool

// loadFeatureFlags reads ~/.pilot/feature-flags.json if it exists. Missing
// file is not an error. Precedence (highest→lowest): CLI flag → env var →
// feature-flags.json → code default (false).
func loadFeatureFlags() {
	featureFlags = map[string]bool{}
	b, err := os.ReadFile(featureFlagsPath())
	if err != nil {
		return // file absent or unreadable — silent, defaults apply
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return
	}
	for k, v := range raw {
		switch val := v.(type) {
		case bool:
			featureFlags[k] = val
		case float64:
			featureFlags[k] = val != 0
		case string:
			featureFlags[k] = val == "true" || val == "1"
		}
	}
}

// featureEnabled returns true when the named flag is on. Checks (in order):
//  1. Non-empty env var named PILOT_FLAG_<UPPER_SNAKE> (e.g. PILOT_FLAG_PING_REUSE_CONN)
//  2. ~/.pilot/feature-flags.json key
//
// CLI flags take precedence at call sites before this function is consulted.
func featureEnabled(name string) bool {
	envKey := "PILOT_FLAG_" + strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(name))
	if v := os.Getenv(envKey); v != "" {
		return v != "0" && v != "false"
	}
	return featureFlags[name]
}

// --- Output helpers ---

func output(data interface{}) {
	if jsonOutput {
		envelope := map[string]interface{}{"status": "ok", "data": data}
		if importantUpdate != "" {
			envelope["important_update"] = importantUpdate
		}
		b, _ := json.Marshal(envelope)
		fmt.Println(string(b))
	} else {
		switch v := data.(type) {
		case map[string]interface{}:
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
		default:
			fmt.Println(v)
		}
	}
}

func outputOK(fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	output(fields)
}

func fatalCode(code string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonOutput {
		env := map[string]string{
			"status":  "error",
			"code":    code,
			"message": msg,
			"error":   msg,
		}
		if importantUpdate != "" {
			env["important_update"] = importantUpdate
		}
		b, _ := json.Marshal(env)
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	exitAfterFatal(code, msg)
}

// classifyDaemonError inspects an error string from the daemon and, when it
// recognizes a transient or operator-friendly failure mode, returns a more
// actionable hint to the user. Returns "" if no specific guidance applies —
// callers fall back to whatever default hint they had.
//
// Currently recognized patterns:
//   - "pending queue full ... key exchange pending" — the encrypted tunnel
//     to the peer is mid-handshake. The packet was queued; waiting a moment
//     and retrying typically succeeds.
//   - "dial timeout"/"dial: daemon: dial timeout" — the SYN went out but no
//     SYN-ACK came back. Often means the relay path is mid-convergence
//     after a beacon roll, or the peer is offline.
func classifyDaemonError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "pending queue full") || strings.Contains(s, "key exchange pending"):
		return "tunnel handshake in progress — the packet was queued. Wait a few seconds and retry; the SYN will go out as soon as the encrypted session keys are derived."
	case strings.Contains(s, "dial timeout"):
		return "no reply from peer. Check reachability with `pilotctl ping <peer>`; if relay is fresh after a beacon roll it can take ~30s for endpoints to converge."
	}
	return ""
}

// fatalHint is like fatalCode but adds an actionable hint telling the user what to do next.
func fatalHint(code, hint, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonOutput {
		env := map[string]any{
			"status":  "error",
			"code":    code,
			"message": msg,
			"error":   msg,
			"hint":    hint,
		}
		if importantUpdate != "" {
			env["important_update"] = importantUpdate
		}
		// Structured recovery steps for a failed `appstore call` (nil for every
		// other exit). Additive: existing keys keep their shape and value.
		if ns := nextStepsEnvelope(exitNextSteps); ns != nil {
			env["next_steps"] = ns
		}
		b, _ := json.Marshal(env)
		fmt.Fprintln(os.Stderr, string(b))
	} else {
		fmt.Fprintf(os.Stderr, "error: %s\nhint:  %s\n", msg, hint)
		// Printed last, after the error it resolves — the reason this is a
		// package var drained here rather than a print at the call site: only
		// fatalHint knows where the output ends, because only it exits.
		printNextSteps(exitNextSteps)
	}
	exitAfterFatal(code, msg)
}

func fatal(format string, args ...interface{}) {
	fatalCode("internal", format, args...)
}

// parseNodeID parses a string as a uint32 node ID or exits with an error (M18 fix).
func parseNodeID(s string) uint32 {
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node_id %q: %v", s, err)
	}
	return uint32(v)
}

// parseUint16 parses a string as a uint16 or exits with an error (M18 fix).
func parseUint16(s, label string) uint16 {
	v, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid %s %q: %v", label, s, err)
	}
	return uint16(v)
}

func formatBytes(b uint64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.1f GB", float64(b)/1024/1024/1024)
	case b >= 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/1024/1024)
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// fmtCount renders a large count compactly: 1234 → "1.2K", 5400000 → "5.4M".
func fmtCount(n uint64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", float64(n)/1e9)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 10_000:
		return fmt.Sprintf("%.1fK", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// --- Env / config helpers ---

func getSocket() string {
	if v := os.Getenv("PILOT_SOCKET"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["socket"].(string); ok && s != "" {
		return s
	}
	return defaultSocket()
}

func getRegistry() string {
	if v := os.Getenv("PILOT_REGISTRY"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["registry"].(string); ok && s != "" {
		return s
	}
	return productionRegistryAddr
}

// getBeacon mirrors getRegistry for the beacon address: env override,
// then config, then the production beacon — the same default compiled
// into pilot-daemon itself (cmd/daemon). Keeping the two in lockstep
// matters because pilotctl always passes an explicit --beacon to the
// daemon, so a divergent fallback here would silently override the
// daemon's own correct default.
func getBeacon() string {
	if v := os.Getenv("PILOT_BEACON"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["beacon"].(string); ok && s != "" {
		return s
	}
	return productionBeaconAddr
}

func loadConfig() map[string]interface{} {
	f, err := os.Open(configPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			// A missing config is normal (defaults apply); anything else —
			// permission denied, an I/O error — is a real problem the user
			// should hear about rather than silently get defaults for.
			slog.Warn("could not read config; using defaults",
				"path", configPath(), "error", err)
		}
		return map[string]interface{}{}
	}
	defer f.Close()
	var cfg map[string]interface{}
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		// A corrupt config silently falling back to defaults can mask a
		// truncated/half-written file and make admin_token/registry
		// settings vanish without explanation. Surface it.
		slog.Warn("config file is corrupt; using defaults",
			"path", configPath(), "error", err)
		return map[string]interface{}{}
	}
	return cfg
}

func getAdminToken() string {
	if v := os.Getenv("PILOT_ADMIN_TOKEN"); v != "" {
		return v
	}
	cfg := loadConfig()
	if s, ok := cfg["admin_token"].(string); ok && s != "" {
		return s
	}
	return ""
}

func requireAdminToken() string {
	token := getAdminToken()
	if token == "" {
		fatalHint("auth_required",
			"set PILOT_ADMIN_TOKEN env var or admin_token in ~/.pilot/config.json",
			"admin token required for this operation")
	}
	return token
}

func saveConfig(cfg map[string]interface{}) error {
	dir := configDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	// config.json holds secrets (admin_token, webhook, registry, etc.), so
	// keep it 0600 and write it atomically: serialize to a temp file in the
	// same directory, fsync, then rename over the target. A crash mid-write
	// can never leave a truncated or world-readable config behind, and we do
	// not inherit loose permissions from any pre-existing file.
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, defaultConfigFile+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close() // #nosec G104 -- best-effort cleanup on the error path; the Chmod error is the one returned
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() // #nosec G104 -- best-effort cleanup on the error path; the Write error is the one returned
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close() // #nosec G104 -- best-effort cleanup on the error path; the Sync error is the one returned
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, configPath()); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// --- Arg parsing helpers ---

// parseFlags extracts --key=value and --flag from args, returns remaining positional args.
func parseFlags(args []string) (map[string]string, []string) {
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		var key string
		if strings.HasPrefix(a, "--") {
			key = a[2:]
		} else if strings.HasPrefix(a, "-") && len(a) > 1 && !isNumericFlag(a[1:]) {
			// Accept single-dash long flags (e.g. -email) so users aren't
			// silently bitten after reading the daemon binary's own -flag help.
			key = a[1:]
		}
		if key != "" {
			if idx := strings.Index(key, "="); idx >= 0 {
				flags[key[:idx]] = key[idx+1:]
			} else if i+1 < len(args) && isFlagValue(args[i+1]) {
				flags[key] = args[i+1]
				i++
			} else {
				flags[key] = "true"
			}
		} else {
			pos = append(pos, a)
		}
	}
	return flags, pos
}

// isFlagValue reports whether tok, appearing immediately after a flag key,
// should be consumed as that flag's value rather than parsed as the next
// flag. Values that begin with "-" used to be silently dropped (forcing
// users onto --key=value); this lets "--key -value" work for the common
// cases without making "--flag --next" ambiguous:
//   - anything not starting with "-" is a value
//   - a bare "-" (stdin sentinel) is a value
//   - "-1", "-3.14" and other negative numbers are values
//   - "-=foo" or "-3x" (a "-" followed by a digit) is a value, since those
//     are not valid flag names
//
// A token shaped like a flag ("--name" or "-name") is treated as the next
// flag, not a value — use --key=value to pass such a literal.
func isFlagValue(tok string) bool {
	if !strings.HasPrefix(tok, "-") {
		return true
	}
	if tok == "-" {
		return true
	}
	// "--something" is always a flag.
	if strings.HasPrefix(tok, "--") {
		return false
	}
	// Single dash: a value if the remainder is numeric ("-1", "-3.14") or
	// begins with a digit ("-3x"); otherwise it looks like a "-name" flag.
	rest := tok[1:]
	if isNumericFlag(rest) {
		return true
	}
	return rest[0] >= '0' && rest[0] <= '9'
}

// isNumericFlag reports whether s looks like a bare number (e.g. "1", "3.14"),
// so that negative number positional args like "-1" are not treated as flags.
func isNumericFlag(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func flagDuration(flags map[string]string, key string, def time.Duration) time.Duration {
	v, ok := flags[key]
	if !ok {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		// Try as seconds
		secs, err2 := strconv.ParseFloat(v, 64)
		if err2 != nil {
			fatalCode("invalid_argument", "invalid duration for --%s: %v", key, err)
		}
		return time.Duration(secs * float64(time.Second))
	}
	return d
}

func flagInt(flags map[string]string, key string, def int) int {
	v, ok := flags[key]
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		fatalCode("invalid_argument", "invalid integer for --%s: %v", key, err)
	}
	return n
}

func flagString(flags map[string]string, key string, def string) string {
	if v, ok := flags[key]; ok {
		return v
	}
	return def
}

func flagBool(flags map[string]string, key string) bool {
	v, ok := flags[key]
	return ok && (v == "true" || v == "1" || v == "")
}

// flagNetID returns --net as a uint16 network ID, refusing to silently
// truncate values that don't fit. Without the bounds check, `--net 70000`
// becomes uint16(70000 & 0xFFFF)=4464 and the command operates on the
// wrong network — caught by CodeQL "Incorrect conversion between integer
// types" (alerts #21, #23, #24, #25, #32).
func flagNetID(flags map[string]string) uint16 {
	n := flagInt(flags, "net", 0)
	if n < 0 || n > 0xFFFF {
		fatalCode("invalid_argument", "--net must be in 0..65535, got %d", n)
	}
	return uint16(n)
}

// fmtDuration formats a duration as a compact human-readable string
// ("3s", "2m5s", "1h4m", "2d3h") for --trace output.
func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dm%ds", m, s)
	}
	if d < 24*time.Hour {
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	if h == 0 {
		return fmt.Sprintf("%dd", days)
	}
	return fmt.Sprintf("%dd%dh", days, h)
}

// --- Connection helpers ---

func connectDriver() *driver.Driver {
	sock := getSocket()
	if verbose {
		fmt.Fprintf(os.Stderr, "connecting to daemon socket %s\n", sock)
	}
	d, err := driver.Connect(sock)
	if err != nil {
		fatalHint("not_running",
			fmt.Sprintf("start the daemon with: pilotctl daemon start  (tried %s)", sock),
			"daemon is not running")
	}
	return d
}

// nodeIDFromDaemon returns the daemon's registered node ID for use in
// telemetry events. Returns 0 silently if the daemon is unreachable.
func nodeIDFromDaemon() int64 {
	d, err := driver.Connect(getSocket())
	if err != nil {
		return 0
	}
	defer d.Close()
	info, err := d.Info()
	if err != nil {
		return 0
	}
	nid, _ := info["node_id"].(float64)
	return int64(nid)
}

// connectRegistry dials the configured registry along the same network
// the daemon uses (see registryRoute: egress proxy, compat TLS registry),
// or exits with a hint.
func connectRegistry() *registry.Client {
	return connectRegistryAt(getRegistry(), "registry")
}

func resolveHostnameToAddr(d *driver.Driver, hostname string) (protocol.Addr, uint32, error) {
	result, err := d.ResolveHostname(hostname)
	if err != nil {
		return protocol.Addr{}, 0, err
	}
	nodeIDVal, ok := result["node_id"].(float64)
	if !ok {
		return protocol.Addr{}, 0, fmt.Errorf("missing node_id in resolve response")
	}
	nodeID := uint32(nodeIDVal)
	addrStr, ok := result["address"].(string)
	if !ok {
		return protocol.Addr{}, 0, fmt.Errorf("missing address in resolve response")
	}
	addr, err := protocol.ParseAddr(addrStr)
	if err != nil {
		return protocol.Addr{}, 0, fmt.Errorf("parse address: %w", err)
	}
	return addr, nodeID, nil
}

// maybeAutoHandshake gates any client-initiated tunnel operation
// (send-message, send-file, connect, ping, publish, etc.)
// based on the peer's visibility and our trust state. Three branches:
//
//  1. **Already trusted**: pass silently (one IPC fast-path, ~5ms).
//  2. **Peer in embedded `internal/trustedagents` list** (curated service
//     agents): print "establishing handshake with Trusted Agent <name>",
//     fire Driver.Handshake, then block on Driver.WaitForTrust until the
//     peer's accept arrives or 5s elapses. Trust formation on cold first
//     contact takes ~700–2400ms (request dial + accept dial back); blocking
//     here serialises trust-then-data so service agents don't drop our
//     payload before peer-side trust is finalised.
//  3. **Otherwise**: registry lookup. If the peer is **Public**, allow the
//     tunnel — public daemons accept all comers by design. If the peer is
//     **Private**, refuse client-side with `trust_required`: a private
//     peer's daemon will silently drop our SYN anyway (daemon.go:2223),
//     so starting a tunnel just produces a timeout. Refusing upfront
//     gives the user a clear, immediate signal and a handshake hint.
//
// Skip with --no-auto-handshake. Pre-#99 daemons don't have SubHandshakeWait;
// we treat the IPC error as "wait unsupported" and proceed best-effort.
func maybeAutoHandshake(d *driver.Driver, addr protocol.Addr, skip bool) {
	if skip {
		return
	}

	// Branch 1 — already trusted. Fast path: one IPC roundtrip, no network.
	if resp, err := d.WaitForTrust(addr.Node, 0); err == nil {
		if trusted, _ := resp["trusted"].(bool); trusted {
			return
		}
	}

	// Branch 2 — peer is in the embedded trusted-agents allowlist.
	//
	// TODO(security/H4): IsTrusted keys on node_id only, with no pubkey
	// binding. This call is outbound (we initiate toward addr), so the
	// peer's authenticated pubkey is not in scope here — node_id match is
	// all we can check. Pubkey pinning (IsTrustedWithKey) must be added in
	// the upstream github.com/pilot-protocol/trustedagents module and wired
	// at the inbound auto-accept path inside its NewService(), where the
	// presented key IS available. See that repo, not this call site.
	if name, ok := trustedagents.IsTrusted(addr.Node); ok {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "establishing handshake with Trusted Agent %s (%s)...\n", name, addr)
		}
		if _, err := d.Handshake(addr.Node, "auto-handshake: trusted agent "+name); err != nil {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  handshake send failed: %v — continuing\n", err)
			}
			return
		}
		resp, err := d.WaitForTrust(addr.Node, 5000)
		if err != nil {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  wait-for-trust unsupported on this daemon; continuing\n")
			}
			return
		}
		if trusted, _ := resp["trusted"].(bool); trusted {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  trust established with %s\n", name)
			}
		} else {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "  trust not established within 5s — continuing (peer may drop)\n")
			}
		}
		return
	}

	// Branch 3 — unknown peer, not trusted. Refuse if private. The
	// visibility check reaches the registry the way connectRegistry does
	// (through the egress proxy when there is one).
	rc, route, err := dialRegistry(getRegistry())
	if err != nil {
		// Registry unreachable — be conservative and refuse rather than
		// silently let an untrusted tunnel attempt go through to a peer
		// we can't characterise.
		hint := fmt.Sprintf("run: pilotctl handshake %s", addr)
		if route.Addr != "" {
			hint += "; " + registryDialHint(route)
		}
		fatalHint("trust_required",
			hint,
			"cannot verify peer visibility (registry unreachable: %v); refusing tunnel to untrusted node", err)
	}
	defer rc.Close()
	info, lookupErr := rc.Lookup(addr.Node)
	if lookupErr != nil {
		fatalHint("trust_required",
			fmt.Sprintf("run: pilotctl handshake %s", addr),
			"cannot look up peer %s (%v); refusing tunnel to untrusted node", addr, lookupErr)
	}
	pub, _ := info["public"].(bool)
	if !pub {
		fatalHint("trust_required",
			fmt.Sprintf("run: pilotctl handshake %s", addr),
			"refusing tunnel to private node %s without trust", addr)
	}
	// Public peer — best-effort handshake so replies survive our local
	// trust gate. Without this, a request/reply pattern (e.g. send-message
	// --wait) gets its ACK back but the responder's reply SYN is silently
	// rejected by our daemon (daemon.go SYN-trust-gate). The peer is
	// public and the embedded trustedagents allowlist may not cover every
	// public hostname (entries can become stale when a public agent is
	// re-deployed under a new node ID), so we treat any registry-resolved
	// public peer the same as a Trusted Agent. Auto-approve peers (most
	// public agents are) finalise mutual trust in ~700-2400 ms; non-auto-
	// approve peers still see the request in pending and the tunnel
	// proceeds best-effort.
	if _, err := d.Handshake(addr.Node, "auto-handshake: public peer"); err != nil {
		// Handshake send failure is non-fatal — fall through to send.
		return
	}
	if resp, err := d.WaitForTrust(addr.Node, 5000); err == nil {
		if trusted, _ := resp["trusted"].(bool); trusted {
			if !jsonOutput {
				fmt.Fprintf(os.Stderr, "auto-handshake established trust with public peer %s\n", addr)
			}
			return
		}
		// PILOT-220: on fresh daemon starts the handshake ACK path
		// may not be fully routed within the initial 5 s window.
		// When the local trust gate drops the reply SYN because
		// trust isn't finalised, send-message --wait times out.
		// Poll WaitForTrust while a pending handshake exists (up
		// to 16 s extra) so trust finalises before the first user
		// query hits the wire.
	} else {
		// WaitForTrust not supported (old daemon); proceed best-effort.
		return
	}
	for poll := 0; poll < 8; poll++ {
		time.Sleep(2 * time.Second)
		pending, err := d.PendingHandshakes()
		if err != nil {
			break
		}
		hasPending := false
		if list, ok := pending["pending"].([]interface{}); ok {
			for _, item := range list {
				m, okMap := item.(map[string]interface{})
				if !okMap {
					continue
				}
				if nid, okNid := m["node_id"].(float64); okNid && uint32(nid) == addr.Node {
					hasPending = true
					break
				}
			}
		}
		if !hasPending {
			break // handshake resolved (accepted or rejected); stop polling
		}
		if resp, err := d.WaitForTrust(addr.Node, 0); err == nil {
			if trusted, _ := resp["trusted"].(bool); trusted {
				if !jsonOutput {
					fmt.Fprintf(os.Stderr, "auto-handshake established trust with public peer %s\n", addr)
				}
				break
			}
		}
	}
}

func parseAddrOrHostname(d *driver.Driver, arg string) (protocol.Addr, error) {
	// Try full address (e.g. "0:0000.0000.000B")
	addr, err := protocol.ParseAddr(arg)
	if err == nil {
		return addr, nil
	}
	// Try bare node ID (e.g. "11" → backbone address 0:0000.0000.000B)
	if id, numErr := strconv.ParseUint(arg, 10, 32); numErr == nil {
		return protocol.Addr{Network: 0, Node: uint32(id)}, nil
	}
	// Try hostname resolution
	resolved, _, resolveErr := resolveHostnameToAddr(d, arg)
	if resolveErr != nil {
		return protocol.Addr{}, fmt.Errorf("cannot resolve %q — is the hostname correct and is there mutual trust? (see: pilotctl handshake)", arg)
	}
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "resolved %q → %s\n", arg, resolved)
	}
	return resolved, nil
}

// resolveToNodeID resolves any of: numeric node ID, pilot address
// (N:NNNN.HHHH.LLLL), or hostname — to a uint32 node ID.
// Prints a resolution line to stderr (text mode) so the user can see
// what was matched. d may be nil only when the arg is numeric or an address.
func resolveToNodeID(d *driver.Driver, arg string) uint32 {
	if id, err := strconv.ParseUint(arg, 10, 32); err == nil {
		return uint32(id)
	}
	if addr, err := protocol.ParseAddr(arg); err == nil {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "parsed address %s → node %d\n", arg, addr.Node)
		}
		return addr.Node
	}
	if d == nil {
		fatalCode("invalid_argument", "cannot resolve hostname without a daemon connection: %q", arg)
	}
	_, nodeID, err := resolveHostnameToAddr(d, arg)
	if err != nil {
		fatalCode("not_found", "cannot resolve %q — check the hostname and that mutual trust exists", arg)
	}
	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "resolved %q → node %d\n", arg, nodeID)
	}
	return nodeID
}

// resolveNetworkNodeArg resolves a node ID, address, or hostname for network
// subcommands that talk directly to the registry (no daemon connection kept open).
// Opens a daemon connection only when the arg is a hostname.
func resolveNetworkNodeArg(arg string) uint32 {
	if id, err := strconv.ParseUint(arg, 10, 32); err == nil {
		return uint32(id)
	}
	if addr, err := protocol.ParseAddr(arg); err == nil {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "parsed address %s → node %d\n", arg, addr.Node)
		}
		return addr.Node
	}
	d := connectDriver()
	defer d.Close()
	return resolveToNodeID(d, arg)
}

// hasHelpFlag returns true when args contains -h or --help.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// commandHelp holds concise usage text for each command. Looked up by
// printCommandHelp when the user passes -h / --help after a command name.
var commandHelp = map[string]string{
	"enterprise": enterpriseHelpText,
	"send-message": `Usage: pilotctl send-message <address|hostname> --data <text> [flags]

Send a message to a remote agent and optionally wait for the reply.

Flags:
  --data <text>         message payload (required)
  --type text|json|binary  payload encoding (default: text)
  --count <n>           send N times (default: 1)
  --reuse-conn          reuse the connection across --count sends (saves ~1 RTT)
  --wait [<dur>]        wait for a reply in the inbox (default timeout: 30s)
  --trace               print per-step timing breakdown to stderr
  --no-auto-handshake   skip automatic trust handshake with known agents
  --enterprise-control <path>  request a signed enterprise decision before sending
  --governed-resource <resource> exact receiver-owned resource bound in that decision

Examples:
  pilotctl send-message list-agents --data '/data {"search":"weather","limit":5}'
  pilotctl send-message my-peer --data "hello" --wait
  pilotctl send-message 0:0000.0000.400E --data "ping" --trace
`,
	"ping": `Usage: pilotctl ping <address|hostname> [flags]

Send echo packets and report round-trip latency.

Flags:
  --count <n>           number of packets to send (default: 4)
  --timeout <dur>       per-ping deadline (default: 5s)
  --reuse-conn          reuse tunnel connection across packets
  --trace               print per-step timing breakdown to stderr

Examples:
  pilotctl ping my-agent
  pilotctl ping 0:0000.0000.400E --count 10 --trace
`,
	"bench": `Usage: pilotctl bench <address|hostname> [size_mb] [flags]

Measure throughput to a remote node via the echo port.

Flags:
  --timeout <dur>       overall deadline (default: 120s)

Examples:
  pilotctl bench my-agent
  pilotctl bench my-agent 10
`,
	"traceroute": `Usage: pilotctl traceroute <address|hostname> [flags]

Probe the hop-by-hop path to a remote node.

Flags:
  --timeout <dur>       overall deadline (default: 30s)
`,
	"connect": `Usage: pilotctl connect <address|hostname> [port] [flags]

Open an interactive tunnel to a remote node.

Flags:
  --message <msg>       send a message on connect
  --timeout <dur>       connection timeout (default: 30s)
`,
	"send": `Usage: pilotctl send <address|hostname> <port> --data <msg> [flags]

Send a raw message to a specific port on a remote node.

Flags:
  --data <msg>          message payload (required)
  --timeout <dur>       timeout (default: 30s)
`,
	"recv": `Usage: pilotctl recv <port> [flags]

Listen on a port and print incoming messages.

Flags:
  --count <n>           stop after N messages (default: 1)
  --timeout <dur>       idle timeout (default: 30s)
`,
	"listen": `Usage: pilotctl listen <port> [flags]

Listen for datagrams on the given port and print them.

Flags:
  --count <n>           stop after N messages
  --timeout <dur>       idle timeout
`,
	"find": `Usage: pilotctl find <hostname>

Look up a hostname in the registry and print its pilot address.
`,
	"handshake": `Usage: pilotctl handshake <node_id|hostname> [justification]

Initiate a trust handshake with another node.
The remote node must approve the request before messages can flow.

See also: pilotctl approve, pilotctl pending, pilotctl trust
`,
	"peers": `Usage: pilotctl peers [flags]

Summarize currently connected peers. Shows a one-line breakdown
(encrypted+authenticated / relay / direct) and then only the exceptions —
peers that are unencrypted or unauthenticated.

PATH=relay means a peer is behind symmetric NAT and traffic goes through
the beacon. It's normal but adds ~50-150ms latency vs a direct path.

Flags:
  --all                 full peer table instead of exceptions only
  --limit <n>           rows to show (default 20, 0 = all)
  --search <query>      filter by node ID substring

See also: pilotctl ping <node_id>  — measure RTT to a specific peer
`,
	"inbox": `Usage: pilotctl inbox [read <id>] [flags]

Show messages received from other agents — newest first, 10 by default.

Subcommands:
  read <id>             print the full body of one message

Flags:
  --latest              full body of the single newest message (after filters)
  --limit <n>           how many to show (default 10, 0 = all)
  --from <peer>         only messages from this address or hostname
  --since <dur|ts>      only messages newer than a duration (5m, 1h) or RFC3339 time
  --full                full bodies instead of one-line previews
  --clear               delete the matched messages (all if no filters)
  --before <dur>        with --clear: only delete messages older than this

Agent patterns:
  pilotctl --json inbox --latest                     # newest reply, full body
  pilotctl --json inbox --from list-agents --limit 3 # last 3 from one peer
  pilotctl inbox --clear --before 24h                # keep today, purge older

Tip: send-message --wait already returns the matching reply inline; the
inbox is for replies that arrive later or that you want to re-read.
`,
	"info": `Usage: pilotctl info [flags]

Print full daemon state, grouped:
  identity   hostname, address, node ID, key fingerprint, email
  network    peers (encrypted/relay/direct), pending handshakes,
             beacon, connections, ports
  traffic    cumulative bytes and packet counts since start
  skills     agent tools with the pilot skill installed

See also: pilotctl health       — lightweight status check
          pilotctl peers        — per-peer detail
          pilotctl connections  — per-connection detail
`,
	"health": `Usage: pilotctl health

Quick daemon health check. Shows uptime, peers (encrypted/relay breakdown),
pending handshakes, traffic, and any queue drops or webhook failures.

Queue Drops > 0 means the daemon's accept queue is overflowing — connections
are being dropped before they're processed. Usually indicates CPU saturation
or a misconfigured system file-descriptor limit.

See also: pilotctl info  — full daemon state with connection list
`,
	"daemon start": `Usage: pilotctl daemon start [flags]

Flags:
  --config <path>              path to config file (JSON)
  --registry <addr>            registry address (default: $PILOT_REGISTRY or 34.71.57.205:9000)
  --beacon <addr>              beacon address (default: $PILOT_BEACON or 34.71.57.205:9001)
  --listen <addr>              UDP listen address (default: :0)
  --socket <path>              Unix socket path (default: /tmp/pilot.sock)
  --identity <path>            Ed25519 identity file path
  --email <addr>               email for account identification and key recovery
  --hostname <name>            discovery hostname (lowercase alphanumeric + hyphens)
  --endpoint <host:port>       fixed public endpoint — skips STUN (for cloud VMs)
  --public                     make this node publicly visible
  --webhook <url>              HTTP(S) endpoint for event notifications
  --admin-token <token>        admin token for network operations
  --networks <ids>             comma-separated network IDs to auto-join
  --trust-auto-approve         automatically approve all incoming trust handshakes
  --log-level <level>          log level: debug, info, warn, error (default: info)
  --log-format <fmt>           log format: text, json (default: text)
  --no-encrypt                 disable tunnel encryption
  --foreground                 run in foreground (no fork; for systemd / shell wrappers)
  --wait <duration>            how long to wait for daemon to become ready (default:
                               15s; 30s with --transport compat or auto)
  --motd-feed-url <url>        message-of-the-day feed (empty to disable; env PILOT_MOTD_URL)
  --motd-interval <duration>   message-of-the-day poll interval (default: 15m)
  --enterprise-control <path>  owner-only managed control attachment
  --transport <udp|compat|auto>
                               tunnel transport. Precedence: this flag,
                               $PILOT_TRANSPORT, config "transport", else auto when
                               the daemon supports it (older daemons: udp).
                               udp = UDP tunnels; compat = registry over TLS and
                               beacon over WSS, TCP 443 only (UDP-blocked or
                               proxy-only hosts); auto = udp when the beacon
                               answers over UDP, else compat when TCP 443 is
                               reachable (through the proxy, if any)
  --proxy <auto|off|URL>       outbound proxy. Precedence: this flag, $PILOT_PROXY,
                               config "proxy", else auto. auto = with compat, use
                               $HTTPS_PROXY/$ALL_PROXY (honoring $NO_PROXY);
                               off (or none) = never; http(s)://[user:pass@]host:port
                               = every connection except loopback. A URL with
                               credentials is passed via env, never on argv
  --compat-beacon <url>        beacon WSS URL for compat mode
  --registry-trust <mode>      registry TLS trust: pinned or system
  --registry-fingerprint <hex> registry certificate SHA-256 (pins the compat registry;
                               for hosts without a CA bundle)
  --tls-trust <mode>           compat beacon TLS trust: system or pinned

Environment passed through to the daemon (never scrubbed):
  HTTPS_PROXY https_proxy HTTP_PROXY http_proxy ALL_PROXY all_proxy
  NO_PROXY no_proxy PILOT_PROXY PILOT_PROXY_CMD PILOT_TRANSPORT
  PILOT_REGISTRY_TRUST PILOT_REGISTRY_FINGERPRINT SSL_CERT_FILE SSL_CERT_DIR

A pilot-daemon too old for --transport, --transport auto or --proxy gets the
flag dropped (auto becomes udp) with a warning instead of crashing it.
Behind an HTTPS proxy with UDP blocked (e.g. hosted agent sandboxes), plain
"pilotctl daemon start" picks compat by itself; to skip the UDP probe:
  pilotctl config --set transport=compat && pilotctl daemon start
If the proxy rotates its credentials, give the daemon a command that prints
the current proxy URL (install.sh does this in hosted agent sandboxes); the
daemon re-runs it every 60s and whenever the proxy answers 407:
  pilotctl config --set proxy_cmd="bash -c 'printf %s \"\$https_proxy\"'"
`,
	"daemon stop": `Usage: pilotctl daemon stop

Stop the running daemon gracefully. Sends SIGTERM; daemon closes active
connections and deregisters from the beacon before exiting.
`,
	"daemon status": `Usage: pilotctl daemon status [flags]

Show daemon status: running/stopped, node ID, address, uptime, peer count
(with encrypted and relay breakdown), active connections, and any pending
trust handshakes.

Flags:
  --check     silent health check — exits 0 if daemon is responsive, 1 otherwise
              useful in scripts: pilotctl daemon status --check || pilotctl daemon start
`,
	"init": `Usage: pilotctl init [flags]

Initialize the local pilot config at ~/.pilot/config.json.
All flags are optional; unset values are written with their defaults.

Flags:
  --registry <addr>     registry address (default: 34.71.57.205:9000)
  --beacon <addr>       beacon address
  --hostname <name>     hostname to register (default: none)
  --socket <path>       daemon socket path (default: /tmp/pilot.sock)
`,
	"network": `Usage: pilotctl network <subcommand> [flags]

Manage overlay networks.

Subcommands:
  list                  list networks this node belongs to
  create --name <name>  create a new network
  join <id>             join a network
  leave <id>            leave a network
  members <id>          list members of a network
  invite <id> <node>    invite a node to a network
  invites               list pending invitations
  accept <id>           accept an invitation
  reject <id>           reject an invitation
  delete <id>           delete a network (owner only)
  rename <id> <name>    rename a network (owner only)
  promote <id> <node>   promote a member to admin
  demote <id> <node>    demote an admin to member
  kick <id> <node>      remove a member from a network
  role <id> <node>      show a member's role in a network
  policy <id>           show or set network policy
`,

	// Trust
	"pending": `Usage: pilotctl pending

List inbound trust handshake requests waiting for your approval.
Each row shows the requesting node ID, their justification, and when they asked.

To approve:  pilotctl approve <node_id|address|hostname>
To reject:   pilotctl reject <node_id|address|hostname> [reason]

Note: nodes in the embedded trusted-agents list are auto-approved on first contact.
`,
	"trust": `Usage: pilotctl trust [flags]

List the nodes this daemon currently trusts, newest first (20 by default).

Mutual trust is the norm and prints nothing; rows tagged "one-way" mean
you approved them but they haven't approved you yet, or vice versa.

Flags:
  --limit <n>           rows to show (default 20, 0 = all)
  --search <substr>     filter by node ID (or hostname when known)

See also: pilotctl pending   — incoming requests waiting for your approval
          pilotctl handshake — initiate trust with a new peer
          pilotctl untrust   — revoke trust with a node
`,
	"trusted": `Usage: pilotctl trusted list

List nodes in the embedded trusted-agents directory (service agents that are
auto-approved on first contact, without requiring manual pilotctl approve).

These are well-known network services (list-agents, weather agents, etc.).
To see live trust state, use: pilotctl trust
`,
	"untrust": `Usage: pilotctl untrust <node_id|address|hostname>

Remove trust with a node. Future messages from or to that node will be blocked
until a new handshake is completed.

This does not notify the remote node — they will see connection failures on
their next attempt to reach you.
`,
	"reject": `Usage: pilotctl reject <node_id|address|hostname> [reason]

Reject a pending inbound trust handshake request. The requesting node is
notified with the optional reason string.

To see pending requests: pilotctl pending
`,
	"approve": `Usage: pilotctl approve <node_id|address|hostname>

Approve a pending inbound trust handshake request from the given node.
Once approved, encrypted messages can flow in both directions (assuming they
also approved you — check with: pilotctl trust).

To see pending requests: pilotctl pending
`,

	// Registry
	"deregister": `Usage: pilotctl deregister

Remove this node from the registry and all network memberships.
Use this for a clean shutdown when you no longer want this node to be reachable.

Note: daemon stop does NOT deregister — the 5-minute TTL reaps inactive nodes
automatically. Only use deregister if you want immediate removal.
`,
	"sign-request": `Usage: pilotctl sign-request --audience <a> (--body-file <f> | --body-hash <64hex> | --body '<string>')

Sign a request-signature envelope (reqsig) proving a request originates from
this node. The daemon constructs the envelope itself — its own address, the
current timestamp, a fresh nonce, the body hash and the audience — and signs
the canonical form with the node's Ed25519 identity key. It never signs
caller-supplied raw strings.

Exactly one body source is required:
  --body-file <f>       hash the file's bytes (sha256)
  --body '<string>'     hash the literal string
  --body-hash <64hex>   use a precomputed sha256 body hash

Prints {envelope, signature, address}. Attach envelope + signature to the
request; the consuming service verifies them against this node's registered
public key (or via: pilotctl verify-request).
`,
	"verify-request": `Usage: pilotctl verify-request --envelope '<canonical>' --signature '<b64>' [--standing] [--max-skew <secs>]

Verify a request-signature envelope produced by a peer's sign-request. The
daemon parses the envelope, checks freshness, resolves the claimed node's
public key (local key cache first, registry on miss) and verifies the
signature.

Flags:
  --standing            also report the signer's registry standing when
                        available (online, last_seen_unix, key_generation,
                        network_member)
  --max-skew <secs>     freshness window in seconds (default 300)

Prints the daemon's verdict. Exit code 1 when the envelope does not verify
(reply carries valid:false plus a reason).
`,
	"rotate-key": `Usage: pilotctl rotate-key

Generate a new Ed25519 keypair and register it with the registry.
Existing trust relationships are preserved if the registry supports key rotation.

The old private key is replaced — there is no rollback.
`,
	"set-public": `Usage: pilotctl set-public

Make this node publicly visible in the directory (hostname, category, description
are searchable via list-agents and similar discovery agents).
`,
	"set-private": `Usage: pilotctl set-private

Hide this node from the public directory. The node remains reachable by
nodes that already know its address or have mutual trust.
`,
	"register": `Usage: pilotctl register [listen_addr]

Register this node with the registry at the configured address.
Normally called automatically by the daemon at startup.
`,
	"lookup": `Usage: pilotctl lookup <node_id|address|hostname>

Look up a node by numeric ID, pilot address, or hostname in the registry and print its address,
hostname, and public key.
`,

	// Discovery
	"set-hostname": `Usage: pilotctl set-hostname <hostname>

Set the discovery hostname for this node. Hostnames must be lowercase
alphanumeric with hyphens (e.g. "my-agent"). Other nodes can then reach
you with: pilotctl send-message my-agent --data "hello"

Changes take effect on the next registry heartbeat (~30s).
`,
	"clear-hostname": `Usage: pilotctl clear-hostname

Remove the discovery hostname from this node. The node remains reachable
by address but not by name.
`,
	"set-webhook": `Usage: pilotctl set-webhook <url>

Set an HTTP(S) webhook URL for event notifications. The daemon will POST
JSON event payloads to this URL for: new connections, incoming messages,
trust handshakes, and network membership changes.
`,
	"clear-webhook": `Usage: pilotctl clear-webhook

Remove the configured webhook URL. Event notifications will stop.
`,

	// Management
	"connections": `Usage: pilotctl connections

List active stream connections with full TCP-like state detail:
local port, remote address, state (SYN_SENT/ESTABLISHED/TIME_WAIT/...),
congestion window, in-flight bytes, SRTT.

See also: pilotctl info  — includes connection list plus full daemon state
`,
	"disconnect": `Usage: pilotctl disconnect <conn_id>

Forcefully close a stream connection by its ID (from pilotctl connections).
Sends FIN to the remote side.
`,

	// Messaging
	"received": `Usage: pilotctl received [flags]

List files received via send-file (~/.pilot/received/), newest first.
Shows the 10 newest by default.

Flags:
  --limit <n>             show at most N files (default: 10, 0 = all)
  --since <dur|rfc3339>   only files newer than a duration (5m, 1h) or timestamp
  --clear                 delete the matched files
  --before <dur>          with --clear: only delete files older than <dur>
`,
	"dgram": `Usage: pilotctl dgram <address|hostname> <port> --data <msg>

Send a single unreliable datagram to a remote node on the given port.
Unlike send-message (which uses the reliable data-exchange stream), datagrams
are fire-and-forget — no ACK, no retry, no ordering guarantee.

Use for: real-time telemetry, heartbeats, anything where freshness > reliability.
`,

	// Bootstrap / config
	"config": `Usage: pilotctl config [flags]

Show or modify the local config file (~/.pilot/config.json).

Flags:
  --set key=value    set a config key (e.g. --set registry=34.71.57.205:9000)

Common keys:
  registry     registry address (overrides $PILOT_REGISTRY)
  beacon       beacon address (overrides $PILOT_BEACON)
  socket       daemon socket path (overrides $PILOT_SOCKET)
  hostname     default hostname passed to daemon start
  transport    daemon transport: udp, compat or auto ($PILOT_TRANSPORT overrides)
  proxy        daemon proxy: auto, off, or http(s)://[user:pass@]host:port
               ($PILOT_PROXY overrides; credentials are redacted when shown)
  registry_fingerprint / registry_trust
               pin the TLS registry (hosts without a CA bundle)
`,
	"version": `Usage: pilotctl version

Print the pilotctl build version string.
`,
	"update": `Usage: pilotctl update [subcommand|flags]

Automatic updates are OFF by default. Control them with:
  pilotctl update status     show whether auto-update is on and the current version
  pilotctl update enable     turn automatic updates ON
  pilotctl update disable    turn automatic updates OFF (default)

With no subcommand, runs the updater ONCE — a manual check that installs the
latest release if available, regardless of the auto-update setting. In manual
mode (daemon not running), re-runs skill install so newly installed binaries
have matching skill definitions.

Flags (one-shot mode):
  --repo <name>   GitHub owner/repo for releases (default: pilot-protocol/pilotprotocol)
  --pin <tag>     pin to a specific release tag (e.g. v1.10.5)
`,
	"updates": `Usage: pilotctl updates [flags]

Show the latest Pilot Protocol changelog entries from the release feed.

Flags:
  --count <n>      number of entries to show (default: 10)
  --scope <name>   filter by scope tag (e.g. protocol, cli, networks)
`,
	"context": `Usage: pilotctl context [command]

Print machine-readable metadata for every command: name, description,
argument templates, and return field names. Used by agent tools (Claude Code,
OpenClaw, etc.) to auto-generate command invocations.

With no argument, prints the full catalog as a JSON object keyed by command
name. With a command name (e.g. 'pilotctl context send-message' or
'pilotctl context daemon start'), prints only that command's entry.
`,
	"skills": `Usage: pilotctl skills [subcommand]

Manage the SKILL.md files the daemon installs for each detected agent
toolchain (the supported set is fetched at runtime from the pilot-skills
repository). The skill file teaches the agent how to use pilotctl without
manual setup.

Subcommands:
  status [--verbose]   (default) per-tool install state; --verbose adds per-file detail
  paths                print install paths only — one per line, shell-friendly
  check                run one reconcile pass right now (re-installs if missing/outdated)
  disable all          remove every managed file + persist the opt-out
                       (only 'all' is accepted; per-skill disable is not yet implemented)
  enable all           re-enable (auto mode) + run one reconcile pass
                       (only 'all' is accepted; per-skill enable is not yet implemented)
  set-mode auto|manual|disabled   persist the reconcile mode to ~/.pilot/config.json

The daemon reconciles skill files every 15 minutes automatically (in auto mode).
`,
	"broadcast": `Usage: pilotctl broadcast <network_id> <message> [flags]

Broadcast a message to all members of a network. Requires an admin token
(PILOT_ADMIN_TOKEN env var or admin_token in ~/.pilot/config.json).

Flags:
  --port <port>         destination port on each member (default: 1000)
`,
	"subscribe": `Usage: pilotctl subscribe <address|hostname> <topic> [flags]

Subscribe to a pub/sub topic on a remote node and print incoming events.

Flags:
  --count <n>       stop after N events (default: unlimited)
  --timeout <dur>   idle timeout before exiting (default: unlimited)
`,
	"publish": `Usage: pilotctl publish <address|hostname> <topic> --data <message>

Publish a message to a topic on a remote node.
`,
	"send-file": `Usage: pilotctl send-file <address|hostname> <filepath> [--timeout <dur>] [--prefer-direct]

Send a file to a remote node via the data-exchange stream. Files are
capped at 1 GiB (the default data-exchange frame ceiling) unless both
daemons have changed PILOT_DATAEXCHANGE_MAX_FRAME (accepted range
64 KiB to 2 GiB) — see the dataexchange package.

Flags:
  --timeout <dur>       give up if the receiver does not ACK within this
                        window (default 90s). Use a value comfortably
                        larger than (file size / expected throughput) +
                        receiver disk-flush time. On timeout the sender
                        exits with a non-zero code and a clear hint
                        instead of hanging until SO_KEEPALIVE trips
                        (~120s by default on the OS).
  --prefer-direct       drop the existing tunnel + sticky relay flag for
                        this peer before dialing, so the daemon retries
                        a direct UDP path instead of reusing the
                        beacon-mediated relay tunnel. Useful when ping
                        works but send-file hangs — typical sign of a
                        relay path that established once and got stuck.
                        Best-effort: if the peer is genuinely behind a
                        symmetric NAT the daemon will still fall back to
                        relay within the dial retry budget.

What you see during a transfer (TTY only):
  sending <file> to <target>… <Ns>            self-rewriting elapsed line
  (--json suppresses it for agent consumption)

Reliability caveats (current implementation):
  - File is transferred as a single atomic frame; on any error the
    receiver may end up with no file or a partial one.
  - No resume protocol — a dropped transfer means a full retry.
  - End-to-end integrity is the tunnel's AEAD tag; there is no
    application-level content hash. See
    docs/PROPOSAL-reliable-file-transfer.md for the planned fix.
`,

	// appstore: keep the help block here in lockstep with
	// AppStoreHelpText in appstore.go (the const it's pulled from).
	// Without this registration, `pilotctl appstore <sub> --help`
	// falls through pilotctl's per-command help intercept and
	// prints "No specific help" — confusing for an RC-shipped CLI.
	"appstore": AppStoreHelpText,

	"review": reviewHelpText,

	"quickstart": `Usage: pilotctl quickstart

Print a fixed 3-step getting-started cheat-sheet (DISCOVER, TRUST, TALK)
plus the one-time setup commands (init + daemon start). Static output —
it does not inspect daemon state:
  1. DISCOVER — pilotctl send-message list-agents --data '...' --wait
  2. TRUST    — pilotctl handshake <node_id>
  3. TALK     — pilotctl send-message <node_id> --data "Hello, world!" --wait
`,

	"verify": `Usage: pilotctl verify [status] [flags]

Verified-address badges — prove a node controls a real, attested identity.

  pilotctl verify                       show this node's verification state (alias: verify status)
  pilotctl verify status [--node <id>]  check a specific node's badge
  pilotctl verify --provider <name>     run a device-flow to become verified
  pilotctl verify --badge <b> --badge-sig <s>   submit a badge you already hold
  pilotctl verify --from <file>         submit a badge from a JSON credential file

Badges are verified OFFLINE against the pinned issuer key — the registry's word
is never trusted.
`,

	"recovery": `Usage: pilotctl recovery <enroll|new-key|recover> ...

Recover a node's address if its identity key is lost.

  pilotctl recovery enroll    record an opaque recovery commitment for this address
  pilotctl recovery new-key   rotate to a fresh identity key
  pilotctl recovery recover   reclaim the address using recovery material

Enrollment + signatures come from the 'pilot-verify' tool.
`,

	"prefer-direct": `Usage: pilotctl prefer-direct <node_id|address|hostname>

Reset routing state for a peer so the next connection prefers a direct
(hole-punched) tunnel over the relay. Useful after a relay path got pinned.
Requires daemon v1.12+.

Returns: had_tunnel, was_relay_active, was_relay_pinned
`,
}

// printCommandHelp prints the help text for a command and exits.
// For subcommands like "daemon start", cmdArgs[0] is the subcommand.
func printCommandHelp(cmd string, cmdArgs []string) {
	// Try compound key first (e.g. "daemon start")
	if len(cmdArgs) > 0 {
		compound := cmd + " " + cmdArgs[0]
		if txt, ok := commandHelp[compound]; ok {
			fmt.Fprint(os.Stderr, txt)
			os.Exit(0)
		}
	}
	if txt, ok := commandHelp[cmd]; ok {
		fmt.Fprint(os.Stderr, txt)
		os.Exit(0)
	}
	// Fallback: tell the user where to look
	fmt.Fprintf(os.Stderr, "No specific help for %q — run 'pilotctl' for the full command list.\n", cmd)
	os.Exit(0)
}

// --- Usage ---

func usage() {
	fmt.Fprintf(os.Stderr, `pilotctl — Pilot Protocol CLI

Global flags:
  --json                        Output structured JSON (for agent/programmatic use)

Getting started:
  pilotctl quickstart             3-command getting-started flow

Bootstrap:
  pilotctl init [--registry <addr>] [--hostname <name>] [--beacon <addr>] [--socket <path>]
  pilotctl config [--set key=value]

Daemon lifecycle:
  pilotctl daemon start [--config <path>] [--registry <addr>] [--beacon <addr>] [--email <addr>] [--webhook <url>] [--trust-auto-approve] [--transport <udp|compat|auto>] [--proxy <auto|off|URL>]
  pilotctl daemon stop
  pilotctl daemon status

Registry commands:
  pilotctl register [listen_addr]
  pilotctl lookup <node_id>
  pilotctl rotate-key
  pilotctl set-public
  pilotctl set-private
  pilotctl deregister

Discovery commands:
  pilotctl find <hostname>
  pilotctl set-hostname <hostname>
  pilotctl clear-hostname
  (discovery tags are operator setup: pilotctl extras set-tags / clear-tags)

Communication commands:
  pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]
  pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]
  pilotctl recv <port> [--count <n>] [--timeout <dur>]
  pilotctl send-file <address|hostname> <filepath> [--enterprise-control <path> --governed-resource <resource>]
  pilotctl send-message <address|hostname> --data <text> [--type text|json|binary] [--count <n>] [--reuse-conn] [--wait <dur>]
  pilotctl dgram <address|hostname> <port> --data <msg>
  pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]
  pilotctl publish <address|hostname> <topic> --data <message>

Trust commands:
  pilotctl handshake <node_id|hostname> [justification]
  pilotctl approve <node_id>
  pilotctl reject <node_id> [reason]
  pilotctl untrust <node_id>
  pilotctl pending
  pilotctl trust [--search <substr>]                  live trust state (peers you trust)
  pilotctl trusted list                               embedded directory of auto-approved service agents
  pilotctl prefer-direct <node_id|address|hostname>   prefer a direct tunnel over the relay (daemon v1.12+)

Identity & recovery:
  pilotctl verify [status]                            show this node's verified-address badge state
  pilotctl verify --provider <name>                   run a device-flow to get a verified-address badge
  pilotctl recovery <enroll|new-key|recover> ...      enroll / rotate / reclaim the address if the key is lost
  pilotctl review <pilot|app-id> [--rating <1-5>] [--text "..."]   rate Pilot or an installed app

Request signing (prove a request originates from this node):
  pilotctl sign-request --audience <a> (--body-file <f> | --body-hash <64hex> | --body '<string>')
  pilotctl verify-request --envelope '<canonical>' --signature '<b64>' [--standing] [--max-skew <secs>]

Management commands:
  pilotctl connections
  pilotctl disconnect <conn_id>

Mailbox:
  pilotctl received [--limit <n>] [--since <dur>] [--clear [--before <dur>]]
  pilotctl inbox [--clear]

Service Agents:
  pilotctl send-message list-agents --data "list all agents"

Agent tool discovery:
  pilotctl context
  pilotctl skills [status]            show where the daemon installs SKILL.md per detected agent tool
  pilotctl skills paths               print only the install paths (shell-friendly)
  pilotctl skills check               run one reconcile pass right now
  pilotctl skills enable|disable all  turn skill injection on/off (only 'all' is implemented)
  pilotctl skills set-mode auto|manual|disabled   persist the reconcile mode

App store (install + call local capability apps; full help: pilotctl appstore help):
  pilotctl appstore catalogue                         list apps available for one-command install
  pilotctl appstore view <id> [--all-changelog]       app detail page (description, methods, permissions)
  pilotctl appstore install <app-id> [--force]        install by catalogue ID (fetch + verify + extract)
  pilotctl appstore list                              list installed apps + their IPC methods
  pilotctl appstore call <id> <method> [json-args]    dispatch an IPC call into an app
  pilotctl appstore status|caps|audit|restart|uninstall <id>

Updates:
  pilotctl update [status|enable|disable] [--pin <tag>]   self-update (auto-update OFF by default)
  pilotctl updates [--count <n>] [--scope <scope>]        read the Pilot changelog feed

Operator / admin (run 'pilotctl extras' or 'pilotctl context' for the full list):
  pilotctl enterprise status|dashboard-url|policy|mandate|receipt --endpoint <URL> --tenant <tenant>  inspect or submit signed enterprise control state
  pilotctl extras <cmd>              network / managed / policy / member-tags / enterprise / low-level plumbing
  pilotctl extras gateway start|stop|map|unmap|list       IP gateway (requires root — creates loopback interface aliases)

Diagnostic commands:
  pilotctl info
  pilotctl health
  pilotctl peers [--search <query>]
  pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>]
  pilotctl traceroute <address> [--timeout <dur>]
  pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]
  pilotctl listen <port> [--count <n>] [--timeout <dur>]
  pilotctl broadcast <network_id> <message>

Environment:
  PILOT_REGISTRY     Registry address (default: 34.71.57.205:9000)
  PILOT_SOCKET       Daemon socket path (default: /tmp/pilot.sock)
  PILOT_TRANSPORT    daemon start transport: udp, compat (TCP 443 only) or auto
  PILOT_PROXY        proxy policy: auto, off, or http(s)://[user:pass@]host:port
  HTTPS_PROXY        proxy for compat mode (proxy=auto) and pilotctl's own connections

Version:
  pilotctl version

Config file: ~/.pilot/config.json

Companion binaries:
  daemon start / start --foreground exec the separately-shipped
  pilot-daemon binary; gateway start / map exec pilot-gateway
  (optional — no longer ships in release tarballs; build it from
  github.com/pilot-protocol/gateway). Both are discovered (in order):
  $PILOT_DAEMON_BIN / $PILOT_GATEWAY_BIN, next to the pilotctl
  executable, then $PATH.
`)
	os.Exit(2)
}

// --- Main ---

func main() {
	loadFeatureFlags()
	loadMOTD()

	// Extract global flags before subcommand
	var args []string
	for _, a := range os.Args[1:] {
		switch a {
		case "--json":
			jsonOutput = true
		case "--verbose", "-v":
			verbose = true
		default:
			args = append(args, a)
		}
	}

	// Prepend the message-of-the-day banner (if any) ahead of every
	// command's output. No-op in --json mode, where the message instead
	// rides in each envelope's important_update field. Pure local read of
	// ~/.pilot/motd.json — no network, no daemon call.
	printMOTDBanner()

	if len(args) < 1 {
		usage()
	}

	cmd := args[0]
	cmdArgs := args[1:]

	// Top-level help
	if cmd == "-h" || cmd == "--help" {
		usage()
	}
	// Per-command help: pilotctl <cmd> -h / --help
	if hasHelpFlag(cmdArgs) {
		printCommandHelp(cmd, cmdArgs)
	}

	extrasOnly := false

dispatch:
	switch cmd {

	case "extras":
		if len(cmdArgs) == 0 {
			cmdExtrasHelp()
			return
		}
		extrasOnly = true
		cmd = cmdArgs[0]
		cmdArgs = cmdArgs[1:]
		goto dispatch

	case "version":
		fmt.Println(version)
		return

	case "quickstart":
		cmdQuickstart()
		return

	case "update":
		cmdUpdate(cmdArgs)
		return

	case "updates":
		cmdUpdates(cmdArgs)
		return

	case "skills":
		cmdSkills(cmdArgs)
		return

	case "appstore":
		cmdAppStore(cmdArgs)
		return

	case "review":
		cmdReview(cmdArgs)
		return

	case "enterprise":
		cmdEnterprise(cmdArgs)
		return

	// Bootstrap
	case "init":
		cmdInit(cmdArgs)
	case "config":
		cmdConfig(cmdArgs)
	case "context":
		cmdContext(cmdArgs)

	// Daemon lifecycle
	case "daemon":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: pilotctl daemon start | stop | status",
				"missing subcommand")
		}
		switch cmdArgs[0] {
		case "start":
			cmdDaemonStart(cmdArgs[1:])
		case "stop":
			cmdDaemonStop()
		case "status":
			cmdDaemonStatus(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: start, stop, status",
				"unknown daemon subcommand: %s", cmdArgs[0])
		}

	// Gateway (extras-only — use 'pilotctl extras gateway' or pilot-gateway binary)
	case "gateway":
		if !extrasOnly {
			fatalHint("invalid_argument",
				"use 'pilotctl extras gateway <subcommand>' or the pilot-gateway binary",
				"gateway commands are not in the core CLI")
		}
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: start, stop, map, unmap, list",
				"missing subcommand")
		}
		switch cmdArgs[0] {
		case "start":
			cmdGatewayStart(cmdArgs[1:])
		case "stop":
			cmdGatewayStop()
		case "map":
			cmdGatewayMap(cmdArgs[1:])
		case "unmap":
			cmdGatewayUnmap(cmdArgs[1:])
		case "list":
			cmdGatewayList()
		default:
			fatalHint("invalid_argument",
				"available: start, stop, map, unmap, list",
				"unknown gateway subcommand: %s", cmdArgs[0])
		}

	// Registry
	case "register":
		cmdRegister(cmdArgs)
	case "lookup":
		cmdLookup(cmdArgs)
	case "rotate-key":
		cmdRotateKey(cmdArgs)
	case "set-public":
		cmdSetPublic(cmdArgs)
	case "set-private":
		cmdSetPrivate(cmdArgs)
	case "deregister":
		cmdDeregister(cmdArgs)
	case "verify":
		cmdVerify(cmdArgs)
	case "recovery":
		cmdRecovery(cmdArgs)
	case "sign-request":
		cmdSignRequest(cmdArgs)
	case "verify-request":
		cmdVerifyRequest(cmdArgs)

	// Discovery
	case "find":
		cmdFind(cmdArgs)
	case "set-hostname":
		cmdSetHostname(cmdArgs)
	case "clear-hostname":
		cmdClearHostname()
	case "set-tags":
		if !extrasOnly {
			fatalHint("invalid_argument", "use 'pilotctl extras set-tags'", "set-tags is not in the core CLI")
		}
		cmdSetTags(cmdArgs)
	case "clear-tags":
		if !extrasOnly {
			fatalHint("invalid_argument", "use 'pilotctl extras clear-tags'", "clear-tags is not in the core CLI")
		}
		cmdClearTags()
	case "set-webhook":
		cmdSetWebhook(cmdArgs)
	case "clear-webhook":
		cmdClearWebhook()

	// Communication
	case "connect":
		cmdConnect(cmdArgs)
	case "send":
		cmdSend(cmdArgs)
	case "dgram":
		cmdDgram(cmdArgs)
	case "recv":
		cmdRecv(cmdArgs)
	case "send-file":
		cmdSendFile(cmdArgs)
	case "send-message":
		cmdSendMessage(cmdArgs)
	case "subscribe":
		cmdSubscribe(cmdArgs)
	case "publish":
		cmdPublish(cmdArgs)

	// Trust
	case "handshake":
		cmdHandshake(cmdArgs)
	case "approve":
		cmdApprove(cmdArgs)
	case "reject":
		cmdReject(cmdArgs)
	case "untrust":
		cmdUntrust(cmdArgs)
	case "pending":
		cmdPending()
	case "trust":
		cmdTrust(cmdArgs)
	case "trusted":
		cmdTrusted(cmdArgs)
	case "prefer-direct":
		cmdPreferDirect(cmdArgs)

	// Networks
	case "network":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: list, join, leave, members, invite, invites, accept, reject, create, delete, rename, promote, demote, kick, role, policy",
				"usage: pilotctl network <subcommand>")
		}
		switch cmdArgs[0] {
		case "list":
			cmdNetworkList()
		case "join":
			cmdNetworkJoin(cmdArgs[1:])
		case "leave":
			cmdNetworkLeave(cmdArgs[1:])
		case "members":
			cmdNetworkMembers(cmdArgs[1:])
		case "invite":
			cmdNetworkInvite(cmdArgs[1:])
		case "invites":
			cmdNetworkInvites()
		case "accept":
			cmdNetworkAccept(cmdArgs[1:])
		case "reject":
			cmdNetworkReject(cmdArgs[1:])
		// Enterprise operations (direct to registry, require admin token)
		case "create":
			cmdNetworkCreate(cmdArgs[1:])
		case "delete":
			cmdNetworkDelete(cmdArgs[1:])
		case "rename":
			cmdNetworkRename(cmdArgs[1:])
		case "promote":
			cmdNetworkPromote(cmdArgs[1:])
		case "demote":
			cmdNetworkDemote(cmdArgs[1:])
		case "kick":
			cmdNetworkKick(cmdArgs[1:])
		case "role":
			cmdNetworkRole(cmdArgs[1:])
		case "policy":
			cmdNetworkPolicy(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: list, join, leave, members, invite, invites, accept, reject, create, delete, rename, promote, demote, kick, role, policy",
				"unknown network subcommand: %s", cmdArgs[0])
		}

	// Managed networks
	case "managed":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: status, cycle, reconcile",
				"usage: pilotctl managed <subcommand>")
		}
		switch cmdArgs[0] {
		case "status":
			cmdManagedStatus(cmdArgs[1:])
		case "cycle":
			cmdManagedCycle(cmdArgs[1:])
		case "reconcile":
			cmdManagedReconcile(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: status, cycle, reconcile",
				"unknown managed subcommand: %s", cmdArgs[0])
		}

	case "member-tags":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: set, get",
				"usage: pilotctl member-tags <subcommand>")
		}
		switch cmdArgs[0] {
		case "set":
			cmdMemberTagsSet(cmdArgs[1:])
		case "get":
			cmdMemberTagsGet(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: set, get",
				"unknown member-tags subcommand: %s", cmdArgs[0])
		}

	case "policy":
		if len(cmdArgs) < 1 {
			fatalHint("invalid_argument",
				"available: get, set, validate, test",
				"usage: pilotctl policy <subcommand>")
		}
		switch cmdArgs[0] {
		case "get":
			cmdPolicyGet(cmdArgs[1:])
		case "set":
			cmdPolicySet(cmdArgs[1:])
		case "validate":
			cmdPolicyValidate(cmdArgs[1:])
		case "test":
			cmdPolicyTest(cmdArgs[1:])
		default:
			fatalHint("invalid_argument",
				"available: get, set, validate, test",
				"unknown policy subcommand: %s", cmdArgs[0])
		}

	// Enterprise admin commands (direct to registry)
	case "audit":
		cmdAudit(cmdArgs)
	case "provision":
		cmdProvision(cmdArgs)
	case "deprovision":
		cmdDeprovision(cmdArgs)
	case "idp":
		cmdIDP(cmdArgs)
	case "audit-export":
		cmdAuditExport(cmdArgs)
	case "provision-status":
		cmdProvisionStatus()
	case "directory-sync":
		cmdDirectorySync(cmdArgs)
	case "directory-status":
		cmdDirectoryStatus(cmdArgs)

	// Management
	case "connections":
		cmdConnections()
	case "disconnect":
		cmdDisconnect(cmdArgs)

	// Diagnostics
	case "info":
		cmdInfo(cmdArgs)
	case "health":
		cmdHealth()
	case "peers":
		cmdPeers(cmdArgs)
	case "ping":
		cmdPing(cmdArgs)
	case "traceroute":
		cmdTraceroute(cmdArgs)
	case "bench":
		cmdBench(cmdArgs)
	case "listen":
		cmdListen(cmdArgs)
	case "broadcast":
		cmdBroadcast(cmdArgs)

	// Mailbox
	case "received":
		cmdReceived(cmdArgs)
	case "inbox":
		cmdInbox(cmdArgs)

	// Internal: forked daemon process
	case "_daemon-run":
		runDaemonInternal(cmdArgs)

	default:
		if jsonOutput {
			fatalHint("invalid_argument",
				"run 'pilotctl context' for the full command list",
				"unknown command: %s", cmd)
		}
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
	}
}

// ===================== QUICKSTART =====================

func cmdQuickstart() {
	fmt.Print(`
╔══════════════════════════════════════════════════════════════╗
║              PILOT PROTOCOL — Quickstart                   ║
╚══════════════════════════════════════════════════════════════╝

Getting started with Pilot Protocol in 3 commands:

  1. DISCOVER — see who is out there:
       pilotctl send-message list-agents --data '/data {"search":"","limit":10}' --wait

  2. TRUST   — shake hands with an agent:
       pilotctl handshake <node_id>

  3. TALK    — send your first message:
       pilotctl send-message <node_id> --data "Hello, world!" --wait

First-time setup (run once):
     pilotctl init --registry 34.71.57.205:9000
     pilotctl daemon start

For the full command list: pilotctl --help
`)
}

// ===================== BOOTSTRAP =====================

func cmdInit(args []string) {
	flags, _ := parseFlags(args)

	registryAddr := flagString(flags, "registry", "34.71.57.205:9000")
	beaconAddr := flagString(flags, "beacon", "34.71.57.205:9001")
	hostname := flagString(flags, "hostname", "")
	socketPath := flagString(flags, "socket", defaultSocket())

	cfg := loadConfig()
	cfg["registry"] = registryAddr
	cfg["beacon"] = beaconAddr
	cfg["socket"] = socketPath
	if hostname != "" {
		cfg["hostname"] = hostname
	}

	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	outputOK(map[string]interface{}{
		"config_path": configPath(),
		"registry":    registryAddr,
		"beacon":      beaconAddr,
		"socket":      socketPath,
		"hostname":    hostname,
	})
}

func cmdConfig(args []string) {
	flags, _ := parseFlags(args)

	if setVal, ok := flags["set"]; ok {
		parts := strings.SplitN(setVal, "=", 2)
		if len(parts) != 2 {
			fatalCode("invalid_argument", "usage: pilotctl config --set key=value")
		}
		// Validate the keys daemon start (and pilot-daemon, which reads
		// config.json itself) interprets, so a typo fails here rather than
		// on the next daemon start. Empty clears the key.
		value := parts[1]
		if value != "" {
			switch parts[0] {
			case "transport":
				t, err := normalizeTransport(value)
				if err == nil && t == "" {
					err = validateTransport(value)
				}
				if err != nil {
					fatalCode("invalid_argument", "config: %v", err)
				}
				value = t
			case "proxy":
				p, err := proxyconf.Normalize(value)
				if err != nil {
					fatalCode("invalid_argument", "config: %v", err)
				}
				value = p
			}
		}
		cfg := loadConfig()
		cfg[parts[0]] = value
		if value == "" && clearableConfigKeys[parts[0]] {
			// Empty clears the key: the default applies again (for
			// transport, pilotctl's auto), and nothing is left for an
			// older pilot-daemon to trip over.
			delete(cfg, parts[0])
		}
		result := map[string]interface{}{"key": parts[0], "value": value}
		// Leaving compat: an install made with a pilotctl that predated
		// --transport pointed the registry at the compat TLS host
		// (install.sh --transport compat). A udp daemon needs the raw-TCP
		// registry back (current daemons cope either way; older ones
		// would dial :443 without TLS).
		if parts[0] == "transport" && value != "compat" {
			if r, _ := cfg["registry"].(string); strings.EqualFold(strings.TrimSpace(r), compatRegistryAddr) {
				cfg["registry"] = productionRegistryAddr
				result["registry"] = productionRegistryAddr
			}
		}
		if err := saveConfig(cfg); err != nil {
			fatalCode("internal", "save config: %v", err)
		}
		if parts[0] == "proxy" {
			result["value"] = redactProxyURL(value)
		}
		outputOK(result)
		return
	}

	// Show config
	cfg := loadConfig()
	cfg["config_path"] = configPath()
	cfg["pid_file"] = pidFilePath()
	cfg["log_file"] = logFilePath()
	// Add defaults for unset values
	if _, ok := cfg["registry"]; !ok {
		cfg["registry"] = getRegistry()
	}
	if _, ok := cfg["socket"]; !ok {
		cfg["socket"] = getSocket()
	}
	// config.json is 0600 for a reason; a proxy URL may carry credentials.
	if p, ok := cfg["proxy"].(string); ok {
		cfg["proxy"] = redactProxyURL(p)
	}
	if jsonOutput {
		output(cfg)
		return
	}

	// Human mode: aligned key-value list, config_path pinned to the top
	// (it's the answer to "which file am I editing?"). Keys are padded
	// before styling so ANSI escapes don't break the column alignment.
	keys := make([]string, 0, len(cfg))
	width := len("config_path")
	for k := range cfg {
		if k == "config_path" {
			continue
		}
		keys = append(keys, k)
		if len(k) > width {
			width = len(k)
		}
	}
	sort.Strings(keys)

	renderValue := func(v interface{}) string {
		if s, ok := v.(string); ok {
			return s
		}
		b, _ := json.Marshal(v)
		return string(b)
	}
	fmt.Printf("%s  %s\n", sDim(fmt.Sprintf("%-*s", width, "config_path")), sAccent(renderValue(cfg["config_path"])))
	for _, k := range keys {
		fmt.Printf("%s  %s\n", sDim(fmt.Sprintf("%-*s", width, k)), renderValue(cfg[k]))
	}
}

// ===================== CONTEXT =====================

// contextCatalog returns the full machine-readable command catalog that
// `pilotctl context` dumps. Kept as a function so cmdContext can also
// serve single-command lookups without holding the map at package scope.
func contextCatalog() map[string]interface{} {
	return map[string]interface{}{
		"version": "1.4",
		"note":    "Core commands cover everything an agent needs. 'app_store' lists the 'pilotctl appstore <sub>' command family (install + call local capability apps). Use 'pilotctl extras <cmd>' for operator/admin operations. 'pilot-gateway' is an optional companion binary (not shipped in release tarballs; build from github.com/pilot-protocol/gateway).",

		// ── Core agent commands ──────────────────────────────────────────────
		"commands": map[string]interface{}{
			// Setup & identity
			"init": map[string]interface{}{
				"args":        []string{"--registry <addr>", "--beacon <addr>", "--hostname <name>", "[--socket <path>]"},
				"description": "Initialize pilot configuration (writes ~/.pilot/config.json)",
				"returns":     "config_path, registry, beacon, socket, hostname",
			},
			"config": map[string]interface{}{
				"args":        []string{"[--set key=value]"},
				"description": "Show or set configuration values",
				"returns":     "current configuration as JSON",
			},
			"version": map[string]interface{}{
				"args":        []string{},
				"description": "Print the installed binary version",
				"returns":     "version string",
			},
			"quickstart": map[string]interface{}{
				"args":        []string{},
				"description": "Print a fixed 3-step getting-started cheat-sheet (discover agents → handshake → send a message) plus one-time setup commands. Static output; does not inspect daemon state",
				"returns":     "static banner text (no JSON structure)",
			},
			"update": map[string]interface{}{
				"args":        []string{"[status|enable|disable]", "[--pin <tag>]"},
				"description": "Self-update. Bare: run the updater once (check + install latest). Subcommands: status, enable, disable (auto-update is OFF by default)",
				"returns":     "updated (bool), from, to | enabled (bool)",
			},
			"updates": map[string]interface{}{
				"args":        []string{"[--count <n>]", "[--scope <scope>]"},
				"description": "Read the Pilot changelog feed (release notes / important updates)",
				"returns":     "entries [{title, scope, published, summary}]",
			},
			"skills": map[string]interface{}{
				"args":        []string{"[status|paths|check|enable|disable|set-mode <mode>]"},
				"description": "Manage SKILL.md install across detected agent tools. status (default), paths (shell-friendly), check (reconcile once), enable/disable, set-mode",
				"returns":     "tools [{tool, path, installed}] | paths",
			},
			"review": map[string]interface{}{
				"args":        []string{"<pilot|app-id>", "[--rating <1-5>]", "[--text <\"...\">]"},
				"description": "Submit a rating/review for Pilot itself ('pilot') or for an installed app (e.g. io.pilot.cosift)",
				"returns":     "ok, target, rating",
			},

			// Daemon lifecycle
			"daemon start": map[string]interface{}{
				"args":        []string{"[--registry <addr>]", "[--beacon <addr>]", "[--listen <addr>]", "[--identity <path>]", "[--email <addr>]", "[--hostname <name>]", "[--log-level <level>]", "[--public]", "[--foreground]", "[--socket <path>]", "[--transport <udp|compat|auto>]", "[--proxy <auto|off|URL>]"},
				"description": "Start the daemon as a background process. Blocks until registered, then exits. The default transport is auto: UDP when it works, else compat (TLS/WSS over TCP 443 only, through $HTTPS_PROXY when set) — so UDP-blocked and proxy-only hosts work without flags. --transport udp|compat (or config transport / $PILOT_TRANSPORT) forces one",
				"returns":     "node_id, address, pid, socket, hostname, log_file, transport (as the daemon reported it), transport_auto (when auto chose it), proxy (when set, credentials redacted)",
			},
			"daemon stop": map[string]interface{}{
				"args":        []string{},
				"description": "Stop the running daemon",
				"returns":     "pid, forced (bool)",
			},
			"daemon status": map[string]interface{}{
				"args":        []string{"[--check]"},
				"description": "Check if daemon is running and responsive. --check: silent, exits 0/1",
				"returns":     "running (bool), responsive (bool), pid, node_id, address, hostname, uptime_secs, peers, connections",
			},

			// Registry / discovery
			"register": map[string]interface{}{
				"args":        []string{"[listen_addr]"},
				"description": "Register this node with the registry",
				"returns":     "node_id, address, public_key",
			},
			"deregister": map[string]interface{}{
				"args":        []string{},
				"description": "Deregister this node from the registry",
				"returns":     "status",
			},
			"lookup": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Look up a node by ID",
				"returns":     "node_id, address, real_addr, public, hostname",
			},
			"find": map[string]interface{}{
				"args":        []string{"<hostname>"},
				"description": "Discover a node by hostname",
				"returns":     "hostname, node_id, address, public",
			},
			"set-hostname": map[string]interface{}{
				"args":        []string{"<hostname>"},
				"description": "Set this node's hostname",
				"returns":     "hostname, node_id",
			},
			"set-public": map[string]interface{}{
				"args":        []string{},
				"description": "Make this node's endpoint publicly visible",
				"returns":     "status",
			},
			"set-private": map[string]interface{}{
				"args":        []string{},
				"description": "Hide this node's endpoint",
				"returns":     "status",
			},
			"rotate-key": map[string]interface{}{
				"args":        []string{},
				"description": "Rotate this node's Ed25519 identity key",
				"returns":     "node_id, address, new public_key",
			},
			"sign-request": map[string]interface{}{
				"args":        []string{"--audience <a>", "(--body-file <f> | --body-hash <64hex> | --body <string>)"},
				"description": "Sign a request-signature envelope (reqsig) proving a request originates from this node",
				"returns":     "envelope, signature, address",
			},
			"verify-request": map[string]interface{}{
				"args":        []string{"--envelope <canonical>", "--signature <b64>", "[--standing]", "[--max-skew <secs>]"},
				"description": "Verify a peer's request-signature envelope; exit code 1 when invalid",
				"returns":     "valid, node_id, address, verified_via, trusted [, online, last_seen_unix, key_generation, network_member]",
			},

			// Trust
			"handshake": map[string]interface{}{
				"args":        []string{"<node_id|hostname>", "[justification]"},
				"description": "Send a trust handshake request to a remote node",
				"returns":     "status, node_id",
			},
			"approve": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Approve a pending handshake request",
				"returns":     "status, node_id",
			},
			"reject": map[string]interface{}{
				"args":        []string{"<node_id>", "[reason]"},
				"description": "Reject a pending handshake request",
				"returns":     "status, node_id",
			},
			"pending": map[string]interface{}{
				"args":        []string{},
				"description": "List pending inbound handshake requests",
				"returns":     "pending [{node_id, justification, received_at}]",
			},
			"trust": map[string]interface{}{
				"args":        []string{},
				"description": "List all trusted peers",
				"returns":     "trusted [{node_id, mutual, network, approved_at}]",
			},
			"untrust": map[string]interface{}{
				"args":        []string{"<node_id>"},
				"description": "Revoke trust for a peer",
				"returns":     "node_id",
			},
			"trusted": map[string]interface{}{
				"args":        []string{"list"},
				"description": "List the embedded trusted-agents directory — well-known service agents (list-agents, weather, etc.) auto-approved on first contact. For live trust state use 'trust'",
				"returns":     "agents [{hostname, node_id}], total",
			},
			"prefer-direct": map[string]interface{}{
				"args":        []string{"<node_id|address|hostname>"},
				"description": "Reset routing state for a peer so the next connection prefers a direct (hole-punched) tunnel over the relay. Requires daemon v1.12+",
				"returns":     "had_tunnel, was_relay_active, was_relay_pinned",
			},

			// Identity verification & key recovery
			"verify": map[string]interface{}{
				"args":        []string{"[status]", "[--node <addr|id>]", "[--provider <name>]", "[--badge <b> --badge-sig <s>]", "[--from <file>]"},
				"description": "Verified-address badges. Bare 'verify' (or 'verify status') shows your verification state; '--provider <name>' runs a device-flow to get verified; '--badge/--badge-sig' (or '--from <file>') submits a badge",
				"returns":     "verified (bool), node_id, address, issuer | submitted",
			},
			"recovery": map[string]interface{}{
				"args":        []string{"<enroll|new-key|recover>", "..."},
				"description": "Address recovery if the identity key is lost. enroll: record a recovery commitment; new-key: rotate to a fresh key; recover: reclaim the address with recovery material",
				"returns":     "status, node_id, address",
			},

			// Networks (agent self-management)
			"network list": map[string]interface{}{
				"args":        []string{},
				"description": "List networks this node belongs to",
				"returns":     "networks [{id, name, role, members}], total",
			},
			"network join": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Join a network",
				"returns":     "network_id, status",
			},
			"network leave": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Leave a network",
				"returns":     "network_id, status",
			},
			"network members": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "List members of a network",
				"returns":     "members [{node_id, role, joined_at}], total",
			},
			"network invite": map[string]interface{}{
				"args":        []string{"<network_id>", "<target_node_id>"},
				"description": "Invite another node to a network",
				"returns":     "network_id, target_node_id, status",
			},
			"network invites": map[string]interface{}{
				"args":        []string{},
				"description": "List pending network invitations for this node",
				"returns":     "invites [{network_id, network_name, invited_by, invited_at}]",
			},
			"network accept": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Accept a network invitation",
				"returns":     "network_id, status",
			},
			"network reject": map[string]interface{}{
				"args":        []string{"<network_id>"},
				"description": "Reject a network invitation",
				"returns":     "network_id, status",
			},
			"network create": map[string]interface{}{
				"args":        []string{"--name <name>", "[--join-rule open|token|invite]", "[--token <T>]", "[--enterprise]", "[--rules <json>|--rules-file <path>]"},
				"description": "Create a new network. Pass --rules/--rules-file for policy-governed (managed) networks",
				"returns":     "network_id, name, managed (bool)",
			},

			// Messaging
			"send-message": map[string]interface{}{
				"args":        []string{"<address|hostname>", "--data <text>", "[--type text|json|binary]", "[--count <n>]", "[--reuse-conn]"},
				"description": "Send a typed message to a node via data exchange (port 1001). --count N sends N messages; --reuse-conn shares one connection across all N (env: PILOT_SENDMSG_REUSE_CONN=1). Default type: text",
				"returns":     "target, to, type, bytes, ack, reuse_conn",
			},
			"send-file": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<filepath>"},
				"description": "Send a file to a node via data exchange (port 1001)",
				"returns":     "filename, bytes, destination, ack",
			},
			"inbox": map[string]interface{}{
				"args":        []string{"[read <id>]", "[--latest]", "[--limit <n>]", "[--from <peer>]", "[--since <dur>]", "[--full]", "[--clear [--before <dur>]]"},
				"description": "List received messages newest-first (~/.pilot/inbox/). Default limit 10 with previews; --latest for the newest full body; read <id> for one message",
				"returns":     "messages [{id, from, received_at, type, bytes, preview|data}], total, shown, dir",
			},
			"received": map[string]interface{}{
				"args":        []string{"[--limit <n>]", "[--since <dur|rfc3339>]", "[--clear [--before <dur>]]"},
				"description": "List received files (~/.pilot/received/) newest-first. Default limit 10 in text mode; --clear deletes the matched set",
				"returns":     "files [{name, bytes, modified, path}], total, shown, dir",
			},

			// Pub/Sub
			"subscribe": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Subscribe to a topic on a node's event stream (port 1002). Use * for all topics. Streams NDJSON without --count",
				"returns":     "events [{topic, data, bytes}], timeout (bool)",
			},
			"publish": map[string]interface{}{
				"args":        []string{"<address|hostname>", "<topic>", "--data <message>"},
				"description": "Publish an event to a topic on a node's event stream (port 1002)",
				"returns":     "target, topic, bytes",
			},

			// Diagnostics
			"info": map[string]interface{}{
				"args":        []string{},
				"description": "Show daemon status: node_id, address, uptime, peers, connections, encryption",
				"returns":     "node_id, address, hostname, uptime_secs, connections, peers, encrypt, bytes_sent, bytes_recv, conn_list, peer_list",
			},
			"ping": map[string]interface{}{
				"args":        []string{"<address|hostname>", "[--count <n>]", "[--timeout <dur>]"},
				"description": "Ping a node via echo port (port 7). Default 4 pings",
				"returns":     "target, to, results [{seq, bytes, rtt_ms, error}], timeout (bool)",
			},
		},

		// ── pilot-gateway binary ─────────────────────────────────────────────
		"pilot_gateway": map[string]interface{}{
			"binary":      "pilot-gateway",
			"description": "IP gateway — bridges standard TCP/IP applications to Pilot Protocol addresses. Optional companion binary: not shipped in release tarballs, build from github.com/pilot-protocol/gateway.",
			"commands": map[string]interface{}{
				"start": map[string]interface{}{
					"args":        []string{"[--subnet <cidr>]", "[--ports <list>]", "[<pilot-addr>...]"},
					"description": "Start the IP gateway",
					"returns":     "pid, subnet, mappings [{local_ip, pilot_addr}]",
				},
				"stop": map[string]interface{}{
					"args":        []string{},
					"description": "Stop the running gateway",
					"returns":     "pid",
				},
				"map": map[string]interface{}{
					"args":        []string{"<pilot-addr>", "[local-ip]"},
					"description": "Add a Pilot-address → local-IP mapping",
					"returns":     "local_ip, pilot_addr",
				},
				"unmap": map[string]interface{}{
					"args":        []string{"<local-ip>"},
					"description": "Remove a mapping and release the loopback alias",
					"returns":     "unmapped",
				},
				"list": map[string]interface{}{
					"args":        []string{},
					"description": "List active gateway mappings",
					"returns":     "mappings [{local_ip, pilot_addr}], total",
				},
			},
		},

		// ── App store ────────────────────────────────────────────────────────
		// Invoke as: pilotctl appstore <subcommand> [args...]
		"app_store": map[string]interface{}{
			"description": "Install and call local capability apps that run on the daemon as typed IPC services. All invoked as: pilotctl appstore <subcommand>. Install root: $PILOT_APPSTORE_ROOT or ~/.pilot/apps.",
			"subcommands": map[string]interface{}{
				"catalogue":      map[string]interface{}{"args": []string{}, "description": "List apps available for one-command install (alias: catalog)"},
				"view":           map[string]interface{}{"args": []string{"<id>", "[--all-changelog]"}, "description": "Detail page: description, vendor, changelog, size, source, methods, permissions (installed or not)"},
				"install":        map[string]interface{}{"args": []string{"<app-id> [--force]", "| <bundle-dir> --local [--force]"}, "description": "Install by catalogue ID (fetch + verify + extract), or sideload a local bundle with --local"},
				"list":           map[string]interface{}{"args": []string{}, "description": "List installed apps and the IPC methods each exposes"},
				"call":           map[string]interface{}{"args": []string{"<id>", "<method>", "[json-args]", "[--timeout <dur>]"}, "description": "Dispatch an IPC call into an app (default timeout 120s; $PILOT_APPSTORE_CALL_TIMEOUT)"},
				"status":         map[string]interface{}{"args": []string{"<id>"}, "description": "Deep-dive on one app's pinned state"},
				"caps":           map[string]interface{}{"args": []string{"<id>"}, "description": "Show the manifest's spend caps and current rolling-window usage"},
				"audit":          map[string]interface{}{"args": []string{"<id>", "[--tail <n>]", "[--event <name>]", "[--since <dur>]"}, "description": "Show the supervisor lifecycle log (spawn/exit/suspend/verify-fail)"},
				"actions":        map[string]interface{}{"args": []string{"[--tail <n>]", "[--event <name>]"}, "description": "Show the pilotctl-side install/uninstall action log (survives app removal)"},
				"restart":        map[string]interface{}{"args": []string{"<id>"}, "description": "Clear crash-loop suspension and respawn the app"},
				"uninstall":      map[string]interface{}{"args": []string{"<id>", "--yes"}, "description": "Remove an installed app from the install root"},
				"verify":         map[string]interface{}{"args": []string{"<bundle-dir>"}, "description": "sha256-check a pre-install bundle against its manifest"},
				"gen-key":        map[string]interface{}{"args": []string{"<key-file>"}, "description": "Generate a fresh ed25519 publisher keypair (publisher tooling)"},
				"sign":           map[string]interface{}{"args": []string{"--key <key-file>", "<manifest>"}, "description": "Sign (or re-sign) a manifest's store.signature (publisher tooling)"},
				"sign-catalogue": map[string]interface{}{"args": []string{"--key <key-file>", "<catalogue.json>"}, "description": "Sign the catalogue, writing a detached .sig (alias: sign-catalog; publisher tooling)"},
			},
		},

		// ── Extras (operator / admin) ────────────────────────────────────────
		// Invoke as: pilotctl extras <command> [args...]
		"extras": map[string]interface{}{
			"description": "Operator and admin commands. All invoked as: pilotctl extras <command> [args]. Not intended for autonomous agent use.",
			"commands": map[string]interface{}{
				// Network admin
				"network delete":  map[string]interface{}{"args": []string{"<network_id>"}, "description": "Delete a network (admin)"},
				"network rename":  map[string]interface{}{"args": []string{"<network_id>", "<new_name>"}, "description": "Rename a network (admin)"},
				"network promote": map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Promote a member to admin"},
				"network demote":  map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Demote an admin to member"},
				"network kick":    map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Remove a member from a network"},
				"network role":    map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Get a member's role"},
				"network policy":  map[string]interface{}{"args": []string{"<network_id>", "[--set <json>]"}, "description": "Get or set network policy"},
				// Policy engine
				"policy get":      map[string]interface{}{"args": []string{"<network_id>"}, "description": "Get the active policy for a managed network"},
				"policy set":      map[string]interface{}{"args": []string{"<network_id>", "--file <path>|--expr <expr>"}, "description": "Set the active policy"},
				"policy validate": map[string]interface{}{"args": []string{"--file <path>|--expr <expr>"}, "description": "Validate a policy expression locally"},
				"policy test":     map[string]interface{}{"args": []string{"--file <path>", "--input <json>"}, "description": "Test a policy against sample input"},
				// Managed networks
				"managed status":    map[string]interface{}{"args": []string{"<network_id>"}, "description": "Status of a managed network (cycle count, last run, member count)"},
				"managed cycle":     map[string]interface{}{"args": []string{"<network_id>"}, "description": "Force a policy evaluation cycle"},
				"managed reconcile": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Reconcile member state against registry"},
				// Member tags
				"member-tags get": map[string]interface{}{"args": []string{"<network_id>", "<node_id>"}, "description": "Get tags for a network member"},
				"member-tags set": map[string]interface{}{"args": []string{"<network_id>", "<node_id>", "--tags <csv>"}, "description": "Set tags for a network member (requires admin token)"},
				// Enterprise / provisioning
				"audit":            map[string]interface{}{"args": []string{"<network_id>", "[--limit <n>]"}, "description": "Fetch audit log for a network (requires admin token)"},
				"provision":        map[string]interface{}{"args": []string{"--file <blueprint>"}, "description": "Provision a new network from a blueprint (requires admin token)"},
				"deprovision":      map[string]interface{}{"args": []string{"<network_id>"}, "description": "Delete a managed network and its data (requires admin token)"},
				"provision-status": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Check provisioning job status (requires admin token)"},
				"idp":              map[string]interface{}{"args": []string{"[--set <json>]"}, "description": "Get or set IdP configuration (requires admin token)"},
				"audit-export":     map[string]interface{}{"args": []string{"[--set <json>]"}, "description": "Get or set audit export config (requires admin token)"},
				"directory-sync":   map[string]interface{}{"args": []string{"<network_id>", "--file <csv>"}, "description": "Sync directory entries into a managed network (requires admin token)"},
				"directory-status": map[string]interface{}{"args": []string{"<network_id>"}, "description": "Check last directory sync status (requires admin token)"},
				// Node config (setup-time, not runtime agent ops)
				"set-tags":       map[string]interface{}{"args": []string{"<tag1>", "[tag2...]"}, "description": "Set discovery tags (max 3) for registry filtering"},
				"clear-tags":     map[string]interface{}{"args": []string{}, "description": "Clear all discovery tags"},
				"clear-hostname": map[string]interface{}{"args": []string{}, "description": "Clear this node's hostname"},
				"set-webhook":    map[string]interface{}{"args": []string{"<url>"}, "description": "Set webhook URL for event push notifications"},
				"clear-webhook":  map[string]interface{}{"args": []string{}, "description": "Clear the webhook URL"},
				// Low-level / plumbing
				"connect":   map[string]interface{}{"args": []string{"<address|hostname>", "[port]", "[--message <msg>]"}, "description": "Open a raw stream connection"},
				"send":      map[string]interface{}{"args": []string{"<address|hostname>", "<port>", "--data <msg>"}, "description": "Send a single raw message to a port"},
				"recv":      map[string]interface{}{"args": []string{"<port>", "[--count <n>]"}, "description": "Accept and print incoming stream messages"},
				"dgram":     map[string]interface{}{"args": []string{"<address|hostname>", "<port>", "--data <msg>"}, "description": "Send a UDP-style datagram"},
				"listen":    map[string]interface{}{"args": []string{"<port>", "[--count <n>]"}, "description": "Listen for incoming datagrams"},
				"broadcast": map[string]interface{}{"args": []string{"<network_id>", "<message>"}, "description": "Broadcast a datagram to all network members"},
				// Connection management
				"connections": map[string]interface{}{"args": []string{}, "description": "List active daemon connections"},
				"disconnect":  map[string]interface{}{"args": []string{"<conn_id>"}, "description": "Close a connection by ID"},
				// Diagnostics
				"health":     map[string]interface{}{"args": []string{}, "description": "Compact health summary (subset of info)"},
				"peers":      map[string]interface{}{"args": []string{"[--search <query>]"}, "description": "List connected peers"},
				"traceroute": map[string]interface{}{"args": []string{"<address>"}, "description": "Trace path to a node"},
				"bench":      map[string]interface{}{"args": []string{"<address|hostname>", "[size_mb]"}, "description": "Throughput benchmark via echo port"},
			},
		},

		"error_codes": map[string]interface{}{
			"invalid_argument":  "Bad input or usage error (do not retry)",
			"not_found":         "Resource not found (hostname/name resolve failure)",
			"already_exists":    "Duplicate operation (daemon/gateway already running)",
			"not_running":       "Service not available (daemon/gateway not running)",
			"connection_failed": "Network or dial failure (may retry)",
			"timeout":           "Operation timed out (may retry with longer timeout)",
			"internal":          "Unexpected system error",
		},
		"global_flags": map[string]interface{}{
			"--json": "Output structured JSON for all commands. Success: {status:ok, data:{...}}. Error: {status:error, code:string, message:string}",
		},
		"environment": map[string]interface{}{
			"PILOT_REGISTRY":  "Registry address (default: 34.71.57.205:9000)",
			"PILOT_SOCKET":    "Daemon socket path (default: /tmp/pilot.sock)",
			"PILOT_TRANSPORT": "daemon start transport: udp, compat (TCP 443 only) or auto",
			"PILOT_PROXY":     "proxy policy: auto, off, or http(s)://[user:pass@]host:port (beats config.json)",
			"HTTPS_PROXY":     "proxy for compat mode (proxy=auto) and pilotctl's own connections; forwarded to the daemon",
		},
		"config_file": "~/.pilot/config.json",
	}
}

// cmdContext prints the full command catalog, or — with a positional
// argument — only that command's entry: `pilotctl context send-message`
// returns the one JSON object instead of the whole ~18 KB dump.
// Multi-word commands work too: `pilotctl context daemon start`.
func cmdContext(args []string) {
	ctx := contextCatalog()
	_, pos := parseFlags(args)
	if len(pos) == 0 {
		output(ctx)
		return
	}
	name := strings.Join(pos, " ")
	commands, _ := ctx["commands"].(map[string]interface{})
	if entry, ok := commands[name]; ok {
		output(entry)
		return
	}
	// Fall back to the extras and gateway catalogs so e.g.
	// `pilotctl context policy set` resolves too.
	for _, section := range []string{"extras", "pilot_gateway"} {
		sec, _ := ctx[section].(map[string]interface{})
		cmds, _ := sec["commands"].(map[string]interface{})
		if entry, ok := cmds[name]; ok {
			output(entry)
			return
		}
	}
	valid := make([]string, 0, len(commands))
	for k := range commands {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	fatalCode("not_found", "unknown command %q — valid: %s (extras/gateway names also accepted)",
		name, strings.Join(valid, ", "))
}

func cmdExtrasHelp() {
	fmt.Println("pilotctl extras <command> [args...]")
	fmt.Println()
	fmt.Println("Operator and admin commands. Run 'pilotctl context' for the full list.")
	fmt.Println()
	fmt.Println("Network admin:  network delete/rename/promote/demote/kick/role/policy")
	fmt.Println("Policy engine:  policy get/set/validate/test")
	fmt.Println("Managed nets:   managed status/cycle/reconcile")
	fmt.Println("Member tags:    member-tags get/set")
	fmt.Println("Enterprise:     audit provision deprovision idp audit-export provision-status directory-sync directory-status")
	fmt.Println("Node config:    set-tags clear-tags clear-hostname set-webhook clear-webhook")
	fmt.Println("Low-level:      connect send recv dgram listen broadcast")
	fmt.Println("Connections:    connections disconnect")
	fmt.Println("Diagnostics:    health peers traceroute bench")
}

// ===================== DAEMON LIFECYCLE =====================

// findCompanionBinary locates a sibling binary distributed alongside
// pilotctl. Discovery order:
//
//  1. If $envVar is set, use that path verbatim.
//  2. Look next to the running pilotctl executable (os.Executable()).
//  3. Fall back to PATH lookup via exec.LookPath.
//
// Returns a clear error mentioning the env override and where pilotctl
// looked. This is the binary discovery contract for the daemon and
// gateway exec paths; it removes the need for cmd/pilotctl to import
// the L11 plugin packages and serve as a second composition root.
func findCompanionBinary(name, envVar string) (string, error) {
	if v := os.Getenv(envVar); v != "" {
		return v, nil
	}
	self, err := os.Executable()
	if err == nil {
		// Resolve symlinks so the sibling lookup follows e.g. Homebrew
		// shims. If EvalSymlinks fails we fall back to the raw path —
		// not fatal.
		if resolved, err2 := filepath.EvalSymlinks(self); err2 == nil {
			self = resolved
		}
		candidate := filepath.Join(filepath.Dir(self), name)
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	siblingHint := ""
	if self != "" {
		siblingHint = fmt.Sprintf(" (expected sibling at %s)", filepath.Join(filepath.Dir(self), name))
	}
	return "", fmt.Errorf("%s not found%s or in PATH; set %s to override", name, siblingHint, envVar)
}

// daemonBinaryPath resolves the pilot-daemon binary.
func daemonBinaryPath() string {
	path, err := findCompanionBinary("pilot-daemon", "PILOT_DAEMON_BIN")
	if err != nil {
		fatalCode("internal", "%v", err)
	}
	return path
}

// gatewayBinaryPath resolves the pilot-gateway binary.
func gatewayBinaryPath() string {
	path, err := findCompanionBinary("pilot-gateway", "PILOT_GATEWAY_BIN")
	if err != nil {
		fatalHint("not_found",
			"pilot-gateway no longer ships in release tarballs — build it from github.com/pilot-protocol/gateway, place it next to pilotctl or on $PATH, or set PILOT_GATEWAY_BIN",
			"%v", err)
	}
	return path
}

// daemonLaunchPlan is everything `pilotctl daemon start` hands to
// pilot-daemon: its argv (without argv[0]) plus the values that travel in
// the child environment instead of on the command line.
type daemonLaunchPlan struct {
	Args       []string
	SocketPath string
	// AdminToken is passed as $PILOT_ADMIN_TOKEN, never on argv (PILOT-290).
	AdminToken string
	// Transport is the resolved --transport ("" = not configured:
	// cmdDaemonStart asks a daemon that supports it for auto).
	Transport string
	// Proxy is the resolved --proxy ("" = daemon default, auto).
	Proxy string
	// ProxyEnv is non-empty when Proxy carries credentials: it is handed to
	// the daemon as $PILOT_PROXY instead of -proxy on argv (PILOT-290).
	ProxyEnv string
}

// buildDaemonArgs translates pilotctl-style flags into pilot-daemon CLI
// args, applying defaults from ~/.pilot/config.json when CLI flags are
// unset. This keeps existing pilotctl invocations working unchanged —
// the only difference is that the daemon runs in a separate
// `pilot-daemon` process rather than re-execing pilotctl.
func buildDaemonArgs(args []string) (daemonArgs []string, socketPath string, adminToken string) {
	plan := planDaemonLaunch(args)
	return plan.Args, plan.SocketPath, plan.AdminToken
}

// planDaemonLaunch resolves pilotctl flags, environment and config.json into
// a daemonLaunchPlan. Precedence for every setting is CLI flag, then (where
// one exists) its environment variable, then config.json, then the daemon's
// own default.
func planDaemonLaunch(args []string) daemonLaunchPlan {
	flags, _ := parseFlags(args)

	cfg := loadConfig()

	transport, err := resolveDaemonTransport(flags, cfg)
	if err != nil {
		fatalCode("invalid_argument", "daemon start: %v", err)
	}
	proxy, err := resolveDaemonProxy(flags, cfg)
	if err != nil {
		fatalCode("invalid_argument", "daemon start: %v", err)
	}

	socketPath := flagString(flags, "socket", "")
	if socketPath == "" {
		socketPath = getSocket()
	}

	registryAddr := flagString(flags, "registry", "")
	if registryAddr == "" {
		if r, ok := cfg["registry"].(string); ok {
			registryAddr = r
		} else {
			registryAddr = getRegistry()
		}
	}
	beaconAddr := flagString(flags, "beacon", "")
	if beaconAddr == "" {
		if b, ok := cfg["beacon"].(string); ok {
			beaconAddr = b
		} else {
			beaconAddr = getBeacon()
		}
	}
	listenAddr := flagString(flags, "listen", ":0")
	hostname := flagString(flags, "hostname", "")
	if hostname == "" {
		if h, ok := cfg["hostname"].(string); ok {
			hostname = h
		}
	}
	encrypt := !flagBool(flags, "no-encrypt")
	identityPath := flagString(flags, "identity", "")
	if identityPath == "" {
		identityPath = configDir() + "/identity.json"
	}
	email := flagString(flags, "email", "")
	owner := flagString(flags, "owner", "")
	if email == "" && owner != "" {
		email = owner // backward compat: -owner as fallback for -email
	}
	if email == "" {
		if e, ok := cfg["email"].(string); ok {
			email = e
		}
	}
	configFile := flagString(flags, "config", "")
	logLevel := flagString(flags, "log-level", "info")
	logFormat := flagString(flags, "log-format", "text")
	public := flagBool(flags, "public")
	webhookURL := flagString(flags, "webhook", "")
	if webhookURL == "" {
		if w, ok := cfg["webhook"].(string); ok {
			webhookURL = w
		}
	}
	adminToken := flagString(flags, "admin-token", "")
	if adminToken == "" {
		if a, ok := cfg["admin_token"].(string); ok {
			adminToken = a
		}
	}
	networks := flagString(flags, "networks", "")
	if networks == "" {
		if n, ok := cfg["networks"].(string); ok {
			networks = n
		}
	}
	trustAutoApprove := flagBool(flags, "trust-auto-approve")
	enterpriseControl := flagString(flags, "enterprise-control", "")
	if enterpriseControl == "" {
		if value, ok := cfg["enterprise_control"].(string); ok {
			enterpriseControl = strings.TrimSpace(value)
		}
	}

	var daemonArgs []string
	// In compat mode the raw-TCP production registry/beacon defaults are
	// left off argv so pilot-daemon applies its 443-only compat defaults
	// (registry.pilotprotocol.network:443 over TLS). Any other address is
	// an operator choice and is forwarded verbatim.
	if !compatSkipsDefault(transport, registryAddr, productionRegistryAddr) {
		daemonArgs = append(daemonArgs, "--registry", registryAddr)
	}
	if !compatSkipsDefault(transport, beaconAddr, productionBeaconAddr) {
		daemonArgs = append(daemonArgs, "--beacon", beaconAddr)
	}
	daemonArgs = append(daemonArgs,
		"--listen", listenAddr,
		"--socket", socketPath,
		"--identity", identityPath,
		"--log-level", logLevel,
		"--log-format", logFormat,
	)
	// pilot-daemon's encrypt flag defaults to true; pass `=false`
	// only when --no-encrypt was supplied.
	if !encrypt {
		daemonArgs = append(daemonArgs, "--encrypt=false")
	}
	if email != "" {
		daemonArgs = append(daemonArgs, "--email", email)
	}
	if hostname != "" {
		daemonArgs = append(daemonArgs, "--hostname", hostname)
	}
	if configFile != "" {
		daemonArgs = append(daemonArgs, "--config", configFile)
	}
	if public {
		daemonArgs = append(daemonArgs, "--public")
	}
	if webhookURL != "" {
		daemonArgs = append(daemonArgs, "--webhook", webhookURL)
	}
	// adminToken is passed via PILOT_ADMIN_TOKEN env var to avoid
	// leaking the secret in /proc/<pid>/cmdline (PILOT-290).
	if networks != "" {
		daemonArgs = append(daemonArgs, "--networks", networks)
	}
	if trustAutoApprove {
		daemonArgs = append(daemonArgs, "--trust-auto-approve")
	}
	if enterpriseControl != "" {
		daemonArgs = append(daemonArgs, "--enterprise-control", enterpriseControl)
	}
	// Daemon flags that are forwarded only when given, so a plain
	// `daemon start` keeps the daemon's own defaults. --endpoint and the
	// motd pair were documented here for a long time but never forwarded.
	for _, name := range []string{"endpoint", "compat-beacon", "registry-trust", "registry-fingerprint", "tls-trust", "motd-feed-url", "motd-interval"} {
		if v, ok := flags[name]; ok {
			daemonArgs = append(daemonArgs, "--"+name, v)
		}
	}
	// --transport / --proxy are passed only when set, so a new pilotctl
	// still starts an older daemon that predates them (cmdDaemonStart
	// additionally drops any the daemon binary does not define).
	if transport != "" {
		daemonArgs = append(daemonArgs, "--transport", transport)
	}
	proxyEnv := ""
	if proxy != "" {
		if proxyHasCredentials(proxy) {
			proxyEnv = proxy
		} else {
			daemonArgs = append(daemonArgs, "--proxy", proxy)
		}
	}
	return daemonLaunchPlan{
		Args:       daemonArgs,
		SocketPath: socketPath,
		AdminToken: adminToken,
		Transport:  transport,
		Proxy:      proxy,
		ProxyEnv:   proxyEnv,
	}
}

// launchdAgentLabels enumerates known launchd labels for the daemon.
// install.sh renamed `com.vulturelabs.pilot-daemon` to
// `network.pilotprotocol.pilot-daemon`; the uninstall path handles both
// for backward compat, and so does pilotctl. The first match wins.
var launchdAgentLabels = []string{
	"network.pilotprotocol.pilot-daemon",
	"com.vulturelabs.pilot-daemon",
}

// launchdAgentPlist returns the path to the per-user launchd plist that
// install.sh creates on macOS, if it exists; otherwise "". When non-empty
// the daemon's lifecycle is owned by launchd (not by the PID file pilotctl
// writes when it forks the daemon itself), and stop/start must go through
// launchctl so KeepAlive doesn't immediately respawn what we kill.
// Returns the plist path AND the label embedded in it.
func launchdAgentPlist() (path, label string) {
	if runtime.GOOS != "darwin" {
		return "", ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}
	for _, lbl := range launchdAgentLabels {
		p := filepath.Join(home, "Library", "LaunchAgents", lbl+".plist")
		if _, err := os.Stat(p); err == nil {
			return p, lbl
		}
	}
	return "", ""
}

// launchdAgentDomainTarget returns the gui/<UID>/<label> target used by
// `launchctl bootout` / `launchctl kickstart`.
func launchdAgentDomainTarget(label string) string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), label)
}

// launchdAgentLoaded reports whether the launchd label is currently
// loaded in the user's gui domain (i.e. plist registered, KeepAlive etc.
// are active even if the underlying process is briefly between restarts).
func launchdAgentLoaded(label string) bool {
	if label == "" {
		return false
	}
	out, err := exec.Command("launchctl", "list", label).Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}

func cmdDaemonStart(args []string) {
	flags, _ := parseFlags(args)

	// Resolve (and validate) the launch before touching the PID file, so a
	// bad --transport / --proxy fails fast with nothing to clean up.
	plan := planDaemonLaunch(args)

	// macOS install.sh installs a launchd plist. When present, route start
	// through launchctl so the agent is registered and KeepAlive supervises
	// the process; otherwise `pilotctl daemon stop` would have nothing to
	// stop (KeepAlive immediately respawns) and the user sees flapping.
	if plist, label := launchdAgentPlist(); plist != "" {
		// launchd starts the daemon from the plist's ProgramArguments and
		// its own environment: neither CLI flags nor this shell's proxy
		// variables reach it. The daemon does read config.json itself.
		if _, ok := flags["transport"]; ok && !jsonOutput {
			fmt.Fprintf(os.Stderr, "warning: --transport is not applied to the launchd-managed daemon; persist it with: pilotctl config --set transport=%s\n", plan.Transport)
		}
		if _, ok := flags["proxy"]; ok && !jsonOutput {
			fmt.Fprintf(os.Stderr, "warning: --proxy is not applied to the launchd-managed daemon; persist it with: pilotctl config --set proxy=<auto|off|URL>\n")
		}
		if launchdAgentLoaded(label) {
			fatalHint("already_exists",
				"stop it first with: pilotctl daemon stop",
				"daemon is already running (launchd agent %s loaded)", label)
		}
		if err := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), plist).Run(); err != nil {
			fatalCode("internal", "launchctl bootstrap: %v", err)
		}
		// Poll socket until daemon is responsive. 30s, not 10s: a daemon
		// with installed app-store apps spawns them before IPC comes up,
		// which can push readiness past 10s on a loaded machine — and a
		// premature "not ready" here reads as a failed start even though
		// launchd keeps supervising and the daemon finishes booting fine.
		waitDeadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(waitDeadline) {
			if d, err := driver.Connect(getSocket()); err == nil {
				if _, err := d.Info(); err == nil {
					d.Close()
					if jsonOutput {
						outputOK(map[string]interface{}{"managed_by": "launchd", "label": label})
					} else {
						fmt.Printf("daemon started via launchd (label %s)\n  Socket: %s\n", label, getSocket())
					}
					return
				}
				d.Close()
			}
			time.Sleep(200 * time.Millisecond)
		}
		fatalHint("timeout",
			"launchd is still supervising it — check `pilotctl daemon status` and the daemon log",
			"launchd loaded the agent but the socket did not become ready within 30s")
	}

	// Check if already running
	if pid := readPID(); pid > 0 {
		if pidLooksLikeDaemon(pid) {
			fatalHint("already_exists",
				"stop it first with: pilotctl daemon stop",
				"daemon is already running (pid %d)", pid)
		}
		// Stale PID file (dead daemon, or the PID was recycled by an
		// unrelated process) — clean up silently.
		os.Remove(pidFilePath())
	} else if _, err := os.Stat(pidFilePath()); err == nil {
		// The file exists but holds no usable PID (empty, garbage, or the
		// literal "0" a pre-fix --foreground start left behind and never
		// replaced). That is never a live daemon — but before this branch
		// existed, the O_EXCL claim below failed on it with "PID file
		// locked" FOREVER, turning any crash of a --foreground daemon
		// (systemd units) into a permanent restart loop that respawn
		// could not clear. Remove it so the claim can proceed.
		os.Remove(pidFilePath())
	}

	// Atomically claim the PID file to prevent concurrent daemon starts.
	// O_CREAT|O_EXCL ensures only one pilotctl daemon start can succeed;
	// a second concurrent invocation fails here before spawning a daemon.
	// The config dir must exist first: on a fresh HOME (no `pilotctl init`,
	// no ~/.pilot/bin) the open failed with ENOENT and was misreported as
	// "PID file locked" on every attempt.
	_ = os.MkdirAll(configDir(), 0700)
	if f, err := os.OpenFile(pidFilePath(), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600); err != nil {
		fatalHint("already_exists",
			"stop it first with: pilotctl daemon stop",
			"another daemon start is in progress (PID file locked)")
	} else {
		_, _ = f.WriteString("0\n")
		f.Close()
	}

	socketPath := plan.SocketPath

	// Clean up stale socket
	if _, err := os.Stat(socketPath); err == nil {
		// Try to connect — if it works, daemon is running
		d, err := driver.Connect(socketPath)
		if err == nil {
			d.Close()
			fatalHint("already_exists",
				"stop it first with: pilotctl daemon stop",
				"daemon is already running (socket %s is active)", socketPath)
		}
		// Stale socket — clean up silently
		os.Remove(socketPath)
	}

	daemonBin := daemonBinaryPath()
	// Fit the launch to the daemon binary (probed once): never hand an
	// older daemon a flag or value it does not define — Go's flag package
	// would abort it on startup — and ask a current one for
	// -transport=auto when no transport is configured.
	daemonArgs, proxyEnv, requestedTransport := adaptDaemonArgs(daemonBin, plan)
	daemonEnv := daemonChildEnv(os.Environ(), plan.AdminToken, proxyEnv, requestedTransport)

	// --foreground: replace the current process so signal/lifetime
	// handling matches what the user expects from systemd unit files
	// or shell wrappers.
	if flagBool(flags, "foreground") {
		// Record OUR pid as the daemon's: syscall.Exec replaces the
		// process image but keeps the PID, so after the exec this IS the
		// daemon's pid. Without this the file kept the "0" placeholder
		// from the claim above forever — `status` showed "pid file
		// stale", and after any crash the next start found a file with
		// no usable PID and died on the O_EXCL claim ("PID file
		// locked"), an unrecoverable restart loop under systemd.
		_ = os.WriteFile(pidFilePath(), []byte(strconv.Itoa(os.Getpid())+"\n"), 0600)
		// syscall.Exec needs argv[0] to be the binary name. Pass the
		// full env (daemonChildEnv) — it carries PILOT_ADMIN_TOKEN so the
		// daemon doesn't need the token on its argv (PILOT-290).
		execArgs := append([]string{daemonBin}, daemonArgs...)
		if err := syscall.Exec(daemonBin, execArgs, daemonEnv); err != nil {
			fatalCode("internal", "exec %s: %v", daemonBin, err)
		}
		return
	}

	// Fork: spawn the daemon detached, redirect output to the log
	// file, then poll the socket until the daemon is ready.
	//
	// Per-PID log files: we write to a temp path first (so we have an fd
	// before knowing the PID), then rename to pilot-{pid}.log once the
	// process is started. pilot.log is updated to a symlink so existing
	// tooling ("tail -f ~/.pilot/pilot.log") keeps working.
	os.MkdirAll(configDir(), 0700)
	// Use a fixed temp name so concurrent starts don't collide.
	tmpLogPath := configDir() + "/pilot-starting.log"
	logFile, err := os.OpenFile(tmpLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		fatalCode("internal", "open log file: %v", err)
	}

	proc := exec.Command(daemonBin, daemonArgs...)
	proc.Stdout = logFile
	proc.Stderr = logFile
	proc.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// Full environment plus overrides (daemonChildEnv): the proxy
	// variables in daemonForwardEnv must reach the daemon, and the admin
	// token travels via env, not argv, to avoid leaking in
	// /proc/<pid>/cmdline (PILOT-290).
	proc.Env = daemonEnv

	if err := proc.Start(); err != nil {
		fatalCode("internal", "start daemon: %v", err)
	}

	pid := proc.Process.Pid
	os.WriteFile(pidFilePath(), []byte(strconv.Itoa(pid)), 0600)

	// Rename the temp log to pilot-{pid}.log. The child's fd follows the
	// inode, so it continues writing to the same file after the rename.
	pidLogPath := configDir() + "/pilot-" + strconv.Itoa(pid) + ".log"
	logFile.Close()
	os.Rename(tmpLogPath, pidLogPath)
	// Update pilot.log symlink to point at the current PID's log.
	// Atomically replace via temp file to avoid TOCTOU race (the
	// gap between Remove and Symlink is exploitable by a local
	// attacker with write access to the config directory).
	symPath := logFilePath()
	tmpSymPath := symPath + ".tmp"
	os.Remove(tmpSymPath) // clean stale temp from prior crash
	os.Symlink(pidLogPath, tmpSymPath)
	os.Rename(tmpSymPath, symPath)

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "starting daemon (pid %d, socket %s)...", pid, socketPath)
	}

	// Wait for daemon to become ready (socket appears and responds).
	// compat (and auto, which may pick it) registers over TLS and brings
	// up the WSS tunnel, possibly through a proxy: allow it more time.
	defaultWait := 15 * time.Second
	if requestedTransport == "compat" || requestedTransport == "auto" {
		defaultWait = 30 * time.Second
	}
	waitDur := flagDuration(flags, "wait", defaultWait)
	deadline := time.Now().Add(waitDur)
	dots := 0
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		dots++
		if !jsonOutput && dots%5 == 0 { // every second
			fmt.Fprint(os.Stderr, ".")
		}
		d, err := driver.Connect(socketPath)
		if err != nil {
			continue
		}
		info, err := d.Info()
		d.Close()
		if err != nil {
			continue
		}
		if !jsonOutput {
			fmt.Fprintln(os.Stderr) // end the dots line
		}
		// Daemon is ready — show a friendly summary
		nodeID := int(info["node_id"].(float64))
		address := info["address"]
		hn, _ := info["hostname"].(string)
		if jsonOutput {
			fields := map[string]interface{}{
				"pid":      pid,
				"node_id":  nodeID,
				"address":  address,
				"hostname": hn,
				"socket":   socketPath,
				"log_file": pidLogPath,
			}
			if t, auto := effectiveTransport(requestedTransport, pidLogPath); t != "" || auto {
				if t != "" {
					fields["transport"] = t
				}
				if auto {
					fields["transport_auto"] = true
				}
			}
			if plan.Proxy != "" {
				fields["proxy"] = redactProxyURL(plan.Proxy)
			}
			outputOK(fields)
		} else {
			fmt.Printf("Daemon running (pid %d)\n", pid)
			fmt.Printf("  Address:  %s\n", address)
			if hn != "" {
				fmt.Printf("  Hostname: %s\n", hn)
			}
			if t, auto := effectiveTransport(requestedTransport, pidLogPath); t != "" {
				if auto {
					t += " (auto)"
				}
				fmt.Printf("  Transport: %s\n", t)
			}
			if plan.Proxy != "" {
				fmt.Printf("  Proxy:    %s\n", redactProxyURL(plan.Proxy))
			}
			fmt.Printf("  Socket:   %s\n", socketPath)
			fmt.Printf("  Logs:     %s\n", pidLogPath)
		}
		return
	}

	if !jsonOutput {
		fmt.Fprintln(os.Stderr) // end the dots line
	}

	fatalHint("timeout",
		fmt.Sprintf("check logs: tail -f %s", pidLogPath),
		"daemon started (pid %d) but did not become ready within %s", pid, waitDur)
}

func cmdDaemonStop() {
	// macOS install.sh installs a launchd plist with KeepAlive=true. When
	// we own it via launchd, SIGTERM to the PID respawns the process
	// immediately — the right way to stop is `launchctl bootout`. Detect
	// this case before falling back to PID-file management.
	if plist, label := launchdAgentPlist(); plist != "" && launchdAgentLoaded(label) {
		if err := exec.Command("launchctl", "bootout", launchdAgentDomainTarget(label)).Run(); err != nil {
			fatalCode("internal", "launchctl bootout: %v", err)
		}
		// Wait for the daemon socket to disappear (launchd reaps the
		// process); the agent stays unloaded across reboots until the
		// user calls `pilotctl daemon start` (bootstrap) again.
		waitDeadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(waitDeadline) {
			if !launchdAgentLoaded(label) {
				if jsonOutput {
					outputOK(map[string]interface{}{"managed_by": "launchd", "label": label})
				} else {
					fmt.Printf("daemon stopped (launchd agent %s unloaded)\n", label)
				}
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		fatalCode("timeout", "launchctl bootout returned but agent did not unload within 10s")
	}

	pid := readPID()
	discovered := false
	if pid <= 0 {
		// PID file is missing (manual start, lost file, crash). If the socket
		// is live the daemon is still running — discover its PID from the
		// socket owner and stop it instead of telling the user to kill it by
		// hand.
		socket := getSocket()
		d, err := driver.Connect(socket)
		if err != nil {
			fatalCode("not_running", "daemon is not running")
		}
		d.Close() // #nosec G104 -- probe connection only; we just needed to confirm the socket is live
		pid = discoverDaemonPID(socket)
		if pid <= 0 {
			fatalHint("not_running",
				fmt.Sprintf("find and kill the process manually: lsof -U | grep %s", socket),
				"daemon socket is active but PID file is missing and the owning process could not be identified")
		}
		discovered = true
	}

	if !pidLooksLikeDaemon(pid) {
		// Dead, or the PID now belongs to an UNRELATED process (reuse
		// after reboot/rollover). Either way we must not signal it —
		// SIGTERM/SIGKILL below would hit a bystander.
		if !discovered {
			os.Remove(pidFilePath()) // #nosec G104 -- best-effort removal of stale PID file; failure is non-fatal
		}
		fatalCode("not_running", "daemon is not running (cleaned up stale state)")
	}

	// Send SIGTERM
	proc, err := os.FindProcess(pid)
	if err != nil {
		fatalCode("internal", "find process: %v", err)
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fatalCode("internal", "signal daemon: %v", err)
	}

	// Wait for exit
	waitDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(waitDeadline) {
		time.Sleep(200 * time.Millisecond)
		if !processExists(pid) {
			os.Remove(pidFilePath())
			if jsonOutput {
				outputOK(map[string]interface{}{"pid": pid})
			} else {
				fmt.Printf("daemon stopped (pid %d)\n", pid)
			}
			return
		}
	}

	// Force kill
	proc.Signal(syscall.SIGKILL)
	os.Remove(pidFilePath())
	if jsonOutput {
		outputOK(map[string]interface{}{"pid": pid, "forced": true})
	} else {
		fmt.Printf("daemon force-stopped (pid %d)\n", pid)
	}
}

func cmdDaemonStatus(args []string) {
	flags, _ := parseFlags(args)
	checkMode := flagBool(flags, "check")

	pid := readPID()
	running := false
	if pidLooksLikeDaemon(pid) {
		running = true
	}

	// --check mode: silent health check, exit 0 if responsive, exit 1 otherwise
	if checkMode {
		d, err := driver.Connect(getSocket())
		if err != nil {
			os.Exit(1)
		}
		_, err = d.Info()
		d.Close()
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	result := map[string]interface{}{
		"running":  running,
		"pid":      pid,
		"pid_file": pidFilePath(),
		"socket":   getSocket(),
	}

	// Try to get info from daemon
	d, err := driver.Connect(getSocket())
	if err != nil {
		if !running {
			// Clean up stale files
			if pid > 0 {
				os.Remove(pidFilePath())
			}
		}
		result["responsive"] = false
		if jsonOutput {
			output(result)
		} else {
			fmt.Printf("%s %s stopped\n", statusDot("err"), sBold("pilot-daemon"))
			fmt.Printf("  %s\n", sDim("start: pilotctl daemon start"))
		}
		return
	}
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		result["responsive"] = false
		if jsonOutput {
			output(result)
		} else {
			fmt.Printf("%s %s unresponsive %s\n", statusDot("err"), sBold("pilot-daemon"), sDim("— socket accepted the connection but info failed"))
			fmt.Printf("  %s\n", sDim("restart: pilotctl daemon stop && pilotctl daemon start"))
		}
		return
	}

	result["responsive"] = true
	result["running"] = true
	result["node_id"] = int(info["node_id"].(float64))
	result["address"] = info["address"]
	if h, ok := info["hostname"].(string); ok {
		result["hostname"] = h
	}
	result["uptime_secs"] = info["uptime_secs"]
	result["peers"] = int(info["peers"].(float64))
	result["connections"] = int(info["connections"].(float64))

	if !jsonOutput {
		// The socket responded, so the daemon IS running — regardless of
		// what the PID file says (it may be missing or stale when the
		// daemon was started by launchd/systemd instead of pilotctl).
		uptime := info["uptime_secs"].(float64)
		hours := int(uptime) / 3600
		mins := (int(uptime) % 3600) / 60
		secs := int(uptime) % 60
		fmt.Printf("%s %s running\n", statusDot("ok"), sBold("pilot-daemon"))
		meta := fmt.Sprintf("uptime %02d:%02d:%02d", hours, mins, secs)
		if running {
			meta += fmt.Sprintf(" · pid %d", pid)
		}
		meta += fmt.Sprintf(" · %d connection(s)", int(info["connections"].(float64)))
		fmt.Printf("  %s\n", sDim(meta))

		nodeLine := fmt.Sprintf("%d · %s", int(info["node_id"].(float64)), info["address"])
		if h, ok := info["hostname"].(string); ok && h != "" {
			nodeLine += " · " + h
		}
		fmt.Printf("  node      %s\n", sAccent(nodeLine))

		peers := int(info["peers"].(float64))
		encPeers := 0
		if ep, ok := info["encrypted_peers"].(float64); ok {
			encPeers = int(ep)
		}
		relayPeers := 0
		if rp, ok := info["relay_peer_count"].(float64); ok {
			relayPeers = int(rp)
		}
		pending := 0
		if hp, ok := info["handshake_pending_count"].(float64); ok {
			pending = int(hp)
		}
		fmt.Printf("  peers     %s %s\n", sBold(fmt.Sprintf("%d", peers)), sDim(fmt.Sprintf("(%d encrypted, %d via relay)", encPeers, relayPeers)))
		if !running {
			fmt.Printf("  %s\n", sDim("pid file stale — daemon was likely started by launchd/systemd"))
		}
		if pending > 0 {
			fmt.Printf("  %s %s\n", sWarn(fmt.Sprintf("%d pending handshake(s)", pending)), sDim("— review with: pilotctl pending"))
		}
		return
	}
	output(result)
}

// runDaemonInternal handles the legacy `pilotctl _daemon-run` hidden
// subcommand, which earlier pilotctl builds used to exec themselves
// for the forked daemon process. The composition root has moved to
// cmd/daemon/main.go; this entry point now exec's pilot-daemon so old
// pilotctl-managed PID files (which point at a `pilotctl _daemon-run`
// process) keep working until the next daemon restart cycles them
// out. The `_daemon-run` flag set is identical to pilot-daemon's, so
// we forward args verbatim apart from translating --no-encrypt.
func runDaemonInternal(args []string) {
	translated := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--no-encrypt" || a == "-no-encrypt" {
			translated = append(translated, "--encrypt=false")
			continue
		}
		translated = append(translated, a)
	}
	daemonBin := daemonBinaryPath()
	execArgs := append([]string{daemonBin}, translated...)
	if err := syscall.Exec(daemonBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", daemonBin, err)
	}
}

// PID file helpers
func readPID() int {
	data, err := os.ReadFile(pidFilePath())
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

func processExists(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Use Signal(0) to check.
	return proc.Signal(syscall.Signal(0)) == nil
}

// pidLooksLikeDaemon reports whether pid is alive AND its command line
// looks like a pilot daemon. Signal(0) alone (processExists) matches ANY
// process that inherited the number after a reboot or PID rollover —
// which made `daemon start` refuse ("already running") and, worse, let
// `daemon stop` SIGTERM an innocent process. Every pidfile consumer
// that acts on the PID goes through this instead.
//
// If the process is alive but its cmdline can't be inspected, we return
// false: for `start` the live-socket probe is the authoritative
// double-start guard anyway, and for `stop` the socket-owner discovery
// path takes over — both fail safe.
func pidLooksLikeDaemon(pid int) bool {
	if pid <= 0 || !processExists(pid) {
		return false
	}
	var cmdline string
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmdline = strings.ReplaceAll(string(data), "\x00", " ")
	} else {
		// #nosec G204 -- fixed argv; pid is an integer we formatted ourselves
		out, psErr := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output()
		if psErr != nil {
			return false
		}
		cmdline = string(out)
	}
	// Match on the executable's base name, not a substring — a substring
	// like "daemon" would match containerd/systemd-journald and make the
	// stop path lethal to bystanders. Accept the two names the binary
	// ships under: "pilot-daemon" (installs) and "daemon" (raw release
	// archive / `make build` output).
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return false
	}
	base := filepath.Base(fields[0])
	return base == "pilot-daemon" || base == "daemon"
}

// discoverDaemonPID finds the PID of the process holding the daemon's Unix
// socket. It is the fallback for `daemon stop` when the PID file is missing
// (manual start, crash that lost the file, etc.) so we can stop the daemon
// instead of punting to "kill it yourself". Returns 0 if the owner can't be
// determined (e.g. lsof unavailable). Only same-UID processes are returned by
// lsof for our own socket, so this can't be used to signal other users' procs.
func discoverDaemonPID(socketPath string) int {
	if socketPath == "" {
		return 0
	}
	// #nosec G204 -- fixed argv (lsof -t -U -a); socketPath is our own config-derived daemon socket passed as a separate arg, no shell, no injection
	out, err := exec.Command("lsof", "-t", "-U", "-a", socketPath).Output()
	if err != nil {
		return 0
	}
	self := os.Getpid()
	for _, line := range strings.Fields(string(out)) {
		pid, perr := strconv.Atoi(line)
		if perr != nil || pid <= 0 || pid == self {
			continue
		}
		if processExists(pid) {
			return pid
		}
	}
	return 0
}

// ===================== GATEWAY =====================

// cmdGatewayStart exec's pilot-gateway in the foreground. The flags
// pilotctl already accepted (--subnet, --ports, plus positional
// addresses) map 1:1 onto pilot-gateway flags + the `run` subcommand,
// so we translate and replace the current process. The gateway runs
// as long as pilotctl's caller chooses; SIGINT/SIGTERM tear it down
// the same as before.
//
// The PID-file pattern from the in-process implementation is dropped:
// pilot-gateway is the canonical CLI for these operations and it
// already manages its own lifetime. `pilotctl gateway stop` now
// degrades to the documented "find and kill" path described in its
// help text.
func cmdGatewayStart(args []string) {
	flags, pos := parseFlags(args)

	subnet := flagString(flags, "subnet", "10.4.0.0/16")
	portsStr := flagString(flags, "ports", "")

	gwArgs := []string{"--socket", getSocket(), "--subnet", subnet}
	if portsStr != "" {
		gwArgs = append(gwArgs, "--ports", portsStr)
	}
	gwArgs = append(gwArgs, "run")
	gwArgs = append(gwArgs, pos...)

	gwBin := gatewayBinaryPath()
	execArgs := append([]string{gwBin}, gwArgs...)
	if err := syscall.Exec(gwBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", gwBin, err)
	}
}

// cmdGatewayStop is now a thin wrapper. The previous in-process
// implementation tracked its own PID file; with pilot-gateway running
// as a separate process pilotctl can't reach into it without
// duplicating that bookkeeping. Surface a clear hint instead.
func cmdGatewayStop() {
	fatalHint("not_running",
		"send SIGTERM to the pilot-gateway process directly (e.g. pkill -TERM pilot-gateway)",
		"pilotctl no longer tracks the gateway process; run pilot-gateway directly")
}

// cmdGatewayMap exec's `pilot-gateway map`. This is a transient
// add-mapping path: pilot-gateway will spin up, register the mapping,
// and exit.
func cmdGatewayMap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway map <pilot-addr> [local-ip]")
	}
	gwBin := gatewayBinaryPath()
	gwArgs := []string{"--socket", getSocket(), "map"}
	gwArgs = append(gwArgs, args...)
	execArgs := append([]string{gwBin}, gwArgs...)
	if err := syscall.Exec(gwBin, execArgs, os.Environ()); err != nil {
		fatalCode("internal", "exec %s: %v", gwBin, err)
	}
}

// cmdGatewayUnmap is no longer routable from pilotctl: pilot-gateway
// owns its in-memory mapping table and there's no IPC for outside
// processes to mutate it. Emit a clear error pointing the caller at
// pilot-gateway directly.
func cmdGatewayUnmap(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl gateway unmap <local-ip>")
	}
	fatalHint("not_supported",
		"restart pilot-gateway without the mapping, or extend pilot-gateway with an unmap subcommand",
		"unmap is owned by the pilot-gateway process and has no remote control path")
}

// cmdGatewayList is no longer accurate from pilotctl: the in-process
// implementation only ever reported an empty list because it spun up
// a fresh gateway per call. Surface the architectural reality: the
// gateway process holds the mapping table.
func cmdGatewayList() {
	if jsonOutput {
		outputOK(map[string]interface{}{
			"mappings": []map[string]interface{}{},
			"total":    0,
			"note":     "mappings live inside the pilot-gateway process; run pilot-gateway with the desired mappings",
		})
		return
	}
	fmt.Println("no mappings")
	fmt.Println("note: mappings live inside the pilot-gateway process; run pilot-gateway with the desired mappings")
}

// ===================== REGISTRY =====================

func cmdRegister(args []string) {
	listenAddr := ""
	if len(args) > 0 {
		listenAddr = args[0]
	}
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Register(listenAddr)
	if err != nil {
		fatalCode("connection_failed", "register: %v", err)
	}
	output(resp)
}

func cmdLookup(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl lookup <node_id|address|hostname>")
	}
	_, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl lookup <node_id|address|hostname>")
	}
	// Resolve hostname/address without a daemon connection when possible.
	// If the arg is a hostname we need the daemon for resolution.
	var nodeID uint32
	arg := pos[0]
	if id, err := strconv.ParseUint(arg, 10, 32); err == nil {
		nodeID = uint32(id)
	} else if addr, err := protocol.ParseAddr(arg); err == nil {
		nodeID = addr.Node
	} else {
		d := connectDriver()
		nodeID = resolveToNodeID(d, arg)
		d.Close()
	}
	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.Lookup(nodeID)
	if err != nil {
		fatalCode("connection_failed", "lookup: %v", err)
	}
	redactPeerEndpoints(resp)
	output(resp)
}

// redactPeerEndpoints walks a registry/daemon response and drops any
// IP-bearing fields. Operates in-place; safe to call on nil/non-map types.
// Removed keys: endpoint, real_addr, lan_addrs, public_addr, ip, addr.
// Recurses into nested maps and into peer_list / nodes / data sub-objects.
func redactPeerEndpoints(v interface{}) {
	switch x := v.(type) {
	case map[string]interface{}:
		for _, k := range []string{"endpoint", "real_addr", "lan_addrs", "public_addr", "stun_addr", "observed_addr"} {
			delete(x, k)
		}
		for _, vv := range x {
			redactPeerEndpoints(vv)
		}
	case []interface{}:
		for _, vv := range x {
			redactPeerEndpoints(vv)
		}
	}
}

func cmdRotateKey(args []string) {
	_ = args
	d := connectDriver()
	defer d.Close()
	resp, err := d.RotateKey()
	if err != nil {
		fatalCode("connection_failed", "rotate-key: %v", err)
	}
	output(resp)
}

func cmdSetPublic(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetVisibility(true)
	if err != nil {
		fatalCode("connection_failed", "set-public: %v", err)
	}
	output(resp)
}

func cmdSetPrivate(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.SetVisibility(false)
	if err != nil {
		fatalCode("connection_failed", "set-private: %v", err)
	}
	output(resp)
}

func cmdDeregister(args []string) {
	d := connectDriver()
	defer d.Close()
	resp, err := d.Deregister()
	if err != nil {
		fatalCode("connection_failed", "deregister: %v", err)
	}
	output(resp)
}

// ===================== DISCOVERY =====================

func cmdFind(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl find <hostname>")
	}
	d := connectDriver()
	defer d.Close()

	hostname := args[0]
	result, err := d.ResolveHostname(hostname)
	if err != nil {
		fatalHint("not_found",
			fmt.Sprintf("establish trust first: pilotctl handshake %s \"reason\"", hostname),
			"cannot find %q — hostname not found or no mutual trust", hostname)
	}

	nodeID := int(result["node_id"].(float64))
	address := result["address"].(string)
	public := false
	if p, ok := result["public"].(bool); ok {
		public = p
	}

	if jsonOutput {
		output(map[string]interface{}{
			"hostname": hostname,
			"node_id":  nodeID,
			"address":  address,
			"public":   public,
		})
	} else {
		fmt.Printf("Hostname:  %s\n", hostname)
		fmt.Printf("Node ID:   %d\n", nodeID)
		fmt.Printf("Address:   %s\n", address)
		visibility := "private"
		if public {
			visibility = "public"
		}
		fmt.Printf("Visible:   %s\n", visibility)
	}
}

func cmdSetHostname(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-hostname <hostname>")
	}
	d := connectDriver()
	defer d.Close()

	hostname := args[0]
	result, err := d.SetHostname(hostname)
	if err != nil {
		fatalCode("connection_failed", "set-hostname: %v", err)
	}

	// Persist to config.json so hostname survives daemon restart. Report a
	// save failure rather than letting persisted config silently diverge
	// from the running daemon.
	cfg := loadConfig()
	if hostname != "" {
		cfg["hostname"] = hostname
	} else {
		delete(cfg, "hostname")
	}
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal",
			"hostname set on daemon but could not persist to %s: %v", configPath(), err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"hostname": result["hostname"],
			"node_id":  result["node_id"],
		})
	} else if hostname == "" {
		fmt.Printf("hostname cleared\n")
	} else {
		fmt.Printf("hostname set: %s\n", result["hostname"])
	}
}

func cmdClearHostname() {
	d := connectDriver()
	defer d.Close()

	_, err := d.SetHostname("")
	if err != nil {
		fatalCode("connection_failed", "clear-hostname: %v", err)
	}

	// Persist to config.json so hostname stays cleared on daemon restart.
	// Report a save failure rather than silently diverging from the daemon.
	cfg := loadConfig()
	delete(cfg, "hostname")
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal",
			"hostname cleared on daemon but could not persist to %s: %v", configPath(), err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"hostname": "",
		})
	} else {
		fmt.Printf("hostname cleared\n")
	}
}

func cmdSetWebhook(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-webhook <url>")
	}
	url := args[0]
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		fatalCode("invalid_argument", "webhook URL must start with http:// or https://")
	}

	// Persist to config so it survives daemon restart
	cfg := loadConfig()
	cfg["webhook"] = url
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	// Apply to running daemon (best-effort — daemon may not be running)
	applied := false
	d, err := driver.Connect(getSocket())
	if err == nil {
		_, err = d.SetWebhook(url)
		d.Close()
		if err == nil {
			applied = true
		}
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"webhook": url,
			"applied": applied,
		})
	} else {
		fmt.Printf("webhook set: %s\n", url)
		if applied {
			fmt.Printf("applied to running daemon\n")
		} else {
			fmt.Printf("will take effect on next daemon start\n")
		}
	}
}

func cmdClearWebhook() {
	cfg := loadConfig()
	delete(cfg, "webhook")
	if err := saveConfig(cfg); err != nil {
		fatalCode("internal", "save config: %v", err)
	}

	// Apply to running daemon (best-effort)
	applied := false
	d, err := driver.Connect(getSocket())
	if err == nil {
		_, err = d.SetWebhook("")
		d.Close()
		if err == nil {
			applied = true
		}
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"webhook": "",
			"applied": applied,
		})
	} else {
		fmt.Printf("webhook cleared\n")
		if applied {
			fmt.Printf("applied to running daemon\n")
		} else {
			fmt.Printf("will take effect on next daemon start\n")
		}
	}
}

func cmdSetTags(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl set-tags <tag1> [tag2] ...")
	}
	if len(args) > 3 {
		fatalCode("invalid_argument", "set-tags: maximum 3 tags allowed, got %d", len(args))
	}
	d := connectDriver()
	defer d.Close()

	result, err := d.SetTags(args)
	if err != nil {
		fatalCode("connection_failed", "set-tags: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"node_id": result["node_id"],
			"tags":    result["tags"],
		})
	} else {
		tags := "none"
		if t, ok := result["tags"].([]interface{}); ok && len(t) > 0 {
			parts := make([]string, len(t))
			for i, v := range t {
				parts[i] = fmt.Sprintf("#%s", v)
			}
			tags = strings.Join(parts, " ")
		}
		fmt.Printf("tags set: %s\n", tags)
	}
}

func cmdClearTags() {
	d := connectDriver()
	defer d.Close()

	_, err := d.SetTags([]string{})
	if err != nil {
		fatalCode("connection_failed", "clear-tags: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"tags": []string{},
		})
	} else {
		fmt.Printf("tags cleared\n")
	}
}

// ===================== COMMUNICATION =====================

func cmdConnect(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl connect <address|hostname> [port] [--message <msg>] [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

	port := protocol.PortStdIO
	if len(pos) > 1 {
		p, err := strconv.ParseUint(pos[1], 10, 16)
		if err != nil {
			fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
		}
		port = uint16(p)
	}

	message := flagString(flags, "message", "")
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	// --message mode: send one message, read one response, exit
	if message != "" {
		// Honor --timeout on the dial itself so the daemon-side dial is
		// cancelled (not left dangling) when the peer never answers.
		conn, err := d.DialAddrTimeout(target, port, timeout)
		if err != nil {
			hint := classifyDaemonError(err)
			if hint == "" {
				hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
			}
			fatalHint("connection_failed", hint,
				"cannot connect to %s port %d", target, port)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte(message)); err != nil {
			fatalCode("connection_failed", "write: %v", err)
		}

		buf := make([]byte, 65535)
		done := make(chan int)
		var readErr error
		go func() {
			n, err := conn.Read(buf)
			readErr = err
			done <- n
		}()

		select {
		case n := <-done:
			response := ""
			if n > 0 {
				response = string(buf[:n])
			}
			if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
				fatalCode("connection_failed", "read: %v", readErr)
			}
			if jsonOutput {
				output(map[string]interface{}{
					"target":   target.String(),
					"port":     port,
					"sent":     message,
					"response": response,
				})
			} else if response != "" {
				fmt.Println(response)
			} else {
				fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(message))
			}
		case <-time.After(timeout):
			fatalHint("timeout",
				"increase with --timeout, or check if the target is listening on that port",
				"no response within %s", timeout)
		}
		return
	}

	// Pipe mode: read all of stdin, send it, read response
	stat, _ := os.Stdin.Stat()
	if stat.Mode()&os.ModeCharDevice != 0 {
		// stdin is a terminal — require --message
		fatalHint("invalid_argument",
			"use --message to send a single message, or pipe data via stdin",
			"--message is required (interactive mode not supported)")
	}

	// Read all piped stdin. bufio.Scanner's default 64 KiB token limit
	// would make a single long line fail silently, and scanner.Err() must be
	// checked or read errors are swallowed. Raise the buffer and surface Err().
	var stdinData []byte
	scanner := bufio.NewScanner(os.Stdin)
	const maxLine = 16 * 1024 * 1024 // 16 MiB per line
	scanner.Buffer(make([]byte, 0, 64*1024), maxLine)
	for scanner.Scan() {
		if len(stdinData) > 0 {
			stdinData = append(stdinData, '\n')
		}
		stdinData = append(stdinData, scanner.Bytes()...)
	}
	if err := scanner.Err(); err != nil {
		fatalCode("invalid_argument", "reading stdin: %v", err)
	}
	if len(stdinData) == 0 {
		fatalCode("invalid_argument", "no data on stdin — use --message or pipe data")
	}

	conn, err := d.DialAddrTimeout(target, port, timeout)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s port %d", target, port)
	}
	defer conn.Close()

	if _, err := conn.Write(stdinData); err != nil {
		fatalCode("connection_failed", "write failed: %v", err)
	}

	buf := make([]byte, 65535)
	done := make(chan int)
	var readErr error
	go func() {
		n, err := conn.Read(buf)
		readErr = err
		done <- n
	}()

	select {
	case n := <-done:
		response := ""
		if n > 0 {
			response = string(buf[:n])
		}
		if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
			fatalCode("connection_failed", "read failed: %v", readErr)
		}
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"port":     port,
				"sent":     string(stdinData),
				"response": response,
			})
		} else if response != "" {
			fmt.Println(response)
		} else {
			fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(stdinData))
		}
	case <-time.After(timeout):
		fatalHint("timeout",
			"increase with --timeout, or check if the target is listening on that port",
			"no response within %s", timeout)
	}
}

func cmdSend(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl send <address|hostname> <port> --data <msg> [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	p, err := strconv.ParseUint(pos[1], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
	}
	port := uint16(p)

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	conn, err := d.DialAddr(target, port)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s port %d", target, port)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(data)); err != nil {
		fatalCode("connection_failed", "write failed: %v", err)
	}

	buf := make([]byte, 65535)
	doneCh := make(chan int)
	var readErr error
	go func() {
		n, err := conn.Read(buf)
		readErr = err
		doneCh <- n
	}()

	select {
	case n := <-doneCh:
		response := ""
		if n > 0 {
			response = string(buf[:n])
		}
		if readErr != nil && response == "" && !errors.Is(readErr, io.EOF) {
			fatalCode("connection_failed", "read failed: %v", readErr)
		}
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"port":     port,
				"sent":     data,
				"response": response,
			})
		} else if response != "" {
			fmt.Println(response)
		} else {
			fmt.Fprintf(os.Stderr, "sent %d bytes (no response)\n", len(data))
		}
	case <-time.After(timeout):
		fatalHint("timeout",
			fmt.Sprintf("increase with --timeout, or check peer: pilotctl ping %s", target),
			"no response within %s", timeout)
	}
}

func cmdRecv(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl recv <port> [--count <n>] [--timeout <dur>]")
	}

	p, err := strconv.ParseUint(pos[0], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[0], err)
	}
	port := uint16(p)
	count := flagInt(flags, "count", 1)
	timeout := flagDuration(flags, "timeout", 30*time.Second)

	d := connectDriver()
	defer d.Close()

	ln, err := d.Listen(port)
	if err != nil {
		fatalCode("connection_failed", "listen: %v", err)
	}

	var messages []map[string]interface{}
	deadline := time.After(timeout)

	for i := 0; i < count; i++ {
		doneCh := make(chan net.Conn)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				doneCh <- nil
				return
			}
			doneCh <- conn
		}()

		select {
		case conn := <-doneCh:
			if conn == nil {
				fatalCode("connection_failed", "accept error")
			}
			// Set a read deadline so io.ReadAll doesn't block forever if
			// the sender leaves the connection open without closing it.
			conn.SetReadDeadline(time.Now().Add(timeout))
			data, err := io.ReadAll(conn)
			conn.Close()
			msg := map[string]interface{}{
				"seq":  i,
				"port": port,
			}
			if err != nil && len(data) == 0 {
				msg["error"] = err.Error()
			} else {
				msg["data"] = string(data)
				msg["bytes"] = len(data)
			}
			messages = append(messages, msg)

			if !jsonOutput {
				if errStr, ok := msg["error"].(string); ok {
					fmt.Fprintf(os.Stderr, "error: %s\n", errStr)
				} else {
					fmt.Println(msg["data"])
				}
			}
		case <-deadline:
			if jsonOutput {
				output(map[string]interface{}{
					"messages": messages,
					"timeout":  true,
				})
			} else {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"messages": messages,
			"timeout":  false,
		})
	}
}

func cmdDgram(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl dgram <address|hostname> <port> --data <msg>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	p, err := strconv.ParseUint(pos[1], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[1], err)
	}
	port := uint16(p)

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}

	if err := d.SendTo(target, port, []byte(data)); err != nil {
		fatalCode("connection_failed", "sendto: %v", err)
	}

	if jsonOutput {
		outputOK(map[string]interface{}{
			"target": target.String(),
			"port":   port,
			"bytes":  len(data),
		})
	} else {
		fmt.Printf("sent %d byte(s) to %s port %d\n", len(data), target, port)
	}
}

// cmdSendFile transfers a file via the dataexchange overlay stream.
//
// Until the chunked streaming protocol lands (see
// docs/PROPOSAL-reliable-file-transfer.md), this M0 implementation gives
// us four reliability primitives without changing the wire format:
//
//  1. **Bounded ACK wait.** The original code blocked on `client.Recv()`
//     forever; if the receiver crashed mid-write, the sender hung until
//     SO_KEEPALIVE finally fired (~120s on most kernels). We now wrap the
//     receive in a context with a configurable `--timeout` (default 90s)
//     and close the connection on expiry so the underlying goroutine
//     unblocks.
//  2. **Progress indicator.** While the transfer is in flight, an
//     elapsed-time line is rewritten on stderr (TTY-only, hidden under
//     --json) so the user knows the command is alive. Uses the existing
//     startWaitProgress helper.
//  3. **Throughput in the result.** The JSON output now carries
//     elapsed_ms and a megabits-per-second rate, so agents can see at a
//     glance whether the transfer was abnormally slow.
//  4. **Sharper error messages.** Timeouts and receiver-side ERR ACKs
//     get distinct exit codes and surface the next command to run
//     ("pilotctl ping" / "pilotctl peers"), matching the house pattern.
func cmdSendFile(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl send-file <address|hostname> <filepath> [--timeout <dur>]")
	}

	// Default 90s is comfortable for transfers up to a hundred MiB over
	// a relay path; users with bigger files or slower peers should bump
	// it explicitly. We intentionally do not derive timeout from file
	// size — that hides the failure mode where the receiver hangs
	// post-write (the actual symptom of the original bug).
	timeout := flagDuration(flags, "timeout", 90*time.Second)

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("invalid_argument", "%v", err)
	}

	// Auto-handshake to peers in the embedded trusted-agents list.
	// Best-effort: warns on stderr and continues if handshake fails.
	maybeAutoHandshake(d, target, false)

	// --prefer-direct breaks the daemon out of a stuck-on-relay tunnel
	// BEFORE we dial port 1001. Without this, a previously-established
	// relay tunnel is reused and the dial inherits its broken stream
	// behavior. We send the IPC, log what the daemon reset, and proceed
	// regardless — an old daemon returns "unknown command" which we
	// treat as a best-effort hint, not a hard failure.
	if flagBool(flags, "prefer-direct") {
		resp, perr := d.PreferDirect(target.Node)
		switch {
		case perr != nil && strings.Contains(perr.Error(), "unknown command"):
			fmt.Fprintln(os.Stderr, sDim("--prefer-direct: daemon does not support it (pre-v1.12.0); proceeding with existing tunnel"))
		case perr != nil:
			fmt.Fprintln(os.Stderr, sDim("--prefer-direct: "+perr.Error()+" (continuing)"))
		default:
			had, _ := resp["had_tunnel"].(bool)
			wasActive, _ := resp["was_relay_active"].(bool)
			wasPinned, _ := resp["was_relay_pinned"].(bool)
			fmt.Fprintln(os.Stderr, sDim(fmt.Sprintf("--prefer-direct: tunnel=%v relay_was_active=%v relay_was_pinned=%v",
				had, wasActive, wasPinned)))
		}
	}

	filePath := pos[1]
	filename := filepath.Base(filePath)

	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			fatalCode("not_found", "file not found: %s", filePath)
		}
		if os.IsPermission(err) {
			fatalCode("internal", "permission denied: %s", filePath)
		}
		fatalCode("internal", "stat file: %v", err)
	}
	if fi.IsDir() {
		fatalCode("invalid_argument", "%s is a directory, not a file", filePath)
	}
	size := fi.Size()
	governedOutbound, governedErr := governedOutboundFromFlags(flags)
	if governedErr != nil {
		fatalCode("invalid_argument", "governed send-file: %v", governedErr)
	}

	// Streamed transfer (default): chunked, ACK'd, resumable, end-to-end
	// SHA-256 verified — no per-frame size cap, and big files no longer
	// collapse into one giant frame that stalls over relay (or over a
	// direct link that flips to relay under one-way load). Falls back to
	// the single-frame TypeFile path when the receiver is too old to
	// understand TypeFileStream (it never sends an INIT-ACK).
	if !flagBool(flags, "no-stream") {
		if res, serr := streamSendFile(d, target, filePath, filename, size, timeout, governedOutbound); serr == nil {
			outputOK(res)
			return
		} else if governedOutbound != nil && errors.Is(serr, dataexchange.ErrStreamUnsupported) {
			fatalCode("connection_failed", "governed send-file requires a receiver that supports governed streaming; refusing legacy fallback")
		} else if !errors.Is(serr, dataexchange.ErrStreamUnsupported) {
			fatalHint("connection_failed",
				"check reachability: pilotctl ping "+target.String()+" · for very large/slow links raise --timeout",
				"streamed send-file failed: %v", serr)
		}
		fmt.Fprintln(os.Stderr, sDim("receiver does not support streamed transfer (pre-v1.12.0); falling back to single-frame TypeFile"))
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			fatalCode("not_found", "file not found: %s", filePath)
		}
		if os.IsPermission(err) {
			fatalCode("internal", "permission denied: %s", filePath)
		}
		fatalCode("internal", "read file: %v", err)
	}

	// Reject files that would exceed the data-exchange frame cap before
	// opening the connection — keeps the failure path clean and avoids
	// streaming a quarter-gigabyte just to have the receiver close.
	if uint32(len(data)) > dataexchange.MaxFrameSize {
		fatalCode("invalid_argument",
			"file too large: %d bytes (max %d) for the legacy single-frame path. Use the default streamed transfer (omit --no-stream) against a v1.12.0+ receiver.",
			len(data), dataexchange.MaxFrameSize)
	}

	client, err := dataexchange.Dial(d, target)
	if err != nil {
		hint := classifyDaemonError(err)
		if hint == "" {
			hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
		}
		fatalHint("connection_failed", hint,
			"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
	}
	defer client.Close()

	stop := startWaitProgress(fmt.Sprintf("sending %s to %s", filename, target))
	start := time.Now()

	var governedDecision decision.Decision
	var governedIntent decision.Intent
	if governedOutbound != nil {
		frame := &dataexchange.Frame{Type: dataexchange.TypeFile, Filename: filename, Payload: data}
		intent, result, authorizeErr := governedOutbound.authorizeFrame(context.Background(), frame)
		if authorizeErr != nil {
			stop()
			fatalCode("permission_denied", "governed send-file: %v", authorizeErr)
		}
		governedIntent = intent
		governedDecision = result
		if disclosure, found := governedOutbound.disclosure(intent.ID); found {
			err = client.SendGovernedWithDisclosure(frame, intent, result, disclosure)
		} else {
			err = client.SendGoverned(frame, intent, result)
		}
	} else {
		err = client.SendFile(filename, data)
	}
	if err != nil {
		governedOutbound.complete(context.Background(), governedIntent.ID, false, "transport_send_failed")
		stop()
		fatalCode("connection_failed", "send failed: %v", err)
	}

	// Wait for the ACK with a bounded deadline. The dataexchange.Client
	// does not expose a Recv-with-context, so we run the read in a
	// goroutine and race it against a timer. On timeout we close the
	// connection — that unblocks the goroutine's ReadFrame with an
	// error, which we then drop on the floor because we've already
	// decided the transfer is a failure.
	type ackResult struct {
		frame *dataexchange.Frame
		err   error
	}
	ackCh := make(chan ackResult, 1)
	go func() {
		f, err := client.Recv()
		ackCh <- ackResult{f, err}
	}()

	var ack *dataexchange.Frame
	select {
	case res := <-ackCh:
		ack = res.frame
		if res.err != nil {
			governedOutbound.complete(context.Background(), governedIntent.ID, false, "ack_unavailable")
			stop()
			// Sender wrote all bytes but never got the receiver's ACK
			// back (likely receiver crashed or restarted mid-transfer).
			fatalHint("connection_failed",
				"the receiver may have crashed or restarted mid-transfer · check reachability: pilotctl ping "+target.String(),
				"send wrote all bytes but no ACK from receiver: %v", res.err)
		}
	case <-time.After(timeout):
		governedOutbound.complete(context.Background(), governedIntent.ID, false, "ack_timeout")
		stop()
		// Closing the conn lets the goroutine unwind. We deliberately
		// don't wait for it here — we've already given the receiver its
		// budget.
		_ = client.Close()
		fatalHint("timeout",
			"the receiver did not ACK within "+timeout.String()+" · check reachability: pilotctl ping "+target.String()+" · for very large files try --timeout 5m",
			"send-file timed out waiting for ACK from %s after %s", target, timeout)
	}

	stop()
	elapsed := time.Since(start)
	mbps := 0.0
	if elapsed > 0 {
		mbps = (float64(len(data)) * 8.0) / (1e6 * elapsed.Seconds())
	}

	result := map[string]interface{}{
		"filename":        filename,
		"bytes":           len(data),
		"destination":     target.String(),
		"elapsed_ms":      elapsed.Milliseconds(),
		"throughput_mbps": mbps,
	}
	if governedOutbound != nil {
		result["governed"] = true
		result["decision_id"] = governedDecision.ID
		result["policy_revision"] = governedDecision.PolicyRevision
	}
	if ack != nil {
		ackText := string(ack.Payload)
		result["ack"] = ackText
		// Receiver-side errors arrive as a TEXT frame whose body starts
		// with "ERR " — surface them as a real failure instead of
		// claiming success (e.g. disk-full, save permission denied).
		if strings.HasPrefix(ackText, "ERR ") {
			governedOutbound.completeWithResponse(context.Background(), governedIntent.ID, false, "receiver_rejected", "text/plain", ack.Payload)
			fatalCode("internal", "receiver rejected file: %s", ackText)
		}
	}
	if ack != nil {
		governedOutbound.completeWithResponse(context.Background(), governedIntent.ID, true, "", frameContentType(ack.Type), ack.Payload)
	} else {
		governedOutbound.complete(context.Background(), governedIntent.ID, true, "")
	}
	outputOK(result)
}

// streamSendFile transfers filePath with the chunked, ACK'd, resumable
// TypeFileStream protocol. It returns a result map on success; the sentinel
// dataexchange.ErrStreamUnsupported tells the caller to fall back to the
// single-frame TypeFile path (the receiver is too old). timeout bounds the
// wait for any single ACK and for the receiver's final verification.
func streamSendFile(d *driver.Driver, target protocol.Addr, filePath, filename string, size int64, timeout time.Duration, governedOutbound *governedOutboundSender) (map[string]interface{}, error) {
	client, err := dataexchange.Dial(d, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stop := startWaitProgress(fmt.Sprintf("streaming %s to %s", filename, target))
	start := time.Now()
	var governedDecision decision.Decision
	var governedIntent decision.Intent
	var res *dataexchange.StreamResult
	var serr error
	if governedOutbound != nil {
		if governedOutbound.hook != nil && governedOutbound.contentBuilder != nil {
			if size > maxInlineHostedFederationBytes {
				return nil, fmt.Errorf("hosted federation currently accepts files up to %d bytes; use an unmanaged transfer or split the file", maxInlineHostedFederationBytes)
			}
			body, readErr := io.ReadAll(io.LimitReader(f, maxInlineHostedFederationBytes+1))
			if readErr != nil {
				return nil, readErr
			}
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				return nil, seekErr
			}
			res, serr = client.SendGovernedFileStreamWithDisclosureAuthorizer(filename, f, size, func(initPayload []byte) (decision.Intent, decision.Decision, decision.DisclosureBinding, error) {
				intent, result, disclosure, authorizeErr := governedOutbound.authorizeFederatedStream(context.Background(), initPayload, body)
				if authorizeErr == nil {
					governedIntent = intent
					governedDecision = result
				}
				return intent, result, disclosure, authorizeErr
			}, timeout)
		} else {
			res, serr = client.SendGovernedFileStreamWithAuthorizer(filename, f, size, func(initPayload []byte) (decision.Intent, decision.Decision, error) {
				intent, result, authorizeErr := governedOutbound.authorizeStream(context.Background(), initPayload)
				if authorizeErr == nil {
					governedIntent = intent
					governedDecision = result
				}
				return intent, result, authorizeErr
			}, timeout)
		}
	} else {
		res, serr = client.SendFileStream(filename, f, size, timeout)
	}
	stop()
	if serr != nil {
		governedOutbound.complete(context.Background(), governedIntent.ID, false, "stream_failed")
		return nil, serr
	}
	if !res.OK {
		governedOutbound.complete(context.Background(), governedIntent.ID, false, "receiver_rejected")
		return nil, fmt.Errorf("receiver rejected file: %s", res.Message)
	}
	governedOutbound.completeWithResponse(context.Background(), governedIntent.ID, true, "", "text/plain", []byte(res.Message))

	elapsed := time.Since(start)
	mbps := 0.0
	if elapsed > 0 {
		mbps = (float64(res.TotalBytes) * 8.0) / (1e6 * elapsed.Seconds())
	}
	result := map[string]interface{}{
		"filename":        filename,
		"bytes":           res.TotalBytes,
		"bytes_sent":      res.BytesSent,
		"bytes_resumed":   res.BytesResumed,
		"sha256":          res.Sha256,
		"destination":     target.String(),
		"elapsed_ms":      elapsed.Milliseconds(),
		"throughput_mbps": mbps,
		"transport":       "filestream",
		"verified":        res.OK,
	}
	if governedOutbound != nil {
		result["governed"] = true
		result["decision_id"] = governedDecision.ID
		result["policy_revision"] = governedDecision.PolicyRevision
	}
	return result, nil
}

func cmdSendMessage(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl send-message <address|hostname> --data <text> [--type text|json|binary] [--trace] [--count <n>] [--reuse-conn] [--wait <dur>] [--enterprise-control <path> --governed-resource <receiver-resource>]")
	}

	sendCount := flagInt(flags, "count", 1)
	if sendCount < 1 {
		sendCount = 1
	}
	// --wait: bare flag → 30s default; --wait <dur> → that duration; absent → don't wait.
	var waitDur time.Duration
	if raw, ok := flags["wait"]; ok {
		if raw == "true" {
			waitDur = 30 * time.Second
		} else {
			waitDur = flagDuration(flags, "wait", 30*time.Second)
		}
	}

	// --reuse-conn (or PILOT_SENDMSG_REUSE_CONN=1): when --count > 1, dial once
	// and reuse the same data-exchange connection for all N sends. Default false
	// (each send dials fresh — current per-invocation behavior). Ablation flag:
	// compare --count N vs --count N --reuse-conn to isolate dial-overhead savings.
	reuseConn := flagBool(flags, "reuse-conn") || os.Getenv("PILOT_SENDMSG_REUSE_CONN") != "" || featureEnabled("sendmsg.reuse_conn")

	// --trace (or PILOTCTL_TRACE_TIME=1) prints per-step timings to stderr:
	// IPC connect, hostname resolve, auto-handshake, dial, send, ACK recv.
	traceTime := os.Getenv("PILOTCTL_TRACE_TIME") != "" || flagBool(flags, "trace")
	t0 := time.Now()
	var traceEvents []map[string]interface{}
	tracef := func(label string) {
		if !traceTime {
			return
		}
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		if jsonOutput {
			traceEvents = append(traceEvents, map[string]interface{}{"label": label, "ms": ms})
		} else {
			fmt.Fprintf(os.Stderr, "TRACE %-22s %12.3fms\n", label, ms)
		}
	}

	d := connectDriver()
	tracef("connectDriver")
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	tracef("parseAddrOrHostname")
	if err != nil {
		fatalCode("not_found", "%v", err)
	}

	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}
	msgType := flagString(flags, "type", "text")

	// Auto-handshake to peers in the embedded trusted-agents list.
	// Best-effort: warns on stderr and continues if handshake fails.
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	tracef("maybeAutoHandshake")

	innerType := map[string]uint32{
		"text":   dataexchange.TypeText,
		"json":   dataexchange.TypeJSON,
		"binary": dataexchange.TypeBinary,
	}[msgType]
	if innerType == 0 && msgType != "text" {
		fatalCode("invalid_argument", "unknown type %q (use text, json, or binary)", msgType)
	}
	governedOutbound, governedErr := governedOutboundFromFlags(flags)
	if governedErr != nil {
		fatalCode("invalid_argument", "governed send-message: %v", governedErr)
	}
	if governedOutbound != nil && traceTime {
		fatalCode("invalid_argument", "--trace is unavailable with --enterprise-control because trace frames are not governed")
	}

	// dialOnce opens a fresh data-exchange connection and returns it. Used
	// both for single sends and for the no-reuse multi-send path.
	dialOnce := func() *dataexchange.Client {
		c, err := dataexchange.Dial(d, target)
		if err != nil {
			hint := classifyDaemonError(err)
			if hint == "" {
				hint = fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target)
			}
			fatalHint("connection_failed", hint,
				"cannot connect to %s (data exchange port %d)", target, protocol.PortDataExchange)
		}
		return c
	}

	// sendOne sends one message on cl and returns timing/ack metadata.
	// reused=true is recorded when the connection was dialled on a prior call.
	sendOne := func(cl *dataexchange.Client, seq int, reused bool) map[string]interface{} {
		var sentAtNs int64
		var sendErr error
		var governedIntent decision.Intent
		var governedDecision decision.Decision
		if governedOutbound != nil {
			frame := &dataexchange.Frame{Type: innerType, Payload: []byte(data)}
			governedIntent, governedDecision, sendErr = governedOutbound.authorizeFrame(context.Background(), frame)
			if sendErr == nil {
				if disclosure, found := governedOutbound.disclosure(governedIntent.ID); found {
					sendErr = cl.SendGovernedWithDisclosure(frame, governedIntent, governedDecision, disclosure)
				} else {
					sendErr = cl.SendGoverned(frame, governedIntent, governedDecision)
				}
			}
			sentAtNs = time.Now().UnixNano()
		} else if traceTime {
			sentAtNs, sendErr = cl.SendTrace(innerType, []byte(data))
		} else {
			sendStart := time.Now()
			switch msgType {
			case "text":
				sendErr = cl.SendText(data)
			case "json":
				sendErr = cl.SendJSON([]byte(data))
			case "binary":
				sendErr = cl.SendBinary([]byte(data))
			}
			sentAtNs = sendStart.UnixNano()
		}
		if sendErr != nil {
			governedOutbound.complete(context.Background(), governedIntent.ID, false, "transport_send_failed")
			return map[string]interface{}{"seq": seq, "error": sendErr.Error()}
		}

		ack, ackErr := cl.Recv()
		ackRecvAtNs := time.Now().UnixNano()
		if ackErr != nil {
			slog.Debug("send-message ACK read failed", "err", ackErr)
			governedOutbound.complete(context.Background(), governedIntent.ID, false, "ack_unavailable")
		} else if ack != nil && strings.HasPrefix(string(ack.Payload), "ERR ") {
			governedOutbound.completeWithResponse(context.Background(), governedIntent.ID, false, "receiver_rejected", frameContentType(ack.Type), ack.Payload)
		} else {
			if ack != nil {
				governedOutbound.completeWithResponse(context.Background(), governedIntent.ID, true, "", frameContentType(ack.Type), ack.Payload)
			} else {
				governedOutbound.complete(context.Background(), governedIntent.ID, true, "")
			}
		}

		r := map[string]interface{}{
			"seq":    seq,
			"bytes":  len(data),
			"reused": reused,
		}
		if governedOutbound != nil && sendErr == nil {
			r["governed"] = true
			r["decision_id"] = governedDecision.ID
			r["policy_revision"] = governedDecision.PolicyRevision
		}
		if ack != nil {
			r["ack"] = string(ack.Payload)
		}
		if traceTime {
			r["total_ms"] = float64(time.Duration(ackRecvAtNs-sentAtNs).Microseconds()) / 1000.0
			if ack != nil && ack.Type == dataexchange.TypeJSON {
				var timing map[string]interface{}
				if json.Unmarshal(ack.Payload, &timing) == nil {
					ns := func(key string) int64 {
						if v, ok := timing[key].(float64); ok {
							return int64(v)
						}
						return 0
					}
					recvNs := ns("received_at_ns")
					inboxNs := ns("inbox_written_at_ns")
					ackSentNs := ns("ack_sent_at_ns")
					if recvNs > 0 {
						r["to_receiver_ms"] = float64(time.Duration(recvNs-sentAtNs).Microseconds()) / 1000.0
						r["receiver_process_ms"] = float64(time.Duration(inboxNs-recvNs).Microseconds()) / 1000.0
						r["return_trip_ms"] = float64(time.Duration(ackRecvAtNs-ackSentNs).Microseconds()) / 1000.0
						r["inner_ack"] = timing["inner_ack"]
					}
				}
			}
		}
		return r
	}
	tracef("dial+send")

	// Snapshot time before the send so --wait can find replies that arrive
	// after this point even if the filesystem has 1-second mtime granularity.
	inboxCutoff := time.Now().Add(-time.Second)
	// agentHint is the resolved pilot address used to filter inbox replies
	// against the "from" field written by the daemon when it saves the message.
	agentHint := target.String()

	if sendCount == 1 {
		cl := dialOnce()
		tracef("dataexchange.Dial")
		defer cl.Close()
		r := sendOne(cl, 0, false)
		if governedOutbound != nil {
			if message, failed := r["error"].(string); failed {
				fatalCode("permission_denied", "governed send-message: %s", message)
			}
		}
		result := map[string]interface{}{
			"target": target.String(),
			"to":     target.String(),
			"type":   msgType,
		}
		for k, v := range r {
			result[k] = v
		}
		if len(traceEvents) > 0 {
			result["trace"] = traceEvents
		}
		if waitDur > 0 {
			// Defer all output until the reply is in (or times out) so that
			// --json emits a SINGLE document: a machine parser reading stdout
			// must not see the send-result object followed by a second reply
			// object. In JSON mode we fold the reply into one envelope; in
			// human mode we still print the send result first, then the reply.
			if jsonOutput {
				stop := startWaitProgress("waiting for reply")
				reply, err := waitForInboxReply(agentHint, inboxCutoff, waitDur)
				stop()
				if err != nil {
					fatalCode("timeout", "%v", err)
				}
				result["reply"] = reply
				outputOK(result)
			} else {
				outputOK(result)
				fmt.Fprintf(os.Stderr, "waiting for reply from %s (up to %s)...\n", pos[0], waitDur)
				stop := startWaitProgress("waiting for reply")
				reply, err := waitForInboxReply(agentHint, inboxCutoff, waitDur)
				stop()
				if err != nil {
					fatalCode("timeout", "%v", err)
				}
				output(reply)
			}
		} else {
			outputOK(result)
		}
	} else if reuseConn {
		// --reuse-conn: one dial shared across all N sends. Seq 0 pays dial
		// cost; seqs 1+ skip it. Savings ≈ one relay RTT (~70ms) per msg.
		cl := dialOnce()
		tracef("dataexchange.Dial (shared)")
		defer cl.Close()
		var results []map[string]interface{}
		for i := 0; i < sendCount; i++ {
			result := sendOne(cl, i, i > 0)
			if governedOutbound != nil {
				if message, failed := result["error"].(string); failed {
					fatalCode("permission_denied", "governed send-message: %s", message)
				}
			}
			results = append(results, result)
			if i < sendCount-1 {
				time.Sleep(50 * time.Millisecond)
			}
		}
		outputOK(map[string]interface{}{
			"target":     target.String(),
			"to":         target.String(),
			"type":       msgType,
			"reuse_conn": true,
			"results":    results,
		})
	} else {
		// No --reuse-conn: each of N sends dials a fresh connection. Ablation
		// baseline — measures true per-message cost including dial overhead.
		var results []map[string]interface{}
		for i := 0; i < sendCount; i++ {
			cl := dialOnce()
			result := sendOne(cl, i, false)
			if governedOutbound != nil {
				if message, failed := result["error"].(string); failed {
					_ = cl.Close()
					fatalCode("permission_denied", "governed send-message: %s", message)
				}
			}
			results = append(results, result)
			cl.Close()
			if i < sendCount-1 {
				time.Sleep(50 * time.Millisecond)
			}
		}
		outputOK(map[string]interface{}{
			"target":     target.String(),
			"to":         target.String(),
			"type":       msgType,
			"reuse_conn": false,
			"results":    results,
		})
	}
	tracef("outputOK")
	maybePromptPilotReview()
}

// maybePromptPilotReview occasionally prints a Pilot review nudge to stderr
// after a send-message completes. Gated by:
//   - reviews consent (default on; no-op when off)
//   - PILOT_FLAG_PILOT_REVIEW_PROMPT env / feature flag (default off)
//   - 5% random roll
//
// Uses stderr so --json output on stdout is byte-identical when off.
func maybePromptPilotReview() {
	if !featureEnabled("pilot.review_prompt") {
		return
	}
	home, _ := os.UserHomeDir()
	if !consent.GetConsent(home, "reviews") {
		return
	}
	var seed [32]byte
	if _, err := io.ReadFull(cryptorand.Reader, seed[:]); err != nil {
		return
	}
	src := rand.New(rand.NewChaCha8(seed))
	if src.Float64() >= 0.05 {
		return
	}
	fmt.Fprintln(os.Stderr, "\nLike Pilot? Run 'pilotctl review pilot --rating N' to leave a review.")
}

func cmdSubscribe(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl subscribe <address|hostname> <topic> [--count <n>] [--timeout <dur>]")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

	topic := pos[1]
	count := flagInt(flags, "count", 0) // 0 = infinite
	timeout := flagDuration(flags, "timeout", 0)

	client, err := eventstream.Subscribe(d, target, topic)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot subscribe on %s (event stream port %d)", target, protocol.PortEventStream)
	}
	defer client.Close()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "subscribed to %q on %s — waiting for events...\n", topic, target)
	}

	var events []map[string]interface{}
	received := 0

	var deadline <-chan time.Time
	if timeout > 0 {
		deadline = time.After(timeout)
	}

	for {
		if count > 0 && received >= count {
			break
		}

		evtCh := make(chan *eventstream.Event)
		errCh := make(chan error)
		go func() {
			evt, err := client.Recv()
			if err != nil {
				errCh <- err
				return
			}
			evtCh <- evt
		}()

		select {
		case evt := <-evtCh:
			received++
			msg := map[string]interface{}{
				"topic": evt.Topic,
				"data":  string(evt.Payload),
				"bytes": len(evt.Payload),
			}
			events = append(events, msg)

			if jsonOutput {
				if count > 0 && received >= count {
					break // will exit loop and print all
				}
				// Stream each event as NDJSON for unbounded
				if count == 0 {
					b, _ := json.Marshal(msg)
					fmt.Println(string(b))
				}
			} else {
				fmt.Printf("[%s] %s\n", evt.Topic, string(evt.Payload))
			}
		case err := <-errCh:
			if count > 0 && received > 0 {
				// Partial results
				if jsonOutput {
					output(map[string]interface{}{
						"events":  events,
						"timeout": false,
						"error":   err.Error(),
					})
				}
				return
			}
			fatalCode("connection_failed", "recv: %v", err)
		case <-deadline:
			if jsonOutput && count > 0 {
				output(map[string]interface{}{
					"events":  events,
					"timeout": true,
				})
			} else if !jsonOutput {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput && count > 0 {
		output(map[string]interface{}{
			"events":  events,
			"timeout": false,
		})
	}
}

func cmdPublish(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl publish <address|hostname> <topic> --data <message>")
	}

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

	topic := pos[1]
	data := flagString(flags, "data", "")
	if data == "" {
		fatalCode("invalid_argument", "--data is required")
	}

	// Subscribe first (required by the broker protocol), then publish
	client, err := eventstream.Subscribe(d, target, topic)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s (event stream port %d)", target, protocol.PortEventStream)
	}
	defer client.Close()

	if err := client.Publish(topic, []byte(data)); err != nil {
		fatalCode("connection_failed", "publish failed: %v", err)
	}

	outputOK(map[string]interface{}{
		"target": target.String(),
		"topic":  topic,
		"bytes":  len(data),
	})
}

// ===================== TRUST =====================

func cmdHandshake(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl handshake <node_id|address|hostname> [justification]")
	}
	d := connectDriver()
	defer d.Close()

	var nodeID uint32
	target := args[0]
	if id, err := strconv.ParseUint(target, 10, 32); err == nil {
		nodeID = uint32(id)
	} else if addr, err := protocol.ParseAddr(target); err == nil {
		nodeID = addr.Node
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "parsed address %s → node %d\n", target, nodeID)
		}
	} else {
		_, resolved, err := resolveHostnameToAddr(d, target)
		if err != nil {
			fatalCode("not_found", "resolve %q: %v", target, err)
		}
		nodeID = resolved
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "resolved %s → node %d\n", target, nodeID)
		}
	}

	justification := ""
	if len(args) > 1 {
		justification = args[1]
	}

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "sending handshake to node %d...\n", nodeID)
	}
	result, err := d.Handshake(nodeID, justification)
	if err != nil {
		fatalCode("connection_failed", "handshake: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		status, _ := result["status"].(string)
		if status == "already_trusted" {
			fmt.Printf("already trusted with node %d — ready to communicate\n", nodeID)
		} else {
			fmt.Printf("handshake request sent to node %d\n", nodeID)
			fmt.Println(sDim("  they must approve on their side · check status: pilotctl trust · propagation can take ~60s"))
		}
	}
}

func cmdApprove(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl approve <node_id|address|hostname>")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := resolveToNodeID(d, args[0])

	result, err := d.ApproveHandshake(nodeID)
	if err != nil {
		fatalCode("connection_failed", "approve: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		fmt.Printf("trust established with node %d\n", nodeID)
		fmt.Println(sDim(fmt.Sprintf("  trust is now mutual — message them: pilotctl send-message %d --data \"hi\"", nodeID)))
	}
}

func cmdReject(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl reject <node_id|address|hostname> [reason]")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := resolveToNodeID(d, args[0])
	reason := ""
	if len(args) > 1 {
		reason = args[1]
	}

	result, err := d.RejectHandshake(nodeID, reason)
	if err != nil {
		fatalCode("connection_failed", "reject: %v", err)
	}
	if jsonOutput {
		result["node_id"] = nodeID
		output(result)
	} else {
		fmt.Printf("handshake from node %d rejected\n", nodeID)
	}
}

// cmdPreferDirect drops the daemon's tunnel + sticky routing state for a
// peer so the next dial retries a fresh direct UDP path.
//
// Use case: ping <peer> works (the small UDP fits through the beacon
// relay just fine) but send-file <peer> hangs ~120s and EOFs — symptom
// of a relay-mediated tunnel that established once and got stuck for
// stream traffic. Calling prefer-direct + retrying the dial routes the
// next attempt through ensureTunnel's resolve-and-punch path, which
// usually re-establishes a working direct UDP path.
func cmdPreferDirect(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl prefer-direct <node_id|address|hostname>")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := resolveToNodeID(d, args[0])
	resp, err := d.PreferDirect(nodeID)
	if err != nil {
		if strings.Contains(err.Error(), "unknown command") {
			fatalHint("not_implemented",
				"upgrade the daemon: brew upgrade pilotprotocol  (or re-run install.sh)",
				"daemon does not support prefer-direct (pre-v1.12.0)")
		}
		fatalCode("connection_failed", "prefer-direct: %v", err)
	}
	if jsonOutput {
		outputOK(resp)
		return
	}
	had, _ := resp["had_tunnel"].(bool)
	wasActive, _ := resp["was_relay_active"].(bool)
	wasPinned, _ := resp["was_relay_pinned"].(bool)
	fmt.Printf("reset routing state for node %d\n", nodeID)
	fmt.Println(sDim(fmt.Sprintf("  tunnel was up: %v · relay was active: %v · relay was pinned: %v", had, wasActive, wasPinned)))
	fmt.Println(sDim("  next dial will re-resolve from registry and prefer direct; falls back to relay if direct still fails"))
}

func cmdUntrust(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl untrust <node_id|address|hostname>")
	}
	d := connectDriver()
	defer d.Close()

	nodeID := resolveToNodeID(d, args[0])
	_, err := d.RevokeTrust(nodeID)
	if err != nil {
		fatalCode("connection_failed", "untrust: %v", err)
	}
	if jsonOutput {
		outputOK(map[string]interface{}{"node_id": nodeID})
		return
	}
	fmt.Printf("trust revoked for node %d\n", nodeID)
	fmt.Println(sDim(fmt.Sprintf("  re-establish later: pilotctl handshake %d", nodeID)))
}

func cmdPending() {
	d := connectDriver()
	defer d.Close()

	result, err := d.PendingHandshakes()
	if err != nil {
		fatalCode("connection_failed", "pending: %v", err)
	}

	pending, ok := result["pending"].([]interface{})
	if !ok {
		pending = []interface{}{}
	}

	if jsonOutput {
		output(map[string]interface{}{"pending": pending})
		return
	}

	if len(pending) == 0 {
		fmt.Println("no pending handshake requests")
		fmt.Println("  requests appear here when another node sends: pilotctl handshake <your-node-id>")
		return
	}

	fmt.Printf("%s\n\n", sBold(fmt.Sprintf("Pending handshakes — %d", len(pending))))
	now := time.Now()
	for _, p := range pending {
		req := p.(map[string]interface{})
		nodeID := int(req["node_id"].(float64))
		justification, _ := req["justification"].(string)
		receivedAt := int64(req["received_at"].(float64))
		t := time.Unix(receivedAt, 0)
		fmt.Printf("  %s %s\n", sAccent(fmt.Sprintf("node %d", nodeID)), sDim(fmt.Sprintf("· %s ago (%s)", fmtDuration(now.Sub(t)), t.Format("2006-01-02 15:04"))))
		if justification != "" {
			fmt.Printf("  %s\n", inboxPreview(justification, 160))
		}
		fmt.Printf("  %s\n\n", sDim(fmt.Sprintf("accept: pilotctl approve %d · decline: pilotctl reject %d \"reason\"", nodeID, nodeID)))
	}
}

func cmdTrust(args []string) {
	flags, _ := parseFlags(args)
	limit := flagInt(flags, "limit", 20)
	_, limitExplicit := flags["limit"]
	search := flagString(flags, "search", "")

	d := connectDriver()
	defer d.Close()

	result, err := d.TrustedPeers()
	if err != nil {
		fatalCode("connection_failed", "trust: %v", err)
	}

	trusted, ok := result["trusted"].([]interface{})
	if !ok {
		trusted = []interface{}{}
	}

	// Filter by --search (node id substring; hostname too when present).
	if search != "" {
		needle := strings.ToLower(search)
		var matched []interface{}
		for _, t := range trusted {
			rec, _ := t.(map[string]interface{})
			if rec == nil {
				continue
			}
			nodeIDStr := fmt.Sprintf("%d", int(rec["node_id"].(float64)))
			hostname, _ := rec["hostname"].(string)
			if strings.Contains(nodeIDStr, needle) || strings.Contains(strings.ToLower(hostname), needle) {
				matched = append(matched, t)
			}
		}
		trusted = matched
		if trusted == nil {
			trusted = []interface{}{}
		}
	}

	// Newest first by approval time.
	sort.SliceStable(trusted, func(i, j int) bool {
		ri, _ := trusted[i].(map[string]interface{})
		rj, _ := trusted[j].(map[string]interface{})
		ai, _ := ri["approved_at"].(float64)
		aj, _ := rj["approved_at"].(float64)
		return ai > aj
	})

	total := len(trusted)

	if jsonOutput {
		// Shape unchanged; "total" is the pre-limit count. The list is
		// only bounded when --limit is passed explicitly so existing
		// agent invocations keep seeing the full set.
		list := trusted
		if limitExplicit && limit > 0 && len(list) > limit {
			list = list[:limit]
		}
		output(map[string]interface{}{"trusted": list, "total": total})
		return
	}

	if total == 0 {
		if search != "" {
			fmt.Printf("no trusted peers matching %q\n", search)
		} else {
			fmt.Println("no trusted peers")
			fmt.Println("  establish trust: pilotctl handshake <node_id|hostname> \"reason\"")
		}
		return
	}

	shown := trusted
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	header := sBold(fmt.Sprintf("Trusted peers — %d", total))
	qualifier := ""
	if search != "" {
		qualifier = fmt.Sprintf(" · matching %q", search)
	}
	if len(shown) < total {
		qualifier += fmt.Sprintf(" · showing %d newest", len(shown))
	}
	fmt.Printf("%s%s\n\n", header, sDim(qualifier))

	for _, t := range shown {
		rec := t.(map[string]interface{})
		nodeID := int(rec["node_id"].(float64))
		mutual := false
		if m, ok := rec["mutual"].(bool); ok {
			mutual = m
		}
		network := uint16(0)
		if n, ok := rec["network"].(float64); ok {
			network = uint16(n)
		}
		approvedAt := int64(rec["approved_at"].(float64))
		at := time.Unix(approvedAt, 0)

		id := sAccent(fmt.Sprintf("node %d", nodeID))
		if hostname, _ := rec["hostname"].(string); hostname != "" {
			id += " " + sAccent(hostname)
		}
		meta := fmt.Sprintf("· approved %s", at.Format("2006-01-02 15:04"))
		if network > 0 {
			meta += fmt.Sprintf(" · net %d", network)
		}
		line := fmt.Sprintf("  %s %s", id, sDim(meta))
		if !mutual {
			// MUTUAL=yes is the norm — only the asymmetric case is news.
			line += " " + sWarn("one-way")
		}
		fmt.Println(line)
	}
	fmt.Printf("\n%s\n", sDim("show more: --limit <n> (0 = all) · search: --search <substr> · revoke: pilotctl untrust <id> · json: --json"))
}

// ===================== MANAGEMENT =====================

func cmdConnections() {
	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	connList, ok := info["conn_list"].([]interface{})
	if !ok {
		connList = []interface{}{}
	}

	if jsonOutput {
		output(map[string]interface{}{
			"connections": connList,
			"total":       len(connList),
		})
		return
	}

	if len(connList) == 0 {
		fmt.Println("no active connections")
		fmt.Println("  connect to a peer: pilotctl connect <address|hostname> --message \"hello\"")
		return
	}

	maxDisplay := 50
	fmt.Printf("Active connections: %d\n\n", len(connList))
	fmt.Printf("%-4s  %-6s  %-22s  %-6s  %-11s  %-8s  %-8s  %-8s  %-6s  %-6s  %-8s  %-8s\n",
		"ID", "LOCAL", "REMOTE ADDR", "RPORT", "STATE", "CWND", "FLIGHT", "SRTT", "UNACK", "OOO", "PEERWIN", "RCVWIN")
	displayed := 0
	for _, c := range connList {
		if displayed >= maxDisplay {
			fmt.Printf("\n... and %d more connections (showing first %d)\n", len(connList)-maxDisplay, maxDisplay)
			break
		}
		displayed++
		conn := c.(map[string]interface{})
		peerWin := int(conn["peer_recv_win"].(float64))
		recvWin := int(conn["recv_win"].(float64))
		peerWinStr := "—"
		if peerWin >= 0 {
			peerWinStr = formatBytes(uint64(peerWin))
		}
		fmt.Printf("%-4d  %-6d  %-22s  %-6d  %-11s  %-8s  %-8s  %-6.0fms  %-6d  %-6d  %-8s  %-8s\n",
			int(conn["id"].(float64)),
			int(conn["local_port"].(float64)),
			conn["remote_addr"],
			int(conn["remote_port"].(float64)),
			conn["state"],
			formatBytes(uint64(conn["cong_win"].(float64))),
			formatBytes(uint64(conn["in_flight"].(float64))),
			conn["srtt_ms"].(float64),
			int(conn["unacked"].(float64)),
			int(conn["ooo_buf"].(float64)),
			peerWinStr,
			formatBytes(uint64(recvWin)),
		)
		bytesSent := uint64(conn["bytes_sent"].(float64))
		bytesRecv := uint64(conn["bytes_recv"].(float64))
		segsSent := uint64(conn["segs_sent"].(float64))
		segsRecv := uint64(conn["segs_recv"].(float64))
		retx := uint64(conn["retransmits"].(float64))
		fastRetx := uint64(conn["fast_retx"].(float64))
		sackRecv := uint64(conn["sack_recv"].(float64))
		sackSent := uint64(conn["sack_sent"].(float64))
		dupAcks := uint64(conn["dup_acks"].(float64))
		fmt.Printf("      tx: %s (%d segs)  rx: %s (%d segs)  retx: %d  fast-retx: %d  sack: %d/%d  dup-ack: %d\n",
			formatBytes(bytesSent), segsSent, formatBytes(bytesRecv), segsRecv,
			retx, fastRetx, sackSent, sackRecv, dupAcks)
	}
}

func cmdDisconnect(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl disconnect <conn_id>")
	}
	connID, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid connection ID: %v", err)
	}

	d := connectDriver()
	defer d.Close()

	if err := d.Disconnect(uint32(connID)); err != nil {
		fatalCode("connection_failed", "disconnect: %v", err)
	}
	outputOK(map[string]interface{}{"conn_id": connID})
}

// ===================== DIAGNOSTICS =====================

func cmdInfo(args []string) {
	_ = args
	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	// Always redact per-peer endpoints and STUN-discovered addresses.
	redactPeerEndpoints(info)

	if jsonOutput {
		output(info)
		return
	}

	// Human-readable: health-style grouped layout.
	uptime := info["uptime_secs"].(float64)

	bytesSent := uint64(info["bytes_sent"].(float64))
	bytesRecv := uint64(info["bytes_recv"].(float64))
	pktsSent := uint64(info["pkts_sent"].(float64))
	pktsRecv := uint64(info["pkts_recv"].(float64))

	encryptEnabled := false
	if e, ok := info["encrypt"].(bool); ok {
		encryptEnabled = e
	}
	encryptedPeers := 0
	if ep, ok := info["encrypted_peers"].(float64); ok {
		encryptedPeers = int(ep)
	}

	const labelW = 10
	label := func(s string) string { return "  " + sDim(fmt.Sprintf("%-*s", labelW, s)) + " " }
	cont := "  " + strings.Repeat(" ", labelW) + " "

	// Headline: ● pilot-daemon v1.10.9 · up 56h12m
	head := statusDot("ok") + " " + sBold("pilot-daemon")
	if v, ok := info["version"].(string); ok && v != "" {
		head += " " + v
	}
	fmt.Printf("%s %s\n\n", head, sDim("· up "+fmtDuration(time.Duration(uptime)*time.Second)))

	// identity — hostname · address · node id, then key/persistence/email.
	var idParts []string
	if hostname, ok := info["hostname"].(string); ok && hostname != "" {
		idParts = append(idParts, sAccent(hostname))
	}
	idParts = append(idParts, sAccent(fmt.Sprint(info["address"])))
	idParts = append(idParts, fmt.Sprintf("node %d", int(info["node_id"].(float64))))
	fmt.Printf("%s%s\n", label("identity"), strings.Join(idParts, " · "))

	hasIdentity := false
	if id, ok := info["identity"].(bool); ok {
		hasIdentity = id
	}
	var keyParts []string
	if hasIdentity {
		pubKey, _ := info["public_key"].(string)
		if len(pubKey) > 8 {
			pubKey = pubKey[:8] + "…"
		}
		keyParts = append(keyParts, "Ed25519 "+pubKey, "persistent")
	} else {
		keyParts = append(keyParts, "ephemeral (not persisted)")
	}
	if email, ok := info["email"].(string); ok && email != "" {
		// Synthetic emails are auto-derived from the public-key fingerprint
		// and end with @nodes.pilotprotocol.network — tag them so users see
		// at a glance whether this node has a real identity.
		if strings.HasSuffix(email, "@nodes.pilotprotocol.network") {
			keyParts = append(keyParts, email+" "+sDim("(auto-generated — set your own: pilotctl set-email <addr>)"))
		} else {
			keyParts = append(keyParts, email)
		}
	}
	fmt.Printf("%s%s\n", cont, strings.Join(keyParts, " · "))

	// network — peers breakdown + pending, then beacon/connections/ports.
	totalPeers := int(info["peers"].(float64))
	relayPeers := 0
	if rp, ok := info["relay_peer_count"].(float64); ok {
		relayPeers = int(rp)
	}
	directPeers := totalPeers - relayPeers
	netLine := fmt.Sprintf("%d peers %s", totalPeers,
		sDim(fmt.Sprintf("(%d encrypted · %d relay · %d direct)", encryptedPeers, relayPeers, directPeers)))
	if !encryptEnabled {
		netLine += " · " + sWarn("encryption disabled")
	}
	if pending, ok := info["handshake_pending_count"].(float64); ok && int(pending) > 0 {
		netLine += " · " + sWarn(fmt.Sprintf("%d pending handshake(s)", int(pending))) + " " + sDim("— pilotctl pending")
	}
	fmt.Printf("%s%s\n", label("network"), netLine)

	var infraParts []string
	if beacon, ok := info["beacon_addr"].(string); ok && beacon != "" {
		infraParts = append(infraParts, "beacon "+sAccent(beacon))
	}
	connList, _ := info["conn_list"].([]interface{})
	connsPart := fmt.Sprintf("%d connections", int(info["connections"].(float64)))
	if len(connList) > 0 {
		connsPart += " " + sDim("(details: pilotctl connections)")
	}
	infraParts = append(infraParts, connsPart)
	infraParts = append(infraParts, fmt.Sprintf("%d ports", int(info["ports"].(float64))))
	fmt.Printf("%s%s\n", cont, strings.Join(infraParts, " · "))

	// networks — joined overlay networks, one compact line.
	if nets, ok := info["networks"].([]interface{}); ok && len(nets) > 0 {
		var netParts []string
		for _, n := range nets {
			nm, _ := n.(map[string]interface{})
			addr, _ := nm["address"].(string)
			netParts = append(netParts, sAccent(addr))
		}
		fmt.Printf("%s%d %s\n", label("networks"), len(nets), sDim("— ")+strings.Join(netParts, " · "))
	}

	// traffic — ↑ sent · ↓ received with compact packet counts.
	fmt.Printf("%s↑ %s %s · ↓ %s %s\n", label("traffic"),
		formatBytes(bytesSent), sDim(fmt.Sprintf("(%s pkts)", fmtCount(pktsSent))),
		formatBytes(bytesRecv), sDim(fmt.Sprintf("(%s pkts)", fmtCount(pktsRecv))))

	// skills — tool names only; full paths live in `pilotctl skills`.
	if tools := skillInstallTools(); len(tools) > 0 {
		fmt.Printf("%sinstalled in %s   %s\n", label("skills"),
			strings.Join(tools, " · "), sDim("(details: pilotctl skills)"))
	}
}

func cmdHealth() {
	d := connectDriver()
	defer d.Close()

	health, err := d.Health()
	if err != nil {
		fatalCode("connection_failed", "health: %v", err)
	}

	if jsonOutput {
		output(health)
		return
	}

	uptime := int64(0)
	if v, ok := health["uptime_seconds"].(float64); ok {
		uptime = int64(v)
	}
	hours := uptime / 3600
	mins := (uptime % 3600) / 60
	secs := uptime % 60

	peers := int(health["peers"].(float64))
	encPeers := 0
	if ep, ok := health["encrypted_peers"].(float64); ok {
		encPeers = int(ep)
	}
	relayPeers := 0
	if rp, ok := health["relay_peer_count"].(float64); ok {
		relayPeers = int(rp)
	}
	pending := 0
	if hp, ok := health["handshake_pending_count"].(float64); ok {
		pending = int(hp)
	}
	queueDrops := uint64(0)
	if qd, ok := health["accept_queue_drops"].(float64); ok {
		queueDrops = uint64(qd)
	}
	webhookDropped := uint64(0)
	if wd, ok := health["webhook_queue_dropped"].(float64); ok {
		webhookDropped = uint64(wd)
	}

	status, _ := health["status"].(string)
	dotState := "ok"
	if status != "ok" {
		dotState = "err"
	}
	fmt.Printf("%s %s %s\n", statusDot(dotState), sBold("pilot-daemon"), status)
	fmt.Printf("  %s\n", sDim(fmt.Sprintf("uptime %02d:%02d:%02d · %d connection(s)", hours, mins, secs, int(health["connections"].(float64)))))
	fmt.Printf("  peers     %s %s\n", sBold(fmt.Sprintf("%d", peers)), sDim(fmt.Sprintf("(%d encrypted, %d via relay)", encPeers, relayPeers)))
	fmt.Printf("  traffic   %s\n", sDim(fmt.Sprintf("↑ %s  ↓ %s",
		formatBytes(uint64(health["bytes_sent"].(float64))),
		formatBytes(uint64(health["bytes_recv"].(float64))))))
	if pending > 0 {
		fmt.Printf("  %s %s\n", sWarn(fmt.Sprintf("%d pending handshake(s)", pending)), sDim("— review with: pilotctl pending"))
	}
	if queueDrops > 0 {
		fmt.Printf("  %s %s\n", sWarn(fmt.Sprintf("%d accept-queue drop(s)", queueDrops)), sDim("— increase system limits if persistent"))
	}
	if webhookDropped > 0 {
		fmt.Printf("  %s\n", sWarn(fmt.Sprintf("%d webhook event(s) dropped", webhookDropped)))
	}
}

func cmdPeers(args []string) {
	flags, _ := parseFlags(args)
	search := flagString(flags, "search", "")
	showAll := flagBool(flags, "all")
	limit := flagInt(flags, "limit", 20)

	d := connectDriver()
	defer d.Close()

	info, err := d.Info()
	if err != nil {
		fatalCode("connection_failed", "info: %v", err)
	}

	peerList, ok := info["peer_list"].([]interface{})
	if !ok {
		peerList = []interface{}{}
	}

	// Strip endpoint fields — never shown in peers output.
	var filtered []interface{}
	for _, p := range peerList {
		peer, _ := p.(map[string]interface{})
		if peer == nil {
			continue
		}
		cp := make(map[string]interface{}, len(peer))
		for k, v := range peer {
			if k == "endpoint" || k == "real_addr" || k == "lan_addrs" || k == "public_addr" {
				continue
			}
			cp[k] = v
		}
		if search != "" {
			nodeIDStr := fmt.Sprintf("%d", int(peer["node_id"].(float64)))
			if !strings.Contains(nodeIDStr, strings.ToLower(search)) {
				continue
			}
		}
		filtered = append(filtered, cp)
	}

	// Summary counts. "secure" = encrypted AND authenticated; everything
	// else is an exception worth surfacing.
	total := len(filtered)
	encCount, secure, relayCount := 0, 0, 0
	var exceptions []map[string]interface{}
	for _, p := range filtered {
		peer := p.(map[string]interface{})
		enc, _ := peer["encrypted"].(bool)
		auth, _ := peer["authenticated"].(bool)
		rly, _ := peer["relay"].(bool)
		if enc {
			encCount++
		}
		if rly {
			relayCount++
		}
		if enc && auth {
			secure++
		} else {
			exceptions = append(exceptions, peer)
		}
	}
	direct := total - relayCount

	if jsonOutput {
		output(map[string]interface{}{
			"peers":     filtered,
			"total":     total,
			"encrypted": encCount,
		})
		return
	}

	if total == 0 {
		if search != "" {
			fmt.Printf("no peers matching %q\n", search)
		} else {
			fmt.Println("no peers connected")
			fmt.Println("  peers appear when you communicate with other nodes")
		}
		return
	}

	noun := "peers"
	if total == 1 {
		noun = "peer"
	}
	dotState := "ok"
	if len(exceptions) > 0 {
		dotState = "warn"
	}
	fmt.Printf("%s %s %s\n", statusDot(dotState),
		sBold(fmt.Sprintf("%d %s", total, noun)),
		sDim(fmt.Sprintf("— %d encrypted+authenticated · %d relay · %d direct", secure, relayCount, direct)))

	if showAll {
		fmt.Printf("\n%-10s  %-10s  %-10s  %-6s\n", "NODE ID", "ENCRYPTED", "AUTH", "PATH")
		shown := 0
		for _, p := range filtered {
			if limit > 0 && shown >= limit {
				fmt.Printf("%s\n", sDim(fmt.Sprintf("  … and %d more — show more: --limit %d (0 = all)", total-shown, total)))
				break
			}
			shown++
			peer := p.(map[string]interface{})
			enc, _ := peer["encrypted"].(bool)
			auth, _ := peer["authenticated"].(bool)
			rly, _ := peer["relay"].(bool)
			encStr := "yes"
			if !enc {
				encStr = sWarn(fmt.Sprintf("%-10s", "no"))
			} else {
				encStr = fmt.Sprintf("%-10s", encStr)
			}
			authStr := "yes"
			if !auth {
				authStr = sWarn(fmt.Sprintf("%-10s", "no"))
			} else {
				authStr = fmt.Sprintf("%-10s", authStr)
			}
			pathStr := sOK("direct")
			if rly {
				pathStr = sDim("relay")
			}
			fmt.Printf("%-10d  %s  %s  %s\n", int(peer["node_id"].(float64)), encStr, authStr, pathStr)
		}
	} else if len(exceptions) > 0 {
		fmt.Println()
		shown := 0
		for _, peer := range exceptions {
			if limit > 0 && shown >= limit {
				fmt.Printf("  %s\n", sDim(fmt.Sprintf("… and %d more exception(s) — show more: --limit %d", len(exceptions)-shown, len(exceptions))))
				break
			}
			shown++
			enc, _ := peer["encrypted"].(bool)
			auth, _ := peer["authenticated"].(bool)
			rly, _ := peer["relay"].(bool)
			var probs []string
			if !enc {
				probs = append(probs, "unencrypted")
			}
			if !auth {
				probs = append(probs, "unauthenticated")
			}
			pathStr := "direct"
			if rly {
				pathStr = "relay"
			}
			fmt.Printf("  %s %s %s\n", statusDot("warn"),
				sAccent(fmt.Sprintf("node %d", int(peer["node_id"].(float64)))),
				sDim(fmt.Sprintf("— %s · %s", strings.Join(probs, " · "), pathStr)))
		}
	}
	fmt.Printf("\n%s\n", sDim("list all: --all · search: --search <query> · json: --json"))
}

func cmdPing(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl ping <address|hostname> [--count <n>] [--timeout <dur>] [--trace]")
	}

	count := flagInt(flags, "count", 4)
	// Default 5s (not the 30s used elsewhere): ping is a reachability probe,
	// and a fast verdict beats a patient one. Override with --timeout.
	timeout := flagDuration(flags, "timeout", 5*time.Second)

	// --trace (or PILOTCTL_TRACE_TIME=1) prints per-step timing to stderr:
	// startup overhead, IPC connect, hostname lookup, and per-packet
	// dial/echo split so you can see where latency actually lives.
	traceTime := os.Getenv("PILOTCTL_TRACE_TIME") != "" || flagBool(flags, "trace")
	// --reuse-conn (or PILOT_PING_REUSE_CONN=1): dial once before the loop
	// and reuse the stream connection for all echo packets. Reconnects only
	// on error. Eliminates the ~1.5×RTT TCP-handshake overhead on packets
	// 2+, saving ~72ms per packet on relay paths. Ablation flag — default
	// off so behavior is identical to previous versions unless opted in.
	reuseConn := flagBool(flags, "reuse-conn") || os.Getenv("PILOT_PING_REUSE_CONN") != "" || featureEnabled("ping.reuse_conn")
	t0 := time.Now()
	var traceEvents []map[string]interface{}
	tracef := func(label string) {
		if !traceTime {
			return
		}
		ms := float64(time.Since(t0).Microseconds()) / 1000.0
		if jsonOutput {
			traceEvents = append(traceEvents, map[string]interface{}{"label": label, "ms": ms})
		} else {
			fmt.Fprintf(os.Stderr, "TRACE %-22s %12.3fms\n", label, ms)
		}
	}

	d := connectDriver()
	tracef("connectDriver")
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	tracef("parseAddrOrHostname")
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))
	tracef("maybeAutoHandshake")

	if !jsonOutput {
		fmt.Printf("PING %s\n", target)
	}

	// On dial/echo failure, print one actionable hint (text mode only,
	// once per invocation) mirroring the send-message dial-timeout hint.
	hintPrinted := false
	printFailHint := func() {
		if jsonOutput || hintPrinted {
			return
		}
		hintPrinted = true
		fmt.Fprintln(os.Stderr, sDim("hint: peer may be relay-converging after a beacon roll (~30s) — check reachability: pilotctl peers · trust state: pilotctl trust"))
	}

	var results []map[string]interface{}
	overall := time.NewTimer(timeout)
	defer overall.Stop()
	// Per-attempt budget so a single dial against a ghost peer cannot
	// blow past the user's --timeout. Split evenly across remaining count
	// with a 10s floor so legitimate cold-start handshakes have room
	// even when the daemon is in the post-restart "trust resync +
	// inbound key-exchange storm" window: 7+ trusted peers can be
	// concurrently establishing crypto state for ~30-60 s after a
	// fresh start, and the dial's encrypted-SYN write competes with
	// those handlers for the relay socket. The previous 4 s floor
	// occasionally expired mid-handshake on the first ping after
	// startup; 10 s covers it without making bad dials feel sluggish.
	perAttempt := timeout / time.Duration(count)
	if perAttempt < 10*time.Second {
		perAttempt = 10 * time.Second
	}

	// reuseConn mode: one shared connection across all iterations.
	// nil = needs dial. Reconnects only on error to avoid the ~1.5×RTT
	// TCP-handshake cost on packets 2+. Disabled by default (ablation flag).
	dialOnce := func() (*driver.Conn, time.Duration, error) {
		// DialAddrTimeout enforces the per-attempt budget at the daemon-IPC
		// layer and cancels the dial on expiry, so a timed-out ping against a
		// ghost peer doesn't leak a goroutine or leave a dangling daemon-side
		// dial (the previous goroutine+select drained but could not cancel the
		// underlying dial).
		t0 := time.Now()
		c, e := d.DialAddrTimeout(target, protocol.PortEcho, perAttempt)
		return c, time.Since(t0), e
	}

	var sharedConn *driver.Conn
	if reuseConn {
		defer func() {
			if sharedConn != nil {
				sharedConn.Close()
			}
		}()
	}

	for i := 0; i < count; i++ {
		select {
		case <-overall.C:
			if jsonOutput {
				output(map[string]interface{}{
					"target":  target.String(),
					"to":      target.String(),
					"results": results,
					"timeout": true,
				})
			} else {
				fmt.Println("timeout")
			}
			return
		default:
		}

		start := time.Now()
		var conn *driver.Conn
		var dialElapsed time.Duration
		connReused := false

		// Per-attempt progress line: dial+echo against a slow or ghost
		// peer can silently block up to perAttempt (>=10s). Stopped
		// before any stdout print so the animation never interleaves
		// with seq=N result lines. stopProgress is idempotent.
		stopProgress := startWaitProgress(fmt.Sprintf("pinging %s", target))

		if reuseConn {
			if sharedConn == nil {
				var dialErr error
				sharedConn, dialElapsed, dialErr = dialOnce()
				if dialErr != nil {
					stopProgress()
					r := map[string]interface{}{"seq": i, "error": dialErr.Error()}
					results = append(results, r)
					if !jsonOutput {
						fmt.Printf("seq=%d error: %v\n", i, dialErr)
					}
					printFailHint()
					if i < count-1 {
						time.Sleep(time.Second)
					}
					continue
				}
			} else {
				connReused = true
			}
			conn = sharedConn
		} else {
			var dialErr error
			conn, dialElapsed, dialErr = dialOnce()
			if dialErr != nil {
				stopProgress()
				r := map[string]interface{}{"seq": i, "error": dialErr.Error()}
				results = append(results, r)
				if !jsonOutput {
					fmt.Printf("seq=%d error: %v\n", i, dialErr)
				}
				printFailHint()
				if i < count-1 {
					time.Sleep(time.Second)
				}
				continue
			}
		}

		// Build payload. In trace mode embed [TRCE][8-byte sent_at_ns] so the
		// echo service can stamp its receive time and reflect it back.
		var pktPayload []byte
		var sentAtNs int64
		if traceTime {
			pktPayload = make([]byte, 12)
			copy(pktPayload[0:4], "TRCE")
			sentAtNs = time.Now().UnixNano()
			binary.BigEndian.PutUint64(pktPayload[4:12], uint64(sentAtNs))
		} else {
			pktPayload = []byte(fmt.Sprintf("ping-%d", i))
		}

		echoStart := time.Now()
		conn.Write(pktPayload)

		conn.SetReadDeadline(time.Now().Add(perAttempt))
		buf := make([]byte, 1024)
		n, readErr := conn.Read(buf)
		recvAtNs := time.Now().UnixNano()
		echoElapsed := time.Since(echoStart)
		stopProgress()

		if !reuseConn {
			conn.Close()
		} else if readErr != nil {
			// Drop the broken connection; next iteration redials.
			sharedConn.Close()
			sharedConn = nil
		}

		rtt := time.Since(start)
		r := map[string]interface{}{
			"seq":    i,
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		}
		if traceTime {
			if !connReused {
				r["dial_ms"] = float64(dialElapsed.Microseconds()) / 1000.0
			}
			r["echo_ms"] = float64(echoElapsed.Microseconds()) / 1000.0
		}
		if connReused {
			r["reused"] = true
		}
		err = readErr
		if err != nil {
			r["error"] = err.Error()
			if !jsonOutput {
				fmt.Printf("seq=%d error: %v\n", i, err)
			}
			printFailHint()
		} else {
			r["bytes"] = n
			// Parse TRCE response: [TRCE][sent_at_ns][server_recv_at_ns]
			var serverRecvNs int64
			if traceTime && n >= 20 && string(buf[0:4]) == "TRCE" {
				serverRecvNs = int64(binary.BigEndian.Uint64(buf[12:20]))
				toServer := time.Duration(serverRecvNs - sentAtNs)
				fromServer := time.Duration(recvAtNs - serverRecvNs)
				r["to_server_ms"] = float64(toServer.Microseconds()) / 1000.0
				r["from_server_ms"] = float64(fromServer.Microseconds()) / 1000.0
			}
			if !jsonOutput {
				reusedTag := ""
				if connReused {
					reusedTag = " [reused]"
				}
				if traceTime && serverRecvNs > 0 {
					toServer := time.Duration(serverRecvNs - sentAtNs)
					fromServer := time.Duration(recvAtNs - serverRecvNs)
					if connReused {
						fmt.Printf("seq=%d bytes=%d time=%v  [→srv=%v ←srv=%v]%s\n",
							i, n, rtt,
							toServer.Round(time.Microsecond),
							fromServer.Round(time.Microsecond),
							reusedTag)
					} else {
						fmt.Printf("seq=%d bytes=%d time=%v  [dial=%v →srv=%v ←srv=%v]\n",
							i, n, rtt,
							dialElapsed.Round(time.Microsecond),
							toServer.Round(time.Microsecond),
							fromServer.Round(time.Microsecond))
					}
				} else {
					// Always show dial/echo breakdown — tells you whether RTT
					// is dominated by relay setup or actual peer latency.
					if connReused {
						fmt.Printf("seq=%d bytes=%d time=%v  [echo=%v]%s\n", i, n, rtt, echoElapsed.Round(time.Microsecond), reusedTag)
					} else {
						fmt.Printf("seq=%d bytes=%d time=%v  [dial=%v echo=%v]\n", i, n, rtt, dialElapsed.Round(time.Microsecond), echoElapsed.Round(time.Microsecond))
					}
				}
			}
		}
		results = append(results, r)

		if i < count-1 {
			time.Sleep(time.Second)
		}
	}

	// Exit non-zero if every attempt failed (rc lets shell scripts
	// distinguish "ping worked" from "all attempts failed under
	// partition").
	allFailed := len(results) > 0
	for _, r := range results {
		if _, hasErr := r["error"]; !hasErr {
			allFailed = false
			break
		}
	}
	if jsonOutput {
		out := map[string]interface{}{
			"target":  target.String(),
			"to":      target.String(),
			"results": results,
			"timeout": false,
		}
		if len(traceEvents) > 0 {
			out["trace"] = traceEvents
		}
		output(out)
	}
	if allFailed {
		os.Exit(1)
	}
}

func cmdTraceroute(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl traceroute <address> [--timeout <dur>]")
	}

	timeout := flagDuration(flags, "timeout", 30*time.Second)

	d := connectDriver()
	defer d.Close()

	target, err := protocol.ParseAddr(pos[0])
	if err != nil {
		fatalCode("invalid_argument", "parse address: %v", err)
	}

	if !jsonOutput {
		fmt.Printf("TRACEROUTE %s\n", target)
	}

	// Tunnel negotiation against a slow or unreachable peer blocks silently
	// for up to --timeout; show elapsed progress on a TTY. DialAddrTimeout
	// cancels the underlying daemon dial on expiry so a timed-out traceroute
	// does not leave a dangling connection behind in the daemon.
	start := time.Now()
	stopProgress := startWaitProgress(fmt.Sprintf("tracing %s", target))
	conn, dialErr := d.DialAddrTimeout(target, protocol.PortEcho, timeout)
	stopProgress()

	setupTime := time.Since(start)
	if dialErr != nil {
		if jsonOutput {
			output(map[string]interface{}{
				"target":   target.String(),
				"setup_ms": float64(setupTime.Microseconds()) / 1000.0,
				"error":    dialErr.Error(),
			})
		} else {
			fmt.Printf("  1  %s  connection failed: %v\n", target, dialErr)
		}
		return
	}

	if !jsonOutput {
		fmt.Printf("  1  %s  setup=%v\n", target, setupTime)
	}

	var rttSamples []map[string]interface{}
	for i := 0; i < 3; i++ {
		pingStart := time.Now()
		payload := fmt.Sprintf("trace-%d", i)
		if _, werr := conn.Write([]byte(payload)); werr != nil {
			// The connection dropped mid-trace: record the write failure and
			// don't block in Read waiting for an echo that will never come.
			rtt := time.Since(pingStart)
			sample := map[string]interface{}{
				"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
				"error":  werr.Error(),
			}
			rttSamples = append(rttSamples, sample)
			if !jsonOutput {
				fmt.Printf("     rtt=%v write error: %v\n", rtt, werr)
			}
			break
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		rtt := time.Since(pingStart)

		sample := map[string]interface{}{
			"rtt_ms": float64(rtt.Microseconds()) / 1000.0,
		}
		if err != nil {
			sample["error"] = err.Error()
			if !jsonOutput {
				fmt.Printf("     rtt=%v error: %v\n", rtt, err)
			}
		} else {
			sample["bytes"] = n
			if !jsonOutput {
				fmt.Printf("     rtt=%v bytes=%d\n", rtt, n)
			}
		}
		rttSamples = append(rttSamples, sample)
	}
	conn.Close()

	if jsonOutput {
		output(map[string]interface{}{
			"target":      target.String(),
			"setup_ms":    float64(setupTime.Microseconds()) / 1000.0,
			"rtt_samples": rttSamples,
		})
	} else {
		fmt.Printf("\nsetup includes: tunnel negotiation + SYN/ACK handshake\n")
		fmt.Printf("rtt is: data round-trip over established connection\n")
	}
}

func cmdBench(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl bench <address|hostname> [size_mb] [--timeout <dur>]")
	}

	timeout := flagDuration(flags, "timeout", 120*time.Second)

	// Validate the size before touching the daemon so a nonsense size fails
	// fast (and can't tie up the transport). Negatives/zero/NaN/Inf would
	// underflow the int conversion or busy-loop the send; an absurd size
	// would run the echo path indefinitely. Cap at a generous 4 GiB.
	totalSize := 1024 * 1024
	if len(pos) > 1 {
		sizeMB, perr := strconv.ParseFloat(pos[1], 64)
		if perr != nil {
			fatalCode("invalid_argument", "invalid size: %v", perr)
		}
		const maxSizeMB = 4096.0
		if !(sizeMB > 0) {
			fatalCode("invalid_argument", "size must be a positive number of MB, got %q", pos[1])
		}
		if sizeMB > maxSizeMB {
			fatalCode("invalid_argument", "size %g MB exceeds maximum of %g MB", sizeMB, maxSizeMB)
		}
		totalSize = int(sizeMB * 1024 * 1024)
		if totalSize <= 0 {
			fatalCode("invalid_argument", "size %q is too small to send", pos[1])
		}
	}
	const chunkSize = 4096

	d := connectDriver()
	defer d.Close()

	target, err := parseAddrOrHostname(d, pos[0])
	if err != nil {
		fatalCode("not_found", "%v", err)
	}
	maybeAutoHandshake(d, target, flagBool(flags, "no-auto-handshake"))

	if !jsonOutput {
		fmt.Printf("BENCH %s — sending %s via echo port\n", target, formatBytes(uint64(totalSize)))
	}

	conn, err := d.DialAddrTimeout(target, protocol.PortEcho, timeout)
	if err != nil {
		fatalHint("connection_failed",
			fmt.Sprintf("check that %s is reachable: pilotctl ping %s", target, target),
			"cannot connect to %s echo port", target)
	}
	defer conn.Close()

	var recvTotal int
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, 65535)
		for recvTotal < totalSize {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			recvTotal += n
		}
	}()

	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	start := time.Now()
	sent := 0
	for sent < totalSize {
		remaining := totalSize - sent
		writeSize := chunkSize
		if remaining < writeSize {
			writeSize = remaining
		}
		if _, err := conn.Write(chunk[:writeSize]); err != nil {
			fatalCode("connection_failed", "write: %v", err)
		}
		sent += writeSize
	}
	sendDuration := time.Since(start)

	// Waiting for the full echo to come back is the silent half of the
	// benchmark — on a slow path it can run to --timeout with no output.
	stopProgress := startWaitProgress(fmt.Sprintf("benchmarking %s", target))
	select {
	case <-recvDone:
		stopProgress()
	case <-time.After(timeout):
		stopProgress()
		if !jsonOutput {
			fmt.Printf("warning: receive timed out (got %s of %s)\n",
				formatBytes(uint64(recvTotal)), formatBytes(uint64(totalSize)))
		}
	}
	totalDuration := time.Since(start)

	sendThroughput := float64(totalSize) / sendDuration.Seconds() / 1024 / 1024
	totalThroughput := float64(totalSize) / totalDuration.Seconds() / 1024 / 1024

	if jsonOutput {
		output(map[string]interface{}{
			"target":            target.String(),
			"sent_bytes":        sent,
			"recv_bytes":        recvTotal,
			"send_duration_ms":  float64(sendDuration.Milliseconds()),
			"total_duration_ms": float64(totalDuration.Milliseconds()),
			"send_mbps":         sendThroughput,
			"total_mbps":        totalThroughput,
		})
	} else {
		fmt.Printf("  Sent:     %s in %v (%.1f MB/s)\n", formatBytes(uint64(sent)), sendDuration.Round(time.Millisecond), sendThroughput)
		fmt.Printf("  Echoed:   %s in %v (%.1f MB/s round-trip)\n", formatBytes(uint64(recvTotal)), totalDuration.Round(time.Millisecond), totalThroughput)
	}
}

func cmdListen(args []string) {
	flags, pos := parseFlags(args)
	if len(pos) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl listen <port> [--count <n>] [--timeout <dur>]")
	}

	p, err := strconv.ParseUint(pos[0], 10, 16)
	if err != nil {
		fatalCode("invalid_argument", "invalid port %q: %v", pos[0], err)
	}
	port := uint16(p)
	count := flagInt(flags, "count", 0) // 0 = infinite
	timeout := flagDuration(flags, "timeout", 0)

	d := connectDriver()
	defer d.Close()

	if !jsonOutput {
		fmt.Fprintf(os.Stderr, "listening on port %d — waiting for datagrams...\n", port)
	}

	var messages []map[string]interface{}
	received := 0

	var deadline <-chan time.Time
	if timeout > 0 {
		deadline = time.After(timeout)
	}

	for {
		if count > 0 && received >= count {
			break
		}

		dgCh := make(chan *driver.Datagram)
		errCh := make(chan error)
		go func() {
			dg, err := d.RecvFrom()
			if err != nil {
				errCh <- err
				return
			}
			dgCh <- dg
		}()

		select {
		case dg := <-dgCh:
			if dg.DstPort == port {
				received++
				msg := map[string]interface{}{
					"src_addr": dg.SrcAddr.String(),
					"src_port": dg.SrcPort,
					"data":     string(dg.Data),
					"bytes":    len(dg.Data),
				}
				messages = append(messages, msg)

				if jsonOutput {
					if count > 0 && received >= count {
						break // will exit loop and print all
					}
					// Stream each message as NDJSON for unbounded
					if count == 0 {
						b, _ := json.Marshal(msg)
						fmt.Println(string(b))
					}
				} else {
					fmt.Printf("[%s:%d] %s\n", dg.SrcAddr, dg.SrcPort, string(dg.Data))
				}
			}
		case err := <-errCh:
			fatalCode("connection_failed", "recv: %v", err)
		case <-deadline:
			if jsonOutput && count > 0 {
				output(map[string]interface{}{
					"messages": messages,
					"timeout":  true,
				})
			} else if !jsonOutput {
				fmt.Fprintln(os.Stderr, "timeout")
			}
			return
		}
	}

	if jsonOutput && count > 0 {
		output(map[string]interface{}{
			"messages": messages,
			"timeout":  false,
		})
	}
}

func cmdBroadcast(args []string) {
	flags, positional := parseFlags(args)
	if len(positional) < 2 {
		fatalCode("usage", "usage: pilotctl broadcast <network_id> <message> [--port <port>]")
	}
	netID64, err := strconv.ParseUint(positional[0], 10, 16)
	if err != nil {
		fatalCode("usage", "invalid network_id: %v", err)
	}
	netID := uint16(netID64)
	message := positional[1]

	port := uint16(1000)
	if v := flagString(flags, "port", ""); v != "" {
		p, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			fatalCode("usage", "invalid --port: %v", err)
		}
		port = uint16(p)
	}

	token := requireAdminToken()

	d := connectDriver()
	defer d.Close()

	if err := d.Broadcast(netID, port, []byte(message), token); err != nil {
		fatalCode("broadcast_failed", "%v", err)
	}

	if jsonOutput {
		output(map[string]interface{}{
			"network_id": netID,
			"port":       port,
			"bytes":      len(message),
		})
	} else {
		fmt.Printf("broadcast on network %d port %d (%d bytes)\n", netID, port, len(message))
	}
}

// ===================== MAILBOX =====================

// receivedFile is one entry in ~/.pilot/received/ — a file delivered by
// the daemon's data-exchange service (filenames carry no sender info).
type receivedFile struct {
	name string
	size int64
	mod  time.Time
	path string
}

// cmdReceived lists or clears files received via data exchange (port 1001).
// Files are saved to ~/.pilot/received/ by the daemon's built-in service.
//
// Same agent-first shape as cmdInbox: newest-first, bounded by default
// (--limit 10), filterable by age (--since <dur|rfc3339>), clearable with
// --clear [--before <dur>]. JSON stays unbounded unless --limit is passed
// explicitly so existing agent invocations keep seeing the full set.
func cmdReceived(args []string) {
	flags, _ := parseFlags(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "cannot determine home directory")
	}
	dir := filepath.Join(home, ".pilot", "received")

	// --since accepts a duration (5m, 1h) or an RFC3339 timestamp.
	var sinceCutoff time.Time
	if s := flagString(flags, "since", ""); s != "" {
		if d, derr := time.ParseDuration(s); derr == nil {
			sinceCutoff = time.Now().Add(-d)
		} else if t, terr := time.Parse(time.RFC3339, s); terr == nil {
			sinceCutoff = t
		} else {
			fatalCode("invalid_argument", "--since must be a duration (5m, 1h) or an RFC3339 timestamp")
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if flagBool(flags, "clear") {
				fatalCode("not_found", "no received files")
			}
			if jsonOutput {
				output(map[string]interface{}{"files": []interface{}{}, "total": 0, "shown": 0})
			} else {
				fmt.Println("no received files")
				fmt.Println("  files appear here when someone sends: pilotctl send-file <your-hostname> <file>")
			}
			return
		}
		fatalCode("internal", "read directory: %v", err)
	}

	var all []receivedFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		all = append(all, receivedFile{
			name: e.Name(),
			size: info.Size(),
			mod:  info.ModTime(),
			path: filepath.Join(dir, e.Name()),
		})
	}
	// Newest first.
	sort.Slice(all, func(i, j int) bool { return all[i].mod.After(all[j].mod) })

	var filtered []receivedFile
	for _, f := range all {
		if !sinceCutoff.IsZero() && f.mod.Before(sinceCutoff) {
			continue
		}
		filtered = append(filtered, f)
	}

	// --clear deletes the matched set (everything if no filters given).
	// --before <dur> restricts the clear to files older than the duration.
	if flagBool(flags, "clear") {
		var beforeCutoff time.Time
		if b := flagString(flags, "before", ""); b != "" {
			d, derr := time.ParseDuration(b)
			if derr != nil {
				fatalCode("invalid_argument", "--before must be a duration (24h, 30m)")
			}
			beforeCutoff = time.Now().Add(-d)
		}
		count := 0
		for _, f := range filtered {
			if !beforeCutoff.IsZero() && !f.mod.Before(beforeCutoff) {
				continue
			}
			if os.Remove(f.path) == nil {
				count++
			}
		}
		if jsonOutput {
			outputOK(map[string]interface{}{"cleared": count, "remaining": len(all) - count})
		} else {
			fmt.Printf("cleared %d received file(s), %d remaining\n", count, len(all)-count)
		}
		return
	}

	limit := flagInt(flags, "limit", 10)
	_, limitExplicit := flags["limit"]
	total := len(filtered)

	if jsonOutput {
		// Back-compat: the list is only bounded when --limit is passed
		// explicitly; "total" is always the pre-limit count.
		list := filtered
		if limitExplicit && limit > 0 && len(list) > limit {
			list = list[:limit]
		}
		files := make([]map[string]interface{}, 0, len(list))
		for _, f := range list {
			files = append(files, map[string]interface{}{
				"name":     f.name,
				"bytes":    f.size,
				"modified": f.mod.Format(time.RFC3339),
				"path":     f.path,
			})
		}
		output(map[string]interface{}{
			"files": files,
			"total": total,
			"shown": len(files),
			"dir":   dir,
		})
		return
	}

	if total == 0 {
		if !sinceCutoff.IsZero() {
			fmt.Println("no received files match the filters")
			return
		}
		fmt.Println("no received files")
		fmt.Println("  files appear here when someone sends: pilotctl send-file <your-hostname> <file>")
		return
	}

	shown := filtered
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}
	qualifier := ""
	if len(shown) < total {
		qualifier = fmt.Sprintf(" · showing %d newest", len(shown))
	}
	fmt.Printf("%s%s\n\n", sBold(fmt.Sprintf("Received files — %d", total)), sDim(qualifier+" · "+dir))
	now := time.Now()
	for _, f := range shown {
		fmt.Printf("  %s\n", sAccent(f.name))
		fmt.Printf("  %s\n\n", sDim(fmt.Sprintf("%s ago · %s", fmtDuration(now.Sub(f.mod)), formatBytes(uint64(f.size)))))
	}
	fmt.Println(sDim("filters: --since <dur> --limit <n> (0 = all) · clear: --clear [--before 24h] · json: --json"))
}

// cmdInbox lists or clears messages received via data exchange (port 1001).
// waitForInboxReply polls ~/.pilot/inbox/ until a JSON file arrives that is
// newer than cutoff and (if agentHint is non-empty) has a matching "agent"
// field. Returns the parsed message or an error on timeout.
func waitForInboxReply(agentHint string, cutoff time.Time, timeout time.Duration) (map[string]interface{}, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, ".pilot", "inbox")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(dir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read inbox: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if !info.ModTime().After(cutoff) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var msg map[string]interface{}
			if json.Unmarshal(data, &msg) != nil {
				continue
			}
			if agentHint != "" {
				from, _ := msg["from"].(string)
				if from != agentHint {
					continue
				}
			}
			return msg, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return nil, fmt.Errorf("no reply from %q within %s", agentHint, timeout)
}

// inboxMessage is one parsed inbox entry plus its stable ID — the filename
// without .json, already unique: {TYPE}-{date}-{time.ms}-{seq}.
type inboxMessage struct {
	id   string
	msg  map[string]interface{}
	name string // filename with extension, used by --clear
}

// readInboxNewestFirst loads all inbox entries sorted newest-first.
// Inbox filenames are {TYPE}-{ts}-{seq}.json. Plain alpha order groups by
// type (BINARY<JSON<TEXT), scrambling chronology when types are mixed;
// sorting by the portion after the first dash (timestamp+seq), descending,
// puts the newest message first — which is what both agents and humans
// want from an inbox.
func readInboxNewestFirst(dir string) ([]inboxMessage, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		ni, nj := entries[i].Name(), entries[j].Name()
		di, dj := strings.Index(ni, "-"), strings.Index(nj, "-")
		if di < 0 || dj < 0 {
			return ni > nj
		}
		return ni[di:] > nj[dj:]
	})
	var out []inboxMessage
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		out = append(out, inboxMessage{
			id:   strings.TrimSuffix(e.Name(), ".json"),
			msg:  m,
			name: e.Name(),
		})
	}
	return out, nil
}

// inboxPreview collapses whitespace and caps the body for one-line display.
// Rune-safe so multi-byte content isn't cut mid-character.
func inboxPreview(data string, max int) string {
	collapsed := strings.Join(strings.Fields(data), " ")
	r := []rune(collapsed)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return collapsed
}

// cmdInboxRead prints the full body of a single message by ID.
func cmdInboxRead(dir, id string) {
	if id != filepath.Base(id) || strings.Contains(id, "..") {
		fatalCode("invalid_argument", "invalid message id %q", id)
	}
	name := id
	if !strings.HasSuffix(name, ".json") {
		name += ".json"
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if os.IsNotExist(err) {
			fatalCode("not_found", "no message %q — list ids with: pilotctl inbox", id)
		}
		fatalCode("internal", "read message: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		fatalCode("internal", "parse message: %v", err)
	}
	m["id"] = strings.TrimSuffix(name, ".json")
	if jsonOutput {
		output(m)
		return
	}
	from, _ := m["from"].(string)
	ts, _ := m["received_at"].(string)
	msgType, _ := m["type"].(string)
	bytes, _ := m["bytes"].(float64)
	fmt.Printf("ID:    %s\nFrom:  %s\nWhen:  %s\nType:  %s\nBytes: %d\n\n", m["id"], from, ts, msgType, int(bytes))
	body, _ := m["data"].(string)
	fmt.Println(body)
}

// Messages are saved to ~/.pilot/inbox/ by the daemon's built-in service.
//
// Agent-first design: newest-first, bounded by default (--limit 10), full
// bodies only on request (--latest, --full, read <id>), filterable by
// sender (--from) and age (--since). Every mode is non-interactive and
// stable under --json so agents can consume the output directly instead of
// scraping ~/.pilot/inbox/ with shell one-liners.
func cmdInbox(args []string) {
	flags, pos := parseFlags(args)

	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "cannot determine home directory")
	}
	dir := filepath.Join(home, ".pilot", "inbox")

	// Subcommand: inbox read <id> — full body of one message.
	if len(pos) > 0 && pos[0] == "read" {
		if len(pos) < 2 {
			fatalCode("invalid_argument", "usage: pilotctl inbox read <id>")
		}
		cmdInboxRead(dir, pos[1])
		return
	}

	// --from accepts an address or a hostname. Hostname resolution needs the
	// daemon; an address-shaped filter works even with the daemon stopped
	// (the inbox is just files on disk).
	fromFilter := flagString(flags, "from", "")
	if fromFilter != "" {
		if _, perr := protocol.ParseAddr(fromFilter); perr != nil {
			d := connectDriver()
			addr, rerr := parseAddrOrHostname(d, fromFilter)
			d.Close()
			if rerr != nil {
				fatalCode("not_found", "cannot resolve --from %q: %v", fromFilter, rerr)
			}
			fromFilter = addr.String()
		}
	}

	// --since accepts a duration (5m, 1h) or an RFC3339 timestamp.
	var sinceCutoff time.Time
	if s := flagString(flags, "since", ""); s != "" {
		if d, derr := time.ParseDuration(s); derr == nil {
			sinceCutoff = time.Now().Add(-d)
		} else if t, terr := time.Parse(time.RFC3339, s); terr == nil {
			sinceCutoff = t
		} else {
			fatalCode("invalid_argument", "--since must be a duration (5m, 1h) or an RFC3339 timestamp")
		}
	}

	all, err := readInboxNewestFirst(dir)
	if err != nil {
		if os.IsNotExist(err) {
			if jsonOutput {
				output(map[string]interface{}{"messages": []interface{}{}, "total": 0, "shown": 0})
			} else {
				fmt.Println("inbox is empty")
				fmt.Println("  messages appear here when someone sends: pilotctl send-message <your-hostname> --data \"hello\"")
			}
			return
		}
		fatalCode("internal", "read directory: %v", err)
	}

	// Apply filters.
	var filtered []inboxMessage
	for _, im := range all {
		if fromFilter != "" {
			from, _ := im.msg["from"].(string)
			if from != fromFilter {
				continue
			}
		}
		if !sinceCutoff.IsZero() {
			ts, _ := im.msg["received_at"].(string)
			t, terr := time.Parse(time.RFC3339Nano, ts)
			if terr != nil || t.Before(sinceCutoff) {
				continue
			}
		}
		filtered = append(filtered, im)
	}

	// --clear deletes the matched set (everything if no filters given).
	// --before <dur> additionally restricts the clear to messages older
	// than the duration, so `--clear --before 24h` keeps today's messages.
	if flagBool(flags, "clear") {
		var beforeCutoff time.Time
		if b := flagString(flags, "before", ""); b != "" {
			d, derr := time.ParseDuration(b)
			if derr != nil {
				fatalCode("invalid_argument", "--before must be a duration (24h, 30m)")
			}
			beforeCutoff = time.Now().Add(-d)
		}
		count := 0
		for _, im := range filtered {
			if !beforeCutoff.IsZero() {
				ts, _ := im.msg["received_at"].(string)
				t, terr := time.Parse(time.RFC3339Nano, ts)
				if terr == nil && !t.Before(beforeCutoff) {
					continue
				}
			}
			if os.Remove(filepath.Join(dir, im.name)) == nil {
				count++
			}
		}
		if jsonOutput {
			outputOK(map[string]interface{}{"cleared": count, "remaining": len(all) - count})
		} else {
			fmt.Printf("cleared %d message(s), %d remaining\n", count, len(all)-count)
		}
		return
	}

	// --latest = full body of the single newest (post-filter) message.
	full := flagBool(flags, "full")
	limit := flagInt(flags, "limit", 10)
	if flagBool(flags, "latest") {
		limit, full = 1, true
	}
	total := len(filtered)
	shown := filtered
	if limit > 0 && len(shown) > limit {
		shown = shown[:limit]
	}

	if jsonOutput {
		msgs := make([]map[string]interface{}, 0, len(shown))
		for _, im := range shown {
			m := map[string]interface{}{
				"id":          im.id,
				"from":        im.msg["from"],
				"received_at": im.msg["received_at"],
				"type":        im.msg["type"],
				"bytes":       im.msg["bytes"],
			}
			if body, _ := im.msg["data"].(string); full {
				m["data"] = body
			} else {
				m["preview"] = inboxPreview(body, 120)
			}
			msgs = append(msgs, m)
		}
		output(map[string]interface{}{
			"messages": msgs,
			"total":    total,
			"shown":    len(msgs),
			"dir":      dir,
		})
		return
	}

	if total == 0 {
		fmt.Println("inbox is empty (no messages match the filters)")
		return
	}

	fmt.Printf("%s %s\n\n", sBold(fmt.Sprintf("Inbox — %d message(s)", total)), sDim(fmt.Sprintf("· showing %d newest", len(shown))))
	now := time.Now()
	for _, im := range shown {
		from, _ := im.msg["from"].(string)
		ts, _ := im.msg["received_at"].(string)
		msgType, _ := im.msg["type"].(string)
		bytes, _ := im.msg["bytes"].(float64)
		age := ""
		if t, terr := time.Parse(time.RFC3339Nano, ts); terr == nil {
			age = fmtDuration(now.Sub(t)) + " ago"
		}
		fmt.Printf("  %s\n", sAccent(im.id))
		fmt.Printf("  %s\n", sDim(fmt.Sprintf("%s · %s · %s · %s", from, msgType, age, formatBytes(uint64(bytes)))))
		body, _ := im.msg["data"].(string)
		if full {
			fmt.Printf("  %s\n\n", body)
		} else {
			fmt.Printf("  %s\n\n", inboxPreview(body, 120))
		}
	}
	fmt.Println(sDim("full body: pilotctl inbox read <id> · --latest · filters: --from --since --limit · clear: --clear [--before 24h]"))
}

// --- Network commands ---

func cmdNetworkList() {
	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkList()
	if err != nil {
		fatalCode("connection_failed", "network list: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	nets, _ := result["networks"].([]interface{})
	if len(nets) == 0 {
		fmt.Println("no networks")
		return
	}
	// Member counts are admin-only at the registry. Without admin_token
	// the registry omits the `members` field for every network — in that
	// case the column would be a wall of "—" that just looks broken, so
	// we drop it entirely and say why in a footnote. When at least one
	// network carries a count, the column stays ("—" marks the hidden ones).
	memberCount := func(nm map[string]interface{}) (string, bool) {
		if members, ok := nm["members"].([]interface{}); ok {
			return fmt.Sprintf("%d", len(members)), true
		}
		if mc, ok := nm["members"].(float64); ok {
			return fmt.Sprintf("%d", int(mc)), true
		}
		return "—", false
	}
	anyMembers := false
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		if _, ok := memberCount(nm); ok {
			anyMembers = true
			break
		}
	}
	if anyMembers {
		fmt.Printf("%-8s %-30s %-10s %s\n", "ID", "NAME", "JOIN RULE", "MEMBERS")
	} else {
		fmt.Printf("%-8s %-30s %s\n", "ID", "NAME", "JOIN RULE")
	}
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		id := uint16(nm["id"].(float64))
		name, _ := nm["name"].(string)
		rule, _ := nm["join_rule"].(string)
		// Pad before styling so ANSI escapes don't break column alignment.
		nameCol := sAccent(fmt.Sprintf("%-30s", name))
		ruleCol := sDim(fmt.Sprintf("%-10s", rule))
		if anyMembers {
			memberStr, _ := memberCount(nm)
			fmt.Printf("%-8d %s %s %s\n", id, nameCol, ruleCol, memberStr)
		} else {
			fmt.Printf("%-8d %s %s\n", id, nameCol, ruleCol)
		}
	}
	if !anyMembers {
		fmt.Printf("\n%s\n", sDim("member counts hidden — admin only"))
	}
}

func cmdNetworkJoin(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network join <network_id> [--token TOKEN] [--node-id N]")
	}
	netID := parseUint16(args[0], "network_id")
	flags, _ := parseFlags(args[1:])
	token := flagString(flags, "token", "")
	nodeIDStr := flagString(flags, "node-id", "")

	// Admin path: --node-id joins a remote node directly via registry
	if nodeIDStr != "" {
		nodeID := parseNodeID(nodeIDStr)
		adminToken := requireAdminToken()
		rc := connectRegistry()
		defer rc.Close()

		result, err := rc.JoinNetwork(nodeID, netID, token, 0, adminToken)
		if err != nil {
			fatalCode("connection_failed", "network join: %v", err)
		}
		if jsonOutput {
			output(result)
		} else {
			fmt.Printf("joined node %d to network %d\n", nodeID, netID)
		}
		return
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkJoin(netID, token)
	if err != nil {
		fatalCode("connection_failed", "network join: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("joined network %d\n", netID)
	}
}

func cmdNetworkLeave(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network leave <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkLeave(netID)
	if err != nil {
		fatalCode("connection_failed", "network leave: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("left network %d\n", netID)
	}
}

func cmdNetworkMembers(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network members <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkMembers(netID)
	if err != nil {
		fatalCode("connection_failed", "network members: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	nodes, _ := result["nodes"].([]interface{})
	if len(nodes) == 0 {
		fmt.Println("no members")
		return
	}
	fmt.Printf("%-12s %-20s %-12s %-10s\n", "NODE ID", "HOSTNAME", "VERSION", "PUBLIC")
	for _, n := range nodes {
		nm, _ := n.(map[string]interface{})
		nodeID := uint32(nm["node_id"].(float64))
		hostname, _ := nm["hostname"].(string)
		ver, _ := nm["version"].(string)
		public := false
		if p, ok := nm["public"].(bool); ok {
			public = p
		}
		vis := "private"
		if public {
			vis = "public"
		}
		if hostname == "" {
			hostname = "-"
		}
		if ver == "" {
			ver = "-"
		}
		fmt.Printf("%-12d %-20s %-12s %-10s\n", nodeID, hostname, ver, vis)
	}
}

func cmdNetworkInvite(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network invite <network_id> <node_id|address|hostname>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	nodeID := resolveToNodeID(d, args[1])

	result, err := d.NetworkInvite(netID, nodeID)
	if err != nil {
		fatalCode("connection_failed", "network invite: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("invited node %d to network %d\n", nodeID, netID)
	}
}

func cmdNetworkInvites() {
	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkPollInvites()
	if err != nil {
		fatalCode("connection_failed", "network invites: %v", err)
	}
	if jsonOutput {
		output(result)
		return
	}
	invites, _ := result["invites"].([]interface{})
	if len(invites) == 0 {
		fmt.Println("no pending invites")
		return
	}
	fmt.Printf("%-12s %-12s %s\n", "NETWORK", "INVITER", "TIMESTAMP")
	for _, inv := range invites {
		im, _ := inv.(map[string]interface{})
		netID := uint16(im["network_id"].(float64))
		inviterID := uint32(im["inviter_id"].(float64))
		ts, _ := im["timestamp"].(string)
		fmt.Printf("%-12d %-12d %s\n", netID, inviterID, ts)
	}
	fmt.Println("\naccept: pilotctl network accept <network_id>")
	fmt.Println("reject: pilotctl network reject <network_id>")
}

func cmdNetworkAccept(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network accept <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkRespondInvite(netID, true)
	if err != nil {
		fatalCode("connection_failed", "network accept: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("accepted invite to network %d\n", netID)
	}
}

func cmdNetworkReject(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network reject <network_id>")
	}
	netID := parseUint16(args[0], "network_id")

	d := connectDriver()
	defer d.Close()

	result, err := d.NetworkRespondInvite(netID, false)
	if err != nil {
		fatalCode("connection_failed", "network reject: %v", err)
	}
	if jsonOutput {
		output(result)
	} else {
		fmt.Printf("rejected invite to network %d\n", netID)
	}
}

// --- Enterprise network commands (direct to registry, admin token required) ---

func cmdNetworkCreate(args []string) {
	flags, _ := parseFlags(args)
	name := flagString(flags, "name", "")
	joinRule := flagString(flags, "join-rule", "open")
	token := flagString(flags, "token", "")
	enterprise := flagBool(flags, "enterprise")
	nodeIDStr := flagString(flags, "node-id", "0")
	networkAdminToken := flagString(flags, "network-admin-token", "")
	rulesJSON := flagString(flags, "rules", "")
	rulesFile := flagString(flags, "rules-file", "")

	if name == "" {
		fatalCode("invalid_argument", "usage: pilotctl network create --name <name> [--join-rule open|token|invite] [--token T] [--enterprise] [--node-id N] [--rules '<json>'] [--rules-file path]")
	}

	// Load rules from file if specified
	if rulesFile != "" && rulesJSON == "" {
		data, err := os.ReadFile(rulesFile)
		if err != nil {
			fatalCode("invalid_argument", "cannot read rules file: %v", err)
		}
		rulesJSON = string(data)
	}

	adminToken := requireAdminToken()
	nodeID := parseNodeID(nodeIDStr)

	rc := connectRegistry()
	defer rc.Close()

	var resp map[string]interface{}
	var err error
	if rulesJSON != "" {
		resp, err = rc.CreateManagedNetwork(nodeID, name, joinRule, token, adminToken, enterprise, rulesJSON, networkAdminToken)
	} else if networkAdminToken != "" {
		resp, err = rc.CreateNetwork(nodeID, name, joinRule, token, adminToken, enterprise, networkAdminToken)
	} else {
		resp, err = rc.CreateNetwork(nodeID, name, joinRule, token, adminToken, enterprise)
	}
	if err != nil {
		fatalCode("connection_failed", "network create: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		managed := ""
		if resp["managed"] == true {
			managed = ", managed=true"
		}
		fmt.Printf("created network %v: %s (join_rule=%s, enterprise=%v%s)\n",
			resp["network_id"], name, joinRule, enterprise, managed)
	}
}

func cmdNetworkDelete(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network delete <network_id>")
	}
	netID := parseUint16(args[0], "network_id")
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DeleteNetwork(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network delete: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("deleted network %d\n", netID)
	}
}

func cmdNetworkRename(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network rename <network_id> <new_name>")
	}
	netID := parseUint16(args[0], "network_id")
	name := args[1]
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.RenameNetwork(netID, name, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network rename: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("renamed network %d to %q\n", netID, name)
	}
}

func cmdNetworkPromote(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network promote <network_id> <node_id|address|hostname>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := resolveNetworkNodeArg(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	// Use node_id=0 since we're authenticating with admin token, not RBAC
	resp, err := rc.PromoteMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network promote: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("promoted node %d to admin in network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkDemote(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network demote <network_id> <node_id|address|hostname>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := resolveNetworkNodeArg(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DemoteMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network demote: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("demoted node %d to member in network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkKick(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network kick <network_id> <node_id|address|hostname>")
	}
	netID := parseUint16(args[0], "network_id")
	targetNodeID := resolveNetworkNodeArg(args[1])
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.KickMember(netID, 0, targetNodeID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network kick: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("kicked node %d from network %d\n", targetNodeID, netID)
	}
}

func cmdNetworkRole(args []string) {
	if len(args) < 2 {
		fatalCode("invalid_argument", "usage: pilotctl network role <network_id> <node_id|address|hostname>")
	}
	netID := parseUint16(args[0], "network_id")
	nodeID := resolveNetworkNodeArg(args[1])

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetMemberRole(netID, nodeID)
	if err != nil {
		fatalCode("connection_failed", "network role: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("node %d in network %d: role=%v\n", nodeID, netID, resp["role"])
	}
}

func cmdNetworkPolicy(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl network policy <network_id> [--set key=value ...]")
	}
	netID := parseUint16(args[0], "network_id")

	// Check if we're setting or getting
	setArgs := args[1:]
	if len(setArgs) == 0 {
		// GET policy
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetNetworkPolicy(netID)
		if err != nil {
			fatalCode("connection_failed", "network policy: %v", err)
		}
		output(resp)
		return
	}

	// SET policy
	adminToken := requireAdminToken()
	policy := make(map[string]interface{})
	flags, _ := parseFlags(setArgs)
	if v := flagString(flags, "max-members", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fatalCode("invalid_argument", "invalid max-members: %v", err)
		}
		policy["max_members"] = float64(n)
	}
	if v := flagString(flags, "description", ""); v != "" {
		policy["description"] = v
	}
	if v := flagString(flags, "allowed-ports", ""); v != "" {
		var ports []interface{}
		for _, p := range strings.Split(v, ",") {
			pv, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil {
				fatalCode("invalid_argument", "invalid port %q: %v", p, err)
			}
			ports = append(ports, float64(pv))
		}
		policy["allowed_ports"] = ports
	}

	rc := connectRegistry()
	defer rc.Close()
	resp, err := rc.SetNetworkPolicy(netID, policy, adminToken)
	if err != nil {
		fatalCode("connection_failed", "network policy set: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("updated policy for network %d\n", netID)
	}
}

func cmdAudit(args []string) {
	adminToken := requireAdminToken()
	flags, _ := parseFlags(args)
	netIDStr := flagString(flags, "network", "0")
	netID := parseUint16(netIDStr, "network_id")

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetAuditLog(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "audit: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}
	entries, ok := resp["entries"].([]interface{})
	if !ok || len(entries) == 0 {
		fmt.Println("no audit entries")
		return
	}
	for _, e := range entries {
		entry, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		ts := entry["timestamp"]
		action := entry["action"]
		nodeID := entry["node_id"]
		netID := entry["network_id"]
		details := entry["details"]

		line := fmt.Sprintf("%-30v  %-30v", ts, action)
		if nodeID != nil && nodeID != float64(0) {
			line += fmt.Sprintf("  node=%v", nodeID)
		}
		if netID != nil && netID != float64(0) {
			line += fmt.Sprintf("  net=%v", netID)
		}
		if details != nil && details != "" {
			line += fmt.Sprintf("  %v", details)
		}
		fmt.Println(line)
	}
}

// --- Provisioning commands ---

func cmdProvision(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl provision <blueprint.json>")
	}
	adminToken := requireAdminToken()

	data, err := os.ReadFile(args[0])
	if err != nil {
		fatalCode("invalid_argument", "read blueprint: %v", err)
	}

	var blueprint map[string]interface{}
	if err := json.Unmarshal(data, &blueprint); err != nil {
		fatalCode("invalid_argument", "parse blueprint: %v", err)
	}

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.ProvisionNetwork(blueprint, adminToken)
	if err != nil {
		fatalCode("connection_failed", "provision: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("provisioned network %v (%s)\n", resp["network_id"], resp["name"])
	if actions, ok := resp["actions"].([]interface{}); ok {
		for _, a := range actions {
			fmt.Printf("  - %v\n", a)
		}
	}
}

func cmdDeprovision(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl deprovision <network-name>")
	}
	name := args[0]
	adminToken := requireAdminToken()

	rc := connectRegistry()
	defer rc.Close()

	// Look up network by name
	resp, err := rc.ListNetworks()
	if err != nil {
		fatalCode("connection_failed", "list networks: %v", err)
	}
	nets, _ := resp["networks"].([]interface{})
	var netID uint16
	found := false
	for _, n := range nets {
		nm, _ := n.(map[string]interface{})
		nname, _ := nm["name"].(string)
		if nname == name {
			netID = uint16(nm["id"].(float64))
			found = true
			break
		}
	}
	if !found {
		fatalCode("not_found", "network %q not found", name)
	}

	delResp, err := rc.DeleteNetwork(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "delete network %q (id=%d): %v", name, netID, err)
	}
	if jsonOutput {
		output(delResp)
		return
	}
	fmt.Printf("deprovisioned network %q (id=%d)\n", name, netID)
}

func cmdIDP(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl idp <get|set> [options]")
	}
	adminToken := requireAdminToken()

	switch args[0] {
	case "get":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetIDPConfig(adminToken)
		if err != nil {
			fatalCode("connection_failed", "idp get: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			if resp["configured"] == true {
				fmt.Printf("IdP: %v (%v)\n", resp["idp_type"], resp["url"])
				if v := resp["issuer"]; v != nil && v != "" {
					fmt.Printf("  issuer: %v\n", v)
				}
				if v := resp["tenant_id"]; v != nil && v != "" {
					fmt.Printf("  tenant: %v\n", v)
				}
				if v := resp["client_id"]; v != nil && v != "" {
					fmt.Printf("  client_id: %v\n", v)
				}
			} else {
				fmt.Println("no identity provider configured")
			}
		}

	case "set":
		flags, _ := parseFlags(args[1:])
		idpType := flagString(flags, "type", "")
		url := flagString(flags, "url", "")
		issuer := flagString(flags, "issuer", "")
		clientID := flagString(flags, "client-id", "")
		tenantID := flagString(flags, "tenant-id", "")
		domain := flagString(flags, "domain", "")

		if idpType == "" || url == "" {
			fatalCode("invalid_argument", "usage: pilotctl idp set --type <oidc|saml|entra_id|ldap|webhook> --url <URL> [--issuer URL] [--client-id ID] [--tenant-id ID] [--domain D]")
		}

		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetIDPConfig(idpType, url, issuer, clientID, tenantID, domain, adminToken)
		if err != nil {
			fatalCode("connection_failed", "idp set: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Printf("identity provider configured: %s (%s)\n", idpType, resp["status"])
		}

	default:
		fatalCode("invalid_argument", "unknown idp subcommand: %s (use get or set)", args[0])
	}
}

func cmdAuditExport(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl audit-export <get|set|disable> [options]")
	}
	adminToken := requireAdminToken()

	switch args[0] {
	case "get":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.GetAuditExport(adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export get: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			if resp["enabled"] == true {
				fmt.Printf("audit export: %v → %v\n", resp["format"], resp["endpoint"])
				if v := resp["exported"]; v != nil {
					fmt.Printf("  exported: %v, dropped: %v\n", v, resp["dropped"])
				}
			} else {
				fmt.Println("audit export not configured")
			}
		}

	case "set":
		flags, _ := parseFlags(args[1:])
		format := flagString(flags, "format", "")
		endpoint := flagString(flags, "endpoint", "")
		token := flagString(flags, "splunk-token", "")
		index := flagString(flags, "index", "")
		source := flagString(flags, "source", "pilot-registry")

		if format == "" || endpoint == "" {
			fatalCode("invalid_argument", "usage: pilotctl audit-export set --format <json|splunk_hec|syslog_cef> --endpoint <URL> [--splunk-token T] [--index I] [--source S]")
		}

		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetAuditExport(format, endpoint, token, index, source, adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export set: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Printf("audit export configured: %s → %s\n", format, endpoint)
		}

	case "disable":
		rc := connectRegistry()
		defer rc.Close()
		resp, err := rc.SetAuditExport("", "", "", "", "", adminToken)
		if err != nil {
			fatalCode("connection_failed", "audit-export disable: %v", err)
		}
		if jsonOutput {
			output(resp)
		} else {
			fmt.Println("audit export disabled")
		}

	default:
		fatalCode("invalid_argument", "unknown audit-export subcommand: %s (use get, set, or disable)", args[0])
	}
}

func cmdProvisionStatus() {
	adminToken := requireAdminToken()
	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.GetProvisionStatus(adminToken)
	if err != nil {
		fatalCode("connection_failed", "provision-status: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	if v := resp["idp_type"]; v != nil {
		fmt.Printf("identity provider: %v\n", v)
	}
	if v := resp["audit_export"]; v != nil {
		fmt.Printf("audit export: %v\n", v)
	}
	if v := resp["webhook_enabled"]; v == true {
		fmt.Println("webhook: enabled")
	}
	fmt.Println()

	networks, ok := resp["networks"].([]interface{})
	if !ok || len(networks) == 0 {
		fmt.Println("no networks provisioned")
		return
	}
	fmt.Printf("%-6s %-20s %-12s %-10s %-8s %s\n", "ID", "Name", "Enterprise", "Members", "Rule", "Pre-Assign")
	for _, n := range networks {
		net, ok := n.(map[string]interface{})
		if !ok {
			continue
		}
		enterprise := "no"
		if net["enterprise"] == true {
			enterprise = "yes"
		}
		preAssign := ""
		if v := net["rbac_pre_assignments"]; v != nil && v != float64(0) {
			preAssign = fmt.Sprintf("%v roles", v)
		}
		fmt.Printf("%-6v %-20v %-12s %-10v %-8v %s\n",
			net["network_id"], net["name"], enterprise,
			net["members"], net["join_rule"], preAssign)
	}
}

// --- Directory sync commands ---

func cmdDirectorySync(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl directory-sync <directory.json> [--network <id>] [--remove-unlisted]")
	}
	adminToken := requireAdminToken()
	flags, pos := parseFlags(args)

	var filePath string
	if len(pos) > 0 {
		filePath = pos[0]
	} else {
		filePath = args[0]
	}

	netIDStr := flagString(flags, "network", "0")
	netID := parseUint16(netIDStr, "network_id")
	removeUnlisted := flagBool(flags, "remove-unlisted")

	data, err := os.ReadFile(filePath)
	if err != nil {
		fatalCode("invalid_argument", "read directory file: %v", err)
	}

	var payload struct {
		NetworkID      uint16                   `json:"network_id"`
		Entries        []map[string]interface{} `json:"entries"`
		RemoveUnlisted bool                     `json:"remove_unlisted"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		fatalCode("invalid_argument", "parse directory file: %v", err)
	}

	if netID == 0 && payload.NetworkID > 0 {
		netID = payload.NetworkID
	}
	if netID == 0 {
		fatalCode("invalid_argument", "network_id required (use --network or set in file)")
	}
	if removeUnlisted {
		payload.RemoveUnlisted = true
	}

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DirectorySync(netID, payload.Entries, payload.RemoveUnlisted, adminToken)
	if err != nil {
		fatalCode("connection_failed", "directory-sync: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("directory sync complete: %v mapped, %v updated, %v disabled, %v unmapped\n",
		resp["mapped"], resp["updated"], resp["disabled"], resp["unmapped"])
	if actions, ok := resp["actions"].([]interface{}); ok {
		for _, a := range actions {
			fmt.Printf("  - %v\n", a)
		}
	}
}

func cmdDirectoryStatus(args []string) {
	if len(args) < 1 {
		fatalCode("invalid_argument", "usage: pilotctl directory-status <network_id>")
	}
	adminToken := requireAdminToken()
	netID := parseUint16(args[0], "network_id")

	rc := connectRegistry()
	defer rc.Close()

	resp, err := rc.DirectoryStatus(netID, adminToken)
	if err != nil {
		fatalCode("connection_failed", "directory-status: %v", err)
	}
	if jsonOutput {
		output(resp)
		return
	}

	fmt.Printf("Network %v directory status:\n", resp["network_id"])
	fmt.Printf("  total members: %v\n", resp["total"])
	fmt.Printf("  directory mapped: %v\n", resp["mapped"])
	fmt.Printf("  unmapped: %v\n", resp["unmapped"])
	if v := resp["pre_assignments"]; v != nil && v != float64(0) {
		fmt.Printf("  pre-assignments: %v\n", v)
	}
	if v := resp["last_sync"]; v != nil && v != "" {
		fmt.Printf("  last sync: %v\n", v)
	}
}

// --- Managed network commands ---

func cmdManagedStatus(args []string) {
	flags, _ := parseFlags(args)
	netID := flagNetID(flags)

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedStatus(netID)
	if err != nil {
		fatalCode("connection_failed", "managed status: %v", err)
	}
	output(resp)
}

func cmdManagedCycle(args []string) {
	flags, _ := parseFlags(args)
	netID := flagNetID(flags)
	force := flagBool(flags, "force")

	if !force {
		fatalCode("invalid_argument", "usage: pilotctl managed cycle --force [--net <id>]")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedForceCycle(netID)
	if err != nil {
		fatalCode("connection_failed", "managed cycle: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("cycle complete: pruned=%v filled=%v peers=%v\n",
			resp["pruned"], resp["filled"], resp["peers"])
	}
}

func cmdManagedReconcile(args []string) {
	flags, _ := parseFlags(args)
	netID := flagNetID(flags)
	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl managed reconcile --net <id>")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.ManagedReconcile(netID)
	if err != nil {
		fatalCode("connection_failed", "managed reconcile: %v", err)
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("reconciled: peers=%v\n", resp["peers"])
	}
}

// --- Policy commands ---

func cmdPolicyGet(args []string) {
	flags, _ := parseFlags(args)
	netID := flagNetID(flags)
	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl policy get --net <id>")
	}

	d := connectDriver()
	defer d.Close()

	resp, err := d.PolicyGet(netID)
	if err != nil {
		fatalCode("connection_failed", "policy get: %v", err)
	}
	output(resp)
}

func cmdPolicySet(args []string) {
	flags, _ := parseFlags(args)
	netID := flagNetID(flags)
	file := flagString(flags, "file", "")
	inline := flagString(flags, "inline", "")

	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl policy set --net <id> --file <path> | --inline '<json>'")
	}

	var policyJSON []byte
	if file != "" {
		var err error
		policyJSON, err = os.ReadFile(file)
		if err != nil {
			fatalCode("io_error", "reading policy file: %v", err)
		}
	} else if inline != "" {
		policyJSON = []byte(inline)
	} else {
		fatalCode("invalid_argument", "provide --file or --inline")
	}

	// Validate locally first
	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy validation: %v", err)
	}
	if _, err := policylang.Compile(doc); err != nil {
		fatalCode("invalid_argument", "policy compilation: %v", err)
	}

	// Send to registry (admin-token gated)
	reg := connectRegistry()
	defer reg.Close()

	adminToken := flagString(flags, "admin-token", "")
	if adminToken == "" {
		adminToken = getAdminToken()
	}
	_, err = reg.SetExprPolicy(netID, policyJSON, adminToken)
	if err != nil {
		fatalCode("connection_failed", "set policy on registry: %v", err)
	}

	// Also apply locally to daemon if running
	d := connectDriver()
	defer d.Close()

	resp, err := d.PolicySet(netID, policyJSON, adminToken)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: policy saved to registry but daemon apply failed: %v\n", err)
		return
	}
	if jsonOutput {
		output(resp)
	} else {
		fmt.Printf("policy set on network %d (registry + daemon)\n", netID)
	}
}

func cmdPolicyValidate(args []string) {
	flags, _ := parseFlags(args)
	file := flagString(flags, "file", "")
	inline := flagString(flags, "inline", "")

	var policyJSON []byte
	if file != "" {
		var err error
		policyJSON, err = os.ReadFile(file)
		if err != nil {
			fatalCode("io_error", "reading policy file: %v", err)
		}
	} else if inline != "" {
		policyJSON = []byte(inline)
	} else {
		fatalCode("invalid_argument", "provide --file or --inline")
	}

	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "validation failed: %v", err)
	}

	cp, err := policylang.Compile(doc)
	if err != nil {
		fatalCode("invalid_argument", "compilation failed: %v", err)
	}

	if jsonOutput {
		output(map[string]interface{}{
			"valid":   true,
			"version": doc.Version,
			"rules":   len(doc.Rules),
			"events":  countEventTypes(cp),
		})
	} else {
		fmt.Printf("valid policy: %d rules\n", len(doc.Rules))
		for _, r := range doc.Rules {
			fmt.Printf("  - %s (on %s): %d actions\n", r.Name, r.On, len(r.Actions))
		}
	}
}

func cmdPolicyTest(args []string) {
	flags, _ := parseFlags(args)
	file := flagString(flags, "file", "")
	eventJSON := flagString(flags, "event", "")

	if file == "" || eventJSON == "" {
		fatalCode("invalid_argument", "usage: pilotctl policy test --file <path> --event '<json>'")
	}

	policyJSON, err := os.ReadFile(file)
	if err != nil {
		fatalCode("io_error", "reading policy file: %v", err)
	}

	doc, err := policylang.Parse(policyJSON)
	if err != nil {
		fatalCode("invalid_argument", "policy: %v", err)
	}
	cp, err := policylang.Compile(doc)
	if err != nil {
		fatalCode("invalid_argument", "policy: %v", err)
	}

	var event map[string]interface{}
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		fatalCode("invalid_argument", "event JSON: %v", err)
	}

	// JSON unmarshaling puts numbers as float64; expr env expects int.
	for k, v := range event {
		if f, ok := v.(float64); ok {
			event[k] = int(f)
		}
	}

	eventType, _ := event["type"].(string)
	if eventType == "" {
		fatalCode("invalid_argument", "event must have a 'type' field (connect, dial, datagram, cycle, join, leave)")
	}
	delete(event, "type")

	dirs, err := cp.Evaluate(policylang.EventType(eventType), event)
	if err != nil {
		fatalCode("invalid_argument", "evaluation: %v", err)
	}

	if jsonOutput {
		results := make([]map[string]interface{}, 0, len(dirs))
		for _, d := range dirs {
			results = append(results, map[string]interface{}{
				"type":   directiveTypeName(d.Type),
				"rule":   d.Rule,
				"params": d.Params,
			})
		}
		output(map[string]interface{}{"directives": results})
	} else {
		fmt.Printf("event type: %s → %d directives\n", eventType, len(dirs))
		for _, d := range dirs {
			fmt.Printf("  %s (from rule %q)\n", directiveTypeName(d.Type), d.Rule)
		}
	}
}

func countEventTypes(cp *policylang.CompiledPolicy) map[string]bool {
	events := map[string]bool{}
	for _, et := range []policylang.EventType{
		policylang.EventConnect, policylang.EventDial, policylang.EventDatagram,
		policylang.EventCycle, policylang.EventJoin, policylang.EventLeave,
	} {
		if cp.HasRulesFor(et) {
			events[string(et)] = true
		}
	}
	return events
}

func directiveTypeName(dt policylang.DirectiveType) string {
	switch dt {
	case policylang.DirectiveAllow:
		return "allow"
	case policylang.DirectiveDeny:
		return "deny"
	case policylang.DirectiveTag:
		return "tag"
	case policylang.DirectiveEvict:
		return "evict"
	case policylang.DirectiveEvictWhere:
		return "evict_where"
	case policylang.DirectivePrune:
		return "prune"
	case policylang.DirectiveFill:
		return "fill"
	case policylang.DirectiveWebhook:
		return "webhook"
	case policylang.DirectiveLog:
		return "log"
	default:
		return "unknown"
	}
}

func cmdMemberTagsSet(args []string) {
	flags, _ := parseFlags(args)
	netID := parseUint16(flagString(flags, "net", "0"), "net")
	nodeID := flagString(flags, "node", "0")
	tagsStr := flagString(flags, "tags", "")

	if netID == 0 || nodeID == "0" || tagsStr == "" {
		fatalCode("invalid_argument", "usage: pilotctl member-tags set --net <id> --node <id> --tags tag1,tag2")
	}

	nid, err := strconv.ParseUint(nodeID, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node ID: %s", nodeID)
	}

	tags := strings.Split(tagsStr, ",")

	// If admin token is available, go directly to registry (no daemon needed)
	if adminToken := getAdminToken(); adminToken != "" {
		rc := connectRegistry()
		defer rc.Close()

		result, err := rc.SetMemberTags(netID, uint32(nid), tags, adminToken)
		if err != nil {
			fatalCode("connection_failed", "member-tags set: %v", err)
		}
		if jsonOutput {
			output(result)
			return
		}
		fmt.Printf("Member tags set for node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tags, ", "))
		return
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.MemberTagsSet(netID, uint32(nid), tags)
	if err != nil {
		fatalCode("connection_failed", "member-tags set: %v", err)
	}

	if jsonOutput {
		output(result)
		return
	}
	fmt.Printf("Member tags set for node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tags, ", "))
}

func cmdMemberTagsGet(args []string) {
	flags, _ := parseFlags(args)
	netID := parseUint16(flagString(flags, "net", "0"), "net")
	nodeID := flagString(flags, "node", "0")

	if netID == 0 {
		fatalCode("invalid_argument", "usage: pilotctl member-tags get --net <id> [--node <id>]")
	}

	nid, err := strconv.ParseUint(nodeID, 10, 32)
	if err != nil {
		fatalCode("invalid_argument", "invalid node ID: %s", nodeID)
	}

	d := connectDriver()
	defer d.Close()

	result, err := d.MemberTagsGet(netID, uint32(nid))
	if err != nil {
		fatalCode("connection_failed", "member-tags get: %v", err)
	}

	if jsonOutput {
		output(result)
		return
	}

	if uint32(nid) != 0 {
		if tags, ok := result["tags"].([]interface{}); ok {
			tagStrs := make([]string, len(tags))
			for i, t := range tags {
				tagStrs[i] = fmt.Sprint(t)
			}
			fmt.Printf("Node %d in network %d: %s\n", uint32(nid), netID, strings.Join(tagStrs, ", "))
		} else {
			fmt.Printf("Node %d in network %d: (no tags)\n", uint32(nid), netID)
		}
	} else {
		if members, ok := result["members"].(map[string]interface{}); ok {
			for mid, tags := range members {
				fmt.Printf("  node %s: %v\n", mid, tags)
			}
		}
	}
}
