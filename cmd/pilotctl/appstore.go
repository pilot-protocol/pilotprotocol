// SPDX-License-Identifier: AGPL-3.0-or-later
//
// pilotctl appstore — list installed apps and call their IPC methods.
//
// The daemon's app-store plugin spawns each installed app under
// ~/.pilot/apps/<id>/ with its own unix-domain socket at
// <install_root>/<id>/app.sock. This subcommand reaches them directly
// (no daemon round-trip): it reads each app's manifest and dials the
// socket using the same length-prefixed JSON framing the apps speak.

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pilot-protocol/app-store/pkg/ipc"
	"github.com/pilot-protocol/app-store/pkg/manifest"
	"github.com/pilot-protocol/common/consent"
	"github.com/pilot-protocol/common/crypto"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

// cryptoSHA256 is named so the sha256 import isn't ambiguous-looking.
func cryptoSHA256() hash.Hash { return sha256.New() }

const defaultAppStoreRoot = ".pilot/apps"

// cmdAppStore is the entry point dispatched from main.go's switch.
func cmdAppStore(args []string) {
	if len(args) == 0 {
		appStoreHelp()
		return
	}
	switch args[0] {
	case "list":
		cmdAppStoreList(args[1:])
	case "call":
		cmdAppStoreCall(args[1:])
	case "status":
		cmdAppStoreStatus(args[1:])
	case "view":
		cmdAppStoreView(args[1:])
	case "audit":
		cmdAppStoreAudit(args[1:])
	case "uninstall":
		cmdAppStoreUninstall(args[1:])
	case "verify":
		cmdAppStoreVerify(args[1:])
	case "install":
		cmdAppStoreInstall(args[1:])
	case "outdated":
		cmdAppStoreOutdated(args[1:])
	case "upgrade":
		cmdAppStoreUpgrade(args[1:])
	case "gen-key":
		cmdAppStoreGenKey(args[1:])
	case "sign":
		cmdAppStoreSign(args[1:])
	case "sign-catalogue", "sign-catalog":
		cmdAppStoreSignCatalogue(args[1:])
	case "catalogue", "catalog":
		cmdAppStoreCatalogue(args[1:])
	case "restart":
		cmdAppStoreRestart(args[1:])
	case "caps":
		cmdAppStoreCaps(args[1:])
	case "actions":
		cmdAppStoreActions(args[1:])
	case "help", "-h", "--help":
		appStoreHelp()
	default:
		fatalHint("invalid_argument",
			"available: list, status, view, audit, uninstall, verify, install, outdated, upgrade, gen-key, sign, sign-catalogue, catalogue, restart, caps, actions, call",
			"unknown appstore subcommand: %s", args[0])
	}
}

// AppStoreHelpText is the appstore subcommand's help block. Exported as
// a const so the upstream `commandHelp` table in main.go can register
// it under the "appstore" key — that way `pilotctl appstore <sub>
// --help` resolves through pilotctl's per-command help intercept and
// prints this text, instead of falling through to "No specific help".
const AppStoreHelpText = `pilotctl appstore — list installed apps and call their methods

Usage:
  pilotctl appstore list                     list installed apps + their methods
  pilotctl appstore status <id>              deep-dive on one app's pinned state
  pilotctl appstore view <id> [--all-changelog]
                                             detail page: description, vendor, changelog,
                                             size, source, methods, permissions (works
                                             whether or not the app is installed)
  pilotctl appstore audit <id> [--tail N] [--event NAME] [--since DURATION]
                                             show the supervisor lifecycle log
                                             event names: supervise-start, supervise-stop,
                                                          spawn, exit, suspend, verify-fail, spawn-fail
                                             duration: Go syntax (e.g. 10m, 1h, 24h)
  pilotctl appstore uninstall <id> --yes     remove an installed app from the install root
  pilotctl appstore verify <bundle-dir>      sha256-check a pre-install bundle against its manifest
  pilotctl appstore catalogue                list apps available for one-command install
  pilotctl appstore install <app-id> [--version <v>] [--force [--reset-state]]
                                             install by catalogue ID (fetches + verifies + extracts).
                                             already installed: a no-op that points at upgrade
                                             (another --version needs --force: conflict otherwise).
                                             --force reinstalls in place and KEEPS the app's state
                                             (keys, data.db, secrets, cap-state, audit log);
                                             --reset-state (implies --force) starts it empty
  pilotctl appstore install <bundle-dir> --local [--force [--reset-state]]
                                             sideload a local bundle (sandbox: fs.read/fs.write
                                             under $APP, audit.log; no net, no key.sign, no hooks)
  pilotctl appstore outdated                 list installed apps with a newer version in the catalogue
  pilotctl appstore upgrade <id> | --all     re-install the catalogue's current version (verified; app
                                             state is kept; supervisor restarts)
  pilotctl appstore gen-key <key-file>       generate a fresh ed25519 publisher keypair; prints the public side
  pilotctl appstore sign --key <key-file> <manifest>
                                             sign (or re-sign) a manifest's store.signature so the supervisor accepts it
  pilotctl appstore sign-catalogue --key <key-file> <catalogue.json>
                                             sign the catalogue, writing a detached <catalogue>.sig pilotctl verifies on load
  pilotctl appstore restart <id>             ask the daemon to clear crash-loop suspension and respawn this app
  pilotctl appstore caps <id>                show the manifest's spend caps and current rolling-window usage
  pilotctl appstore actions [--tail N] [--event NAME]
                                             show the pilotctl-side action log (install/uninstall — survives app removal)
  pilotctl appstore call <id> <method> [json-args] [--timeout 2m]
                                             dispatch an IPC call into an app
                                             (--timeout / $PILOT_APPSTORE_CALL_TIMEOUT;
                                              default 120s — raise for slow methods)

Install root is taken from $PILOT_APPSTORE_ROOT or ~/.pilot/apps.
Every install that replaces an app keeps the replaced dir as a backup under
$PILOT_APPSTORE_BACKUP_ROOT or app-backups/<id>/ beside the install root
(~/.pilot/app-backups). Routine backups are rotated (the newest 3 upgrades
and 3 same-version reinstalls per app); one that holds the only copy of
state (--reset-state, state that could not be carried) is never removed.
`

func appStoreHelp() {
	fmt.Fprint(os.Stderr, AppStoreHelpText)
}

func appStoreRoot() string {
	if r := os.Getenv("PILOT_APPSTORE_ROOT"); r != "" {
		return r
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaultAppStoreRoot
	}
	return filepath.Join(home, defaultAppStoreRoot)
}

// ── list ───────────────────────────────────────────────────────────────

type appListEntry struct {
	ID              string   `json:"id"`
	AppVersion      string   `json:"app_version"`
	ManifestVersion int      `json:"manifest_version"`
	Protection      string   `json:"protection"`
	Methods         []string `json:"methods"`
	SocketReady     bool     `json:"socket_ready"`
	BinaryPresent   bool     `json:"binary_present"`
	Suspended       bool     `json:"suspended,omitempty"`
	ManifestValid   bool     `json:"manifest_valid"`
	Sideloaded      bool     `json:"sideloaded,omitempty"`
}

func cmdAppStoreList(_ []string) {
	root := appStoreRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if jsonOutput {
				_ = json.NewEncoder(os.Stdout).Encode([]appListEntry{})
				return
			}
			fmt.Fprintf(os.Stderr, "no install root at %s — install an app first\n", root)
			return
		}
		fatalHint("io_error", "check the install root permissions", "read %s: %v", root, err)
	}

	var apps []appListEntry
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		mfPath := filepath.Join(dir, "manifest.json")
		raw, err := os.ReadFile(mfPath)
		if err != nil {
			continue
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			continue
		}
		binPath := filepath.Join(dir, m.Binary.Path)
		sockPath := filepath.Join(dir, "app.sock")
		_, sockErr := os.Stat(sockPath)
		_, binErr := os.Stat(binPath)
		// The supervisor drops a .suspended sentinel when the crash-loop
		// budget is spent. Detecting it from disk lets list report
		// "suspended" without daemon IPC.
		_, suspErr := os.Stat(filepath.Join(dir, ".suspended"))
		_, sideErr := os.Stat(filepath.Join(dir, manifest.SideloadMarkerName))
		// Run the manifest's semantic Validate too — an app the
		// supervisor will silently skip should be VISIBLY broken in
		// list output, not look like a normal "stopped" app.
		validationOK := len(m.Validate()) == 0
		apps = append(apps, appListEntry{
			ID:              m.ID,
			AppVersion:      m.AppVersion,
			ManifestVersion: m.ManifestVersion,
			Protection:      m.Protection,
			Methods:         append([]string(nil), m.Exposes...),
			SocketReady:     sockErr == nil,
			BinaryPresent:   binErr == nil,
			Suspended:       suspErr == nil,
			ManifestValid:   validationOK,
			Sideloaded:      sideErr == nil,
		})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(apps)
		return
	}

	if len(apps) == 0 {
		fmt.Printf("no apps installed under %s\n", root)
		return
	}
	fmt.Printf("install root: %s\n\n", root)
	for _, a := range apps {
		state := "stopped"
		switch {
		case !a.ManifestValid:
			state = "INVALID — manifest fails validation; supervisor will skip it (see `pilotctl appstore status " + a.ID + "`)"
		case a.Suspended:
			state = "SUSPENDED — run `pilotctl appstore restart " + a.ID + "` to clear"
		case !a.BinaryPresent:
			state = "missing-binary"
		case a.SocketReady:
			state = "ready"
		}
		fmt.Printf("  %s\n", a.ID)
		versionLine := fmt.Sprintf("%s (manifest v%d, %s)", a.AppVersion, a.ManifestVersion, a.Protection)
		if a.Sideloaded {
			versionLine += " [sideloaded]"
		}
		fmt.Printf("    version:  %s\n", versionLine)
		fmt.Printf("    state:    %s\n", state)
		if len(a.Methods) > 0 {
			fmt.Printf("    methods:  %v\n", a.Methods)
		}
		fmt.Println()
	}
}

// ── status ─────────────────────────────────────────────────────────────

type appStatusReport struct {
	ID                 string   `json:"id"`
	AppVersion         string   `json:"app_version"`
	ManifestVersion    int      `json:"manifest_version"`
	Protection         string   `json:"protection"`
	Methods            []string `json:"methods"`
	BinaryPath         string   `json:"binary_path"`
	BinarySize         int64    `json:"binary_size,omitempty"`
	BinarySHA256       string   `json:"binary_sha256_pinned"`
	BinarySHA256OK     bool     `json:"binary_sha256_ok"`
	BinarySHA256Actual string   `json:"binary_sha256_actual,omitempty"` // populated on mismatch so operators can diagnose without recomputing
	BinaryPresent      bool     `json:"binary_present"`
	SocketPath         string   `json:"socket_path"`
	SocketReady        bool     `json:"socket_ready"`
	DBPresent          bool     `json:"db_present"`
	IdentityPresent    bool     `json:"identity_present"`
	AuditLogPath       string   `json:"audit_log_path"`
	AuditLogPresent    bool     `json:"audit_log_present"`
	AuditLogSize       int64    `json:"audit_log_size,omitempty"`
	ManifestValid      bool     `json:"manifest_valid"`
	ManifestErrors     []string `json:"manifest_errors,omitempty"`
	Grants             []string `json:"grants"`
	SpendCaps          []string `json:"spend_caps,omitempty"`
	Extends            []string `json:"extends,omitempty"`
}

func cmdAppStoreStatus(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore status <app-id>",
			"missing app id")
	}
	appID := args[0]
	root := appStoreRoot()
	dir := filepath.Join(root, appID)
	mfPath := filepath.Join(dir, "manifest.json")
	raw, err := os.ReadFile(mfPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed: %v", appID, err)
		}
		fatalHint("io_error", "check install root permissions",
			"read %s: %v", mfPath, err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("internal_error",
			"the pinned manifest is corrupt; reinstall the app",
			"parse manifest: %v", err)
	}

	binPath := filepath.Join(dir, m.Binary.Path)
	sockPath := filepath.Join(dir, "app.sock")
	dbPath := filepath.Join(dir, "data.db")
	idPath := filepath.Join(dir, "identity.json")
	auditPath := filepath.Join(dir, "supervisor.log")

	// Validate the manifest semantically. The supervisor silently
	// skips manifests that fail Validate (see scanInstalled), so an
	// operator debugging "why isn't this spawning?" needs to see
	// validation status here — not buried in the daemon's log.
	validationErrs := m.Validate()
	validationStrs := make([]string, 0, len(validationErrs))
	for _, e := range validationErrs {
		validationStrs = append(validationStrs, e.Error())
	}

	report := appStatusReport{
		ID:              m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		Protection:      m.Protection,
		Methods:         append([]string(nil), m.Exposes...),
		BinaryPath:      binPath,
		ManifestValid:   len(validationErrs) == 0,
		ManifestErrors:  validationStrs,
		BinarySHA256:    m.Binary.SHA256,
		SocketPath:      sockPath,
		AuditLogPath:    auditPath,
	}
	if info, err := os.Stat(binPath); err == nil {
		report.BinaryPresent = true
		report.BinarySize = info.Size()
		actual := sha256File(binPath)
		report.BinarySHA256OK = actual == m.Binary.SHA256
		if !report.BinarySHA256OK {
			// Only surface the actual hash on mismatch — for the
			// matching case it duplicates the pinned value. Lets
			// operators diff against the manifest without re-running
			// shasum themselves.
			report.BinarySHA256Actual = actual
		}
	}
	if _, err := os.Stat(sockPath); err == nil {
		report.SocketReady = true
	}
	if _, err := os.Stat(dbPath); err == nil {
		report.DBPresent = true
	}
	if _, err := os.Stat(idPath); err == nil {
		report.IdentityPresent = true
	}
	if info, err := os.Stat(auditPath); err == nil {
		report.AuditLogPresent = true
		report.AuditLogSize = info.Size()
	}
	for _, g := range m.Grants {
		report.Grants = append(report.Grants, fmt.Sprintf("%s:%s", g.Cap, g.Target))
	}
	// Lift the structured spend caps out of the grants block too —
	// the raw `Grants` strings only show cap+target, not the rolling
	// window or amount. Operators looking at "what is this wallet
	// allowed to spend?" need the structured view. Including the
	// sign-purpose target distinguishes manifests that declare
	// multiple caps with identical asset/limit/window for different
	// signing surfaces (e.g. x402-auth vs evm-eip3009).
	for _, c := range parseCapsFromGrants(m.Grants) {
		report.SpendCaps = append(report.SpendCaps,
			fmt.Sprintf("%d %s per %s (target=%s)", c.limit, c.asset, humanDuration(c.window), c.target))
	}
	for _, e := range m.Extends {
		report.Extends = append(report.Extends, e.Primitive)
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}

	state := "stopped"
	switch {
	case !report.BinaryPresent:
		state = "missing-binary"
	case !report.BinarySHA256OK:
		state = "BINARY-SHA256-MISMATCH"
	case report.SocketReady:
		state = "ready"
	}

	fmt.Printf("app:            %s\n", report.ID)
	fmt.Printf("version:        %s (manifest v%d)\n", report.AppVersion, report.ManifestVersion)
	fmt.Printf("protection:     %s\n", report.Protection)
	fmt.Printf("state:          %s\n", state)
	if report.ManifestValid {
		fmt.Printf("manifest:       valid\n")
	} else {
		fmt.Printf("manifest:       INVALID — %d validation error(s); the supervisor will skip this app:\n", len(report.ManifestErrors))
		for _, e := range report.ManifestErrors {
			fmt.Printf("                  - %s\n", e)
		}
	}
	fmt.Printf("\n")
	fmt.Printf("binary:         %s\n", report.BinaryPath)
	if report.BinaryPresent {
		fmt.Printf("  size:         %d bytes\n", report.BinarySize)
		fmt.Printf("  sha256 pin:   %s\n", report.BinarySHA256)
		if report.BinarySHA256OK {
			fmt.Printf("  sha256 ok:    yes\n")
		} else {
			fmt.Printf("  sha256 ok:    NO — on-disk binary does not match the pinned hash\n")
			if report.BinarySHA256Actual != "" {
				fmt.Printf("  sha256 actual: %s\n", report.BinarySHA256Actual)
			}
		}
	} else {
		fmt.Printf("  status:       NOT PRESENT — the daemon will refuse to spawn this app\n")
	}
	fmt.Printf("socket:         %s (%s)\n", report.SocketPath, boolToReady(report.SocketReady))
	fmt.Printf("data.db:        %s\n", boolToPresent(report.DBPresent))
	fmt.Printf("identity:       %s\n", boolToPresent(report.IdentityPresent))
	if report.AuditLogPresent {
		fmt.Printf("audit log:      %s (%d bytes) — read with `pilotctl appstore audit %s`\n",
			report.AuditLogPath, report.AuditLogSize, report.ID)
	} else {
		fmt.Printf("audit log:      %s (none yet)\n", report.AuditLogPath)
	}
	if len(report.Methods) > 0 {
		fmt.Printf("\nexposes:\n")
		for _, m := range report.Methods {
			fmt.Printf("  - %s\n", m)
		}
	}
	if len(report.Grants) > 0 {
		fmt.Printf("\ngrants (user accepted at install):\n")
		for _, g := range report.Grants {
			fmt.Printf("  - %s\n", g)
		}
	}
	if len(report.SpendCaps) > 0 {
		fmt.Printf("\nspend caps (rolling-window limits):\n")
		for _, c := range report.SpendCaps {
			fmt.Printf("  - %s\n", c)
		}
		fmt.Printf("  (use `pilotctl appstore caps %s` for live usage)\n", report.ID)
	}
	if len(report.Extends) > 0 {
		fmt.Printf("\nextends (hooks registered):\n")
		for _, e := range report.Extends {
			fmt.Printf("  - %s\n", e)
		}
	}
}

func boolToReady(b bool) string {
	if b {
		return "ready"
	}
	return "not ready"
}

func boolToPresent(b bool) string {
	if b {
		return "present"
	}
	return "missing"
}

// exposedMethods reads the pinned manifest for appID and returns its
// `exposes` list. Best-effort: returns nil on any read/parse failure so
// the caller can fall through to the bare IPC error rather than mask it.
func exposedMethods(appID string) []string {
	raw, err := os.ReadFile(filepath.Join(appStoreRoot(), appID, "manifest.json"))
	if err != nil {
		return nil
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return nil
	}
	out := append([]string(nil), m.Exposes...)
	sort.Strings(out)
	return out
}

func sha256File(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := cryptoSHA256()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ── audit ──────────────────────────────────────────────────────────────

type auditLine struct {
	At       string `json:"at"`
	AppID    string `json:"app"`
	Event    string `json:"event"`
	PID      int    `json:"pid,omitempty"`
	ExitCode int    `json:"exit_code,omitempty"`
	Reason   string `json:"reason,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	BinaryAt string `json:"binary_path,omitempty"`
}

func cmdAppStoreAudit(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore audit <app-id> [--tail N] [--event NAME] [--since DURATION]",
			"missing app id")
	}
	appID := args[0]
	tail := 0
	eventFilter := ""
	var sinceCutoff time.Time
	var sinceDuration time.Duration
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--tail", "-n":
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--tail expects an integer count",
					"missing tail count")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				fatalHint("invalid_argument",
					"--tail expects a non-negative integer",
					"parse tail %q: %v", args[i+1], err)
			}
			tail = n
			i++
		case "--event", "-e":
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--event expects an event name (spawn, exit, suspend, verify-fail, spawn-fail)",
					"missing event name")
			}
			eventFilter = args[i+1]
			i++
		case "--since", "-s":
			// Accept Go duration syntax (10m, 1h30m, 24h). Anything
			// time.ParseDuration accepts works — same shape ops people
			// already know from `journalctl --since`-ish tools.
			if i+1 >= len(args) {
				fatalHint("invalid_argument",
					"--since expects a Go duration (e.g. 10m, 1h, 24h)",
					"missing duration")
			}
			d, err := time.ParseDuration(args[i+1])
			if err != nil || d <= 0 {
				fatalHint("invalid_argument",
					"--since expects a positive duration like 10m, 1h, 24h",
					"parse since %q: %v", args[i+1], err)
			}
			sinceCutoff = time.Now().Add(-d)
			sinceDuration = d
			i++
		default:
			fatalHint("invalid_argument",
				"available flags: --tail N, --event NAME, --since DURATION",
				"unknown audit flag: %s", args[i])
		}
	}

	appDir := filepath.Join(appStoreRoot(), appID)
	logPath := filepath.Join(appDir, "supervisor.log")
	rotatedPath := filepath.Join(appDir, "supervisor.log.1")

	// Read rotated file first (older entries) then active (newer)
	// so display order stays chronological after rotation. The
	// rotated file is optional — missing means rotation never fired.
	var lines []auditLine
	appendLogFile := func(path string, required bool) bool {
		f, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return !required // ok when optional, fail when required
			}
			fatalHint("io_error",
				"check the install root permissions and that the app id is correct",
				"open %s: %v", path, err)
			return false
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(raw) == 0 {
				continue
			}
			var ev auditLine
			if err := json.Unmarshal(raw, &ev); err != nil {
				// Skip malformed lines but don't fail the command — a single
				// corrupt line shouldn't block forensics on the rest.
				continue
			}
			lines = append(lines, ev)
		}
		if err := scanner.Err(); err != nil {
			fatalHint("io_error",
				"the log file may be corrupt; try `cat` to inspect raw bytes",
				"scan %s: %v", path, err)
		}
		return true
	}
	_ = appendLogFile(rotatedPath, false) // optional
	activeExists := appendLogFile(logPath, false)
	if !activeExists && len(lines) == 0 {
		// Neither file exists — no audit log at all yet.
		if jsonOutput {
			_ = json.NewEncoder(os.Stdout).Encode([]auditLine{})
			return
		}
		fmt.Printf("no audit log yet at %s — the app has not run since the supervisor started writing logs\n", logPath)
		return
	}

	if eventFilter != "" {
		filtered := lines[:0]
		for _, ev := range lines {
			if ev.Event == eventFilter {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if !sinceCutoff.IsZero() {
		filtered := lines[:0]
		for _, ev := range lines {
			// Audit timestamps land as RFC3339Nano (supervisor uses
			// time.Now().UTC()); parse defensively and drop lines we
			// can't interpret rather than blowing up the whole query.
			t, err := time.Parse(time.RFC3339Nano, ev.At)
			if err != nil {
				continue
			}
			if !t.Before(sinceCutoff) {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(lines)
		return
	}

	if len(lines) == 0 {
		switch {
		case eventFilter != "" && sinceDuration > 0:
			fmt.Printf("no %q events in last %s for %s\n", eventFilter, humanDuration(sinceDuration), logPath)
		case eventFilter != "":
			fmt.Printf("no %q events in %s\n", eventFilter, logPath)
		case sinceDuration > 0:
			fmt.Printf("no events in last %s for %s\n", humanDuration(sinceDuration), logPath)
		default:
			fmt.Printf("audit log %s is empty\n", logPath)
		}
		return
	}
	header := fmt.Sprintf("audit log: %s (%d events shown", logPath, len(lines))
	if eventFilter != "" {
		header += fmt.Sprintf(", filtered to event=%q", eventFilter)
	}
	if sinceDuration > 0 {
		header += fmt.Sprintf(", since last %s", humanDuration(sinceDuration))
	}
	header += ")"
	fmt.Println(header)
	fmt.Println()
	for _, ev := range lines {
		fmt.Printf("  %s  %-12s", ev.At, ev.Event)
		if ev.PID > 0 {
			fmt.Printf(" pid=%d", ev.PID)
		}
		if ev.Event == "exit" {
			fmt.Printf(" exit_code=%d", ev.ExitCode)
		}
		if ev.SHA256 != "" {
			fmt.Printf(" sha256=%s", shortHex(ev.SHA256))
		}
		if ev.Reason != "" {
			fmt.Printf(" reason=%q", ev.Reason)
		}
		fmt.Println()
	}
}

// shortHex collapses a hex digest to "abcd1234…ef01" — first 8 + last 4
// characters joined by an ellipsis — keeping audit-log lines readable
// while still pinning down the binary version when grepping for
// incidents. Returns the input unchanged if it's already short.
func shortHex(h string) string {
	if len(h) <= 16 {
		return h
	}
	return h[:8] + "…" + h[len(h)-4:]
}

// ── uninstall ──────────────────────────────────────────────────────────

// cmdAppStoreUninstall removes an installed app's directory tree from the
// install root. Destructive — requires --yes to confirm. Does NOT
// coordinate with the daemon's supervisor, so until the daemon is
// restarted the supervisor will keep failing the binary sha256 check on
// every respawn (visible in the audit log as "verify-fail" lines, capped
// at one per 30s by the supervisor backoff).
func cmdAppStoreUninstall(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore uninstall <app-id> --yes",
			"missing app id")
	}
	appID := args[0]
	confirmed := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--yes", "-y":
			confirmed = true
		default:
			fatalHint("invalid_argument",
				"available flags: --yes",
				"unknown uninstall flag: %s", args[i])
		}
	}
	if !confirmed {
		fatalHint("invalid_argument",
			"uninstall is destructive — pass --yes to confirm",
			"refusing to uninstall %q without --yes", appID)
	}

	// appID is user input; confine it under the app-store root so a
	// crafted id (e.g. "../../something") can't RemoveAll outside the
	// install tree. Same guard the install/verify paths use.
	root := appStoreRoot()
	dir, err := resolveUnder(root, appID)
	if err != nil {
		fatalHint("invalid_argument",
			"app ids are single directory names; try `pilotctl appstore list`",
			"invalid app id %q: %v", appID, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions",
			"stat %s: %v", dir, err)
	}
	if !info.IsDir() {
		fatalHint("internal_error",
			"the install root layout is corrupt; inspect manually",
			"%s is not a directory", dir)
	}
	// Not in the middle of an install or upgrade of the same app.
	unlock, err := lockAppInstall(root, appID)
	if err != nil {
		fatalHint("timeout", "wait for the other install or upgrade of this app to finish, then re-run", "%v", err)
	}
	defer unlock()

	// Read the manifest BEFORE deleting it so we can snapshot the
	// binary sha256 + app_version into the uninstall audit record.
	// The per-app supervisor.log is going away with the dir; the
	// pilotctl-audit log at the install-root level is what survives.
	var snapSHA, snapVer string
	mfPath := filepath.Join(dir, "manifest.json")
	if raw, err := os.ReadFile(mfPath); err == nil {
		if m, perr := manifest.Parse(raw); perr == nil {
			snapSHA = m.Binary.SHA256
			snapVer = m.AppVersion
		}
	}

	// Race-aware removal. The daemon's supervise goroutine is still
	// running and writes to <dir>/supervisor.log on every verify-fail
	// (every 30s), which can racily recreate the log file mid-delete
	// and turn RemoveAll into a "directory not empty" failure. Manifest
	// removal first triggers the supervisor's rescanForGone to cancel
	// the per-app goroutine; then the dir delete has no live writer.
	if err := os.Remove(mfPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		fatalHint("io_error",
			"check install root permissions",
			"remove manifest %s: %v", mfPath, err)
	}
	// Stop everything still running from the app's files: the app itself
	// and whatever it started that outlives it (a smolvm microVM, a
	// daemonized database server, an instance orphaned by a daemon that
	// died hard). After the delete nothing could reach them any more. The
	// backups of earlier installs are included: a process started before an
	// upgrade keeps running from the retired dir. See appstore_procs.go.
	backups := listAppBackups(root, appID)
	procRoots := appDirRoots(dir)
	for _, b := range backups {
		procRoots = append(procRoots, appDirRoots(b)...)
	}
	stopped, _ := stopProcessesRunningFrom(procRoots, appDirStopGrace)

	// Retry RemoveAll a few times to ride out the supervisor's
	// in-flight audit writes; the rescan loop cancels the goroutine
	// within ~RescanInterval (default 30s in prod, but the audit
	// writes themselves happen at the 30s verify-fail cadence, so a
	// handful of short retries is usually enough).
	const (
		removeRetries = 8
		retryDelay    = 250 * time.Millisecond
	)
	var rmErr error
	for i := 0; i < removeRetries; i++ {
		if err := removeAllForce(dir); err == nil { // read-only dirs in $APP (a Go module cache) included
			rmErr = nil
			break
		} else {
			rmErr = err
			time.Sleep(retryDelay)
		}
	}
	if rmErr != nil {
		fatalHint("io_error",
			"manifest removed but the dir is racing the supervisor; rerun `pilotctl appstore uninstall --yes` after the daemon's next rescan settles (~30s)",
			"remove %s: %v", dir, rmErr)
	}

	// A supervisor that had not yet seen the manifest go may have respawned
	// the app between the stop above and the delete (its restart backoff
	// starts at 1s). That instance runs a now-deleted binary; stop it too.
	respawned, _ := stopProcessesRunningFrom(procRoots, appDirStopGrace)
	for _, p := range respawned {
		if !slices.ContainsFunc(stopped, func(q appDirProcess) bool { return q.PID == p.PID }) {
			stopped = append(stopped, p)
		}
	}
	stillRunning := processesRunningFrom(procRoots)

	// Forensic trail at the install-root level (survives the deletion
	// of the app dir). Pairs with the install-time event we wrote
	// into supervisor.log earlier — gives "this app existed between
	// install T0 and uninstall T1" reconstructable post-hoc.
	reason := fmt.Sprintf("actor=%s removed=%s", currentActor(), dir)
	if len(stopped) > 0 {
		reason += " stopped=" + describeAppDirProcesses(stopped)
	}
	if len(stillRunning) > 0 {
		reason += " still_running=" + describeAppDirProcesses(stillRunning)
	}
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "uninstalled",
		AppID:  appID,
		SHA256: snapSHA,
		AppVer: snapVer,
		Reason: reason,
	})

	// Replaced installs are kept as backups (appstore_state.go), wherever
	// retireAppDir had to put them, and may hold the app's keys. Uninstall
	// leaves them, so it says where every one of them is.
	if jsonOutput {
		out := map[string]any{
			"id":            appID,
			"removed":       dir,
			"daemon_notice": "supervisor's next rescan (≤30s) will cancel the per-app goroutine; manifest already removed",
		}
		if len(backups) > 0 {
			out["backups"] = backups
		}
		if len(stopped) > 0 {
			out["stopped_processes"] = stopped
		}
		if len(stillRunning) > 0 {
			out["still_running"] = stillRunning
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	fmt.Printf("removed %s\n", dir)
	if len(stopped) > 0 {
		fmt.Printf("stopped %d process(es) still running from the app's files: %s\n", len(stopped), describeAppDirProcesses(stopped))
	}
	if len(stillRunning) > 0 {
		fmt.Fprintf(os.Stderr, "warn: still running from the removed app's files after SIGKILL: %s; stop them by hand\n", describeAppDirProcesses(stillRunning))
	}
	fmt.Println("note: the daemon's supervisor will cancel its per-app goroutine on its next rescan")
	fmt.Println("      (≤30s); no daemon restart needed")
	if len(backups) > 0 {
		fmt.Printf("note: %d backup(s) of earlier installs remain; they may hold the app's keys and data. Delete them by hand once you no longer need them:\n", len(backups))
		for _, b := range backups {
			fmt.Printf("      %s\n", b)
		}
	}
}

// ── verify ─────────────────────────────────────────────────────────────

// verifyReport is the --json shape returned by `appstore verify`.
type verifyReport struct {
	BundleDir       string `json:"bundle_dir"`
	AppID           string `json:"id"`
	AppVersion      string `json:"app_version"`
	ManifestVersion int    `json:"manifest_version"`
	Protection      string `json:"protection"`
	BinaryPath      string `json:"binary_path"` // path inside the bundle (manifest.Binary.Path)
	BinarySize      int64  `json:"binary_size"`
	ExpectedSHA256  string `json:"expected_sha256"` // from manifest.Binary.SHA256
	ActualSHA256    string `json:"actual_sha256"`   // computed from on-disk bytes
	OK              bool   `json:"ok"`
}

// cmdAppStoreVerify sha256-checks a pre-install bundle against its
// own manifest. This is the same trust check the supervisor runs at
// every launch, exposed pre-install so app authors can validate their
// build output AND users can sanity-check a downloaded bundle before
// dropping it into <install_root>/<id>/.
//
// Bundle layout (same as the on-disk install layout):
//
//	<bundle-dir>/
//	  manifest.json
//	  <manifest.Binary.Path>  (typically bin/<name>)
func cmdAppStoreVerify(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore verify <bundle-dir>",
			"missing bundle dir")
	}
	bundleDir := args[0]
	info, err := os.Stat(bundleDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				"pass a directory containing manifest.json and the binary",
				"bundle dir %q does not exist", bundleDir)
		}
		fatalHint("io_error", "check the bundle path", "stat %s: %v", bundleDir, err)
	}
	if !info.IsDir() {
		fatalHint("invalid_argument",
			"verify expects a directory, not a file (extract the tarball first)",
			"%s is not a directory", bundleDir)
	}

	mfPath := filepath.Join(bundleDir, "manifest.json")
	raw, err := os.ReadFile(mfPath)
	if err != nil {
		fatalHint("invalid_argument",
			"every bundle must contain a manifest.json at the top level",
			"read %s: %v", mfPath, err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("invalid_argument",
			"the bundle's manifest.json failed JSON parsing",
			"parse manifest: %v", err)
	}
	if errs := m.Validate(); len(errs) > 0 {
		// Catch semantic errors (unknown cap, missing required fields,
		// malformed store.publisher) BEFORE telling the user "verified" —
		// otherwise install/scan silently skip the app later.
		fatalHint("invalid_argument",
			"the bundle's manifest passed JSON parsing but failed semantic validation; fix the listed issues before installing",
			"manifest validation: %s", validationErrSummary(errs))
	}

	binPath := filepath.Join(bundleDir, m.Binary.Path)
	binInfo, err := os.Stat(binPath)
	if err != nil {
		fatalHint("invalid_argument",
			fmt.Sprintf("manifest expects binary at %q (relative to bundle root)", m.Binary.Path),
			"binary not found: %v", err)
	}
	actual := sha256File(binPath)

	report := verifyReport{
		BundleDir:       bundleDir,
		AppID:           m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		Protection:      m.Protection,
		BinaryPath:      m.Binary.Path,
		BinarySize:      binInfo.Size(),
		ExpectedSHA256:  m.Binary.SHA256,
		ActualSHA256:    actual,
		OK:              actual == m.Binary.SHA256 && m.Binary.SHA256 != "",
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		if !report.OK {
			os.Exit(2)
		}
		return
	}

	fmt.Printf("bundle:         %s\n", report.BundleDir)
	fmt.Printf("app:            %s\n", report.AppID)
	fmt.Printf("version:        %s (manifest v%d, %s)\n", report.AppVersion, report.ManifestVersion, report.Protection)
	fmt.Printf("binary:         %s (%d bytes)\n", report.BinaryPath, report.BinarySize)
	fmt.Printf("  expected:     %s\n", report.ExpectedSHA256)
	fmt.Printf("  actual:       %s\n", report.ActualSHA256)
	if report.OK {
		fmt.Printf("\nVERIFY OK — bundle's binary matches the manifest's pinned sha256.\n")
		return
	}
	if report.ExpectedSHA256 == "" {
		fmt.Fprintf(os.Stderr, "\nVERIFY FAILED — manifest is missing binary.sha256; refuse to install.\n")
	} else {
		fmt.Fprintf(os.Stderr, "\nVERIFY FAILED — bundle binary does NOT match the manifest's pinned sha256.\n")
	}
	os.Exit(2)
}

// ── install ────────────────────────────────────────────────────────────

// installReport is the --json shape returned by `appstore install`.
type installReport struct {
	AppID           string `json:"id"`
	AppVersion      string `json:"app_version"`
	ManifestVersion int    `json:"manifest_version"`
	InstalledTo     string `json:"installed_to"`
	BinarySHA256    string `json:"binary_sha256"`
	DaemonNotice    string `json:"daemon_notice"`

	// AlreadyInstalled marks the no-op answer to `install` of an app that is
	// already installed without --force; Hint says what to run instead.
	AlreadyInstalled bool   `json:"already_installed,omitempty"`
	Hint             string `json:"hint,omitempty"`
	// PreservedState lists the app-state paths (relative to the app dir)
	// carried from the replaced install into the new one.
	PreservedState []string `json:"preserved_state,omitempty"`
	// StateReset is true when --reset-state deliberately started the app
	// without its previous state.
	StateReset bool `json:"state_reset,omitempty"`
	// StateNotCarried lists app state that could not be carried into the
	// new install; it is only in BackupDir, which is never pruned.
	StateNotCarried []string `json:"state_not_carried,omitempty"`
	// BackupDir is where the replaced install was kept.
	BackupDir string `json:"backup_dir,omitempty"`
	// BackupWarning is set when the backup is not where it was configured
	// to go (or could not be completed); the same text goes to stderr.
	BackupWarning string `json:"backup_warning,omitempty"`
}

// cmdAppStoreInstall places a verified bundle into the install root.
// Layout matches what the supervisor expects (see plugin/appstore/supervisor.go:
// scanInstalled). Atomic move-rename means a daemon scanning the install
// root never sees a partially-written app dir.
//
// Steps:
//  1. sha256-check the bundle (same logic as `verify`) and refuse a binary
//     built for another platform
//  2. if the app is already installed: without --force, a no-op that points
//     at `upgrade`; with --force, replace it (state kept, see below)
//  3. stage into <install_root>/<id>.staging/, carrying the installed app's
//     state (appstore_state.go) unless --reset-state
//  4. swap .staging → <id>, keeping the old dir at <id>.previous until the
//     new one verifies, then retire it to the backups
//
// The daemon's supervisor only scans on Start, so an install while the
// daemon is running is invisible until the next daemon restart — the
// success message and JSON note callers about this.
// resolveUnder joins rel onto base, cleans it, and verifies the result
// is contained inside base. Returns an error otherwise.
//
// filepath.Join alone does NOT block traversal: a manifest with
// binary.path = "../../etc/x" resolves outside the bundle/staging dir,
// which would let a hostile manifest read an arbitrary host file as the
// "binary" or plant a copy outside the staging tree. This mirrors the
// supervisor's resolveUnder guard so the install path enforces the same
// containment the supervisor relies on at spawn.
func resolveUnder(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("absolute path not permitted")
	}
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", fmt.Errorf("abs base: %w", err)
	}
	joined := filepath.Clean(filepath.Join(absBase, rel))
	if joined != absBase && !strings.HasPrefix(joined, absBase+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes %s", rel, absBase)
	}
	return joined, nil
}

func cmdAppStoreInstall(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore install <app-id-or-dir> [--force [--reset-state]] [--local] [--version <v>]",
			"missing app id or bundle dir")
	}
	target := args[0]
	force := false
	resetState := false
	wantVersion := ""
	allowLocal := false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--force", "-f":
			force = true
		case "--reset-state":
			// The explicit destructive variant: reinstall WITHOUT carrying the
			// app's state forward. Implies --force; warns loudly below.
			resetState = true
			force = true
		case "--version":
			// Read the value before advancing so the bound is checked against
			// the index actually used.
			if i+1 >= len(args) {
				fatalHint("invalid_argument", "usage: --version <exact-catalogue-version>", "--version needs a value")
				return
			}
			wantVersion = args[i+1]
			i++
		case "--local":
			// Required acknowledgement when installing from a local
			// directory. Catalogue installs ignore this; path installs
			// without --local fail closed so a typo'd app id (which
			// happens to also exist as a directory in the cwd) can't
			// silently sideload an unsigned bundle.
			allowLocal = true
		default:
			fatalHint("invalid_argument",
				"available flags: --force, --reset-state, --local, --version",
				"unknown install flag: %s", args[i])
		}
	}

	// Already installed and no --force: answer before downloading anything.
	// (A local bundle path is only known to be installed once its manifest
	// is read, so that case is answered after validation below.) A pinned
	// --version other than the installed one is not answered here: it is
	// either unavailable or a replacement that needs --force, both errors.
	if !force && !allowLocal && target != "" && !strings.HasPrefix(target, ".") && !strings.ContainsAny(target, `/\`) {
		if dir, err := resolveUnder(appStoreRoot(), target); err == nil {
			im, _, merr := readInstalledManifest(dir)
			if merr != nil {
				if _, perr := os.Lstat(dir + appPreviousSuffix); perr == nil {
					// No live manifest but a <id>.previous: an install of
					// this app died mid-swap, or is mid-swap right now. The
					// lock waits for a running one to finish; only then is
					// what is left a crash leftover to repair.
					if unlock, lerr := lockAppInstall(appStoreRoot(), target); lerr == nil {
						if notes, rerr := recoverInterruptedInstall(dir, target); rerr == nil {
							printInstallNotes(notes)
						}
						unlock()
						im, _, merr = readInstalledManifest(dir)
					}
				}
			}
			if merr == nil && im.ID == target && (wantVersion == "" || wantVersion == im.AppVersion) {
				reportAlreadyInstalled(dir, im, target, false)
				return
			}
		}
	}

	// Resolve `target` to a local bundle dir and a source tag.
	// Catalogue path = signed, runs the standard signature gate.
	// Local path = sideload, requires --local AND must satisfy the
	// sideload allow-list before the supervisor will load it.
	bundleDir, source, err := resolveInstallTargetVersion(target, wantVersion)
	if err != nil {
		if errors.Is(err, ErrCatalogueVersionUnavailable) {
			// Distinct from a bad argument: the caller asked for a version the
			// catalogue no longer carries. Installing whatever is current
			// instead would hand a node software nobody approved.
			fatalHint("version_unavailable",
				"the catalogue carries only each app's current release; re-approve the app to move the pinned version forward",
				"%v", err)
		}
		fatalHint("invalid_argument",
			"the argument must be either a catalogue ID (`pilotctl appstore catalogue` to list) or a path to a bundle dir containing manifest.json",
			"%v", err)
	}
	if source == installSourceLocal && !allowLocal {
		fatalHint("invalid_argument",
			"local sideloads carry no catalogue signature; pass --local to confirm you trust this bundle's source. The supervisor will clamp the manifest to a small allow-list (fs.read/fs.write under $APP, audit.log). No net.dial, key.sign, ipc.call to other apps, or daemon hooks.",
			"refusing to install local path %q without --local", target)
	}

	// 1. Validate the bundle — same shape as verify. Reusing the
	//    surface manifest.Parse + sha256File makes the trust check
	//    identical to what the supervisor runs at every spawn.
	info, err := os.Stat(bundleDir)
	if err != nil || !info.IsDir() {
		fatalHint("invalid_argument",
			"pass a directory containing manifest.json and the binary",
			"bundle dir %q is not a directory: %v", bundleDir, err)
	}
	raw, err := os.ReadFile(filepath.Join(bundleDir, "manifest.json"))
	if err != nil {
		fatalHint("invalid_argument",
			"every bundle must contain a manifest.json at the top level",
			"read manifest: %v", err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		fatalHint("invalid_argument",
			"the bundle's manifest.json failed JSON parsing",
			"parse manifest: %v", err)
	}
	if errs := m.Validate(); len(errs) > 0 {
		// Same gate as verify — never plant a manifest that the
		// supervisor will silently skip on scanInstalled.
		fatalHint("invalid_argument",
			"refusing to install a manifest the supervisor will reject; fix the listed issues and re-run",
			"manifest validation: %s", validationErrSummary(errs))
	}
	if source == installSourceLocal {
		// Same allow-list the supervisor enforces at scan time. We
		// check it here too so users find out at install time, not at
		// the next supervisor poll, what they need to strip from the
		// manifest. Failing closed: no marker is planted unless the
		// manifest passes.
		if err := manifest.EnforceSideloadPolicy(m); err != nil {
			fatalHint("invalid_argument",
				"sideloaded apps may only declare audit.log, fs.read $APP/*, fs.write $APP/*. Remove the offending grant or use the catalogue install path for a reviewed app.",
				"%v", err)
		}
	}
	srcBin, err := resolveUnder(bundleDir, m.Binary.Path)
	if err != nil {
		fatalHint("invalid_argument",
			"manifest binary.path must be a relative path inside the bundle; refusing a path that escapes the bundle dir",
			"binary path %q escapes bundle: %v", m.Binary.Path, err)
	}
	if _, err := os.Stat(srcBin); err != nil {
		fatalHint("invalid_argument",
			fmt.Sprintf("manifest pins binary at %q", m.Binary.Path),
			"binary missing in bundle: %v", err)
	}
	if m.Binary.SHA256 == "" {
		fatalHint("invalid_argument",
			"every binary must declare a sha256 in the manifest; refuse to install unsigned bytes",
			"manifest missing binary.sha256")
	}
	if got := sha256File(srcBin); got != m.Binary.SHA256 {
		fatalHint("integrity_error",
			"run `pilotctl appstore verify` for a side-by-side; this bundle is tampered or built from a different source than the manifest claims",
			"binary sha256 mismatch: manifest=%s actual=%s", m.Binary.SHA256, got)
	}
	if err := checkAppBinaryPlatform(srcBin); err != nil {
		hint := fmt.Sprintf("nothing was installed and any existing install of %s is untouched. The bundle ships a binary for another platform; the publisher needs to publish a per-platform `bundles` entry for %s/%s (see catalogue/README.md)",
			m.ID, runtime.GOOS, runtime.GOARCH)
		if source == installSourceLocal {
			hint = fmt.Sprintf("nothing was installed and any existing install of %s is untouched. Rebuild the bundle's binary for %s/%s",
				m.ID, runtime.GOOS, runtime.GOARCH)
		}
		fatalHint("platform_mismatch", hint,
			"refusing to install %s v%s: %s is built for a different platform than this host (%s/%s): %v",
			m.ID, m.AppVersion, m.Binary.Path, runtime.GOOS, runtime.GOARCH, err)
	}

	root := appStoreRoot()
	finalDir := filepath.Join(root, m.ID)
	stagingDir := finalDir + appStagingSuffix

	// Everything from here to the retire of the replaced install runs under
	// the app's install lock (appstore_lock.go): a concurrent install or
	// upgrade of the same app waits, instead of interleaving its swap with
	// ours or mistaking our in-flight swap for a crash leftover.
	unlock, err := lockAppInstall(root, m.ID)
	if err != nil {
		fatalHint("timeout", "wait for the other install, upgrade or uninstall of this app to finish, then re-run", "%v", err)
	}
	defer unlock()

	// 2. Already installed? First repair anything a crashed install left
	//    behind (this can only restore or back up, never delete), then:
	//    without --force this is a no-op pointing at `upgrade`; with --force
	//    the existing install is replaced and its state carried over.
	notes, err := recoverInterruptedInstall(finalDir, m.ID)
	if err != nil {
		fatalHint("io_error",
			"a previous install of this app was interrupted and could not be repaired automatically; inspect the install root",
			"%v", err)
	}
	printInstallNotes(notes)
	replacing := false
	var oldManifest *manifest.Manifest
	if _, err := os.Lstat(finalDir); err == nil {
		replacing = true
		if im, _, merr := readInstalledManifest(finalDir); merr == nil {
			oldManifest = im
			if !force {
				// A caller that named a version (--version, or a local
				// bundle) other than the installed one asked for a
				// replacement: refuse it rather than report success.
				if (wantVersion != "" || source == installSourceLocal) && m.AppVersion != im.AppVersion {
					how := "pass --force to replace it (app state is kept)"
					if source != installSourceLocal {
						how += ", or run `pilotctl appstore upgrade " + m.ID + "` for the catalogue's current version"
					}
					fatalHint("conflict", how,
						"%s v%s is installed; refusing to replace it with v%s without --force", m.ID, im.AppVersion, m.AppVersion)
				}
				reportAlreadyInstalled(finalDir, im, target, source == installSourceLocal)
				return
			}
		} else {
			// A dir without a readable manifest is a broken install (e.g. an
			// interrupted uninstall). Replace it, keeping whatever state it has.
			fmt.Fprintf(os.Stderr, "note: %s has no readable manifest (%v); repairing it with this bundle and keeping its app state\n", finalDir, merr)
		}
	}

	// 3. Stage atomically. recoverInterruptedInstall above already dropped a
	//    leftover staging dir (it holds only a bundle copy plus links to state
	//    whose originals are in finalDir), so this only matters when an older
	//    pilotctl, which takes no lock, is writing one right now.
	if err := removeAllForce(stagingDir); err != nil {
		fatalHint("io_error", "check install root permissions",
			"clean stale staging dir %s: %v", stagingDir, err)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		fatalHint("io_error", "check install root permissions",
			"mkdir staging %s: %v", stagingDir, err)
	}
	// manifest.json is written LAST (after the binary and the carried
	// state): the supervisor adopts any dir under the install root that
	// holds a manifest, so staging must not carry one while still filling.
	//
	// Place the binary at the manifest-declared path inside staging.
	// Re-apply the containment guard against the staging root: defence
	// in depth so the write target can't escape even if bundleDir and
	// stagingDir ever diverge.
	dstBin, err := resolveUnder(stagingDir, m.Binary.Path)
	if err != nil {
		// #nosec G703 -- stagingDir is appStoreRoot()/<m.ID>.staging; m.ID is reverse-DNS validated by m.Validate() above, so it cannot escape the install root
		_ = os.RemoveAll(stagingDir)
		fatalHint("invalid_argument",
			"manifest binary.path must stay inside the staging dir",
			"binary path %q escapes staging: %v", m.Binary.Path, err)
	}
	if err := os.MkdirAll(filepath.Dir(dstBin), 0o700); err != nil {
		_ = os.RemoveAll(stagingDir)
		fatalHint("io_error", "check install root permissions", "mkdir binary parent: %v", err)
	}
	if err := copyFile(srcBin, dstBin, 0o755); err != nil {
		_ = os.RemoveAll(stagingDir)
		fatalHint("io_error", "check install root permissions", "copy binary: %v", err)
	}
	// Re-verify the staged binary against the manifest pin. Cheap
	// defense against a copy that silently went wrong (FS bug, disk
	// error). If this ever fails it's a hard refusal — staging gets
	// cleaned up, no partial install ever reaches the supervisor.
	if got := sha256File(dstBin); got != m.Binary.SHA256 {
		_ = os.RemoveAll(stagingDir)
		fatalHint("integrity_error",
			"the staged copy does not match the bundle — possible disk-level corruption",
			"staged binary sha256 mismatch: manifest=%s staged=%s", m.Binary.SHA256, got)
	}

	// Carry the native-delivery install spec (and its human-readable script) into
	// $APP when the bundle ships them. A cli adapter with assets reads
	// $APP/install.json at startup to fetch + verify + stage its binaries from the
	// R2 artifact registry. These files are covered by the bundle's sha (verified
	// above at the tarball level), so copying them adds no new trust surface.
	for _, aux := range []string{"install.json", "install.sh"} {
		// Resolve both ends through the same containment guard the binary copy
		// uses: aux is a constant allow-list entry, and resolveUnder cleans the
		// join and verifies it stays under the root — so neither path can escape.
		src, serr := resolveUnder(bundleDir, aux)
		dst, derr := resolveUnder(stagingDir, aux)
		if serr != nil || derr != nil {
			_ = os.RemoveAll(stagingDir) // #nosec G703 -- stagingDir is appStoreRoot()/<m.ID>.staging (m.ID reverse-DNS validated), confined to the install root; cleanup of our own dir
			fatalHint("internal_error", "aux install file path escaped the bundle/staging root", "resolve %s: %v / %v", aux, serr, derr)
		}
		if _, err := os.Stat(src); err != nil { // #nosec G703 -- src is resolveUnder(bundleDir, <const aux>), proven to stay under the bundle root above; no traversal
			continue // not an asset-delivering app
		}
		mode := os.FileMode(0o644)
		if aux == "install.sh" {
			mode = 0o755
		}
		if err := copyFile(src, dst, mode); err != nil { // #nosec G703 -- src/dst are resolveUnder-confined (bundle/staging roots); aux is a constant allow-list entry, so neither can escape
			_ = os.RemoveAll(stagingDir) // #nosec G703 -- stagingDir is the confined install-root staging dir; cleanup of our own dir
			fatalHint("io_error", "check install root permissions", "copy %s: %v", aux, err)
		}
	}

	if source == installSourceLocal {
		// Plant the sentinel before the atomic rename so the moment
		// the dir appears under InstallRoot it's already tagged
		// sideloaded — there's no window where the supervisor could
		// scan a sideloaded dir and treat it as catalogue-trusted.
		// 0o400: read-only to the owning user; the file's mere
		// existence is the signal, no content needed.
		markerPath := filepath.Join(stagingDir, manifest.SideloadMarkerName)
		if err := os.WriteFile(markerPath, nil, 0o400); err != nil {
			_ = os.RemoveAll(stagingDir)
			fatalHint("io_error", "check install root permissions",
				"write sideload marker: %v", err)
		}
	}

	// Carry the installed app's state (keys, databases, secrets, spend-cap
	// ledger, audit log — everything the new bundle does not ship) into
	// staging, and check it landed, BEFORE the live dir is touched. Any
	// failure here aborts with the existing install exactly as it was.
	var (
		carry      *appStateCarry
		carried    []string
		oldBinary  string
		oldVersion string
	)
	if oldManifest != nil {
		oldBinary, oldVersion = oldManifest.Binary.Path, oldManifest.AppVersion
	}
	if replacing && !resetState {
		carry, err = carryAppState(finalDir, stagingDir, oldBinary)
		if err == nil {
			carried = carry.Carried
			err = verifyCarriedState(stagingDir, carried, false)
		}
		if err != nil {
			err = withStagingDiscarded(stagingDir, err)
			fatalHint("io_error",
				"nothing was changed: the existing install and its state are untouched. Fix the error (e.g. free disk space) and re-run",
				"carry app state from %s: %v", finalDir, err)
		}
		if len(carry.Unreadable) > 0 {
			fmt.Fprintf(os.Stderr, "note: %d entr(ies) of %s's state cannot be linked or read by this user (%s); they are moved into the new install after the swap instead\n",
				len(carry.Unreadable), m.ID, summarizePaths(carry.Unreadable, 4))
		}
	}
	if replacing && resetState {
		fmt.Fprintf(os.Stderr, "WARNING: --reset-state: %s is being reinstalled WITHOUT its saved state.\n", m.ID)
		fmt.Fprintln(os.Stderr, "WARNING: keys (identity*.json), databases (data.db*), secrets, the spend-cap ledger and the")
		fmt.Fprintln(os.Stderr, "WARNING: audit log of the current install will NOT be in the new install; the app starts empty.")
		fmt.Fprintf(os.Stderr, "WARNING: the current install is kept as a backup under %s, and that backup is never removed automatically.\n", filepath.Join(appStoreBackupRoot(), m.ID))
	}

	// Write manifest.json (0644 — readable by everyone in the user's group; not secret).
	if err := os.WriteFile(filepath.Join(stagingDir, "manifest.json"), raw, 0o644); err != nil { // #nosec G306 G703 -- manifest is public metadata read by the daemon's supervisor; stagingDir is appStoreRoot()/<m.ID>.staging (m.ID reverse-DNS validated by m.Validate()), confined to the install root
		fatalHint("io_error", "check install root permissions", "write manifest: %v", withStagingDiscarded(stagingDir, err))
	}

	if testHookBeforeSwap != nil {
		testHookBeforeSwap(finalDir)
	}
	// 4. Swap. The live dir is renamed to <id>.previous and kept there
	//    until the new dir verifies (exact manifest, pinned binary sha,
	//    carried state); on any failure the previous install is restored.
	previousDir, err := swapInAppDir(finalDir, stagingDir, func(dir string) error {
		return verifyInstalledApp(dir, raw, m, carried)
	})
	if err != nil {
		fatalHint("io_error", "check install root permissions and re-run; see the error for the state of the previous install", "%v", err)
	}
	// 5. Reconcile: bring into the new install what the still-running old
	//    process changed in the old dir since the carry, and move across the
	//    entries that could not be linked (appstore_state.go, step 5).
	var reconciled stateReconcile
	if previousDir != "" && carry != nil {
		reconciled = reconcileAppState(previousDir, finalDir, oldBinary, carry)
		carried = mergeSortedUnique(carried, reconciled.Updated)
		if len(reconciled.Removed) > 0 {
			fmt.Fprintf(os.Stderr, "note: dropped %d stale file(s) the running app deleted during the upgrade: %s\n",
				len(reconciled.Removed), summarizePaths(reconciled.Removed, 4))
		}
	}
	// 6. Retire the replaced install out of the install root, where the
	//    supervisor would otherwise adopt it. Kept as a backup; retention
	//    never removes one that holds the only copy of something.
	backupDir, backupWarning := "", ""
	if previousDir != "" {
		kind := replacedInstallBackupKind(resetState, reconciled.Leftover, oldVersion, m.AppVersion)
		backupDir, err = retireAppDir(previousDir, m.ID, appBackupMeta{
			Kind:        kind,
			FromVersion: oldVersion,
			ToVersion:   m.AppVersion,
			NotCarried:  reconciled.Leftover,
		})
		if err != nil {
			backupWarning = err.Error()
			fmt.Fprintf(os.Stderr, "warn: %v\n", err)
		}
	}
	if len(reconciled.Leftover) > 0 {
		fmt.Fprintf(os.Stderr, "warn: %d entr(ies) of %s's state could not be carried into the new install and are only in the backup %s (never removed automatically): %s. Copy what the app needs back into %s.\n",
			len(reconciled.Leftover), m.ID, backupDir, summarizePaths(reconciled.Leftover, 6), finalDir)
	}

	// Drop a forensic line into the supervisor's audit log so the
	// install moment is recoverable post-hoc. Without this, the
	// only timestamp for "when did this app land?" is the
	// supervisor's first supervise-start, which happens later (up
	// to RescanInterval) and doesn't record who ran the command.
	// Best-effort: a log-write failure is reported as a warning,
	// not fatal — the install itself already succeeded on disk.
	writeInstallAudit(finalDir, m.ID, m.AppVersion, m.Binary.SHA256, bundleDir, force)

	// Cache the app's next-steps graph out of the sha-verified catalogue
	// metadata, so every later `appstore call` can render its hints from a
	// local file instead of reaching for the network on the hot path. Wholly
	// best-effort: a sideload, an app with no graph, or an unreachable
	// catalogue simply means no hints — never a failed install.
	cacheNextSteps(finalDir, fetchNextStepsForInstall(m.ID))

	// Record the catalogue bundle sha we just installed so `outdated`/`upgrade`
	// can detect a SAME-VERSION republish — a rebuilt adapter shipped under an
	// unchanged app_version (the aegis argv-fix shape) that a version compare
	// alone silently misses. Catalogue installs only; a sideload has no
	// catalogue bundle to compare against. Best-effort.
	if source == installSourceCatalogue {
		recordInstalledBundleSHA(finalDir, m.ID)
	}

	// Mirror to the install-root-level pilotctl-audit log too, so
	// the install+uninstall lifecycle pair stays reconstructable
	// after the app dir (and its per-app supervisor.log) is gone.
	reason := fmt.Sprintf("actor=%s source=%s", currentActor(), bundleDir)
	if force {
		reason += " --force"
	}
	if replacing {
		if resetState {
			reason += " --reset-state"
		} else {
			reason += fmt.Sprintf(" state_kept=%d", len(carried))
		}
		if len(reconciled.Leftover) > 0 {
			reason += fmt.Sprintf(" state_not_carried=%d", len(reconciled.Leftover))
		}
		if backupDir != "" {
			reason += " backup=" + backupDir
		}
	}
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "installed",
		AppID:  m.ID,
		AppVer: m.AppVersion,
		SHA256: m.Binary.SHA256,
		Reason: reason,
	})
	// Nothing below touches the app dir; let a waiting install of this app
	// go ahead instead of waiting out telemetry and the demo fetch.
	unlock()

	// Emit a telemetry event for the successful install.
	// Consent-gated (telemetry flag, default on). Best-effort: a send
	// failure is logged but not fatal — the install already succeeded on disk.
	{
		home, _ := os.UserHomeDir()
		if consent.GetConsent(home, "telemetry") {
			url := os.Getenv("PILOT_TELEMETRY_URL")
			if url == "" {
				url = telemetry.DefaultEndpoint
			}
			sourceStr := "catalogue"
			if source == installSourceLocal {
				sourceStr = "local"
			}
			payload, _ := json.Marshal(map[string]string{
				"app_id":  m.ID,
				"version": m.AppVersion,
				"source":  sourceStr,
			})
			identityPath := configDir() + "/identity.json"
			client := telemetry.NewClientFromIdentity(url, identityPath, nodeIDFromDaemon())
			err := client.Send(telemetry.Event{
				Kind:    "app_installed",
				TS:      time.Now().UTC().Format(time.RFC3339),
				Payload: payload,
			})
			if err != nil {
				slog.Warn("telemetry send failed, install still successful", "app", m.ID, "err", err)
			}
		}
	}

	report := installReport{
		AppID:           m.ID,
		AppVersion:      m.AppVersion,
		ManifestVersion: m.ManifestVersion,
		InstalledTo:     finalDir,
		BinarySHA256:    m.Binary.SHA256,
		DaemonNotice:    "supervisor periodically rescans the install root; this app will be picked up within ~30s (no daemon restart needed)",
		PreservedState:  carried,
		StateNotCarried: reconciled.Leftover,
		StateReset:      replacing && resetState,
		BackupDir:       backupDir,
		BackupWarning:   backupWarning,
	}
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}
	fmt.Printf("installed %s v%s (manifest v%d) → %s\n",
		report.AppID, report.AppVersion, report.ManifestVersion, report.InstalledTo)
	switch {
	case replacing && resetState:
		fmt.Println("state: RESET — the app starts without its previous state (--reset-state)")
	case replacing && len(carried) > 0:
		fmt.Printf("state: kept %d file(s) from the previous install (%s)\n", len(carried), summarizePaths(carried, 6))
	case replacing:
		fmt.Println("state: the previous install had no app state to keep")
	}
	if backupDir != "" {
		fmt.Printf("backup: the replaced install is kept at %s\n", backupDir)
	}
	if source == installSourceLocal {
		fmt.Println("mode: SIDELOADED — manifest-level allow-list applied (audit.log, fs.read/$APP, fs.write/$APP).")
		fmt.Println("      this is NOT an OS sandbox: a malicious binary that ignores its manifest can still")
		fmt.Println("      misbehave at the syscall level. Only install paths from sources you trust.")
	}
	fmt.Println("note: the daemon rescans the install root periodically —")
	fmt.Println("      this app will be picked up within ~30s (no daemon restart needed)")

	// Last step: if this catalogue app ships a product demo in its
	// sha-verified metadata, print it and drop a SKILL.md so the agent can
	// drive the app right away. Best-effort and additive — no demo, or any
	// failure fetching/rendering it, leaves the install above untouched.
	if source == installSourceCatalogue {
		maybeShowProductDemo(m.ID)
	}
}

// pilotctlAuditFileName is the JSONL log of operator-initiated
// pilotctl actions, sitting at the INSTALL ROOT level (not inside
// any app dir) so it survives uninstall. 0600 — same threat model
// as the per-app supervisor.log.
const pilotctlAuditFileName = ".pilotctl-audit.log"

// pilotctlAuditMaxSize is the size cap for the root-level audit log.
// When reached, the log is rotated to .pilotctl-audit.log.1 (single
// rotation — only one historical file kept). At ~150 B/event this gives
// roughly 700,000 entries before rotation, or decades of heavy use.
const pilotctlAuditMaxSize = 100 * 1024 * 1024 // 100 MiB

// pilotctlAuditEvent is one row of the root-level audit log.
// Operator-side counterpart to the supervisor's auditEvent; lives in
// a different file because the use cases differ — supervisor.log
// tracks the supervised process's lifecycle and dies with the app;
// .pilotctl-audit.log tracks operator commands and persists for
// post-uninstall forensics.
type pilotctlAuditEvent struct {
	At     string `json:"at"`
	Event  string `json:"event"`
	AppID  string `json:"app"`
	AppVer string `json:"app_version,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// currentActor returns the OS user invoking pilotctl, for the audit
// trail. Falls back to "unknown" so the log is still parseable when
// $USER isn't set (test runs, exotic init environments).
func currentActor() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "unknown"
}

// writePilotctlAudit appends a single JSONL line to the install-
// root-level pilotctl audit log. Best-effort: failures land as
// warnings on stderr — the operator's command already succeeded
// on disk; an audit-write failure shouldn't make pilotctl exit
// non-zero and confuse scripting consumers.
func writePilotctlAudit(installRoot string, ev pilotctlAuditEvent) {
	if ev.At == "" {
		ev.At = time.Now().UTC().Format(time.RFC3339Nano)
	}
	body, err := json.Marshal(ev)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit marshal: %v\n", err)
		return
	}
	body = append(body, '\n')
	path := filepath.Join(installRoot, pilotctlAuditFileName)

	// Rotate if the log exceeds the size cap. Single-rotation model:
	// .pilotctl-audit.log → .pilotctl-audit.log.1, then start fresh.
	// Best-effort — rotation failure doesn't block the audit write.
	// Matches the supervisor.log.1 pattern so readers that already
	// handle supervisor.log rotation can consume this with no changes.
	if fi, err := os.Stat(path); err == nil && fi.Size() >= pilotctlAuditMaxSize {
		rotatedPath := path + ".1"
		if err := os.Rename(path, rotatedPath); err != nil {
			fmt.Fprintf(os.Stderr, "warn: pilotctl audit rotate %s → %s: %v\n",
				path, rotatedPath, err)
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "warn: pilotctl audit write %s: %v\n", path, err)
	}
}

// writeInstallAudit appends a single JSONL line to the supervisor's
// audit log marking the install moment. Mirrors the supervisor's own
// auditEvent shape so `pilotctl appstore audit` reads the line back
// without special handling. 0600 matches the supervisor's audit-log
// perms (see plugin/appstore/supervisor.go:writeAuditLine).
//
// Fields populated:
//   - at:    RFC3339Nano of the install moment
//   - app:   manifest id
//   - event: "installed"
//   - sha256: pinned binary hash (same field the supervisor stamps on spawn)
//   - reason: bundle source path + actor + --force flag — operator + provenance
//     trail in case forensics need to chase "where did this come from?"
func writeInstallAudit(appDir, appID, appVer, binSHA, bundleSrc string, forced bool) {
	actor := os.Getenv("USER")
	if actor == "" {
		actor = "unknown"
	}
	reason := fmt.Sprintf("actor=%s source=%s app_version=%s", actor, bundleSrc, appVer)
	if forced {
		reason += " --force"
	}
	line := map[string]any{
		"at":     time.Now().UTC().Format(time.RFC3339Nano),
		"app":    appID,
		"event":  "installed",
		"sha256": binSHA,
		"reason": reason,
	}
	body, err := json.Marshal(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit marshal: %v\n", err)
		return
	}
	body = append(body, '\n')
	path := filepath.Join(appDir, "supervisor.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit open %s: %v\n", path, err)
		return
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		fmt.Fprintf(os.Stderr, "warn: install audit write %s: %v\n", path, err)
	}
}

// copyFile writes src's bytes to dst with the given mode. Uses an
// O_TRUNC|O_CREATE open so a partial previous file is replaced; the
// destination perm is set explicitly because umask can strip bits
// from the OpenFile mode argument.
func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, perm)
}

// ── restart ────────────────────────────────────────────────────────────

// cmdAppStoreRestart drops a `.resume` sentinel file into the app's
// install dir. The daemon's supervisor rescan picks it up on its next
// tick (≤30s default), clears the crash-loop record, removes the
// marker, and relaunches the supervise goroutine.
//
// Sentinel-file design: pilotctl can't talk to the supervisor
// directly (it dials individual app sockets, not the daemon), so a
// well-known file in the app dir is the lowest-friction signaling
// surface. Idempotent: writing it twice before the supervisor sees
// it collapses to one resume, which is what the user wants.
func cmdAppStoreRestart(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore restart <app-id>",
			"missing app id")
	}
	appID := args[0]
	root := appStoreRoot()
	dir := filepath.Join(root, appID)
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", root),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions",
			"stat %s: %v", dir, err)
	}
	markerPath := filepath.Join(dir, ".resume")
	if err := os.WriteFile(markerPath, []byte{}, 0o644); err != nil {
		fatalHint("io_error",
			"check install root permissions",
			"write %s: %v", markerPath, err)
	}

	// Audit the operator-initiated restart so forensics can answer
	// "when was crash-loop suspension cleared, and by whom?"
	// Lands in the durable install-root log alongside install/uninstall.
	writePilotctlAudit(root, pilotctlAuditEvent{
		Event:  "restart-requested",
		AppID:  appID,
		Reason: fmt.Sprintf("actor=%s marker=%s", currentActor(), markerPath),
	})

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"id":            appID,
			"marker_path":   markerPath,
			"daemon_notice": "supervisor's next rescan (≤30s) will consume this marker and respawn the app",
		})
		return
	}
	fmt.Printf("resume marker written: %s\n", markerPath)
	fmt.Println("note: the daemon's supervisor will consume this on its next rescan (≤30s) —")
	fmt.Println("      crash-loop record clears, app respawns; check progress with `pilotctl appstore audit`")
}

// ── caps ──────────────────────────────────────────────────────────────

// capUsageReport is one row in the --json output of `appstore caps`.
type capUsageReport struct {
	Asset          string `json:"asset"`
	Target         string `json:"target,omitempty"` // sign-purpose: distinguishes multiple caps with identical (asset,limit,window) for different surfaces
	Limit          uint64 `json:"limit"`
	WindowString   string `json:"window"`     // human-readable, e.g. "24h"
	WindowSec      int64  `json:"window_sec"` // raw seconds, for scripts that compute resets
	Used           uint64 `json:"used"`
	Remaining      int64  `json:"remaining"`                   // limit - used, can be negative if over (shouldn't happen — Pay refuses)
	Records        int    `json:"records"`                     // count of spend-log entries inside the window
	OldestInWindow string `json:"oldest_in_window,omitempty"`  // RFC3339Nano of the oldest in-window spend, "" if no spends
	NextResetIn    string `json:"next_reset_in,omitempty"`     // human duration until the oldest entry drops out
	NextResetInSec int64  `json:"next_reset_in_sec,omitempty"` // raw seconds for the same
}

// cmdAppStoreCaps reports the current rolling-window spend usage for
// each cap the app's manifest declares. Reads the manifest's grants
// block to discover caps, then reads cap-state.jsonl (the wallet's
// persistent spend log) to sum the in-window total per asset. Both
// files are read directly off disk — no IPC, no live wallet needed.
func cmdAppStoreCaps(args []string) {
	if len(args) < 1 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore caps <app-id>",
			"missing app id")
	}
	appID := args[0]
	// appID is user input; confine it to a single entry under the app
	// store root so a crafted id (e.g. "../../etc") can't read or open
	// files outside the install tree.
	appDir, err := resolveUnder(appStoreRoot(), appID)
	if err != nil {
		fatalHint("invalid_argument",
			"app ids are single directory names; try `pilotctl appstore list`",
			"invalid app id %q: %v", appID, err)
	}

	mfRaw, err := os.ReadFile(filepath.Join(appDir, "manifest.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fatalHint("invalid_argument",
				fmt.Sprintf("try `pilotctl appstore list` to see what's installed under %s", appStoreRoot()),
				"app %q not installed", appID)
		}
		fatalHint("io_error", "check install root permissions", "read manifest: %v", err)
	}
	m, err := manifest.Parse(mfRaw)
	if err != nil {
		fatalHint("internal_error",
			"the pinned manifest is corrupt; reinstall the app",
			"parse manifest: %v", err)
	}

	caps := parseCapsFromGrants(m.Grants)

	// Derive HMAC key from daemon identity for cap-state integrity.
	// Falls back to nil (no verification) if identity is unavailable.
	hmacKey := loadCapStateHMACKey()
	records, err := loadCapStateRecordsAnchored(filepath.Join(appDir, "cap-state.jsonl"), hmacKey)
	if err != nil {
		// Fail closed: a tampered or corrupt spend log must surface as
		// an error, not be papered over with an under-reported usage
		// figure that makes an erased cap look healthy.
		fatalHint("integrity_error",
			"the wallet's cap-state spend log failed its integrity check; do not trust reported usage. Inspect cap-state.jsonl and, if the wallet's identity is intact, let the wallet rewrite it.",
			"cap-state: %v", err)
	}

	now := time.Now()
	reports := make([]capUsageReport, 0, len(caps))
	for _, c := range caps {
		cutoff := now.Add(-c.window)
		var used uint64
		var count int
		var oldest time.Time
		for _, r := range records {
			if r.asset != c.asset {
				continue
			}
			if r.at.Before(cutoff) {
				continue
			}
			used += r.amount
			count++
			if oldest.IsZero() || r.at.Before(oldest) {
				oldest = r.at
			}
		}
		report := capUsageReport{
			Asset:        c.asset,
			Target:       c.target,
			Limit:        c.limit,
			WindowString: humanDuration(c.window),
			WindowSec:    int64(c.window.Seconds()),
			Used:         used,
			Remaining:    int64(c.limit) - int64(used),
			Records:      count,
		}
		if !oldest.IsZero() {
			report.OldestInWindow = oldest.Format(time.RFC3339Nano)
			// When `oldest + window` arrives, that spend record falls
			// out of the rolling sum and headroom returns by its amount.
			// "First drop in" is what an operator wants to plan around.
			remaining := oldest.Add(c.window).Sub(now)
			if remaining < 0 {
				remaining = 0
			}
			report.NextResetIn = humanDuration(remaining)
			report.NextResetInSec = int64(remaining.Seconds())
		}
		reports = append(reports, report)
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(reports)
		return
	}
	if len(reports) == 0 {
		fmt.Printf("no spend caps declared for %s — manifest's grants block has no key.sign cap conditions\n", appID)
		return
	}
	fmt.Printf("spend caps for %s:\n\n", appID)
	for _, r := range reports {
		label := r.Asset
		if r.Target != "" {
			label = fmt.Sprintf("%s [%s]", r.Asset, r.Target)
		}
		fmt.Printf("  %s: %d / %d used in last %s",
			label, r.Used, r.Limit, r.WindowString)
		if r.Remaining < 0 {
			fmt.Printf(" (%d OVER — wallet should be refusing further spends)\n", -r.Remaining)
		} else {
			fmt.Printf(" (%d remaining, %d records)\n", r.Remaining, r.Records)
			if r.NextResetIn != "" && r.NextResetInSec > 0 {
				fmt.Printf("    first drop in %s — headroom returns when the oldest in-window spend ages out\n", r.NextResetIn)
			}
		}
	}
}

// validationErrSummary joins a slice of validation errors into one
// human-readable string. Manifest.Validate returns []error rather
// than a single error; we surface the first one verbatim and tag
// "(+N more)" if there are siblings — same shape the supervisor
// uses for its skip-on-invalid log line, so output stays consistent
// between install-time and scan-time messaging.
func validationErrSummary(errs []error) string {
	if len(errs) == 0 {
		return "(no errors)"
	}
	first := errs[0].Error()
	if len(errs) == 1 {
		return first
	}
	return fmt.Sprintf("%s (+%d more)", first, len(errs)-1)
}

// humanDuration formats a Duration cleanly: "24h", "1h30m", "10m",
// "45s". Go's Duration.String() emits "24h0m0s" which is fine for
// machines but noisy for humans — drop any trailing zero components.
// Sub-second durations stay as "Xms" / "Xµs" via the stdlib default.
//
// The previous implementation used strings.TrimSuffix(s, "0m") which
// over-stripped: "1h30m0s" → "1h30m" → "1h3" and "10m0s" → "10m" → "1".
// We now decompose the duration into h/m/s components and emit only the
// non-zero ones (e.g. "1h30m0s" → "1h30m", "10m0s" → "10m",
// "2h5m30s" → "2h5m30s", "1h0m0s" → "1h").
func humanDuration(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	// Sub-second durations (e.g. test fixtures with 100ms intervals)
	// keep their precision via the stdlib default — the h/m/s
	// decomposition below has nothing to render.
	if d < time.Second {
		return d.String()
	}
	// Round to whole seconds for anything ≥1s so we don't render
	// "23h29m58.948334s".
	d = d.Round(time.Second)

	hours := int64(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int64(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int64(d / time.Second)

	var b strings.Builder
	if hours > 0 {
		fmt.Fprintf(&b, "%dh", hours)
	}
	if minutes > 0 {
		fmt.Fprintf(&b, "%dm", minutes)
	}
	if seconds > 0 {
		fmt.Fprintf(&b, "%ds", seconds)
	}
	if b.Len() == 0 {
		// d rounded to zero — shouldn't happen given d ≥ 1s above,
		// but fall back to the stdlib default for safety.
		return d.String()
	}
	return b.String()
}

// capDecl is the local pilotctl-side projection of a manifest cap.
// Mirrors wallet.SpendCap but lives here to avoid cross-repo
// dependency (the wallet sits in a different module).
type capDecl struct {
	asset  string
	limit  uint64
	window time.Duration
	target string // the manifest grant's `target` field (sign-purpose), e.g. "x402-auth" / "evm-eip3009"
}

// parseCapsFromGrants extracts cap-style grants from a manifest. Same
// shape as wallet.ParseSpendCapsFromManifest, duplicated locally so
// pilotctl doesn't pull a wallet-pkg dep just to render usage rows.
// Skip-on-malformed: a corrupt entry never refuses the whole report.
func parseCapsFromGrants(grants []manifest.Grant) []capDecl {
	var out []capDecl
	for _, g := range grants {
		if g.Cap != "key.sign" || g.Condition == nil || g.Condition.Kind != "cap" {
			continue
		}
		asset, _ := g.Condition.Params["asset"].(string)
		per, _ := g.Condition.Params["per"].(string)
		rawLimit, _ := g.Condition.Params["limit"].(float64)
		if asset == "" || rawLimit <= 0 {
			continue
		}
		var window time.Duration
		switch per {
		case "min", "minute":
			window = time.Minute
		case "hour":
			window = time.Hour
		case "day":
			window = 24 * time.Hour
		default:
			continue
		}
		out = append(out, capDecl{asset: asset, limit: uint64(rawLimit), window: window, target: g.Target})
	}
	return out
}

// deriveCapStateHMACKey derives a 32-byte HMAC-SHA256 key from the
// daemon's Ed25519 identity private key using HKDF with
// info="pilot-cap-state-v1". Returns nil if privKey is empty.
func deriveCapStateHMACKey(privKey ed25519.PrivateKey) []byte {
	if len(privKey) == 0 {
		return nil
	}
	// HKDF-Extract: PRK = HMAC-SHA256(salt=nil, IKM=privateKey)
	mac := hmac.New(sha256.New, nil)
	mac.Write(privKey)
	prk := mac.Sum(nil)
	// HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)
	mac = hmac.New(sha256.New, prk)
	mac.Write([]byte("pilot-cap-state-v1"))
	mac.Write([]byte{0x01})
	return mac.Sum(nil)
}

// loadCapStateHMACKey loads the daemon identity from ~/.pilot/identity.json
// and derives the cap-state HMAC key. Returns nil if unavailable.
func loadCapStateHMACKey() []byte {
	identityPath := configDir() + "/identity.json"
	id, err := crypto.LoadIdentity(identityPath)
	if err != nil || id == nil {
		return nil
	}
	return deriveCapStateHMACKey(id.PrivateKey)
}

// capStateJSON is the on-disk JSON format for one cap-state.jsonl line.
type capStateJSON struct {
	At     time.Time `json:"at"`
	Asset  string    `json:"asset"`
	Amount uint64    `json:"amount"`
	HMAC   string    `json:"hmac,omitempty"` // base64 HMAC-SHA256 (chained)
}

// capStateJSONNoHMAC is the canonical form for HMAC computation.
type capStateJSONNoHMAC struct {
	At     time.Time `json:"at"`
	Asset  string    `json:"asset"`
	Amount uint64    `json:"amount"`
}

// capStateRecord is the local pilotctl-side projection of one
// cap-state.jsonl line. hmacOK is true when HMAC verified or absent.
// chain holds this record's decoded chained HMAC, or nil when the
// record carries no HMAC (or no key was supplied).
type capStateRecord struct {
	at     time.Time
	asset  string
	amount uint64
	hmacOK bool
	chain  []byte
}

// loadCapStateRecords reads the wallet's persistent spend log, failing
// closed on any sign of corruption or tampering rather than silently
// dropping records (which would under-report usage and make a tampered
// or partially-erased cap look healthy).
//
// Behaviour:
//   - a missing file is normal first-run state: returns (nil, nil);
//   - a malformed JSON line is always an error — never silently skipped;
//   - when hmacKey is non-nil and a line carries an "hmac" field, the
//     chained HMAC-SHA256 must verify, else it's a tamper signal (error);
//   - a file that mixes authenticated and unauthenticated records (only
//     reachable by tampering with a signed chain) is rejected;
//   - a wholly-unauthenticated (legacy) file is accepted for read-only
//     reporting even when a key is available — the wallet migrates it to
//     an authenticated chain on its next write.
func loadCapStateRecords(path string, hmacKey []byte) ([]capStateRecord, error) {
	// #nosec G304 -- path is appDir/cap-state.jsonl where appDir is confined to the app store root by resolveUnder in the sole production caller
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []capStateRecord
	var prevHMAC []byte
	sawHMAC, sawPlain := false, false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		// Parse the full JSON line including optional HMAC.
		var line capStateJSON
		if err := json.Unmarshal(raw, &line); err != nil {
			// Fail closed: a garbage line is corruption or tampering,
			// not something to drop on the floor.
			return nil, fmt.Errorf("malformed cap-state line %d in %s: %w", lineNo, path, err)
		}

		if line.HMAC != "" {
			sawHMAC = true
		} else {
			sawPlain = true
		}

		rec := capStateRecord{at: line.At, asset: line.Asset, amount: line.Amount, hmacOK: line.HMAC == ""}

		// HMAC verification — only when key is available AND this line
		// carries an HMAC field (post-migration or wallet-written).
		if hmacKey != nil && line.HMAC != "" {
			canonical, _ := json.Marshal(capStateJSONNoHMAC{
				At: line.At, Asset: line.Asset, Amount: line.Amount,
			})

			mac := hmac.New(sha256.New, hmacKey)
			mac.Write(canonical)
			mac.Write(prevHMAC)
			expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(expected), []byte(line.HMAC)) {
				return nil, fmt.Errorf("cap-state line %d in %s: HMAC mismatch — spend log tampered with or truncated", lineNo, path)
			}
			rec.hmacOK = true
			prevHMAC, _ = base64.StdEncoding.DecodeString(line.HMAC)
			rec.chain = prevHMAC
		}

		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// A signed chain with an unauthenticated record spliced in can only
	// arise from tampering. Reject (only meaningful when we have a key).
	if hmacKey != nil && sawHMAC && sawPlain {
		return nil, fmt.Errorf("cap-state %s mixes authenticated and unauthenticated records — refusing (possible tampering)", path)
	}
	return out, nil
}

// capStateAnchorSuffix is appended to the cap-state path to name the
// sidecar anchor file that sits beside it.
const capStateAnchorSuffix = ".anchor"

// capStateAnchorEnv, when set to a truthy value, makes a missing anchor
// beside an authenticated chain an error instead of something to adopt.
// Default (unset) is adopt-on-first-sight.
const capStateAnchorEnv = "PILOT_CAP_STATE_STRICT_ANCHOR"

// capStateAnchor is the sidecar record of how far the authenticated
// cap-state chain had advanced the last time it was read: how many
// chained records there were and the chain value of the last of them.
// MAC binds those two fields together under the same key the chain
// itself uses, so the anchor cannot be rewritten without the key.
type capStateAnchor struct {
	Version int    `json:"v"`
	Count   int    `json:"count"`
	Tail    string `json:"tail"`
	MAC     string `json:"mac"`
}

// capStateAnchorMAC computes the keyed MAC over an anchor's fields.
func capStateAnchorMAC(key []byte, version, count int, tail string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("pilot-cap-state-anchor-v1"))
	fmt.Fprintf(mac, "|%d|%d|%s", version, count, tail)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// capStateAnchorPath names the sidecar anchor for a cap-state file.
func capStateAnchorPath(path string) string { return path + capStateAnchorSuffix }

// capStateStrictAnchor reports whether the strict-anchor flag is set.
func capStateStrictAnchor() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(capStateAnchorEnv))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// loadCapStateAnchor reads the sidecar anchor. A missing file is normal
// first-run state and returns (nil, nil). A file that is unparseable,
// of an unknown version, or whose MAC does not verify is an error.
func loadCapStateAnchor(path string, key []byte) (*capStateAnchor, error) {
	// #nosec G304 -- derived from the cap-state path, which the sole production caller confines to the app store root
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var a capStateAnchor
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("malformed cap-state anchor %s: %w", path, err)
	}
	if a.Version != 1 {
		return nil, fmt.Errorf("cap-state anchor %s: unsupported version %d", path, a.Version)
	}
	want := capStateAnchorMAC(key, a.Version, a.Count, a.Tail)
	if !hmac.Equal([]byte(want), []byte(a.MAC)) {
		return nil, fmt.Errorf("cap-state anchor %s: MAC mismatch", path)
	}
	return &a, nil
}

// writeCapStateAnchor writes the sidecar anchor atomically.
func writeCapStateAnchor(path string, key []byte, count int, tail string) error {
	blob, err := json.Marshal(capStateAnchor{
		Version: 1, Count: count, Tail: tail,
		MAC: capStateAnchorMAC(key, 1, count, tail),
	})
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// loadCapStateRecordsAnchored loads the spend log and cross-checks it
// against the sidecar anchor left by the previous read.
//
// The per-record chain only commits to the records that precede each
// record, so any prefix of a valid chain is itself a valid chain: a log
// rewound to an earlier prefix verifies line by line and simply reports
// less usage. The anchor closes that by committing separately to the
// record count and to the final chain value, so a shorter or diverging
// log is rejected instead of accepted.
//
// Behaviour:
//   - with no key, or with no authenticated records, the anchor is not
//     consulted and records are returned as-is (legacy files keep working);
//   - an authenticated chain with no anchor beside it is accepted and an
//     anchor is written for it, unless PILOT_CAP_STATE_STRICT_ANCHOR is
//     set (default unset), in which case it is an error;
//   - fewer authenticated records than the anchor recorded is an error;
//   - a record at the anchored position whose chain value differs from
//     the anchored one is an error;
//   - a strictly longer chain that still matches at the anchored
//     position advances the anchor.
//
// Anchor writes are best-effort: a read-only install tree degrades to
// the previous behaviour rather than failing the command.
func loadCapStateRecordsAnchored(path string, hmacKey []byte) ([]capStateRecord, error) {
	records, err := loadCapStateRecords(path, hmacKey)
	if err != nil {
		return nil, err
	}
	if hmacKey == nil {
		return records, nil
	}

	// Measure the authenticated prefix and remember its chain value.
	count, tail := 0, ""
	for _, r := range records {
		if len(r.chain) == 0 {
			break
		}
		count++
		tail = base64.StdEncoding.EncodeToString(r.chain)
	}

	anchorPath := capStateAnchorPath(path)
	anchor, err := loadCapStateAnchor(anchorPath, hmacKey)
	if err != nil {
		return nil, err
	}

	if count == 0 {
		// Nothing authenticated to anchor to: legacy or empty log. An
		// anchor that recorded records is still a mismatch.
		if anchor != nil && anchor.Count > 0 {
			return nil, fmt.Errorf("cap-state %s: anchor records %d authenticated entries, none present now", path, anchor.Count)
		}
		return records, nil
	}

	if anchor == nil {
		if capStateStrictAnchor() {
			return nil, fmt.Errorf("cap-state %s: no anchor beside an authenticated chain (%s is set)", path, capStateAnchorEnv)
		}
		_ = writeCapStateAnchor(anchorPath, hmacKey, count, tail)
		return records, nil
	}

	if count < anchor.Count {
		return nil, fmt.Errorf("cap-state %s: %d authenticated records present, anchor records %d — entries removed", path, count, anchor.Count)
	}
	if anchor.Count > 0 {
		at := base64.StdEncoding.EncodeToString(records[anchor.Count-1].chain)
		if !hmac.Equal([]byte(at), []byte(anchor.Tail)) {
			return nil, fmt.Errorf("cap-state %s: record %d does not match the anchored chain value — log rewritten", path, anchor.Count)
		}
	}
	if count > anchor.Count {
		_ = writeCapStateAnchor(anchorPath, hmacKey, count, tail)
	}
	return records, nil
}

// ── actions ────────────────────────────────────────────────────────────

// cmdAppStoreActions reads the root-level pilotctl-audit log written
// by install/uninstall (ticks 49/50). Unlike `appstore audit <id>`
// which reads a per-app file that dies with the app, this log lives
// at the install-root level and survives uninstall — the right place
// for post-uninstall forensics.
func cmdAppStoreActions(args []string) {
	tail := 0
	eventFilter := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--tail", "-n":
			if i+1 >= len(args) {
				fatalHint("invalid_argument", "--tail expects an integer count", "missing tail count")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 0 {
				fatalHint("invalid_argument", "--tail expects a non-negative integer", "parse tail %q: %v", args[i+1], err)
			}
			tail = n
			i++
		case "--event", "-e":
			if i+1 >= len(args) {
				fatalHint("invalid_argument", "--event expects an event name (installed, uninstalled)", "missing event name")
			}
			eventFilter = args[i+1]
			i++
		default:
			fatalHint("invalid_argument", "available flags: --tail N, --event NAME", "unknown actions flag: %s", args[i])
		}
	}

	logPath := filepath.Join(appStoreRoot(), pilotctlAuditFileName)
	f, err := os.Open(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if jsonOutput {
				_ = json.NewEncoder(os.Stdout).Encode([]pilotctlAuditEvent{})
				return
			}
			fmt.Printf("no pilotctl actions logged yet at %s\n", logPath)
			return
		}
		fatalHint("io_error", "check install root permissions", "open %s: %v", logPath, err)
	}
	defer f.Close()

	var lines []pilotctlAuditEvent
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var ev pilotctlAuditEvent
		if err := json.Unmarshal(raw, &ev); err != nil {
			// Skip malformed lines — same forgiving shape as audit.
			continue
		}
		lines = append(lines, ev)
	}
	if err := scanner.Err(); err != nil {
		fatalHint("io_error", "the log file may be corrupt; try `cat` to inspect raw bytes",
			"scan %s: %v", logPath, err)
	}

	if eventFilter != "" {
		filtered := lines[:0]
		for _, ev := range lines {
			if ev.Event == eventFilter {
				filtered = append(filtered, ev)
			}
		}
		lines = filtered
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(lines)
		return
	}
	if len(lines) == 0 {
		if eventFilter != "" {
			fmt.Printf("no %q actions in %s\n", eventFilter, logPath)
		} else {
			fmt.Printf("action log %s is empty\n", logPath)
		}
		return
	}
	header := fmt.Sprintf("pilotctl action log: %s (%d events shown", logPath, len(lines))
	if eventFilter != "" {
		header += fmt.Sprintf(", filtered to event=%q", eventFilter)
	}
	header += ")"
	fmt.Println(header)
	fmt.Println()
	for _, ev := range lines {
		// Event column wide enough for the longest current event
		// name ("restart-requested" — 17 chars) with one space pad.
		fmt.Printf("  %s  %-18s app=%-30s", ev.At, ev.Event, ev.AppID)
		if ev.SHA256 != "" {
			fmt.Printf(" sha256=%s", shortHex(ev.SHA256))
		}
		if ev.AppVer != "" {
			fmt.Printf(" v=%s", ev.AppVer)
		}
		if ev.Reason != "" {
			fmt.Printf(" reason=%q", ev.Reason)
		}
		fmt.Println()
	}
}

// ── call ───────────────────────────────────────────────────────────────

// callTimeoutDefault bounds how long `appstore call` waits for an app's reply.
// It must comfortably exceed the slowest legitimate method (e.g. multi-step
// research / cold LLM synthesis), which can run tens of seconds. Override per
// call with --timeout, or globally with $PILOT_APPSTORE_CALL_TIMEOUT.
const callTimeoutDefault = 120 * time.Second

// reviewPromptRand is the randomness source for the review-prompt feature.
// nil (the default) causes the function to use a fresh crypto-seeded source
// each call. Tests set this to a deterministic source for reproducibility.
var reviewPromptRand *rand.Rand

// reviewPromptProbability is the chance (0.0–1.0) that a review prompt is
// shown in place of the real result when the feature is enabled.
const reviewPromptProbability = 0.05 // ~5%

// reviewPromptText returns the review prompt message for the given app ID.
func reviewPromptText(appID string) string {
	return fmt.Sprintf("consider leaving a review for %s", appID)
}

// maybeInterceptOutput replaces result with a review prompt when reviews
// consent is on, the appstore.review_prompt feature flag is on, and the
// random roll hits.
func maybeInterceptOutput(result []byte, appID string) ([]byte, bool) {
	home, _ := os.UserHomeDir()
	if !consent.GetConsent(home, "reviews") {
		return result, false
	}
	if !featureEnabled("appstore.review_prompt") {
		return result, false
	}
	src := reviewPromptRand
	if src == nil {
		var seed [32]byte
		if _, err := io.ReadFull(cryptorand.Reader, seed[:]); err != nil {
			return result, false
		}
		src = rand.New(rand.NewChaCha8(seed))
	}
	if src.Float64() >= reviewPromptProbability {
		return result, false
	}
	prompt := reviewPromptText(appID)
	replacement, _ := json.Marshal(prompt)
	return replacement, true
}

func cmdAppStoreCall(args []string) {
	// Resolve the reply timeout (env default, then --timeout flag) and strip
	// the flag from the positional args so <app-id> <method> [json] still parse.
	callTimeout := callTimeoutDefault
	if v := os.Getenv("PILOT_APPSTORE_CALL_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			callTimeout = d
		}
	}
	var pos []string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--timeout" && i+1 < len(args):
			if d, err := time.ParseDuration(args[i+1]); err == nil && d > 0 {
				callTimeout = d
			}
			i++
		case strings.HasPrefix(args[i], "--timeout="):
			if d, err := time.ParseDuration(strings.TrimPrefix(args[i], "--timeout=")); err == nil && d > 0 {
				callTimeout = d
			}
		default:
			pos = append(pos, args[i])
		}
	}
	args = pos
	if len(args) < 2 {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore call <app-id> <method> [json-args] [--timeout 2m]",
			"missing arguments")
	}
	appID := args[0]
	method := args[1]
	var argsJSON []byte
	if len(args) >= 3 {
		argsJSON = []byte(args[2])
		var tmp any
		if err := json.Unmarshal(argsJSON, &tmp); err != nil {
			fatalHint("invalid_argument",
				"json-args must be a valid JSON value",
				"parse json-args: %v", err)
		}
	}

	sockPath := filepath.Join(appStoreRoot(), appID, "app.sock")
	if _, err := os.Stat(sockPath); err != nil {
		// Not installed here at all: if the id is a rename tombstone, say so
		// instead of blaming the daemon. No silent retarget: the method
		// namespace changed too. (An installed app whose daemon is down skips
		// the catalogue fetch.)
		if _, derr := os.Stat(filepath.Dir(sockPath)); errors.Is(derr, os.ErrNotExist) {
			if c, lerr := loadCatalogue(); lerr == nil {
				if e := c.findEntry(appID); e != nil && e.RenamedTo != "" {
					fatalHint("invalid_argument",
						fmt.Sprintf("install it with `pilotctl appstore install %s` and call its methods (`pilotctl appstore view %s`)", e.RenamedTo, e.RenamedTo),
						"app %q was renamed to %q", appID, e.RenamedTo)
				}
			}
		}
		fatalHint("io_error",
			"is the daemon running and has it supervised this app yet?",
			"socket %s not present: %v", sockPath, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sockPath)
	if err != nil {
		fatalHint("network_error",
			"the app may have crashed; try `pilotctl appstore list` to check state",
			"dial %s: %v", sockPath, err)
	}
	defer conn.Close()
	// Reply deadline (not the dial): bounds the whole call so a slow method
	// (research, cold LLM) isn't cut off. Tune with --timeout / env.
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	// args is a JSON value, but ipc.Call takes a Go value. Marshal it
	// back into a json.RawMessage so the wrapper round-trips cleanly.
	var argsValue any
	if len(argsJSON) > 0 {
		if err := json.Unmarshal(argsJSON, &argsValue); err != nil {
			fatalHint("invalid_argument", "json-args must be valid JSON", "%v", err)
		}
	}
	// Lazily self-heal the cached graph before the call so it is current for
	// whichever outcome renders — this is what lets an app installed before its
	// graph existed (or a republished graph) reach the fleet without a manual
	// reinstall. Off the render path, bounded, best-effort: steady state is a
	// single stat and returns instantly (see ensureNextStepsFresh).
	ensureNextStepsFresh(appID)

	var result json.RawMessage
	if err := ipc.Call(conn, method, argsValue, &result); err != nil {
		hint := fmt.Sprintf("the app %q rejected or could not handle %q", appID, method)
		// "method not found" almost always means a typo or a stale call —
		// surface the exposed methods so the user can correct it without
		// having to `pilotctl appstore status` first.
		if strings.Contains(err.Error(), "method not found") {
			if methods := exposedMethods(appID); len(methods) > 0 {
				hint = fmt.Sprintf("app %q exposes: %v", appID, methods)
			}
		}
		// A FAILED call is the highest-value moment to say what to do next:
		// this is where an agent otherwise gives up on the app for good. The
		// graph turns the app's own error into the fix — 402 into "top up",
		// 401 into "signup first", a missing param into the schema. Handed to
		// fatalHint (rather than printed here) so the steps land AFTER the
		// error text they resolve; fatalHint owns the exit.
		exitNextSteps = renderNextSteps(appID, method, false, err.Error())
		fatalHint("ipc_error", hint, "%v", err)
	}

	// A SUCCESSFUL call is where an app is won or lost: the agent has a result
	// and no idea the flow continues. Resolve the graph now and print it via
	// defer so it lands after the result on every return path below — and,
	// crucially, on stderr, so stdout stays the pure JSON that agents pipe to jq.
	//
	// The RESULT BODY is the match payload, not just the outcome: a soft-failed
	// gateway ({"needs_signup":true, exit 0}) is indistinguishable from a real
	// result without reading it, and that case — "sign up before anything
	// works" — is the one an agent most needs told.
	//
	// Resolved BEFORE maybeInterceptOutput deliberately: the review prompt
	// replaces the result wholesale, and matching a graph against
	// "consider leaving a review for ..." would silently drop the real hint on
	// whatever fraction of calls the prompt rolls.
	edge := renderNextSteps(appID, method, true, string(result))

	// Maybe replace the real result with a review prompt (gated by
	// appstore.review_prompt feature flag + random roll).
	replaced, intercepted := maybeInterceptOutput(result, appID)
	if intercepted {
		result = replaced
	}

	if edge != nil {
		defer func() {
			if jsonOutput {
				// In --json mode the caller is parsing, not reading: give it
				// structured steps on stderr rather than prose to re-parse.
				if env := nextStepsEnvelope(edge); env != nil {
					if b, err := json.Marshal(env); err == nil {
						fmt.Fprintln(os.Stderr, string(b))
					}
				}
				return
			}
			printNextSteps(edge)
		}()
	}

	if jsonOutput {
		_, _ = os.Stdout.Write(result)
		_, _ = os.Stdout.Write([]byte("\n"))
		return
	}
	// Pretty-print non-JSON-flag output.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, result, "", "  "); err != nil {
		_, _ = os.Stdout.Write(result)
		fmt.Println()
		return
	}
	_, _ = pretty.WriteTo(os.Stdout)
	fmt.Println()
}
