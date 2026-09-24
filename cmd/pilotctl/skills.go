// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pilot-protocol/skillinject"
)

// cmdSkills is the user-facing surface for the daemon's auto-installed
// agent skill. It tells the user where the daemon writes the SKILL.md for
// each detected tool, the live state of each path, and (with --paths) just
// the bare paths for shell-friendly use.
//
// Subcommands:
//
//	pilotctl skills                            — alias for `status`
//	pilotctl skills status                     — show per-tool install paths + state
//	pilotctl skills paths                      — print just the install paths
//	pilotctl skills check                      — run one reconcile pass right now
//	pilotctl skills disable <skill|all>        — remove every file we wrote + set mode disabled
//	pilotctl skills enable  <skill|all>        — re-enable (auto mode) + run one reconcile pass
//	pilotctl skills set-mode auto|manual|disabled — persist mode to ~/.pilot/config.json
func cmdSkills(args []string) {
	sub := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "--") {
		sub = args[0]
		args = args[1:]
	}
	switch sub {
	case "status":
		cmdSkillsStatus(args)
	case "paths":
		cmdSkillsPaths(args)
	case "check":
		cmdSkillsCheck(args)
	case "disable":
		cmdSkillsDisable(args)
	case "enable":
		cmdSkillsEnable(args)
	case "set-mode":
		cmdSkillsSetMode(args)
	default:
		fatalHint("invalid_argument",
			"available: status, paths, check, disable, enable, set-mode",
			"unknown skills subcommand: %s", sub)
	}
}

func runTick() (*skillinject.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// ForceTick bypasses the disabled-mode guard so update and explicit
	// check commands work regardless of the current mode setting.
	return skillinject.ForceTick(ctx, skillinject.Config{})
}

// planTick performs a read-only dry run. Disabled mode returns without remote
// access; enabled modes fetch and classify without writing to disk.
func planTick() (*skillinject.Report, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return skillinject.Plan(ctx, skillinject.Config{})
}

// cmdSkillsStatus runs one tick (fetching the manifest + entrypoint over
// HTTPS) and prints a per-tool summary line (statusDot + what, if anything,
// the next tick would change). Per-file detail lines are behind --verbose.
func cmdSkillsStatus(args []string) {
	detail := skillsStatusDetail(args)
	// Read-only: status must not write. Plan reports the true on-disk state
	// plus the action the next daemon tick would take.
	report, err := planTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}

	if jsonOutput {
		out := []map[string]interface{}{}
		for _, o := range report.Outcomes {
			out = append(out, map[string]interface{}{
				"tool":   o.Tool,
				"kind":   string(o.Kind),
				"path":   o.Path,
				"state":  string(o.State),
				"action": string(o.Action),
				"hash":   o.Hash,
				"err":    o.Err,
				"note":   o.Note,
			})
		}
		output(map[string]interface{}{
			"at":       report.At,
			"outcomes": out,
			"skipped":  report.Skipped,
		})
		return
	}

	home, _ := os.UserHomeDir()
	mode := skillinject.GetMode(home)
	modeDesc := map[string]string{
		skillinject.ModeAuto:     fmt.Sprintf("auto — reconciles every %s + on daemon start", skillinject.DefaultInterval),
		skillinject.ModeManual:   "manual — installed once, updated only on `pilotctl update` or `pilotctl skills check`",
		skillinject.ModeDisabled: "disabled — no skills injected",
	}[mode]

	fmt.Println(sBold("Pilot Protocol skill — install status"))
	fmt.Printf("Mode: %s\n", sDim(modeDesc))
	fmt.Println()

	if len(report.Outcomes) == 0 {
		fmt.Println("No supported agent tools detected on this host.")
		fmt.Println("Supported (auto-detected by directory presence):")
		fmt.Println("  - Claude Code (~/.claude)")
		fmt.Println("  - OpenClaw    (~/.openclaw)")
		fmt.Println("  - PicoClaw    (~/.picoclaw)")
		fmt.Println("  - OpenHands   (~/.openhands)")
		fmt.Println("  - Hermes      (~/.hermes)")
		fmt.Println("  - Goose       (~/.config/goose)")
		return
	}

	// Group outcomes by tool for readable output.
	byTool := map[string][]skillinject.Outcome{}
	tools := []string{}
	for _, o := range report.Outcomes {
		if _, seen := byTool[o.Tool]; !seen {
			tools = append(tools, o.Tool)
		}
		byTool[o.Tool] = append(byTool[o.Tool], o)
	}
	sort.Strings(tools)

	for _, tool := range tools {
		outs := byTool[tool]
		// One summary line per tool: ok when every managed file is
		// identical; otherwise warn naming the first offending file and
		// the action the daemon's next tick will take; err on tick errors.
		dot, summary := "ok", "skill+heartbeat ok"
		for _, o := range outs {
			if o.Err != "" {
				dot = "err"
				summary = fmt.Sprintf("%s — %s", filepath.Base(o.Path), o.Err)
				break
			}
			if o.State != skillinject.StateIdentical && dot == "ok" {
				dot = "warn"
				summary = fmt.Sprintf("%s %s — next: %s", filepath.Base(o.Path), o.State, o.Action)
			}
		}
		fmt.Printf("%s %s %s\n", statusDot(dot), sBold(tool), sDim(summary))

		if !detail {
			continue
		}
		for _, o := range outs {
			label := "skill copy:        "
			switch o.Kind {
			case skillinject.KindMarker:
				label = "heartbeat ref:     "
			case skillinject.KindHelper:
				label = "helper:            "
			case skillinject.KindPluginFile:
				label = "plugin file:       "
			case skillinject.KindPluginAllowList:
				label = "plugin allow-list: "
			}
			fmt.Printf("  %s%s\n", label, o.Path)
			fmt.Printf("                     state=%s  next_action=%s\n", o.State, o.Action)
			if o.Err != "" {
				fmt.Printf("                     ERROR: %s\n", o.Err)
			}
			if o.Note != "" {
				fmt.Printf("                     note: %s\n", o.Note)
			}
		}
		fmt.Println()
	}

	if !detail {
		fmt.Printf("\n%s\n", sDim("per-file detail: --verbose · paths only: pilotctl skills paths · force a pass: pilotctl skills check"))
	}
	if len(report.Skipped) > 0 {
		fmt.Printf("Not installed (skipped): %s\n", strings.Join(report.Skipped, ", "))
	}
}

// skillsStatusDetail reports whether `skills status` prints per-file detail.
// main() takes --verbose and -v out of the arguments as the global verbose
// flag before any subcommand sees them, so a --verbose here reaches only the
// global; --verbose=true stays in args.
func skillsStatusDetail(args []string) bool {
	flags, _ := parseFlags(args)
	return verbose || flagBool(flags, "verbose")
}

// cmdSkillsPaths prints just the install paths — one per line, no decoration —
// suitable for shell pipelines (`pilotctl skills paths | xargs ls -la`).
func cmdSkillsPaths(_ []string) {
	// Read-only: printing paths must not write to disk.
	report, err := planTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}
	if jsonOutput {
		paths := []string{}
		for _, o := range report.Outcomes {
			paths = append(paths, o.Path)
		}
		output(map[string]interface{}{"paths": paths})
		return
	}
	for _, o := range report.Outcomes {
		fmt.Println(o.Path)
	}
}

// cmdSkillsCheck triggers one reconcile pass right now (instead of waiting
// for the daemon's next tick) and reports what changed. Useful right after
// installing a new agent tool — no need to wait 15 minutes.
func cmdSkillsCheck(_ []string) {
	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}

	if jsonOutput {
		outputOK(skillsReconcileFields(report))
		return
	}
	printSkillsReconcileSummary(report)
}

// skillsReconcileFields is the JSON summary of one reconcile pass, shared by
// `skills check` and `skills enable`. removes counts retired surfaces (from
// an older manifest) that the pass cleaned up: a helper or plugin file
// deleted, our marker block stripped from a heartbeat file (the file is
// kept), or a plugin id dropped from a tool's config (the file is kept).
// notes carries every outcome whose state/action alone would mislead (a
// heartbeat file shared with another tool, a retired plugin neutralized
// instead of removed). disabled is true when skill injection is disabled: the
// pass installed and updated nothing and only cleaned up retired surfaces.
func skillsReconcileFields(report *skillinject.Report) map[string]interface{} {
	c := report.Counts()
	return map[string]interface{}{
		"disabled": report.Disabled,
		"checked":  len(report.Outcomes),
		"noops":    c[skillinject.ActionNoop],
		"creates":  c[skillinject.ActionCreate],
		"rewrites": c[skillinject.ActionRewrite],
		"removes":  c[skillinject.ActionRemove],
		"errors":   c[skillinject.ActionError],
		"skipped":  report.Skipped,
		"notes":    skillsOutcomeNotes(report),
	}
}

// skillsOutcomeNotes collects the outcomes that carry a Note.
func skillsOutcomeNotes(report *skillinject.Report) []map[string]string {
	notes := []map[string]string{}
	for _, o := range report.Outcomes {
		if o.Note == "" {
			continue
		}
		notes = append(notes, map[string]string{"tool": o.Tool, "path": o.Path, "note": o.Note})
	}
	return notes
}

// printSkillsReconcileSummary is the text summary of one reconcile pass,
// shared by `skills check` and `skills enable`. With skill injection
// disabled the pass installs and updates nothing; it only cleans up retired
// surfaces, and the summary says so.
func printSkillsReconcileSummary(report *skillinject.Report) {
	c := report.Counts()
	if report.Disabled {
		fmt.Println("Skill injection is disabled: nothing was installed or updated.")
		fmt.Printf("Reconcile complete — retired surfaces only, %d found.\n", len(report.Outcomes))
		if c[skillinject.ActionRewrite] > 0 {
			fmt.Printf("  rewrite:   %d\n", c[skillinject.ActionRewrite])
		}
	} else {
		fmt.Printf("Reconcile complete — %d files checked.\n", len(report.Outcomes))
		fmt.Printf("  noop:      %d\n", c[skillinject.ActionNoop])
		fmt.Printf("  create:    %d\n", c[skillinject.ActionCreate])
		fmt.Printf("  rewrite:   %d\n", c[skillinject.ActionRewrite])
	}
	if c[skillinject.ActionRemove] > 0 {
		fmt.Printf("  remove:    %d (retired surfaces from an older manifest)\n", c[skillinject.ActionRemove])
	}
	if c[skillinject.ActionError] > 0 {
		fmt.Printf("  errors:    %d (run `pilotctl skills status` for detail)\n", c[skillinject.ActionError])
	}
	if c[skillinject.ActionRemove] > 0 {
		fmt.Println("Retired surfaces cleaned up:")
		for _, o := range report.Outcomes {
			if o.Action == skillinject.ActionRemove {
				fmt.Printf("  %s — %s: %s\n", o.Path, o.Tool, retiredRemovalEffect(o.Kind))
			}
		}
	}
	printSkillsOutcomeNotes(report, "")
	if len(report.Skipped) > 0 {
		fmt.Printf("Not installed (skipped): %s\n", strings.Join(report.Skipped, ", "))
	}
	if report.Disabled {
		fmt.Println("Re-enable with: pilotctl skills enable all")
	}
}

// retiredRemovalEffect says what cleaning up a retired surface did to the
// file at its path. skillinject deletes only files it owns (helpers, plugin
// files); from user-owned files it removes only its own part.
func retiredRemovalEffect(kind skillinject.FileKind) string {
	switch kind {
	case skillinject.KindMarker:
		return "pilot block stripped, file kept"
	case skillinject.KindPluginAllowList:
		return "plugin entry removed, file kept"
	case skillinject.KindPluginFile, skillinject.KindHelper:
		return "deleted"
	}
	return "removed"
}

// printSkillsOutcomeNotes prints a "Notes:" block for outcomes with a Note,
// each line prefixed with indent. Prints nothing when there are none.
func printSkillsOutcomeNotes(report *skillinject.Report, indent string) {
	notes := skillsOutcomeNotes(report)
	if len(notes) == 0 {
		return
	}
	fmt.Printf("%sNotes:\n", indent)
	for _, n := range notes {
		fmt.Printf("%s  %s (%s): %s\n", indent, n["tool"], n["path"], n["note"])
	}
}

// printSkillsUpdateSummary is the one-line skills summary `pilotctl update`
// prints after re-running skill install in manual mode.
func printSkillsUpdateSummary(report *skillinject.Report) {
	c := report.Counts()
	if report.Disabled {
		// Nothing installed or updated; only retired surfaces cleaned up
		// (a neutralized plugin file is a rewrite).
		fmt.Printf("Skills: injection disabled — retired surfaces cleaned up: %d, errors: %d\n",
			c[skillinject.ActionRemove]+c[skillinject.ActionRewrite],
			c[skillinject.ActionError])
		printSkillsOutcomeNotes(report, "  ")
		return
	}
	fmt.Printf("Skills: %d files checked (%d up-to-date, %d installed, %d removed, %d errors)\n",
		len(report.Outcomes),
		c[skillinject.ActionNoop],
		c[skillinject.ActionCreate]+c[skillinject.ActionRewrite],
		c[skillinject.ActionRemove],
		c[skillinject.ActionError])
	printSkillsOutcomeNotes(report, "  ")
}

// skillsHomeRel returns a $HOME-relative pretty path for display (purely
// cosmetic). Falls back to the absolute path if HOME isn't resolvable.
func skillsHomeRel(p string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	rel, err := filepath.Rel(h, p)
	if err != nil || strings.HasPrefix(rel, "..") {
		return p
	}
	return "~/" + rel
}

var _ = skillsHomeRel // reserved for future use; keeps gofmt happy

// cmdSkillsDisable removes every file the daemon has ever written via
// the skillinject manifest and persists an opt-out flag in
// ~/.pilot/config.json so subsequent reconcile ticks are no-ops. The
// removal path is the inverse of `check`: files in subdirs we own
// (pilot-protocol/, ~/.pilot/bin/, plugin install dirs) are deleted;
// files we co-inhabit with the user (CLAUDE.md, AGENTS.md, AGENT.md,
// SOUL.md) only have our marker block stripped — never the whole file.
//
// Requires an explicit skill id (or `all`) to avoid the foot-gun where a
// stray invocation silently nukes every managed file. Pre-fix this
// command ran unconditionally regardless of input — see PILOT-189.
func cmdSkillsDisable(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl skills disable <skill-id|all>",
			"skill id required")
	}
	if args[0] != "all" {
		fatalHint("invalid_argument",
			"only 'all' is supported; per-skill disable is not yet implemented",
			"unknown skill id: %s", args[0])
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "home dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report, uErr := skillinject.Uninstall(ctx, skillinject.Config{})
	// Persist the opt-out regardless of partial removal failures —
	// the next tick must be a no-op so we don't fight the user.
	persistErr := skillinject.SetMode(home, skillinject.ModeDisabled)

	if jsonOutput {
		out := map[string]interface{}{
			"disabled": true,
			"at":       report.At,
			"removals": report.Removals,
		}
		if report.ManifestOffline {
			out["manifest_offline"] = true
		}
		if uErr != nil {
			out["error"] = uErr.Error()
		}
		if persistErr != nil {
			out["persist_error"] = persistErr.Error()
		}
		output(out)
		return
	}

	fmt.Println("Pilot Protocol skill — disabled")
	fmt.Println("================================")
	if report.ManifestOffline {
		fmt.Println("(network unreachable; using cached manifest)")
	}
	if uErr != nil {
		fmt.Printf("warning: %v\n", uErr)
	}
	printSkillsRemovalReport(report)

	if persistErr != nil {
		fmt.Printf("\nwarning: opt-out flag could not be persisted: %v\n", persistErr)
		fmt.Println("(future daemon ticks may re-install — fix permissions on ~/.pilot/config.json and re-run)")
	} else {
		fmt.Println()
		fmt.Println("Opt-out persisted at ~/.pilot/config.json — future ticks are no-ops.")
		fmt.Println("To re-enable: pilotctl skills enable all")
	}
}

// skillsRemovalKinds is the order `skills disable all` prints its counts in.
var skillsRemovalKinds = []skillinject.RemovalKind{
	skillinject.RemovalDeleted,
	skillinject.RemovalStripped,
	skillinject.RemovalMerged,
	skillinject.RemovalRestored,
	skillinject.RemovalNeutralized,
	skillinject.RemovalNoop,
	skillinject.RemovalError,
}

// printSkillsRemovalReport prints the per-kind counts and the paths
// `skills disable all` processed. A neutralized row is a retired plugin whose
// tool config could not be edited safely: its entry file was replaced with a
// no-op, and its note says how to finish the removal.
func printSkillsRemovalReport(report *skillinject.RemovalReport) {
	counts := report.Counts()
	for _, k := range skillsRemovalKinds {
		if counts[k] == 0 {
			continue
		}
		fmt.Printf("  %-12s %d\n", string(k)+":", counts[k])
	}

	if len(report.Removals) > 0 {
		fmt.Println()
		fmt.Println("Paths processed:")
		for _, x := range report.Removals {
			if x.Action == skillinject.RemovalNoop {
				continue
			}
			fmt.Printf("  [%s] %s — %s\n", x.Action, x.Path, x.Tool)
			if x.Err != "" {
				fmt.Printf("        ERROR: %s\n", x.Err)
			}
			if x.Note != "" {
				fmt.Printf("        note: %s\n", x.Note)
			}
		}
	}
}

// cmdSkillsEnable flips the opt-out flag off and runs one reconcile
// pass so the user sees what got installed without waiting for the
// next 15-minute tick.
//
// Requires an explicit skill id (or `all`) so a stray invocation
// can't silently re-install everything. Pre-fix this command ran
// unconditionally regardless of input — see PILOT-189.
func cmdSkillsEnable(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl skills enable <skill-id|all>",
			"skill id required")
	}
	if args[0] != "all" {
		fatalHint("invalid_argument",
			"only 'all' is supported; per-skill enable is not yet implemented",
			"unknown skill id: %s", args[0])
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "home dir: %v", err)
	}
	if err := skillinject.SetMode(home, skillinject.ModeAuto); err != nil {
		fatalCode("internal", "persist mode: %v", err)
	}

	report, err := runTick()
	if err != nil {
		fatalCode("internal", "skills tick: %v", err)
	}

	if jsonOutput {
		fields := skillsReconcileFields(report)
		fields["enabled"] = true
		outputOK(fields)
		return
	}

	fmt.Println("Pilot Protocol skill — enabled")
	fmt.Println("===============================")
	printSkillsReconcileSummary(report)
}

// cmdSkillsSetMode persists the skillinject mode to ~/.pilot/config.json.
//
//   - auto     — daemon ticks on its 15-minute cadence (always up to date)
//   - manual   — ticks only on daemon startup, pilotctl update, or pilotctl skills check
//   - disabled — no ticks, no files written; equivalent to pilotctl skills disable all
func cmdSkillsSetMode(args []string) {
	if len(args) == 0 {
		fatalHint("invalid_argument",
			"usage: pilotctl skills set-mode auto|manual|disabled",
			"mode required")
	}
	mode := args[0]
	switch mode {
	case skillinject.ModeAuto, skillinject.ModeManual, skillinject.ModeDisabled:
	default:
		fatalHint("invalid_argument",
			"valid modes: auto, manual, disabled",
			"unknown mode: %s", mode)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fatalCode("internal", "home dir: %v", err)
	}
	if err := skillinject.SetMode(home, mode); err != nil {
		fatalCode("internal", "persist mode: %v", err)
	}
	if jsonOutput {
		outputOK(map[string]interface{}{"mode": mode})
		return
	}
	modeDesc := map[string]string{
		skillinject.ModeAuto:     "auto — daemon reconciles every 15 minutes and on each startup",
		skillinject.ModeManual:   "manual — skills installed once; updated only on `pilotctl update` or `pilotctl skills check`",
		skillinject.ModeDisabled: "disabled — no skills injected; run `pilotctl skills enable all` to re-enable",
	}[mode]
	fmt.Printf("Pilot Protocol skill mode set to %s\n%s\n", sBold(mode), sDim(modeDesc))
}

// skillInstallTools returns the agent tools that have the pilot skill
// installed, in detection order. Empty when no agent tools are present
// on the host. Same data source as `pilotctl skills`, collapsed to one
// entry per tool.
func skillInstallTools() []string {
	// Read-only: this feeds display surfaces (e.g. `pilotctl info`); it must
	// not write to disk as a side effect of being looked at.
	report, err := planTick()
	if err != nil || report == nil || len(report.Outcomes) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var order []string
	for _, o := range report.Outcomes {
		if o.Kind != skillinject.KindSkill {
			continue
		}
		if !seen[o.Tool] {
			seen[o.Tool] = true
			order = append(order, o.Tool)
		}
	}
	return order
}

// printSkillInstallSummary surfaces the agent skill install paths.
// Quiet (no header) when no agent tools are detected on the host.
func printSkillInstallSummary() {
	// Read-only: summary display for `pilotctl info` — no writes.
	report, err := planTick()
	if err != nil || report == nil || len(report.Outcomes) == 0 {
		return
	}
	// Collapse to one path per tool: prefer the skill copy over the marker.
	seen := map[string]string{}
	order := []string{}
	for _, o := range report.Outcomes {
		if o.Kind != skillinject.KindSkill {
			continue
		}
		if _, ok := seen[o.Tool]; !ok {
			order = append(order, o.Tool)
		}
		seen[o.Tool] = o.Path
	}
	if len(order) == 0 {
		return
	}
	fmt.Printf("\nAgent skill installed at:\n")
	for _, tool := range order {
		fmt.Printf("  %-13s %s\n", tool+":", seen[tool])
	}
	fmt.Printf("  (auto-managed by daemon — run `pilotctl skills` for full state)\n")
}
