// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pilot-protocol/skillinject"
)

const (
	testSharedNote      = "same file as the opencode heartbeat (/home/u/AGENTS.md), which keeps a single block written for opencode"
	testNeutralizedNote = "parse openclaw.json: invalid character; index.mjs is replaced with a no-op, so the retired plugin stays listed but does nothing"
)

// summaryReport is a reconcile report with every row shape skillinject
// v0.2.4 can produce: plain noop/create/rewrite, two retired surfaces
// removed, a retired plugin neutralized (rewrite + note), a shared heartbeat
// (noop + note) and an error.
func summaryReport() *skillinject.Report {
	return &skillinject.Report{
		Outcomes: []skillinject.Outcome{
			{Tool: "claude-code", Kind: skillinject.KindSkill, Path: "/home/u/.claude/skills/pilot/SKILL.md", State: skillinject.StateIdentical, Action: skillinject.ActionNoop},
			{Tool: "claude-code", Kind: skillinject.KindMarker, Path: "/home/u/.claude/CLAUDE.md", State: skillinject.StateAbsent, Action: skillinject.ActionCreate},
			{Tool: "opencode", Kind: skillinject.KindMarker, Path: "/home/u/AGENTS.md", State: skillinject.StateDrifted, Action: skillinject.ActionRewrite},
			{Tool: "goose", Kind: skillinject.KindMarker, Path: "/home/u/AGENTS.md", State: skillinject.StateIdentical, Action: skillinject.ActionNoop, Note: testSharedNote},
			{Tool: "openclaw", Kind: skillinject.KindMarker, Path: "/home/u/.openclaw/workspace/HEARTBEAT.md", State: skillinject.StateRetired, Action: skillinject.ActionRemove},
			{Tool: "pilot-ask", Kind: skillinject.KindHelper, Path: "/home/u/.pilot/bin/pilot-ask", State: skillinject.StateRetired, Action: skillinject.ActionRemove},
			{Tool: "pilotprotocol-prompt-injector", Kind: skillinject.KindPluginFile, Path: "/home/u/.openclaw/extensions/pilotprotocol-prompt-injector/index.mjs", State: skillinject.StateRetired, Action: skillinject.ActionRewrite, Note: testNeutralizedNote},
			{Tool: "picoclaw", Kind: skillinject.KindSkill, Path: "/home/u/.picoclaw/skills/pilot/SKILL.md", State: skillinject.StateAbsent, Action: skillinject.ActionError, Err: "permission denied"},
		},
		Skipped: []string{"hermes"},
	}
}

// TestSkillsReconcileFields_CountsRemovesAndNotes: `skills check|enable
// --json` used to drop ActionRemove rows from its counts and ignore
// Outcome.Note.
func TestSkillsReconcileFields_CountsRemovesAndNotes(t *testing.T) {
	fields := skillsReconcileFields(summaryReport())
	want := map[string]int{"checked": 8, "noops": 2, "creates": 1, "rewrites": 2, "removes": 2, "errors": 1}
	for k, v := range want {
		if fields[k] != v {
			t.Errorf("%s = %v, want %d", k, fields[k], v)
		}
	}
	notes, ok := fields["notes"].([]map[string]string)
	if !ok || len(notes) != 2 {
		t.Fatalf("notes = %#v, want 2 entries", fields["notes"])
	}
	if notes[0]["tool"] != "goose" || notes[0]["note"] != testSharedNote {
		t.Errorf("notes[0] = %v", notes[0])
	}
	if notes[1]["tool"] != "pilotprotocol-prompt-injector" || notes[1]["note"] != testNeutralizedNote {
		t.Errorf("notes[1] = %v", notes[1])
	}
}

// TestSkillsReconcileFields_NotesIsEmptyArray keeps the JSON shape stable:
// "notes": [] rather than null when nothing carries a note.
func TestSkillsReconcileFields_NotesIsEmptyArray(t *testing.T) {
	fields := skillsReconcileFields(&skillinject.Report{Outcomes: []skillinject.Outcome{
		{Tool: "claude-code", Action: skillinject.ActionNoop},
	}})
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"notes":[]`) {
		t.Errorf("want \"notes\":[] in %s", b)
	}
	if !strings.Contains(string(b), `"removes":0`) {
		t.Errorf("want \"removes\":0 in %s", b)
	}
}

func TestPrintSkillsReconcileSummary_ShowsRemovesAndNotes(t *testing.T) {
	out := captureStdout(t, func() { printSkillsReconcileSummary(summaryReport()) })
	for _, want := range []string{
		"Reconcile complete — 8 files checked.",
		"  rewrite:   2",
		"  remove:    2 (retired surfaces from an older manifest)",
		"  errors:    1",
		"Removed:",
		"  /home/u/.openclaw/workspace/HEARTBEAT.md — openclaw",
		"  /home/u/.pilot/bin/pilot-ask — pilot-ask",
		"Notes:",
		"  goose (/home/u/AGENTS.md): " + testSharedNote,
		"  pilotprotocol-prompt-injector (/home/u/.openclaw/extensions/pilotprotocol-prompt-injector/index.mjs): " + testNeutralizedNote,
		"Not installed (skipped): hermes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestPrintSkillsReconcileSummary_QuietWithoutRemovesOrNotes(t *testing.T) {
	out := captureStdout(t, func() {
		printSkillsReconcileSummary(&skillinject.Report{Outcomes: []skillinject.Outcome{
			{Tool: "claude-code", Action: skillinject.ActionNoop},
		}})
	})
	for _, unwanted := range []string{"remove:", "Removed:", "Notes:", "errors:"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("summary must not print %q for a clean pass:\n%s", unwanted, out)
		}
	}
}

// TestPrintSkillsUpdateSummary pins the one-line summary `pilotctl update`
// prints after re-running skill install.
func TestPrintSkillsUpdateSummary(t *testing.T) {
	out := captureStdout(t, func() { printSkillsUpdateSummary(summaryReport()) })
	if !strings.Contains(out, "Skills: 8 files checked (2 up-to-date, 3 installed, 2 removed, 1 errors)") {
		t.Errorf("summary line:\n%s", out)
	}
	if !strings.Contains(out, "  Notes:\n") || !strings.Contains(out, testNeutralizedNote) {
		t.Errorf("notes missing:\n%s", out)
	}
}

// TestPrintSkillsRemovalReport_Neutralized: `skills disable all` counts
// RemovalNeutralized and prints the note that says how to finish removal.
func TestPrintSkillsRemovalReport_Neutralized(t *testing.T) {
	report := &skillinject.RemovalReport{Removals: []skillinject.Removal{
		{Tool: "claude-code", Kind: skillinject.KindMarker, Path: "/home/u/.claude/CLAUDE.md", Action: skillinject.RemovalStripped},
		{Tool: "pilotprotocol-prompt-injector", Kind: skillinject.KindPluginFile, Path: "/home/u/.openclaw/extensions/pilotprotocol-prompt-injector/index.mjs", Action: skillinject.RemovalNeutralized, Note: testNeutralizedNote},
		{Tool: "goose", Kind: skillinject.KindMarker, Path: "/home/u/AGENTS.md", Action: skillinject.RemovalNoop},
	}}
	out := captureStdout(t, func() { printSkillsRemovalReport(report) })
	for _, want := range []string{
		"  stripped:    1",
		"  neutralized: 1",
		"  noop:        1",
		"[neutralized] /home/u/.openclaw/extensions/pilotprotocol-prompt-injector/index.mjs — pilotprotocol-prompt-injector",
		"        note: " + testNeutralizedNote,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("disable report missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[noop]") {
		t.Errorf("noop rows must not be listed under paths processed:\n%s", out)
	}
}
