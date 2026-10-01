// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Call-time "next steps" rendering — the dynamic context an agent sees after
// EVERY `pilotctl appstore call`, on success and on failure.
//
// The problem: an autonomous agent installs an app and then stops caring. The
// product demo (appstore_demo.go) addresses the install→first-call step, once.
// This addresses every call after it: when a call lands, the agent is told the
// small set of RECOMMENDED commands for where it now stands — the next step in
// the flow on success, and the specific fix on failure (402 → top up, 401 →
// signup, missing param → the schema).
//
// # Where the data comes from, and why the call path never touches the network
//
// The graph is authored in submission.json beside product_demo and flows
// verbatim into the catalogue's metadata.json, whose bytes are pinned by
// metadata_sha256 under the catalogue signature. At install we cache the graph
// to $APP/next-steps.json (see cacheNextSteps). Every call then resolves against
// that local file: no fetch, no DNS, no added latency, and it works offline. A
// call is the hottest path in the app store — it must not grow a network
// dependency to print a hint.
//
// # Trust
//
// The cached bytes came out of the sha-verified metadata.json, so this adds no
// new trust surface. $APP is already the app's own confined directory holding
// its signed manifest; a graph is strictly less privileged than the manifest
// sitting next to it — it produces text, never an action. Nothing here ever
// executes a recommended command; it prints it for the agent to decide on.
//
// # Failure posture
//
// Everything is additive and best-effort, and every entry point is guarded: an
// absent, unreadable, malformed, future-schema, or simply unmatched graph means
// the call behaves EXACTLY as it does today. A hint is a nicety; a call is not.
// Under no circumstances may this file's code turn a working call into a failed
// one — hence the recover() in renderNextSteps and the silent error drops.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// nextStepsFileName is the per-app cache written at install, read at call.
const nextStepsFileName = "next-steps.json"

// maxNextStepsBytes bounds the cached graph read. A graph is a flow summary of a
// few KB; anything near this ceiling is not a graph and is not worth parsing on
// the call path.
const maxNextStepsBytes = 256 << 10

// maxThenRendered hard-caps recommendations per edge at render time, even if a
// graph somehow shipped with more (validation is authoring-side and this is a
// different binary — never trust the file to have been gated).
const maxThenRendered = 3

// nextStepsGraph mirrors the FROZEN `next_steps` object authors write in
// submission.json and that flows verbatim into catalogue metadata.json. It is a
// deliberate duplicate of app-template's internal/nextsteps types — the same
// call the ProductDemo mirror makes in appstore_demo.go. pilotctl must not
// depend on the app-template module, and a frozen wire contract is exactly the
// thing it is safe to restate.
type nextStepsGraph struct {
	Schema int             `json:"schema"`
	App    string          `json:"app"`
	Edges  []nextStepsEdge `json:"edges"`
}

// nextStepsEdge is one rule: "the agent ran From and it went On — recommend Then".
type nextStepsEdge struct {
	From string `json:"from"`
	On   string `json:"on"`
	// Match is a regex over the call's OUTCOME PAYLOAD: the error text on
	// failure, the JSON RESULT BODY on success.
	//
	// Matching the success body is load-bearing, not a nicety. The most
	// important case in the feature — "you must call <ns>.signup first" — is not
	// an error: the scaffold's requireKey wrapper soft-fails an unauthenticated
	// call with exit 0 and
	//   {"ok":false,"needs_signup":true,"activate":"primitive.signup"}
	// so an outcome-only matcher would see a plain success and stay silent,
	// precisely for the cold agent who most needs the gateway named.
	Match string          `json:"match,omitempty"`
	Code  int             `json:"code,omitempty"`
	Why   string          `json:"why,omitempty"`
	Then  []nextStepsStep `json:"then"`
}

// nextStepsStep is one recommended command and the reason to run it.
type nextStepsStep struct {
	Cmd  string `json:"cmd"`
	Why  string `json:"why"`
	Kind string `json:"kind,omitempty"`
}

const (
	nextStepsWildcard   = "*"
	nextStepsOutcomeOK  = "ok"
	nextStepsOutcomeErr = "err"
	nextStepsKindGate   = "gateway"
	nextStepsKindRecov  = "recovery"
)

// nextStepsStatusRe reads the backend status out of an adapter error. The
// generated HTTP adapter formats every non-2xx as
//
//	backend: POST /v1/run -> 402: {"error":"insufficient credit ..."}
//
// (internal/scaffold/templates/client_http.go.tmpl), so the status is present in
// the text today even though there is no structured error code on the wire yet.
// This regex is the bridge; when apps grow a machine-readable code, this is the
// only place that has to learn about it.
var nextStepsStatusRe = regexp.MustCompile(`->\s*(\d{3})\b`)

// nextStepsDisabled reports whether the operator turned the feature off.
// PILOT_NEXT_STEPS=off is the escape hatch for anyone who finds the banner
// noisy in a tight loop — an unconditional per-call print with no off switch is
// how a helpful feature becomes one people route around.
func nextStepsDisabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PILOT_NEXT_STEPS"))) {
	case "off", "0", "false", "no":
		return true
	}
	return false
}

// loadNextStepsGraph reads the cached graph for an app. Every failure returns
// nil: a missing cache is the NORMAL case (an app installed before this feature,
// or one that never published a graph), not an error worth a word to the user.
func loadNextStepsGraph(appID string) *nextStepsGraph {
	// appID arrives straight from argv, so filepath.Join alone is not enough:
	// `pilotctl appstore call ../../etc/x ...` would resolve outside the install
	// root and we would happily read (and print) whatever we found. resolveUnder
	// is the same containment guard install and the supervisor use.
	dir, err := resolveAppDir(appStoreRoot(), appID)
	if err != nil {
		return nil
	}
	path := filepath.Join(dir, nextStepsFileName)
	f, err := os.Open(path) // #nosec G304 -- path is confined to appStoreRoot() by resolveUnder above
	if err != nil {
		return nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() > maxNextStepsBytes {
		return nil
	}
	var g nextStepsGraph
	if err := json.NewDecoder(f).Decode(&g); err != nil {
		return nil
	}
	// Schema 1 is the only shape this binary understands. A newer graph must be
	// IGNORED rather than half-read: printing a guessed-at hint is worse than
	// printing none.
	if g.Schema != 1 || g.App != appID {
		return nil
	}
	return &g
}

// resolveNextStepsEdge picks the single best edge for a completed call, or nil
// when the graph has nothing to say (the common, silent case).
//
// Specificity decides, not file order. The governing rule:
//
//	AN EDGE THAT MATCHED THE ACTUAL SITUATION BEATS ONE THAT MERELY MATCHED
//	THE METHOD NAME.
//
// So every discriminated edge outranks every undiscriminated one, however exact
// its From:
//
//	from exact + code   (7)
//	*          + code   (6)
//	from exact + match  (5)
//	*          + match  (4)
//	from exact          (1)   "you called this method", nothing more
//	*                   (0)   the catch-all
//
// The gap between 4 and 1 is load-bearing. A signup app's gateway edge is
// `*` + match on {"needs_signup":true} (the soft-fail is exit 0, so it cannot key
// on the outcome). If a bare From-exact flow edge could outrank it, a COLD agent
// calling primitive.send_email would be told "now read your inbox" instead of
// "sign up first" — the exact failure this feature exists to prevent.
//
// This MUST stay in lockstep with nextsteps.Graph.Resolve in app-template, which
// validates the graphs this resolves; TestResolveMatchesAppTemplateSemantics
// pins the shared cases.
func resolveNextStepsEdge(g *nextStepsGraph, method string, ok bool, payload string) *nextStepsEdge {
	if g == nil {
		return nil
	}
	want := nextStepsOutcomeErr
	if ok {
		want = nextStepsOutcomeOK
	}
	best, bestScore := -1, -1
	for i := range g.Edges {
		e := &g.Edges[i]
		if e.On != want {
			continue
		}
		score := 0
		switch e.From {
		case method:
			score++ // a named method is the WEAKEST signal — see the ordering above
		case nextStepsWildcard:
		default:
			continue // names a different method
		}
		// An edge that declares a discriminator and does not match is not
		// applicable at all — it must NOT fall back to winning on its From
		// bonus, or an unrelated failure would print a confidently wrong fix.
		if e.Code != 0 {
			if !nextStepsMatchesCode(payload, e.Code) {
				continue
			}
			score += 6 // matched the situation, and pinned an exact status
		} else if e.Match != "" {
			re, err := regexp.Compile("(?i)" + e.Match)
			if err != nil || !re.MatchString(payload) {
				continue
			}
			score += 4 // matched the situation
		}
		if score > bestScore {
			bestScore, best = score, i
		}
	}
	if best < 0 {
		return nil
	}
	return &g.Edges[best]
}

func nextStepsMatchesCode(payload string, code int) bool {
	m := nextStepsStatusRe.FindStringSubmatch(payload)
	return m != nil && m[1] == fmt.Sprintf("%d", code)
}

// renderNextStepsText builds the block printed after a call. The budget is
// brutal because this lands after EVERY call: a few lines, or the agent learns
// to skip it and the feature has made things worse than silence.
//
//	next: budget exhausted — top up before retrying
//	  1. pilotctl appstore call io.pilot.wallet wallet.balance '{}'
//	     why: check remaining USDC (fixes the error above)
func renderNextStepsText(e *nextStepsEdge) string {
	if e == nil || len(e.Then) == 0 {
		return ""
	}
	var b strings.Builder
	if w := oneLineNS(e.Why); w != "" {
		fmt.Fprintf(&b, "next: %s\n", w)
	} else {
		b.WriteString("next:\n")
	}
	for i, s := range e.Then {
		if i >= maxThenRendered {
			break
		}
		cmd := strings.TrimSpace(s.Cmd)
		if cmd == "" {
			continue
		}
		fmt.Fprintf(&b, "  %d. %s\n", i+1, cmd)
		if w := oneLineNS(s.Why); w != "" {
			fmt.Fprintf(&b, "     why: %s%s\n", w, nextStepsKindSuffix(s.Kind))
		}
	}
	return b.String()
}

// nextStepsKindSuffix marks the two kinds an agent must not read past: a gateway
// is non-optional, and a recovery step is the fix for the error just printed.
// The ordinary forward step is unmarked — "the next useful thing" needs no label.
func nextStepsKindSuffix(kind string) string {
	switch kind {
	case nextStepsKindGate:
		return " (required first)"
	case nextStepsKindRecov:
		return " (fixes the error above)"
	default:
		return ""
	}
}

func oneLineNS(s string) string { return strings.Join(strings.Fields(s), " ") }

// exitNextSteps is drained by fatalHint so a FAILED call prints its recovery
// steps after the error, not before it. fatalHint owns the process exit, so a
// caller cannot print anything after it — the same reason motd's
// importantUpdate is a package var consumed there. Set it immediately before
// fatalHint; it is inert everywhere else.
var exitNextSteps *nextStepsEdge

// renderNextSteps resolves and returns the block for a completed call, and is
// the ONLY entry point the call path uses. It is recover()-guarded and
// fail-silent by construction: a hint is a nicety, a call is not, and no bug in
// graph handling may ever turn a working call into a failed one.
func renderNextSteps(appID, method string, ok bool, payload string) *nextStepsEdge {
	if nextStepsDisabled() {
		return nil
	}
	var edge *nextStepsEdge
	func() {
		defer func() {
			if r := recover(); r != nil {
				edge = nil
			}
		}()
		edge = resolveNextStepsEdge(loadNextStepsGraph(appID), method, ok, payload)
	}()
	return edge
}

// printNextSteps writes the block for a SUCCESSFUL call to stderr.
//
// stderr, never stdout — this is the load-bearing decision in the whole file.
// stdout carries the call's JSON result and agents pipe it straight into jq;
// one line of prose there corrupts the parse and breaks the very workflow this
// feature exists to encourage. stderr is still captured by every agent harness,
// so the hint is seen without ever touching the data contract.
func printNextSteps(e *nextStepsEdge) {
	if txt := renderNextStepsText(e); txt != "" {
		fmt.Fprint(os.Stderr, txt)
	}
}

// nextStepsJSON is the machine-readable form attached to --json output, so an
// agent parsing the envelope gets structured steps rather than prose to re-parse.
type nextStepsJSON struct {
	Why   string          `json:"why,omitempty"`
	Steps []nextStepsStep `json:"steps"`
}

func nextStepsEnvelope(e *nextStepsEdge) *nextStepsJSON {
	if e == nil || len(e.Then) == 0 {
		return nil
	}
	steps := e.Then
	if len(steps) > maxThenRendered {
		steps = steps[:maxThenRendered]
	}
	return &nextStepsJSON{Why: oneLineNS(e.Why), Steps: steps}
}

// cacheNextSteps writes the graph from the (already sha-verified) catalogue
// metadata into the installed app dir, so the call path is a local read.
//
// Best-effort by design: a failure here must never fail an install that has
// otherwise fully succeeded. The cost of no cache is no hints; the cost of a
// failed install is a broken app.
func cacheNextSteps(appDir string, g *nextStepsGraph) {
	if g == nil || len(g.Edges) == 0 {
		return
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return
	}
	// Confine the write to the install root for the same reason the read is
	// confined: appDir is derived from an app id, and a graph is never worth
	// writing a byte outside the tree the app store owns.
	out, err := resolveUnder(appStoreRoot(), filepath.Base(appDir))
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(out, nextStepsFileName), data, 0o600) // #nosec G304 G703 -- path re-confined to the install root by resolveUnder above
}

// fetchNextStepsForInstall pulls the graph out of the catalogue metadata for an
// app id. Best-effort and quiet: an app with no catalogue entry (a sideload), no
// metadata_url, or an unreachable host simply gets no graph. It is called once
// per install, never on the call path.
func fetchNextStepsForInstall(appID string) *nextStepsGraph {
	g, _ := fetchNextStepsAuthoritative(appID)
	return g
}

// fetchNextStepsAuthoritative fetches the app's graph from the catalogue and
// reports whether the answer is AUTHORITATIVE — i.e. whether the catalogue and
// (if present) the metadata doc were actually reached. It is the distinction
// ensureNextStepsFresh needs: a nil graph with ok=true means "this app has no
// graph, stop asking for a while", whereas ok=false means "we couldn't reach the
// catalogue, try again soon". Collapsing the two (as a bare *graph return does)
// would either re-fetch every call forever or give up on a transient blip.
func fetchNextStepsAuthoritative(appID string) (graph *nextStepsGraph, ok bool) {
	c, err := loadCatalogue()
	if err != nil {
		return nil, false // could not reach/verify the catalogue
	}
	for i := range c.Apps {
		if c.Apps[i].ID != appID {
			continue
		}
		m, err := loadAppMetadata(c.Apps[i])
		if err != nil {
			return nil, false // entry found but the detail fetch/verify failed
		}
		if m == nil {
			return nil, true // no metadata doc = authoritatively no graph
		}
		return m.NextSteps, true
	}
	return nil, true // not in the catalogue (e.g. a sideload) = authoritatively none
}

// ── lazy self-heal ───────────────────────────────────────────────────────────
//
// The graph is cached at install, but the installed FLEET predates most graphs,
// and a republished graph never touches an existing cache. Without healing, the
// feature only reaches apps installed AFTER their graph shipped — a blocker.
//
// ensureNextStepsFresh closes that gap from the call path, off the render:
//   - steady state is a single stat of a freshness marker → returns immediately,
//     no network (the hot-path-is-local guarantee holds for all but the rare
//     re-check);
//   - when the TTL has elapsed it spends ONE bounded fetch, so an app installed
//     before its graph existed renders on its very next call, and a republished
//     graph propagates within the TTL;
//   - a fetch that can't reach the catalogue backs off briefly rather than
//     re-trying every call.
const (
	// nextStepsFreshTTL bounds how often we re-consult the catalogue per app.
	// Graphs change rarely; a half-day is plenty fresh and keeps fetches rare.
	nextStepsFreshTTL = 12 * time.Hour
	// nextStepsRetryCool caps re-tries after a failed fetch so an offline host
	// doesn't spend the fetch budget on every call.
	nextStepsRetryCool = 2 * time.Minute
	// nextStepsFetchBudget bounds the ONE inline fetch on the call path. Generous
	// for a ~15 KiB metadata doc from a CDN, tight enough that a slow/hung host
	// never noticeably delays the app call. On a miss past this budget the app
	// simply renders no hint this once and the next call (past the retry cool)
	// tries again.
	nextStepsFetchBudget = 400 * time.Millisecond
	nsCheckedMarker      = ".next-steps.checked" // mtime = last authoritative check
	nsRetryMarker        = ".next-steps.retry"   // mtime = last failed fetch
)

// ensureNextStepsFresh is called once per `appstore call`, before the IPC call,
// so the cache is current for whichever outcome renders. It never blocks longer
// than nextStepsFetchBudget and never errors out of the call.
func ensureNextStepsFresh(appID string) {
	if nextStepsDisabled() {
		return
	}
	dir, err := resolveAppDir(appStoreRoot(), appID)
	if err != nil {
		return
	}
	// Recent authoritative answer (a cached graph, or a confirmed absence) → done.
	if markerFresh(filepath.Join(dir, nsCheckedMarker), nextStepsFreshTTL) {
		return
	}
	// Recently failed → back off rather than re-fetch on every call.
	if markerFresh(filepath.Join(dir, nsRetryMarker), nextStepsRetryCool) {
		return
	}
	g, ok := fetchNextStepsTimed(appID, nextStepsFetchBudget)
	if !ok {
		touchMarker(dir, nsRetryMarker) // couldn't reach the catalogue; short cooldown
		return
	}
	if g != nil && len(g.Edges) > 0 {
		cacheNextSteps(dir, g)
	} else {
		// The catalogue authoritatively has no graph for this app now — drop any
		// stale cache so we never render a graph the catalogue stopped publishing.
		removeUnderAppDir(dir, nextStepsFileName)
	}
	touchMarker(dir, nsCheckedMarker)
	removeUnderAppDir(dir, nsRetryMarker)
}

// fetchNextStepsTimed runs the authoritative fetch under a hard deadline. On
// timeout it reports ok=false (treated as a transient failure) and lets the
// goroutine finish and fall off on its own — it never writes anything, so an
// abandoned fetch can't race the cache.
func fetchNextStepsTimed(appID string, budget time.Duration) (*nextStepsGraph, bool) {
	type res struct {
		g  *nextStepsGraph
		ok bool
	}
	ch := make(chan res, 1)
	go func() {
		g, ok := fetchNextStepsAuthoritative(appID)
		ch <- res{g, ok}
	}()
	select {
	case r := <-ch:
		return r.g, r.ok
	case <-time.After(budget):
		return nil, false
	}
}

// markerFresh reports whether a marker file exists and is younger than ttl.
func markerFresh(path string, ttl time.Duration) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < ttl
}

// touchMarker writes/updates a freshness marker in the app dir (mtime = now).
func touchMarker(dir, name string) {
	out, err := resolveUnder(appStoreRoot(), filepath.Base(dir))
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(out, name), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600) // #nosec G304 G703 -- path re-confined to the install root by resolveUnder above
}

// removeUnderAppDir deletes a file inside an installed app dir, re-confining the
// path to the install root (the same guard the read and write paths use) so a
// crafted app id can never delete outside the tree the app store owns.
func removeUnderAppDir(dir, name string) {
	out, err := resolveUnder(appStoreRoot(), filepath.Base(dir))
	if err != nil {
		return
	}
	_ = os.Remove(filepath.Join(out, name)) // #nosec G304 G703 -- path re-confined to the install root by resolveUnder above
}
