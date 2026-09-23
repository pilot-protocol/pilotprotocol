// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pilot-protocol/common/driver"
	"github.com/pilot-protocol/skillinject"
	"github.com/pilot-protocol/updater"
)

// autoUpdateStatePath is the JSON control file ({"enabled": bool}) shared with
// the pilot-updater loop (passed as its --state-path). Automatic updates are
// OFF by default: when the file is absent the updater applies nothing.
func autoUpdateStatePath() string { return configDir() + "/auto-update.json" }

// autoUpdateEnabled reports the persisted auto-update setting (default off).
func autoUpdateEnabled() bool {
	data, err := os.ReadFile(autoUpdateStatePath())
	if err != nil {
		return false
	}
	var s struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return false
	}
	return s.Enabled
}

// cmdAutoUpdateSet turns automatic updates on or off (`pilotctl update
// enable|disable`). The pilot-updater re-reads the file each tick, so this
// takes effect without restarting it.
func cmdAutoUpdateSet(on bool) {
	path := autoUpdateStatePath()
	_ = os.MkdirAll(configDir(), 0o755)
	data, _ := json.MarshalIndent(map[string]bool{"enabled": on}, "", "  ")
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		fatalCode("internal", "write %s: %v", path, err)
	}
	if jsonOutput {
		outputOK(map[string]interface{}{"auto_update": on})
		return
	}
	if on {
		fmt.Println("Automatic updates ENABLED. The updater will install new stable releases on its check interval.")
		fmt.Println("Disable any time with: pilotctl update disable")
	} else {
		fmt.Println("Automatic updates DISABLED. Nothing will be installed automatically.")
		fmt.Println("Run a one-time manual update with: pilotctl update")
	}
}

// cmdAutoUpdateStatus shows whether automatic updates are on and the current
// version (`pilotctl update status`).
func cmdAutoUpdateStatus() {
	on := autoUpdateEnabled()
	if jsonOutput {
		outputOK(map[string]interface{}{
			"auto_update":     on,
			"current_version": version,
			"state_file":      autoUpdateStatePath(),
		})
		return
	}
	state := "disabled"
	if on {
		state = "enabled"
	}
	fmt.Printf("Automatic updates: %s\n", state)
	fmt.Printf("Current version:   %s\n", version)
	fmt.Printf("State file:        %s\n", autoUpdateStatePath())
	if on {
		fmt.Println("\nTurn off with:  pilotctl update disable")
	} else {
		fmt.Println("\nTurn on with:   pilotctl update enable")
		fmt.Println("One-time check: pilotctl update")
	}
}

// changelogFeedURL is the canonical RSS 2.0 feed for the public Pilot
// Protocol changelog. Hosted on GitHub Pages from the pilot-changelog
// repo (per `pilot-changelog/README.md`). RSS chosen over feed.json so
// we can stay on the standard library only — no JSON-feed dep needed.
//
// Declared as a var (not const) so tests can point at httptest.Server.
var changelogFeedURL = "https://pilot-protocol.github.io/pilot-changelog/feed.xml"

// rssDoc is the minimal RSS 2.0 shape we care about. Only fields needed
// for the human-readable + JSON output are decoded; unknown elements are
// ignored by encoding/xml.
type rssDoc struct {
	XMLName xml.Name `xml:"rss"`
	Channel rssChan  `xml:"channel"`
}

type rssChan struct {
	Title string    `xml:"title"`
	Items []rssItem `xml:"item"`
}

type rssItem struct {
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`
	GUID        string   `xml:"guid"`
	PubDate     string   `xml:"pubDate"`
	Description string   `xml:"description"`
	Categories  []string `xml:"category"`
}

// cmdUpdates fetches the changelog feed, parses it, and prints recent
// entries. Cached at ~/.pilot/updates-cache.xml for 5 minutes so a tight
// loop of `pilotctl updates` doesn't hammer the GH-Pages origin.
//
// Flags:
//
//	--count N        : how many entries to show (default 10)
//	--scope <name>   : filter by RSS <category> (e.g. protocol, networks, ops)
//	--refresh        : force a fresh fetch, bypass cache
//	(global) --json  : emit machine-readable JSON instead of human text
func cmdUpdates(args []string) {
	flags, _ := parseFlags(args)
	count := flagInt(flags, "count", 10)
	scope := strings.ToLower(flagString(flags, "scope", ""))
	refresh := flagBool(flags, "refresh")

	body, fromCache, err := fetchChangelogFeed(refresh)
	if err != nil {
		fatalCode("connection_failed", "fetch %s: %v", changelogFeedURL, err)
	}

	var doc rssDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		fatalCode("internal", "parse RSS: %v", err)
	}

	items := filterAndTruncate(doc.Channel.Items, scope, count)

	if jsonOutput {
		out := make([]map[string]interface{}, 0, len(items))
		for _, it := range items {
			out = append(out, map[string]interface{}{
				"title":       strings.TrimSpace(it.Title),
				"link":        strings.TrimSpace(it.Link),
				"guid":        strings.TrimSpace(it.GUID),
				"pub_date":    strings.TrimSpace(it.PubDate),
				"description": strings.TrimSpace(it.Description),
				"categories":  it.Categories,
			})
		}
		output(map[string]interface{}{
			"source":     changelogFeedURL,
			"from_cache": fromCache,
			"channel":    doc.Channel.Title,
			"count":      len(out),
			"updates":    out,
		})
		return
	}

	if len(items) == 0 {
		if scope != "" {
			fmt.Printf("no updates matching scope %q (try omitting --scope)\n", scope)
		} else {
			fmt.Println("no updates available")
		}
		return
	}
	if fromCache {
		fmt.Fprintf(os.Stderr, "(cached; --refresh to force re-fetch)\n")
	}
	fmt.Printf("%s — %s\n\n", doc.Channel.Title, changelogFeedURL)
	for _, it := range items {
		date := strings.TrimSpace(it.PubDate)
		// Trim RSS pubDate to YYYY-MM-DD for compactness when we can.
		if t, err := time.Parse(time.RFC1123Z, date); err == nil {
			date = t.Format("2006-01-02")
		} else if t, err := time.Parse(time.RFC1123, date); err == nil {
			date = t.Format("2006-01-02")
		}
		title := strings.TrimSpace(it.Title)
		fmt.Printf("• %s  %s\n", sAccent(date), title)
		if len(it.Categories) > 0 {
			fmt.Printf("    %s\n", sDim("["+strings.Join(it.Categories, ", ")+"]"))
		}
		if d := strings.TrimSpace(it.Description); d != "" {
			fmt.Printf("    %s\n", wrapText(collapseWhitespace(d), 100, 4))
		}
		if l := strings.TrimSpace(it.Link); l != "" {
			fmt.Printf("    %s\n", sDim(l))
		}
		fmt.Println()
	}
}

// wrapText word-wraps s at word boundaries so no line exceeds width
// columns (counting the indent), with a hanging indent: continuation
// lines are prefixed with `indent` spaces to line up under a first line
// the caller has already indented by the same amount. Words longer than
// a full line are emitted unbroken — never split mid-word.
func wrapText(s string, width, indent int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	pad := strings.Repeat(" ", indent)
	var b strings.Builder
	lineLen := indent // caller prints the first line's indent
	for i, w := range words {
		wl := len([]rune(w))
		switch {
		case i == 0:
			b.WriteString(w)
			lineLen += wl
		case lineLen+1+wl > width:
			b.WriteString("\n")
			b.WriteString(pad)
			b.WriteString(w)
			lineLen = indent + wl
		default:
			b.WriteString(" ")
			b.WriteString(w)
			lineLen += 1 + wl
		}
	}
	return b.String()
}

// filterAndTruncate applies the --scope category filter (case-insensitive,
// match-any-category) and the --count cap to a list of feed items. Both
// arguments are inert when zero/empty, so callers can pass scope="" or
// count=0 to skip either step.
func filterAndTruncate(items []rssItem, scope string, count int) []rssItem {
	if scope != "" {
		filtered := make([]rssItem, 0, len(items))
		for _, it := range items {
			for _, c := range it.Categories {
				if strings.EqualFold(c, scope) {
					filtered = append(filtered, it)
					break
				}
			}
		}
		items = filtered
	}
	if count > 0 && len(items) > count {
		items = items[:count]
	}
	return items
}

func collapseWhitespace(s string) string {
	// Cheap inline whitespace collapse — RSS descriptions often carry HTML
	// linebreaks that print badly in a terminal. We keep one space between
	// runs of any whitespace.
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	return strings.TrimSpace(b.String())
}

// cmdUpdate runs the updater once — checking for new releases, downloading and
// installing if available. When the daemon is not running (manual mode), it
// also re-runs skill install so newly installed binaries have matching skills.
//
// Flags:
//
//	--repo <name>   : GitHub owner/repo for releases (default: pilot-protocol/pilotprotocol)
//	--pin <tag>     : pin to a specific release tag (e.g. v1.10.5)
//	(global) --json : emit machine-readable JSON
func cmdUpdate(args []string) {
	// Auto-update control surface: `pilotctl update status|enable|disable`.
	// Bare `pilotctl update` (or with --repo/--pin flags) runs a one-shot
	// manual update, which works regardless of the auto-update setting.
	if len(args) >= 1 {
		switch args[0] {
		case "status":
			cmdAutoUpdateStatus()
			return
		case "enable", "on":
			cmdAutoUpdateSet(true)
			return
		case "disable", "off":
			cmdAutoUpdateSet(false)
			return
		}
	}
	flags, _ := parseFlags(args)
	repo := flagString(flags, "repo", "pilot-protocol/pilotprotocol")
	pin := flagString(flags, "pin", "")

	// Determine install directory: where the updater binary lives.
	updaterBin, err := findCompanionBinary("pilot-updater", "PILOT_UPDATER_BIN")
	if err != nil {
		fatalCode("internal", "cannot locate pilot-updater binary: %v", err)
	}
	installDir := filepath.Dir(updaterBin)

	u := updater.New(updater.Config{
		CheckInterval: 0, // unused for RunOnce
		Repo:          repo,
		InstallDir:    installDir,
		Version:       version,
		PinnedVersion: pin,
	})

	u.RunOnce()

	// A pinned older release may predate settings config.json holds.
	note := ""
	if bin := filepath.Join(installDir, "pilot-daemon"); pin != "" {
		if _, err := os.Stat(bin); err == nil {
			note = fitTransportToDaemon(bin)
		}
	}

	if jsonOutput {
		fields := map[string]interface{}{
			"install_dir": installDir,
			"repo":        repo,
			"pinned":      pin != "",
		}
		if note != "" {
			fields["note"] = note
		}
		outputOK(fields)
		return
	}
	fmt.Printf("Update check complete. Install dir: %s\n", installDir)
	if note != "" {
		fmt.Printf("Note: %s\n", note)
	}

	// In manual mode (no daemon running), re-run skill install so skills
	// match the (possibly updated) binaries.
	if !daemonRunning() {
		report, err := runTick()
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: skill install failed: %v\n", err)
		} else {
			c := report.Counts()
			fmt.Printf("Skills: %d files checked (%d up-to-date, %d installed, %d errors)\n",
				len(report.Outcomes),
				c[skillinject.ActionNoop],
				c[skillinject.ActionCreate]+c[skillinject.ActionRewrite],
				c[skillinject.ActionError])
		}
	}
}

// daemonRunning checks whether the daemon socket is reachable.
func daemonRunning() bool {
	sock := getSocket()
	d, err := driver.Connect(sock)
	if err != nil {
		return false
	}
	d.Close()
	return true
}

// fetchChangelogFeed returns the cached feed body if it's fresh (< 5 min)
// and `refresh` is false; otherwise hits the network. Returns
// (body, fromCache, err). Cache lives at ~/.pilot/updates-cache.xml so
// repeat invocations within the cache window are zero-network.
func fetchChangelogFeed(refresh bool) ([]byte, bool, error) {
	cachePath := updatesCachePath()
	if !refresh && cachePath != "" {
		if info, err := os.Stat(cachePath); err == nil {
			if time.Since(info.ModTime()) < 5*time.Minute {
				if data, err := os.ReadFile(cachePath); err == nil && len(data) > 0 {
					return data, true, nil
				}
			}
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, changelogFeedURL, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "pilotctl/"+version)
	req.Header.Set("Accept", "application/rss+xml, application/xml, text/xml")
	resp, err := client.Do(req)
	if err != nil {
		// Fall back to stale cache rather than hard-failing the user — an
		// offline laptop should still be able to see what we knew last.
		if cachePath != "" {
			if data, ferr := os.ReadFile(cachePath); ferr == nil && len(data) > 0 {
				return data, true, nil
			}
		}
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, false, err
	}
	if cachePath != "" {
		// Best-effort cache write; swallow errors so a read-only home
		// doesn't break the command.
		tmp := cachePath + ".tmp"
		if werr := os.WriteFile(tmp, body, 0644); werr == nil {
			_ = os.Rename(tmp, cachePath)
		}
	}
	return body, false, nil
}

func updatesCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	dir := filepath.Join(home, ".pilot")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ""
	}
	return filepath.Join(dir, "updates-cache.xml")
}
