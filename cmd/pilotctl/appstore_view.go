// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `pilotctl appstore view <app-id>` — the human-app-store detail page.
//
// Unlike `status` (which reads ONLY the local installed manifest) and
// `catalogue` (which reads ONLY the remote index), `view` merges three
// bands and labels their provenance:
//
//   - catalogue index   — teaser fields (publisher-attested, sha-anchored)
//   - metadata.json      — full listing: description, changelog, vendor…
//   - local manifest     — verified install facts: integrity, grants, methods
//
// It works whether or not the app is installed, and whether or not it is
// in the catalogue (a sideloaded app still renders from local facts). The
// two provenance bands are kept visually distinct so an agent never
// conflates marketing copy with verified integrity.

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pilot-protocol/app-store/pkg/manifest"

	"github.com/pilot-protocol/common/consent"
	"github.com/pilot-protocol/pilotprotocol/pkg/telemetry"
)

// installedAppFacts is the verified, local-only band of `view` — derived
// from the pinned manifest and on-disk state, never from the catalogue.
type installedAppFacts struct {
	Installed      bool     `json:"installed"`
	AppVersion     string   `json:"app_version,omitempty"`
	State          string   `json:"state,omitempty"` // ready | stopped | missing-binary | sha256-mismatch | corrupt-manifest
	IntegrityOK    bool     `json:"integrity_ok"`
	InstalledBytes int64    `json:"installed_bytes,omitempty"`
	Protection     string   `json:"protection,omitempty"`
	Methods        []string `json:"methods,omitempty"`
	Grants         []string `json:"grants,omitempty"`
	ManifestValid  bool     `json:"manifest_valid"`
}

// gatherInstalledFacts reads the pinned manifest for appID and computes
// its on-disk state. Returns nil when the app is not installed — `view`
// treats that as "catalogue-only", not an error. This mirrors the
// integrity logic in cmdAppStoreStatus without disturbing it.
func gatherInstalledFacts(appID string) *installedAppFacts {
	dir := filepath.Join(appStoreRoot(), appID)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil // not installed
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		return &installedAppFacts{Installed: true, State: "corrupt-manifest"}
	}
	f := &installedAppFacts{
		Installed:     true,
		AppVersion:    m.AppVersion,
		Protection:    m.Protection,
		Methods:       append([]string(nil), m.Exposes...),
		ManifestValid: len(m.Validate()) == 0,
	}
	for _, g := range m.Grants {
		f.Grants = append(f.Grants, fmt.Sprintf("%s:%s", g.Cap, g.Target))
	}
	binPath := filepath.Join(dir, m.Binary.Path)
	state := "stopped"
	if info, err := os.Stat(binPath); err != nil {
		state = "missing-binary"
	} else {
		f.InstalledBytes = info.Size()
		if sha256File(binPath) == m.Binary.SHA256 {
			f.IntegrityOK = true
			if _, err := os.Stat(filepath.Join(dir, "app.sock")); err == nil {
				state = "ready"
			}
		} else {
			state = "sha256-mismatch"
		}
	}
	f.State = state
	return f
}

// appViewReport is the merged, flattened view — the `--json` shape and the
// source of truth for the human renderer. Detail (publisher) fields and
// the Install (verified) band stay separate so consumers can tell them
// apart. Sources records which bands actually contributed.
type appViewReport struct {
	ID             string             `json:"id"`
	DisplayName    string             `json:"display_name,omitempty"`
	Version        string             `json:"version,omitempty"`
	Tagline        string             `json:"tagline,omitempty"`
	Description    string             `json:"description,omitempty"`
	Vendor         *mdVendor          `json:"vendor,omitempty"`
	Homepage       string             `json:"homepage,omitempty"`
	SourceURL      string             `json:"source_url,omitempty"`
	License        string             `json:"license,omitempty"`
	Categories     []string           `json:"categories,omitempty"`
	Keywords       []string           `json:"keywords,omitempty"`
	Screenshots    []mdScreenshot     `json:"screenshots,omitempty"`
	BundleBytes    int64              `json:"bundle_bytes,omitempty"`
	InstalledBytes int64              `json:"installed_bytes,omitempty"`
	Methods        []mdMethod         `json:"methods,omitempty"`
	Changelog      []mdChangelog      `json:"changelog,omitempty"`
	Compat         *mdCompat          `json:"compat,omitempty"`
	Links          []mdLink           `json:"links,omitempty"`
	Reviews        *mdReviews         `json:"reviews"` // null until the reviews service lands
	InCatalogue    bool               `json:"in_catalogue"`
	DetailVerified bool               `json:"detail_verified"` // metadata.json fetched AND sha-pinned
	Install        *installedAppFacts `json:"install,omitempty"`
	PublishedAt    string             `json:"published_at,omitempty"`
	UpdatedAt      string             `json:"updated_at,omitempty"`
	Sources        []string           `json:"sources"`
}

func cmdAppStoreView(args []string) {
	allChangelog := false
	appID := ""
	for _, a := range args {
		switch a {
		case "--all-changelog", "--all":
			allChangelog = true
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: pilotctl appstore view <app-id> [--all-changelog]")
			return
		default:
			if strings.HasPrefix(a, "-") {
				fatalHint("invalid_argument",
					"usage: pilotctl appstore view <app-id> [--all-changelog]",
					"unknown flag: %s", a)
			}
			if appID == "" {
				appID = a
			}
		}
	}
	if appID == "" {
		fatalHint("invalid_argument",
			"usage: pilotctl appstore view <app-id> [--all-changelog]",
			"missing app id")
	}

	// Local install facts first — these work offline and are the only band
	// for a sideloaded app.
	facts := gatherInstalledFacts(appID)

	// Catalogue entry + detail doc, best-effort. A failed catalogue lookup
	// must not block `view` for an installed app.
	var entry *catalogueEntry
	var meta *appMetadata
	if c, err := loadCatalogue(); err == nil {
		for i := range c.Apps {
			if c.Apps[i].ID == appID {
				entry = &c.Apps[i]
				break
			}
		}
		if entry != nil && entry.RenamedTo != "" {
			fmt.Fprintf(os.Stderr, "warn: app %q was renamed to %q; see `pilotctl appstore view %s`\n", appID, entry.RenamedTo, entry.RenamedTo)
		}
		if entry != nil {
			if m, err := loadAppMetadata(*entry); err != nil {
				fmt.Fprintf(os.Stderr, "warn: could not load detail metadata: %v\n", err)
			} else {
				meta = m
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "warn: catalogue lookup failed (%v); showing local facts only\n", err)
	}

	if entry == nil && facts == nil {
		fatalHint("invalid_argument",
			"try `pilotctl appstore catalogue` (installable) or `pilotctl appstore list` (installed)",
			"app %q not found in catalogue or install root", appID)
	}

	// Emit a telemetry event for the detail view.
	// Consent-gated (telemetry flag, default on). Best-effort: a send
	// failure is logged but not fatal — the view already resolved and rendered below.
	{
		home, _ := os.UserHomeDir()
		if consent.GetConsent(home, "telemetry") {
			url := os.Getenv("PILOT_TELEMETRY_URL")
			if url == "" {
				url = telemetry.DefaultEndpoint
			}
			payload, _ := json.Marshal(map[string]string{
				"app_id": appID,
			})
			identityPath := configDir() + "/identity.json"
			client := telemetry.NewClientFromIdentity(url, identityPath, nodeIDFromDaemon())
			err := client.Send(telemetry.Event{
				Kind:    "appstore_view",
				TS:      time.Now().UTC().Format(time.RFC3339),
				Payload: payload,
			})
			if err != nil {
				slog.Warn("telemetry send failed, view still shown", "app", appID, "err", err)
			}
		}
	}

	report := buildAppViewReport(appID, entry, meta, facts)
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
		return
	}
	renderAppView(report, allChangelog)
}

// buildAppViewReport merges the bands with a clear precedence: the detail
// doc (richest, publisher-authored) wins over the index teaser; verified
// install facts are layered on top and never overwrite publisher copy
// except for the on-disk installed size.
func buildAppViewReport(appID string, entry *catalogueEntry, meta *appMetadata, facts *installedAppFacts) appViewReport {
	r := appViewReport{ID: appID}
	var sources []string

	if entry != nil {
		r.InCatalogue = true
		sources = append(sources, "catalogue")
		r.Version = entry.Version
		r.DisplayName = entry.DisplayName
		r.Description = entry.Description // one-line teaser, overridden by detail below
		if entry.Vendor != "" {
			r.Vendor = &mdVendor{Name: entry.Vendor}
		}
		r.Categories = entry.Categories
		r.License = entry.License
		r.SourceURL = entry.SourceURL
		r.BundleBytes = entry.BundleSize
	}

	if meta != nil {
		sources = append(sources, "metadata")
		if entry != nil {
			r.DetailVerified = metadataPinned(*entry)
		}
		if meta.DisplayName != "" {
			r.DisplayName = meta.DisplayName
		}
		r.Tagline = meta.Tagline
		if meta.DescriptionMD != "" {
			r.Description = meta.DescriptionMD
		}
		if meta.Vendor != nil {
			r.Vendor = meta.Vendor
		}
		if meta.Homepage != "" {
			r.Homepage = meta.Homepage
		}
		if meta.SourceURL != "" {
			r.SourceURL = meta.SourceURL
		}
		if meta.License != "" {
			r.License = meta.License
		}
		if len(meta.Categories) > 0 {
			r.Categories = meta.Categories
		}
		r.Keywords = meta.Keywords
		r.Screenshots = meta.Screenshots
		r.Methods = meta.Methods
		r.Changelog = meta.Changelog
		r.Compat = meta.Compat
		r.Links = meta.Links
		r.Reviews = meta.Reviews
		if meta.Size != nil {
			if meta.Size.BundleBytes > 0 {
				r.BundleBytes = meta.Size.BundleBytes
			}
			if meta.Size.InstalledBytes > 0 {
				r.InstalledBytes = meta.Size.InstalledBytes
			}
		}
		r.PublishedAt = meta.PublishedAt
		r.UpdatedAt = meta.UpdatedAt
	}

	if facts != nil {
		sources = append(sources, "local-manifest")
		r.Install = facts
		if facts.InstalledBytes > 0 {
			r.InstalledBytes = facts.InstalledBytes // real on-disk size wins
		}
		if r.Version == "" {
			r.Version = facts.AppVersion
		}
		// Fall back to manifest-declared (verified) methods when the detail
		// doc didn't enumerate them.
		if len(r.Methods) == 0 {
			for _, name := range facts.Methods {
				r.Methods = append(r.Methods, mdMethod{Name: name})
			}
		}
	}

	r.Sources = sources
	return r
}

func renderAppView(r appViewReport, allChangelog bool) {
	// Title line.
	title := r.ID
	if r.DisplayName != "" {
		title = fmt.Sprintf("%s  (%s)", r.DisplayName, r.ID)
	}
	if r.Version != "" {
		title = fmt.Sprintf("%s  v%s", title, r.Version)
	}
	fmt.Println(title)

	// Subtitle: vendor · categories · license.
	var sub []string
	if r.Vendor != nil && r.Vendor.Name != "" {
		sub = append(sub, r.Vendor.Name)
	}
	if len(r.Categories) > 0 {
		sub = append(sub, strings.Join(r.Categories, ", "))
	}
	if r.License != "" {
		sub = append(sub, r.License)
	}
	if len(sub) > 0 {
		fmt.Println(strings.Join(sub, " · "))
	}
	if r.Tagline != "" {
		fmt.Println(r.Tagline)
	}
	fmt.Println()

	// Facts block (label width 14, matching `status`).
	if r.Install != nil {
		integ := "integrity OK"
		if !r.Install.IntegrityOK {
			integ = "integrity NOT verified"
		}
		fmt.Printf("  %-12s yes (%s, %s)\n", "installed:", r.Install.State, integ)
	} else {
		fmt.Printf("  %-12s no\n", "installed:")
	}
	if r.BundleBytes > 0 || r.InstalledBytes > 0 {
		var parts []string
		if r.BundleBytes > 0 {
			parts = append(parts, "download "+formatBytes(uint64(r.BundleBytes)))
		}
		if r.InstalledBytes > 0 {
			parts = append(parts, "installed "+formatBytes(uint64(r.InstalledBytes)))
		}
		fmt.Printf("  %-12s %s\n", "size:", strings.Join(parts, "   "))
	}
	if r.SourceURL != "" {
		fmt.Printf("  %-12s %s\n", "source:", r.SourceURL)
	}
	if r.Homepage != "" {
		fmt.Printf("  %-12s %s\n", "homepage:", r.Homepage)
	}
	if r.Vendor != nil && r.Vendor.Name != "" {
		v := r.Vendor.Name
		if r.Vendor.Contact != "" {
			v = fmt.Sprintf("%s <%s>", v, r.Vendor.Contact)
		}
		fmt.Printf("  %-12s %s\n", "vendor:", v)
	}
	if r.Compat != nil && r.Compat.MinPilotVersion != "" {
		fmt.Printf("  %-12s pilot >= %s\n", "requires:", r.Compat.MinPilotVersion)
	}

	// Description.
	if r.Description != "" {
		fmt.Printf("\nDescription\n")
		for _, ln := range strings.Split(strings.TrimRight(r.Description, "\n"), "\n") {
			fmt.Printf("  %s\n", ln)
		}
	}

	// Methods.
	if len(r.Methods) > 0 {
		fmt.Printf("\nMethods (%d)\n", len(r.Methods))
		for _, m := range r.Methods {
			if m.Summary != "" {
				fmt.Printf("  %-24s %s\n", m.Name, m.Summary)
			} else {
				fmt.Printf("  %s\n", m.Name)
			}
		}
	}

	// Changelog.
	if len(r.Changelog) > 0 {
		shown := r.Changelog
		if allChangelog {
			fmt.Printf("\nChangelog\n")
		} else {
			latest := shown[0]
			hdr := "What's new"
			if latest.Version != "" {
				hdr = "What's new in " + latest.Version
			}
			if latest.Date != "" {
				hdr = fmt.Sprintf("%s  (%s)", hdr, latest.Date)
			}
			fmt.Printf("\n%s\n", hdr)
			shown = shown[:1]
		}
		for _, c := range shown {
			if allChangelog {
				head := c.Version
				if c.Date != "" {
					head = fmt.Sprintf("%s  (%s)", head, c.Date)
				}
				fmt.Printf("  %s\n", head)
			}
			for _, n := range c.Notes {
				fmt.Printf("    • %s\n", n)
			}
		}
		if !allChangelog && len(r.Changelog) > 1 {
			fmt.Printf("  (use --all-changelog for full history)\n")
		}
	}

	// Permissions — from the verified manifest only.
	if r.Install != nil && len(r.Install.Grants) > 0 {
		fmt.Printf("\nPermissions (granted at install)\n")
		for _, g := range r.Install.Grants {
			fmt.Printf("  %s\n", g)
		}
	}

	// Links.
	if len(r.Links) > 0 {
		fmt.Printf("\nLinks\n")
		for _, l := range r.Links {
			fmt.Printf("  %-12s %s\n", l.Label, l.URL)
		}
	}

	// Reviews — reserved.
	fmt.Printf("\nReviews: ")
	if r.Reviews != nil && r.Reviews.Count > 0 {
		fmt.Printf("%.1f from %d (★ distribution %v)\n", r.Reviews.Average, r.Reviews.Count, r.Reviews.Distribution)
	} else {
		fmt.Printf("n/a (community reviews not yet available)\n")
	}

	// Provenance + next step.
	detail := ""
	if sliceHas(r.Sources, "metadata") {
		if r.DetailVerified {
			detail = " (detail sha-verified)"
		} else {
			detail = " (detail UNVERIFIED — no sha pin)"
		}
	}
	fmt.Printf("\nSources: %s%s\n", strings.Join(r.Sources, ", "), detail)
	if r.Install == nil && r.InCatalogue {
		fmt.Printf("Install: pilotctl appstore install %s\n", r.ID)
	}
}

func sliceHas(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
