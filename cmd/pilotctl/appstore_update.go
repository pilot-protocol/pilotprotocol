package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pilot-protocol/app-store/pkg/manifest"
)

// installedApp is one app present in the install root, identified by the
// authoritative on-disk record: its manifest's id + app_version.
type installedApp struct {
	ID         string
	AppVersion string
	// BundleSHA is the catalogue bundle sha this app was installed from, recorded
	// at install into $APP/.bundle-sha256. Empty for a sideload or an app
	// installed before this was recorded (the pre-feature fleet) — in which case
	// a same-version republish can't be detected until the next install/upgrade
	// writes the marker, and only a version bump flags it. That graceful
	// degradation is deliberate: no marker → behave exactly as before.
	BundleSHA string
}

// bundleSHAMarker records, in an installed app dir, the catalogue bundle sha the
// app was installed from — the signal `outdated` uses to catch a same-version
// republish.
const bundleSHAMarker = ".bundle-sha256"

// recordInstalledBundleSHA writes the catalogue's host-appropriate bundle sha for
// appID into the installed app dir. Best-effort: a failure just means a
// same-version republish won't be auto-detected for this app (it still installs
// fine and version bumps are still caught).
func recordInstalledBundleSHA(appDir, appID string) {
	c, err := loadCatalogue()
	if err != nil {
		return
	}
	for i := range c.Apps {
		if c.Apps[i].ID != appID {
			continue
		}
		_, sha, err := c.Apps[i].resolveBundle()
		if err != nil || sha == "" {
			return
		}
		out, err := resolveUnder(appStoreRoot(), filepath.Base(appDir))
		if err != nil {
			return
		}
		_ = os.WriteFile(filepath.Join(out, bundleSHAMarker), []byte(sha), 0o600) // #nosec G304 G703 -- path re-confined to the install root by resolveUnder
		return
	}
}

// scanInstalledApps reads the install root and returns each installed app's id
// and version straight from its manifest.json (the version of record). Apps with
// an unreadable/invalid manifest are skipped — they surface as broken in `list`.
func scanInstalledApps() ([]installedApp, error) {
	root := appStoreRoot()
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var apps []installedApp
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, e.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		m, err := manifest.Parse(raw)
		if err != nil {
			continue
		}
		// Same confinement as the manifest read just above: root is the install
		// root and e.Name() a direntry within it, joined to a fixed marker name.
		bsha, _ := os.ReadFile(filepath.Join(root, e.Name(), bundleSHAMarker)) // #nosec G304 G703 -- install-root + direntry + constant filename
		apps = append(apps, installedApp{
			ID: m.ID, AppVersion: m.AppVersion, BundleSHA: strings.TrimSpace(string(bsha)),
		})
	}
	sort.Slice(apps, func(i, j int) bool { return apps[i].ID < apps[j].ID })
	return apps, nil
}

// outdatedApp pairs an installed app with the newer version the catalogue offers.
type outdatedApp struct {
	ID        string `json:"id"`
	Installed string `json:"installed"`
	Available string `json:"available"`
	// Reason is why the app is outdated: "version" (a newer app_version) or
	// "rebuilt" (a same-version republish — the catalogue bundle changed under a
	// version we already have). Both upgrade the same way.
	Reason string `json:"reason,omitempty"`
	// RenamedTo is set when the installed id is a rename tombstone. Such an app
	// is reported but never auto-upgraded: the new id has its own publisher key
	// and method namespace, so moving to it is the operator's call.
	RenamedTo string `json:"renamed_to,omitempty"`
}

// findOutdated cross-references installed apps against the signed catalogue and
// returns those whose catalogue version is strictly newer than what's installed.
// This is the missing client link: install records a version, the catalogue
// advertises one, but nothing compared them until now.
func findOutdated() ([]outdatedApp, error) {
	installed, err := scanInstalledApps()
	if err != nil {
		return nil, err
	}
	cat, err := loadCatalogue()
	if err != nil {
		return nil, err
	}
	entries := make(map[string]catalogueEntry, len(cat.Apps))
	for _, e := range cat.Apps {
		entries[e.ID] = e
	}
	var out []outdatedApp
	for _, a := range installed {
		e, ok := entries[a.ID]
		if !ok {
			continue
		}
		if e.RenamedTo != "" {
			out = append(out, outdatedApp{ID: a.ID, Installed: a.AppVersion, Available: e.RenamedTo, Reason: "renamed", RenamedTo: e.RenamedTo})
			continue
		}
		// resolveBundle picks THIS host's platform bundle, matching what install
		// recorded; an error/empty sha just disables republish detection for the app.
		catBundleSHA := ""
		if _, sha, err := e.resolveBundle(); err == nil {
			catBundleSHA = sha
		}
		if reason := outdatedReason(a.AppVersion, e.Version, a.BundleSHA, catBundleSHA); reason != "" {
			out = append(out, outdatedApp{ID: a.ID, Installed: a.AppVersion, Available: e.Version, Reason: reason})
		}
	}
	return out, nil
}

// outdatedReason decides whether an installed app is outdated relative to the
// catalogue, and why. It is the pure core of findOutdated, split out so the
// version-vs-rebuilt logic is testable without a signed catalogue.
//
//   - "version": the catalogue has a newer app_version.
//   - "rebuilt": SAME app_version, but the catalogue bundle sha differs from the
//     one recorded at install — a republished adapter (the aegis argv-fix shape)
//     that a version compare alone misses. Requires both shas; a pre-feature
//     install with no recorded sha degrades to version-only detection.
//   - "": up to date (or not enough information to say otherwise).
func outdatedReason(installedVer, catVer, installedBundleSHA, catBundleSHA string) string {
	switch cmp := semverCompare(catVer, installedVer); {
	case cmp > 0:
		return "version"
	case cmp == 0 && installedBundleSHA != "" && catBundleSHA != "" && catBundleSHA != installedBundleSHA:
		return "rebuilt"
	default:
		return ""
	}
}

// cmdAppStoreOutdated lists installed apps that have a newer version in the
// catalogue. Exit status is 0 even when some are outdated (it's a report); the
// JSON form is stable for scripting an auto-upgrade.
func cmdAppStoreOutdated(_ []string) {
	out, err := findOutdated()
	if err != nil {
		fatalHint("io_error", "is the install root present and the catalogue reachable?", "outdated: %v", err)
	}
	if jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	if len(out) == 0 {
		fmt.Println("all installed apps are up to date")
		return
	}
	fmt.Printf("%-32s %-12s %-12s %s\n", "APP", "INSTALLED", "AVAILABLE", "WHY")
	upgradable := 0
	for _, o := range out {
		if o.RenamedTo == "" {
			upgradable++
		}
		why := o.Reason
		switch why {
		case "rebuilt":
			why = "rebuilt (same version, new bundle)"
		case "renamed":
			why = fmt.Sprintf("renamed: install %s, then uninstall %s", o.RenamedTo, o.ID)
		}
		fmt.Printf("%-32s %-12s %-12s %s\n", o.ID, o.Installed, o.Available, why)
	}
	if upgradable > 0 {
		fmt.Printf("\nupgrade with: pilotctl appstore upgrade <id>   (or --all)\n")
	}
}

// cmdAppStoreUpgrade upgrades one app (or --all outdated apps) to the catalogue's
// current version by re-running the same verified install with --force. The
// supervisor detects the on-disk version bump on its next rescan, refuses any
// downgrade, and restarts the app at the new version. Reusing install means the
// upgrade goes through the exact catalogue-sha + manifest-sha + trust-anchor
// checks a fresh install does — no second, weaker code path.
func cmdAppStoreUpgrade(args []string) {
	all := false
	var id string
	for _, a := range args {
		switch a {
		case "--all":
			all = true
		case "-h", "--help":
			fmt.Fprintln(os.Stderr, "usage: pilotctl appstore upgrade <id> | --all")
			return
		default:
			id = a
		}
	}
	if !all && id == "" {
		fatalHint("invalid_argument", "usage: pilotctl appstore upgrade <id> | --all", "missing app id (or --all)")
	}

	outdated, err := findOutdated()
	if err != nil {
		fatalHint("io_error", "is the install root present and the catalogue reachable?", "upgrade: %v", err)
	}
	byID := make(map[string]outdatedApp, len(outdated))
	for _, o := range outdated {
		byID[o.ID] = o
	}

	var targets []outdatedApp
	if all {
		skipped := 0
		for _, o := range outdated {
			if o.RenamedTo != "" {
				// Never migrate across a rename on its own: the hourly updater
				// runs --all, and the new id has its own publisher key and
				// method names, so switching is the operator's call.
				fmt.Printf("skip %s: renamed to %s (install it with `pilotctl appstore install %s`, then `pilotctl appstore uninstall %s --yes`)\n", o.ID, o.RenamedTo, o.RenamedTo, o.ID)
				skipped++
				continue
			}
			targets = append(targets, o)
		}
		if len(targets) == 0 {
			if skipped > 0 {
				fmt.Println("nothing else to upgrade")
			} else {
				fmt.Println("all installed apps are up to date")
			}
			return
		}
	} else {
		o, ok := byID[id]
		if !ok {
			// Either not installed, not in the catalogue, or already current.
			fmt.Printf("%s is already up to date (or not a catalogue app)\n", id)
			return
		}
		if o.RenamedTo != "" {
			fatalHint("invalid_argument",
				fmt.Sprintf("install the new id: pilotctl appstore install %s (then: pilotctl appstore uninstall %s --yes)", o.RenamedTo, o.ID),
				"%s was renamed to %s; upgrade does not switch app ids", o.ID, o.RenamedTo)
		}
		targets = []outdatedApp{o}
	}

	var failed []string
	for _, o := range targets {
		fmt.Printf("==> upgrading %s %s → %s\n", o.ID, o.Installed, o.Available)
		// --force: install over the existing app dir; the supervisor applies the
		// version bump (and refuses a downgrade) on its next rescan. The app's
		// state (keys, data.db, secrets, cap-state, audit log) is carried into
		// the new install and the replaced dir is kept as a backup — see
		// appstore_state.go. This is the path the hourly updater drives.
		install := func() { cmdAppStoreInstall([]string{o.ID, "--force"}) }
		if len(targets) == 1 {
			install()
			continue
		}
		// One app that cannot be upgraded (its error is printed, and it is
		// left exactly as it was) must not stop the upgrade of every app
		// after it, security fixes included.
		if f := runTrappingFatal(install); f != nil {
			failed = append(failed, o.ID)
			fmt.Fprintf(os.Stderr, "==> %s was not upgraded (%s) and stays at %s; continuing with the remaining apps\n", o.ID, f.Code, o.Installed)
		}
	}
	if len(failed) > 0 {
		fatalHint("upgrade_failed",
			"every app that failed is unchanged and its error is printed above; fix the cause and re-run `pilotctl appstore upgrade <id>`",
			"upgraded %s; %d failed: %s", pluralApps(len(targets)-len(failed)), len(failed), strings.Join(failed, ", "))
	}
	fmt.Printf("\nupgraded %s\n", strings.TrimSpace(pluralApps(len(targets))))
}

func pluralApps(n int) string {
	if n == 1 {
		return "1 app"
	}
	return fmt.Sprintf("%d apps", n)
}

// semverCompare compares two MAJOR.MINOR.PATCH versions, ignoring any
// prerelease/build suffix beyond the numeric core. Returns -1, 0, or 1. A
// missing component counts as 0 (so "1.2" == "1.2.0").
func semverCompare(a, b string) int {
	ap := semverParts(a)
	bp := semverParts(b)
	for i := 0; i < 3; i++ {
		if ap[i] != bp[i] {
			if ap[i] < bp[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func semverParts(v string) [3]int {
	core := v
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		core = core[:i]
	}
	var out [3]int
	for i, s := range strings.SplitN(core, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}
