// SPDX-License-Identifier: AGPL-3.0-or-later

// Command catalogue-lint gates changes to catalogue/catalogue.json in CI. It
// compares the catalogue at the PR's base with the PR's head and fails on:
//
//  1. Stateful-app release freeze (overridable). Every node upgrades its
//     installed apps hourly (`pilotctl appstore upgrade --all`) with the
//     pilotctl it already has. Until a node runs a pilotctl that carries the
//     app-state fix, that upgrade DELETES the app's saved state: the wallet's
//     EVM key and payment DB, smol's secrets, per-app identities. So any update
//     of a stateful app (a new version, or a same-version republish, which
//     newer pilotctl also upgrades to) is refused unless it is approved in
//     catalogue/stateful-apps.json or the PR carries the approval label. An app
//     is stateful when it is listed in stateful-apps.json or when its bundle
//     manifest (old or new) grants fs.write or key.sign.
//
//  2. Bundle checks (not overridable) for every added or changed entry: each
//     published bundle downloads, matches its pinned sha256, carries a manifest
//     whose id and app_version match the entry and whose binary matches its
//     pinned sha256, and its binary can run on the platform it is published
//     for. A legacy single-bundle entry (no `bundles` map) is installed by every
//     platform, so it must not ship a native binary at all.
//
// Usage:
//
//	catalogue-lint --base base.json --head catalogue/catalogue.json \
//	  [--policy catalogue/stateful-apps.json] [--allow-stateful-bumps] [--offline]
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Platforms pilotctl resolves a `bundles` entry for (see resolveBundle in
// cmd/pilotctl/appstore_catalogue.go) and the release matrix builds.
var knownPlatforms = []string{"darwin/amd64", "darwin/arm64", "linux/amd64", "linux/arm64"}

const (
	approvalLabel  = "catalogue:stateful-bump-approved"
	maxBundleBytes = 128 << 20 // same cap pilotctl applies to a download
	maxEntryBytes  = 64 << 20  // same per-file cap pilotctl applies to an extract
)

type catalogue struct {
	Version int     `json:"version"`
	Apps    []entry `json:"apps"`
}

type entry struct {
	ID        string             `json:"id"`
	Version   string             `json:"version"`
	BundleURL string             `json:"bundle_url"`
	BundleSHA string             `json:"bundle_sha256"`
	Bundles   map[string]variant `json:"bundles,omitempty"`
	RenamedTo string             `json:"renamed_to,omitempty"`
}

type variant struct {
	BundleURL string `json:"bundle_url"`
	BundleSHA string `json:"bundle_sha256"`
}

type policy struct {
	StatefulApps  []string   `json:"stateful_apps"`
	ApprovedBumps []approval `json:"approved_bumps"`
}

type approval struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

type manifest struct {
	ID         string `json:"id"`
	AppVersion string `json:"app_version"`
	Binary     struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"binary"`
	Grants []struct {
		Cap    string `json:"cap"`
		Target string `json:"target"`
	} `json:"grants"`
}

// finding is one lint result. Warnings never fail the run.
type finding struct {
	Warning bool
	AppID   string
	Title   string
	Msg     string
}

type linter struct {
	policy    policy
	allowBump bool
	offline   bool
	fetch     func(rawURL string) (io.ReadCloser, error)
	cache     map[string]*bundleInfo
}

type bundleInfo struct {
	manifest   *manifest
	binary     binaryFormat
	binarySHA  string
	fetchError error
}

func main() {
	base := flag.String("base", "", "catalogue.json at the PR base (omit or empty file: every entry is new)")
	head := flag.String("head", "catalogue/catalogue.json", "catalogue.json at the PR head")
	policyPath := flag.String("policy", "", "stateful-apps.json (default: beside --head)")
	allow := flag.Bool("allow-stateful-bumps", false, "the PR carries the "+approvalLabel+" label: report stateful updates as warnings")
	offline := flag.Bool("offline", false, "skip bundle downloads (stateful detection uses the policy list only; bundle checks are skipped)")
	flag.Parse()

	if *policyPath == "" {
		*policyPath = filepath.Join(filepath.Dir(*head), "stateful-apps.json")
	}
	l, err := newLinter(*policyPath, *allow, *offline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalogue-lint: %v\n", err)
		os.Exit(2)
	}
	baseCat, err := loadCatalogue(*base, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalogue-lint: base: %v\n", err)
		os.Exit(2)
	}
	headCat, err := loadCatalogue(*head, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "catalogue-lint: head: %v\n", err)
		os.Exit(2)
	}
	findings := l.lint(baseCat, headCat)
	os.Exit(report(os.Stdout, findings, os.Getenv("GITHUB_ACTIONS") == "true"))
}

func newLinter(policyPath string, allow, offline bool) (*linter, error) {
	raw, err := os.ReadFile(policyPath) // #nosec G304 -- CI tool reading the repo's own policy file
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	var p policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", policyPath, err)
	}
	return &linter{policy: p, allowBump: allow, offline: offline, fetch: openURL, cache: map[string]*bundleInfo{}}, nil
}

func loadCatalogue(p string, optional bool) (*catalogue, error) {
	if p == "" && optional {
		return &catalogue{}, nil
	}
	raw, err := os.ReadFile(p) // #nosec G304 -- CI tool reading a catalogue it was pointed at
	if err != nil {
		return nil, err
	}
	if optional && len(strings.TrimSpace(string(raw))) == 0 {
		return &catalogue{}, nil
	}
	var c catalogue
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &c, nil
}

// lint runs every check and returns the findings sorted by app id.
func (l *linter) lint(base, head *catalogue) []finding {
	var out []finding
	for _, a := range l.policy.ApprovedBumps {
		if a.ID == "" || a.Version == "" || strings.TrimSpace(a.Reason) == "" || strings.TrimSpace(a.ApprovedBy) == "" {
			out = append(out, finding{AppID: a.ID, Title: "incomplete stateful-bump approval",
				Msg: fmt.Sprintf("approved_bumps entry %+v needs id, version, reason and approved_by", a)})
		}
	}
	baseByID := map[string]entry{}
	for _, e := range base.Apps {
		baseByID[e.ID] = e
	}
	seen := map[string]bool{}
	for _, e := range head.Apps {
		if seen[e.ID] {
			out = append(out, finding{AppID: e.ID, Title: "duplicate catalogue id", Msg: fmt.Sprintf("%s appears more than once in the catalogue", e.ID)})
		}
		seen[e.ID] = true
		old, existed := baseByID[e.ID]
		if existed && reflect.DeepEqual(old, e) {
			continue // untouched entry
		}
		if tombstone(e) {
			continue // not installable; nothing to check
		}
		out = append(out, l.checkBundles(e)...)
		if existed {
			if reason := updateTrigger(old, e); reason != "" {
				out = append(out, l.checkStatefulUpdate(old, e, reason)...)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].AppID < out[j].AppID })
	return out
}

func tombstone(e entry) bool { return e.BundleURL == "" && len(e.Bundles) == 0 }

// resolved mirrors pilotctl's resolveBundle for one platform.
func resolved(e entry, plat string) variant {
	if len(e.Bundles) == 0 {
		return variant{e.BundleURL, e.BundleSHA}
	}
	return e.Bundles[plat]
}

// updateTrigger says why nodes that have base installed will reinstall head,
// or "" when they will not. A new version triggers every pilotctl; a changed
// bundle sha under the same version triggers pilotctl's same-version
// republish detection. A platform that had no bundle has no installs to touch.
func updateTrigger(base, head entry) string {
	if base.Version != head.Version {
		return fmt.Sprintf("version %s → %s", base.Version, head.Version)
	}
	var plats []string
	for _, p := range knownPlatforms {
		b, h := resolved(base, p), resolved(head, p)
		if b.BundleSHA != "" && h.BundleSHA != "" && b.BundleSHA != h.BundleSHA {
			plats = append(plats, p)
		}
	}
	if len(plats) > 0 {
		return fmt.Sprintf("same-version republish of %s (new bundle for %s)", head.Version, strings.Join(plats, ", "))
	}
	return ""
}

func (l *linter) checkStatefulUpdate(base, head entry, trigger string) []finding {
	why := l.statefulReason(base, head)
	if why == "" {
		return nil
	}
	for _, a := range l.policy.ApprovedBumps {
		if a.ID == head.ID && a.Version == head.Version && strings.TrimSpace(a.Reason) != "" && strings.TrimSpace(a.ApprovedBy) != "" {
			return []finding{{Warning: true, AppID: head.ID, Title: "approved stateful-app update",
				Msg: fmt.Sprintf("%s: %s is approved in stateful-apps.json by %s (%s)", head.ID, trigger, a.ApprovedBy, a.Reason)}}
		}
	}
	msg := fmt.Sprintf("%s: %s updates a stateful app (%s). Every node applies it within the hour via `pilotctl appstore upgrade --all`, "+
		"and a node whose pilotctl predates the app-state fix DELETES the app's saved state (keys, data.db, secrets) while doing so. "+
		"Hold this release until the fleet runs the fixed pilotctl, or approve it: add {\"id\":%q,\"version\":%q,\"reason\":...,\"approved_by\":...} "+
		"to approved_bumps in catalogue/stateful-apps.json, or apply the PR label %q. See catalogue/README.md.",
		head.ID, trigger, why, head.ID, head.Version, approvalLabel)
	if l.allowBump {
		return []finding{{Warning: true, AppID: head.ID, Title: "stateful-app update (approved by label)", Msg: msg}}
	}
	return []finding{{AppID: head.ID, Title: "stateful-app update needs approval", Msg: msg}}
}

// statefulReason returns why an app counts as stateful, or "".
func (l *linter) statefulReason(base, head entry) string {
	for _, id := range l.policy.StatefulApps {
		if id == head.ID {
			return "listed in catalogue/stateful-apps.json"
		}
	}
	if l.offline {
		return ""
	}
	for _, e := range []entry{base, head} {
		v, plat, ok := anyBundle(e)
		if !ok {
			continue
		}
		info := l.inspect(v)
		if info.fetchError != nil {
			return fmt.Sprintf("its %s bundle for %s could not be inspected (%v), so it is treated as stateful", e.Version, plat, info.fetchError)
		}
		if g := persistentGrant(info.manifest); g != "" {
			return fmt.Sprintf("its %s manifest grants %s", e.Version, g)
		}
	}
	return ""
}

// persistentGrant names the first grant through which an app keeps state in
// $APP across restarts: fs.write (files it writes) or key.sign (its identity key).
func persistentGrant(m *manifest) string {
	for _, g := range m.Grants {
		if g.Cap == "fs.write" || g.Cap == "key.sign" {
			return g.Cap + " " + g.Target
		}
	}
	return ""
}

func anyBundle(e entry) (variant, string, bool) {
	if len(e.Bundles) == 0 {
		return variant{e.BundleURL, e.BundleSHA}, "every platform", e.BundleURL != ""
	}
	keys := make([]string, 0, len(e.Bundles))
	for k := range e.Bundles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if e.Bundles[k].BundleURL != "" {
			return e.Bundles[k], k, true
		}
	}
	return variant{}, "", false
}

// checkBundles downloads each bundle of an added or changed entry and checks
// it against its pin, the entry, and the platform it is published for.
func (l *linter) checkBundles(e entry) []finding {
	var out []finding
	fail := func(title, format string, args ...any) {
		out = append(out, finding{AppID: e.ID, Title: title, Msg: e.ID + " " + e.Version + ": " + fmt.Sprintf(format, args...)})
	}
	type target struct {
		plat string // "" = legacy single bundle, installed on every platform
		v    variant
	}
	var targets []target
	if len(e.Bundles) == 0 {
		targets = append(targets, target{"", variant{e.BundleURL, e.BundleSHA}})
	} else {
		keys := make([]string, 0, len(e.Bundles))
		for k := range e.Bundles {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !contains(knownPlatforms, k) {
				fail("unknown bundle platform", "bundles key %q is not a platform pilotctl selects (%s)", k, strings.Join(knownPlatforms, ", "))
				continue
			}
			targets = append(targets, target{k, e.Bundles[k]})
		}
	}
	for _, t := range targets {
		where := t.plat
		if where == "" {
			where = "bundle_url"
		}
		if !isSHA256(t.v.BundleSHA) {
			fail("bad bundle pin", "%s: bundle_sha256 %q is not a sha256", where, t.v.BundleSHA)
			continue
		}
		if l.offline {
			continue
		}
		info := l.inspect(t.v)
		if info.fetchError != nil {
			fail("bundle does not verify", "%s: %v", where, info.fetchError)
			continue
		}
		m := info.manifest
		if m.ID != e.ID {
			fail("bundle does not match entry", "%s: manifest id is %q", where, m.ID)
		}
		if m.AppVersion != e.Version {
			fail("bundle does not match entry", "%s: manifest app_version is %q; nodes would see the app as outdated forever and reinstall it every hour", where, m.AppVersion)
		}
		if info.binarySHA != m.Binary.SHA256 {
			fail("bundle does not match entry", "%s: binary %s has sha256 %s but the manifest pins %s; pilotctl refuses to install it", where, m.Binary.Path, info.binarySHA, m.Binary.SHA256)
		}
		bf := info.binary
		switch {
		case !bf.Native:
			// Scripts and adapters are portable; the OS decides.
		case t.plat == "":
			fail("single-platform binary in a legacy bundle",
				"bundle_url ships a native binary (%s: %s) with no per-platform `bundles` map, so every platform installs it and it only runs on %s. Publish a `bundles` map (catalogue/README.md)",
				m.Binary.Path, bf.Desc, strings.Join(bf.Platforms(), ", "))
		case !bf.RunsOn(t.plat):
			fail("bundle binary is for another platform", "%s: binary %s is %s", t.plat, m.Binary.Path, bf.Desc)
		}
	}
	return out
}

// inspect downloads a bundle (once per sha), verifies its pin and reads its
// manifest and binary.
func (l *linter) inspect(v variant) *bundleInfo {
	key := v.BundleURL + "#" + v.BundleSHA
	if info, ok := l.cache[key]; ok {
		return info
	}
	info := &bundleInfo{}
	info.manifest, info.binary, info.binarySHA, info.fetchError = l.readBundle(v)
	l.cache[key] = info
	return info
}

func (l *linter) readBundle(v variant) (*manifest, binaryFormat, string, error) {
	var none binaryFormat
	body, err := l.fetch(v.BundleURL)
	if err != nil {
		return nil, none, "", fmt.Errorf("fetch %s: %w", v.BundleURL, err)
	}
	defer body.Close()
	tmp, err := os.MkdirTemp("", "catalogue-lint-*")
	if err != nil {
		return nil, none, "", err
	}
	defer os.RemoveAll(tmp)
	tarPath := filepath.Join(tmp, "bundle.tar.gz")
	f, err := os.Create(tarPath) // #nosec G304 -- fixed name in our own temp dir
	if err != nil {
		return nil, none, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, maxBundleBytes+1))
	_ = f.Close()
	if err != nil {
		return nil, none, "", fmt.Errorf("download %s: %w", v.BundleURL, err)
	}
	if n > maxBundleBytes {
		return nil, none, "", fmt.Errorf("%s is larger than pilotctl's %d-byte download cap", v.BundleURL, maxBundleBytes)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != v.BundleSHA {
		return nil, none, "", fmt.Errorf("%s has sha256 %s, the catalogue pins %s", v.BundleURL, got, v.BundleSHA)
	}
	files, err := extract(tarPath, tmp)
	if err != nil {
		return nil, none, "", fmt.Errorf("unpack %s: %w", v.BundleURL, err)
	}
	mfPath, ok := files["manifest.json"]
	if !ok {
		return nil, none, "", errors.New("bundle has no top-level manifest.json")
	}
	raw, err := os.ReadFile(mfPath) // #nosec G304 -- a file we extracted into our temp dir
	if err != nil {
		return nil, none, "", err
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, none, "", fmt.Errorf("parse manifest.json: %w", err)
	}
	binPath, ok := files[path.Clean(m.Binary.Path)]
	if !ok {
		return nil, none, "", fmt.Errorf("manifest binary %q is not in the bundle", m.Binary.Path)
	}
	bin, err := os.ReadFile(binPath) // #nosec G304 -- a file we extracted into our temp dir
	if err != nil {
		return nil, none, "", err
	}
	sum := sha256.Sum256(bin)
	bf, err := detectBinary(binPath)
	if err != nil {
		return nil, none, "", err
	}
	return &m, bf, hex.EncodeToString(sum[:]), nil
}

// extract writes each regular file of the gzipped tar at tarPath into dir under
// a generated name (never the archive's own path, so a hostile entry name
// cannot escape dir) and returns archive path → extracted file.
func extract(tarPath, dir string) (map[string]string, error) {
	f, err := os.Open(tarPath) // #nosec G304 -- our own temp file
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for i := 0; ; i++ {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		out := filepath.Join(dir, fmt.Sprintf("entry-%d", i))
		w, err := os.Create(out) // #nosec G304 -- generated name in our own temp dir
		if err != nil {
			return nil, err
		}
		n, err := io.Copy(w, io.LimitReader(tr, maxEntryBytes+1))
		_ = w.Close()
		if err != nil {
			return nil, err
		}
		if n > maxEntryBytes {
			return nil, fmt.Errorf("entry %q exceeds pilotctl's %d-byte extract cap", hdr.Name, maxEntryBytes)
		}
		files[path.Clean(strings.TrimPrefix(hdr.Name, "./"))] = out
	}
}

// binaryFormat describes an app binary for platform matching.
type binaryFormat struct {
	Native bool
	OS     string
	Archs  []string
	Desc   string
}

func (b binaryFormat) RunsOn(plat string) bool {
	for _, p := range b.Platforms() {
		if p == plat {
			return true
		}
	}
	return false
}

func (b binaryFormat) Platforms() []string {
	var out []string
	for _, a := range b.Archs {
		out = append(out, b.OS+"/"+a)
	}
	return out
}

// detectBinary classifies an executable: native ELF, Mach-O (thin or
// universal) and PE images report their platform; anything else (scripts,
// portable adapters) is not native.
func detectBinary(p string) (binaryFormat, error) {
	if f, err := elf.Open(p); err == nil {
		defer f.Close()
		arch := elfArch(f.Machine)
		return binaryFormat{Native: true, OS: "linux", Archs: []string{arch}, Desc: "ELF " + arch}, nil
	}
	if f, err := macho.OpenFat(p); err == nil {
		defer f.Close()
		var archs []string
		for _, a := range f.Arches {
			archs = append(archs, machoArch(a.Cpu))
		}
		sort.Strings(archs)
		return binaryFormat{Native: true, OS: "darwin", Archs: archs, Desc: "universal Mach-O " + strings.Join(archs, "+")}, nil
	}
	if f, err := macho.Open(p); err == nil {
		defer f.Close()
		arch := machoArch(f.Cpu)
		return binaryFormat{Native: true, OS: "darwin", Archs: []string{arch}, Desc: "Mach-O " + arch}, nil
	}
	if f, err := pe.Open(p); err == nil {
		defer f.Close()
		arch := peArch(f.Machine)
		return binaryFormat{Native: true, OS: "windows", Archs: []string{arch}, Desc: "PE " + arch}, nil
	}
	return binaryFormat{Desc: "portable (script or adapter)"}, nil
}

func elfArch(m elf.Machine) string {
	switch m {
	case elf.EM_X86_64:
		return "amd64"
	case elf.EM_AARCH64:
		return "arm64"
	case elf.EM_386:
		return "386"
	case elf.EM_ARM:
		return "arm"
	}
	return m.String()
}

func machoArch(c macho.Cpu) string {
	switch c {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "386"
	case macho.CpuArm:
		return "arm"
	}
	return c.String()
}

func peArch(m uint16) string {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	}
	return fmt.Sprintf("machine-%#x", m)
}

func openURL(raw string) (io.ReadCloser, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "file":
		return os.Open(u.Path)
	case "https", "http":
		c := &http.Client{Timeout: 5 * time.Minute}
		resp, err := c.Get(raw) // #nosec G107 -- CI tool fetching the bundles the catalogue under review pins
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("http %d", resp.StatusCode)
		}
		return resp.Body, nil
	}
	return nil, fmt.Errorf("unsupported url scheme %q", u.Scheme)
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// report prints findings (as GitHub annotations under Actions) and returns the
// exit code: 1 when any finding is an error.
func report(w io.Writer, findings []finding, github bool) int {
	errs := 0
	for _, f := range findings {
		level := "warning"
		if !f.Warning {
			level = "error"
			errs++
		}
		if github {
			fmt.Fprintf(w, "::%s file=catalogue/catalogue.json,title=%s::%s\n", level, f.Title, strings.ReplaceAll(f.Msg, "\n", " "))
		} else {
			fmt.Fprintf(w, "%s: [%s] %s\n", strings.ToUpper(level), f.Title, f.Msg)
		}
	}
	if errs > 0 {
		fmt.Fprintf(w, "catalogue-lint: %d error(s)\n", errs)
		return 1
	}
	fmt.Fprintf(w, "catalogue-lint: ok (%d warning(s))\n", len(findings))
	return 0
}
