package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveRenamed(t *testing.T) {
	c := &catalogue{Apps: []catalogueEntry{
		{ID: "io.pilot.smolmachines", RenamedTo: "io.pilot.smol", Hidden: true, Publisher: "ed25519:old"},
		{ID: "io.pilot.smol", Version: "1.2.0", BundleURL: "https://x/smol.tgz", BundleSHA: hex64, Publisher: "ed25519:new"},
		{ID: "io.pilot.gone", RenamedTo: "io.pilot.missing", Hidden: true},
		{ID: "io.pilot.chain", RenamedTo: "io.pilot.smolmachines", Hidden: true},
	}}

	e, err := resolveRenamed(c, "io.pilot.smolmachines")
	if err != nil || e == nil || e.ID != "io.pilot.smol" {
		t.Fatalf("tombstone: got (%+v, %v), want io.pilot.smol", e, err)
	}
	if e, err := resolveRenamed(c, "io.pilot.smol"); err != nil || e == nil || e.ID != "io.pilot.smol" {
		t.Fatalf("plain id: got (%+v, %v)", e, err)
	}
	if e, err := resolveRenamed(c, "io.pilot.unknown"); err != nil || e != nil {
		t.Fatalf("unknown id: got (%+v, %v), want (nil, nil)", e, err)
	}
	if _, err := resolveRenamed(c, "io.pilot.gone"); err == nil || !strings.Contains(err.Error(), "not in the catalogue") {
		t.Fatalf("missing canonical: err = %v", err)
	}
	if _, err := resolveRenamed(c, "io.pilot.chain"); err == nil || !strings.Contains(err.Error(), "one hop") {
		t.Fatalf("chained tombstone: err = %v", err)
	}
}

// The committed catalogue carries the io.pilot.smolmachines tombstone. It must
// not be listed, and an installed copy must be reported as renamed (never as up
// to date, and never as a plain version upgrade).
func TestRepoCatalogueTombstone(t *testing.T) {
	p := repoCataloguePath(t)
	t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+p)
	c, err := loadCatalogue()
	if err != nil {
		t.Fatal(err)
	}
	e := c.findEntry("io.pilot.smolmachines")
	if e == nil {
		t.Skip("tombstone no longer in the catalogue")
	}
	if e.RenamedTo != "io.pilot.smol" || !e.Hidden {
		t.Fatalf("tombstone fields not decoded: %+v", *e)
	}
	if e.listed() {
		t.Error("tombstone must not be listed")
	}

	root := t.TempDir()
	t.Setenv("PILOT_APPSTORE_ROOT", root)
	d := filepath.Join(root, "io.pilot.smolmachines")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	mf := `{"id":"io.pilot.smolmachines","app_version":"1.2.0","manifest_version":1,` +
		`"binary":{"path":"bin/x","sha256":"` + hex64 + `"},"exposes":["smolmachines.help"],` +
		`"store":{"publisher":"ed25519:AAA"}}`
	if err := os.WriteFile(filepath.Join(d, "manifest.json"), []byte(mf), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := findOutdated()
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Reason != "renamed" || out[0].RenamedTo != "io.pilot.smol" {
		t.Fatalf("findOutdated = %+v, want one renamed → io.pilot.smol", out)
	}
}

// The CLI surface for a renamed id, against the committed signed catalogue:
// hidden from the listing, a version pin fails closed naming the new id,
// `upgrade --all` (the hourly updater) never crosses the rename, `upgrade
// <old>` explains how to move, and `call` of an old id that is not installed
// says it was renamed instead of blaming the daemon.
func TestRenamedAppCLI(t *testing.T) {
	cat := repoCataloguePath(t)
	root := t.TempDir()
	env := map[string]string{
		"PILOT_APPSTORE_CATALOG_URL": "file://" + cat,
		"PILOT_APPSTORE_ROOT":        root,
		"PILOT_SOCKET":               filepath.Join(t.TempDir(), "no-daemon.sock"),
		"PILOT_TELEMETRY_URL":        "http://127.0.0.1:9/",
	}
	c, err := func() (*catalogue, error) {
		t.Setenv("PILOT_APPSTORE_CATALOG_URL", "file://"+cat)
		return loadCatalogue()
	}()
	if err != nil {
		t.Fatal(err)
	}
	if e := c.findEntry("io.pilot.smolmachines"); e == nil || e.RenamedTo == "" {
		t.Skip("the committed catalogue no longer carries the io.pilot.smolmachines tombstone")
	}

	out, _, code := runCLI(t, []string{"--json", "appstore", "catalogue"}, env)
	if code != 0 || strings.Contains(out, `"io.pilot.smolmachines"`) || !strings.Contains(out, `"io.pilot.smol"`) {
		t.Fatalf("catalogue --json (exit %d) must list io.pilot.smol and not the tombstone:\n%s", code, out)
	}

	_, errOut, code := runCLI(t, []string{"appstore", "install", "io.pilot.smolmachines", "--version", "1.2.0"}, env)
	if code == 0 || !strings.Contains(errOut, "renamed to io.pilot.smol") || !strings.Contains(errOut, "pin io.pilot.smol") {
		t.Fatalf("install --version of the old id (exit %d) must fail naming the new id:\n%s", code, errOut)
	}

	_, errOut, code = runCLI(t, []string{"appstore", "call", "io.pilot.smolmachines", "smolmachines.help"}, env)
	if code == 0 || !strings.Contains(errOut, `renamed to "io.pilot.smol"`) {
		t.Fatalf("call of the old id (exit %d) must say it was renamed:\n%s", code, errOut)
	}

	d := filepath.Join(root, "io.pilot.smolmachines")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	mf := `{"id":"io.pilot.smolmachines","app_version":"1.2.0","manifest_version":1,` +
		`"binary":{"path":"bin/x","sha256":"` + hex64 + `"},"exposes":["smolmachines.help"],` +
		`"store":{"publisher":"ed25519:AAA"}}`
	if err := os.WriteFile(filepath.Join(d, "manifest.json"), []byte(mf), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, code = runCLI(t, []string{"appstore", "upgrade", "--all"}, env)
	if code != 0 || !strings.Contains(out, "skip io.pilot.smolmachines: renamed to io.pilot.smol") || strings.Contains(out, "upgrading") {
		t.Fatalf("upgrade --all (exit %d) must skip the renamed app and upgrade nothing:\n%s", code, out)
	}
	_, errOut, code = runCLI(t, []string{"appstore", "upgrade", "io.pilot.smolmachines"}, env)
	if code == 0 || !strings.Contains(errOut, "pilotctl appstore install io.pilot.smol") {
		t.Fatalf("upgrade of the old id (exit %d) must point at installing the new id:\n%s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(root, "io.pilot.smol")); !os.IsNotExist(err) {
		t.Fatalf("nothing may be installed under the new id by upgrade: %v", err)
	}
}
