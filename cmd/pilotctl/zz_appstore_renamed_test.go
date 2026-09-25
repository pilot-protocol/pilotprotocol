package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hidden entry is resolvable but not listed: io.pilot.smolmachines stayed in
// the listing as "Smol Machines (renamed → io.pilot.smol)" and failed to install.
func TestCmdAppStoreCatalogueSkipsHiddenEntries(t *testing.T) {
	stageCatalogue(t, `{"version":2,"apps":[
		{"id":"io.pilot.smolmachines","renamed_to":"io.pilot.smol","hidden":true,"display_name":"Smol Machines (renamed)"},
		{"id":"io.pilot.smol","version":"1.2.0","display_name":"Smol Machines","bundle_url":"https://x/a.tgz","bundle_sha256":"abc"}
	]}`)
	prev := jsonOutput
	defer func() { jsonOutput = prev }()
	jsonOutput = false

	out := captureStdout(t, func() { cmdAppStoreCatalogue(nil) })
	if strings.Contains(out, "io.pilot.smolmachines") {
		t.Errorf("hidden entry listed:\n%s", out)
	}
	if !strings.Contains(out, "io.pilot.smol ") {
		t.Errorf("visible entry missing:\n%s", out)
	}
}

// Installing a renamed id installs the app it moved to, instead of failing
// with "placeholder sha256" on the bundle-less stub entry.
func TestResolveInstallTargetFollowsRename(t *testing.T) {
	dir := makeTestBundleDir(t)
	path, sha := tarGzBundle(t, dir)
	stageCatalogue(t, fmt.Sprintf(`{"version":2,"apps":[
		{"id":"io.pilot.old","renamed_to":"io.pilot.new","hidden":true},
		{"id":"io.pilot.new","version":"1.0.0","bundle_url":"file://%s","bundle_sha256":"%s"}
	]}`, path, sha))

	var got string
	stderr := captureStderr(t, func() {
		d, src, err := resolveInstallTarget("io.pilot.old")
		if err != nil {
			t.Fatalf("resolve renamed id: %v", err)
		}
		if src != installSourceCatalogue {
			t.Errorf("source = %v, want catalogue", src)
		}
		got = d
	})
	if _, err := os.Stat(filepath.Join(got, "manifest.json")); err != nil {
		t.Errorf("renamed install did not unpack the new app's bundle: %v", err)
	}
	if !strings.Contains(stderr, "io.pilot.old was renamed to io.pilot.new") {
		t.Errorf("no rename notice on stderr: %q", stderr)
	}
}

func TestResolveInstallTargetRenameToMissingApp(t *testing.T) {
	stageCatalogue(t, `{"version":2,"apps":[{"id":"io.pilot.old","renamed_to":"io.pilot.gone","hidden":true}]}`)
	_, _, err := resolveInstallTarget("io.pilot.old")
	if err == nil || !strings.Contains(err.Error(), "renamed to io.pilot.gone") {
		t.Errorf("err = %v, want a renamed-to-missing error", err)
	}
}

func makeTestBundleDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "manifest.json"), `{"id":"io.pilot.new","app_version":"1.0.0"}`, 0o644)
	mustWrite(t, filepath.Join(dir, "bin", "app"), "#!/bin/sh\n", 0o755)
	return dir
}
