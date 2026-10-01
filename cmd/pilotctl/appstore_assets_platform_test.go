// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The install.json of io.pilot.smolmachines 1.2.0 (every platform's bundle
// carried the same one): smolvm for darwin/arm64, linux/amd64 and linux/arm64,
// nothing for darwin/amd64 — yet a darwin/amd64 bundle was published.
const smolmachinesInstallJSON = `{"schema":1,"app":"io.pilot.smolmachines","version":"1.2.0","command":"smolvm","assets":[
 {"name":"smolvm","role":"binary","os":"darwin","arch":"arm64","exec_path":"smolvm-1.2.0-darwin-arm64/smolvm"},
 {"name":"smolvm","role":"binary","os":"linux","arch":"amd64","exec_path":"smolvm-1.2.0-linux-x86_64/smolvm"},
 {"name":"smolvm","role":"binary","os":"linux","arch":"arm64","exec_path":"smolvm-1.2.0-linux-arm64/smolvm"}]}`

func bundleWithInstallJSON(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if body != "" {
		if err := os.WriteFile(filepath.Join(dir, "install.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCheckBundleAssetsPlatform(t *testing.T) {
	smol := bundleWithInstallJSON(t, smolmachinesInstallJSON)
	for _, plat := range [][2]string{{"darwin", "arm64"}, {"linux", "amd64"}, {"linux", "arm64"}} {
		if err := checkBundleAssetsPlatform(smol, plat[0], plat[1]); err != nil {
			t.Errorf("%s/%s has a smolvm asset: %v", plat[0], plat[1], err)
		}
	}
	err := checkBundleAssetsPlatform(smol, "darwin", "amd64")
	if err == nil {
		t.Fatal("darwin/amd64 has no smolvm asset; the install must be refused")
	}
	for _, want := range []string{"smolvm", "darwin/arm64, linux/amd64, linux/arm64", "darwin/amd64"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// Left to the app, as before: no install.json (not a cli app), an
	// install.json without assets, or one that does not parse.
	for name, body := range map[string]string{
		"no install.json": "",
		"no assets":       `{"schema":1,"command":"x","assets":[]}`,
		"unparseable":     `{"assets":`,
	} {
		if err := checkBundleAssetsPlatform(bundleWithInstallJSON(t, body), "darwin", "amd64"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
