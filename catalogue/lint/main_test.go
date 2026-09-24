// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	scriptBin = []byte("#!/bin/sh\necho hi\n")
	elfAmd64  = elfHeader(62)
	elfArm64  = elfHeader(183)
	machArm64 = machHeader(macho.CpuArm64)
)

func elfHeader(machine uint16) []byte {
	h := make([]byte, 64)
	copy(h, "\x7fELF")
	h[4], h[5], h[6] = 2, 1, 1 // 64-bit, little endian, EV_CURRENT
	binary.LittleEndian.PutUint16(h[16:], 2)
	binary.LittleEndian.PutUint16(h[18:], machine)
	binary.LittleEndian.PutUint32(h[20:], 1)
	binary.LittleEndian.PutUint16(h[52:], 64)
	binary.LittleEndian.PutUint16(h[54:], 56)
	binary.LittleEndian.PutUint16(h[58:], 64)
	return h
}

func machHeader(cpu macho.Cpu) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], macho.Magic64)
	binary.LittleEndian.PutUint32(h[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(h[12:], uint32(macho.TypeExec))
	return h
}

// bundleServer serves generated app bundles over HTTP.
type bundleServer struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	n   int
	tgz map[string][]byte
}

func newBundleServer(t *testing.T) *bundleServer {
	b := &bundleServer{t: t, tgz: map[string][]byte{}}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		body, ok := b.tgz[r.URL.Path]
		b.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(b.srv.Close)
	return b
}

// publish serves a bundle for id/version with the given grant caps and binary,
// returning its catalogue variant. binSHAOverride, when set, is what the
// manifest pins instead of the binary's real sha.
func (b *bundleServer) publish(id, version string, caps []string, bin []byte, binSHAOverride string) variant {
	b.t.Helper()
	return b.publishWith(id, version, caps, bin, binSHAOverride, nil)
}

// publishWith is publish with extra top-level files in the bundle (a cli
// app's install.json).
func (b *bundleServer) publishWith(id, version string, caps []string, bin []byte, binSHAOverride string, extra map[string][]byte) variant {
	b.t.Helper()
	sum := sha256.Sum256(bin)
	binSHA := hex.EncodeToString(sum[:])
	if binSHAOverride != "" {
		binSHA = binSHAOverride
	}
	var grants []map[string]string
	for _, c := range caps {
		grants = append(grants, map[string]string{"cap": c, "target": "$APP/state"})
	}
	mf, _ := json.Marshal(map[string]any{
		"id": id, "app_version": version, "manifest_version": 1,
		"binary": map[string]string{"runtime": "go", "path": "bin/app", "sha256": binSHA},
		"grants": grants,
	})
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	type file struct {
		name string
		body []byte
	}
	files := []file{{"./manifest.json", mf}, {"bin/app", bin}}
	for name, body := range extra {
		files = append(files, file{name, body})
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Size: int64(len(f.body)), Typeflag: tar.TypeReg, Mode: 0o755}); err != nil {
			b.t.Fatal(err)
		}
		_, _ = tw.Write(f.body)
	}
	_ = tw.Close()
	_ = gz.Close()
	b.mu.Lock()
	b.n++
	p := fmt.Sprintf("/bundle-%d.tar.gz", b.n)
	b.tgz[p] = buf.Bytes()
	b.mu.Unlock()
	tsum := sha256.Sum256(buf.Bytes())
	return variant{BundleURL: b.srv.URL + p, BundleSHA: hex.EncodeToString(tsum[:])}
}

func legacy(id, version string, v variant) entry {
	return entry{ID: id, Version: version, BundleURL: v.BundleURL, BundleSHA: v.BundleSHA}
}

func testLinter(p policy, allow bool) *linter {
	return &linter{policy: p, allowBump: allow, fetch: openURL, cache: map[string]*bundleInfo{}}
}

func errorsOf(fs []finding) []finding {
	var out []finding
	for _, f := range fs {
		if !f.Warning {
			out = append(out, f)
		}
	}
	return out
}

func hasFinding(fs []finding, warning bool, titleSub, msgSub string) bool {
	for _, f := range fs {
		if f.Warning == warning && strings.Contains(f.Title, titleSub) && strings.Contains(f.Msg, msgSub) {
			return true
		}
	}
	return false
}

func TestStatefulAppUpdateNeedsApproval(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.pilot.wallet"
	base := &catalogue{Apps: []entry{legacy(id, "0.3.3", s.publish(id, "0.3.3", nil, scriptBin, ""))}}
	head := &catalogue{Apps: []entry{legacy(id, "0.3.4", s.publish(id, "0.3.4", nil, scriptBin, ""))}}
	listed := policy{StatefulApps: []string{id}}

	got := testLinter(listed, false).lint(base, head)
	if len(errorsOf(got)) != 1 || !hasFinding(got, false, "needs approval", "version 0.3.3 → 0.3.4") ||
		!hasFinding(got, false, "", "listed in catalogue/stateful-apps.json") {
		t.Fatalf("listed stateful bump: %+v", got)
	}
	if code := report(&bytes.Buffer{}, got, false); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}

	// Approval by file entry for this exact version.
	approved := listed
	approved.ApprovedBumps = []approval{{ID: id, Version: "0.3.4", Reason: "fleet on fixed pilotctl", ApprovedBy: "release-owner"}}
	if got := testLinter(approved, false).lint(base, head); len(errorsOf(got)) != 0 || !hasFinding(got, true, "approved", "release-owner") {
		t.Fatalf("approved bump: %+v", got)
	}
	// An approval for a different version does not count.
	approved.ApprovedBumps[0].Version = "0.3.5"
	if got := testLinter(approved, false).lint(base, head); len(errorsOf(got)) != 1 {
		t.Fatalf("approval for another version accepted: %+v", got)
	}
	// Approval by PR label.
	if got := testLinter(listed, true).lint(base, head); len(errorsOf(got)) != 0 || !hasFinding(got, true, "approved by label", id) {
		t.Fatalf("label-approved bump: %+v", got)
	}
}

func TestIncompleteApprovalIsAnError(t *testing.T) {
	p := policy{ApprovedBumps: []approval{{ID: "io.pilot.wallet", Version: "0.3.4"}}}
	if got := testLinter(p, false).lint(&catalogue{}, &catalogue{}); !hasFinding(got, false, "incomplete", "approved_by") {
		t.Fatalf("got %+v", got)
	}
}

func TestManifestDeclaredStateIsFrozen(t *testing.T) {
	s := newBundleServer(t)
	for _, tc := range []struct {
		caps     []string
		stateful bool
	}{
		{[]string{"fs.write"}, true},
		{[]string{"net.dial", "key.sign"}, true},
		{[]string{"net.dial", "fs.read", "audit.log"}, false},
	} {
		id := "io.test.app" + strings.ReplaceAll(strings.Join(tc.caps, ""), ".", "")
		base := &catalogue{Apps: []entry{legacy(id, "1.0.0", s.publish(id, "1.0.0", tc.caps, scriptBin, ""))}}
		head := &catalogue{Apps: []entry{legacy(id, "1.1.0", s.publish(id, "1.1.0", tc.caps, scriptBin, ""))}}
		got := testLinter(policy{}, false).lint(base, head)
		if tc.stateful != (len(errorsOf(got)) == 1 && hasFinding(got, false, "needs approval", "manifest grants")) {
			t.Errorf("caps %v: stateful=%v but findings %+v", tc.caps, tc.stateful, got)
		}
		if !tc.stateful && len(got) != 0 {
			t.Errorf("stateless update produced findings: %+v", got)
		}
	}
}

func TestSameVersionRepublishOfStatefulAppIsFrozen(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.pilot.smol"
	base := &catalogue{Apps: []entry{legacy(id, "1.2.0", s.publish(id, "1.2.0", nil, scriptBin, ""))}}
	head := &catalogue{Apps: []entry{legacy(id, "1.2.0", s.publish(id, "1.2.0", nil, []byte("#!/bin/sh\necho rebuilt\n"), ""))}}
	got := testLinter(policy{StatefulApps: []string{id}}, false).lint(base, head)
	if !hasFinding(got, false, "needs approval", "same-version republish") {
		t.Fatalf("got %+v", got)
	}
}

func TestNewAndUntouchedEntriesAreNotFrozen(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.pilot.wallet"
	e := legacy(id, "0.3.3", s.publish(id, "0.3.3", []string{"fs.write"}, scriptBin, ""))
	p := policy{StatefulApps: []string{id}}
	if got := testLinter(p, false).lint(&catalogue{}, &catalogue{Apps: []entry{e}}); len(got) != 0 {
		t.Fatalf("new stateful app: %+v", got)
	}
	if got := testLinter(p, false).lint(&catalogue{Apps: []entry{e}}, &catalogue{Apps: []entry{e}}); len(got) != 0 {
		t.Fatalf("untouched entry: %+v", got)
	}
}

func TestLegacyBundleMustNotShipANativeBinary(t *testing.T) {
	s := newBundleServer(t)
	for name, bin := range map[string][]byte{"mach-o arm64": machArm64, "elf amd64": elfAmd64} {
		id := "io.test.legacy" + strings.ReplaceAll(strings.ReplaceAll(name, " ", ""), "-", "")
		head := &catalogue{Apps: []entry{legacy(id, "0.1.0", s.publish(id, "0.1.0", nil, bin, ""))}}
		got := testLinter(policy{}, false).lint(&catalogue{}, head)
		if !hasFinding(got, false, "legacy bundle", "every platform installs it") {
			t.Errorf("%s legacy bundle: %+v", name, got)
		}
	}
	head := &catalogue{Apps: []entry{legacy("io.test.script", "0.1.0", s.publish("io.test.script", "0.1.0", nil, scriptBin, ""))}}
	if got := testLinter(policy{}, false).lint(&catalogue{}, head); len(got) != 0 {
		t.Fatalf("portable legacy bundle: %+v", got)
	}
}

func TestPerPlatformBundlesMustMatchTheirPlatform(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.test.multi"
	e := entry{ID: id, Version: "1.0.0", Bundles: map[string]variant{
		"linux/amd64":  s.publish(id, "1.0.0", nil, elfAmd64, ""),
		"linux/arm64":  s.publish(id, "1.0.0", nil, elfArm64, ""),
		"darwin/arm64": s.publish(id, "1.0.0", nil, elfAmd64, ""),
		"macos/arm64":  s.publish(id, "1.0.0", nil, machArm64, ""),
	}}
	e.BundleURL, e.BundleSHA = e.Bundles["linux/amd64"].BundleURL, e.Bundles["linux/amd64"].BundleSHA
	got := testLinter(policy{}, false).lint(&catalogue{}, &catalogue{Apps: []entry{e}})
	if len(errorsOf(got)) != 2 ||
		!hasFinding(got, false, "another platform", "darwin/arm64: binary bin/app is ELF amd64") ||
		!hasFinding(got, false, "unknown bundle platform", "macos/arm64") {
		t.Fatalf("got %+v", got)
	}
}

func TestBundlesMustVerifyAgainstEntry(t *testing.T) {
	s := newBundleServer(t)
	good := s.publish("io.test.v", "1.0.0", nil, scriptBin, "")
	for name, tc := range map[string]struct {
		e    entry
		want string
	}{
		"bundle sha":       {legacy("io.test.v", "1.0.0", variant{good.BundleURL, strings.Repeat("0", 64)}), "the catalogue pins"},
		"bad pin":          {legacy("io.test.v", "1.0.0", variant{good.BundleURL, "REPLACE_AT_RELEASE_TIME"}), "is not a sha256"},
		"manifest version": {legacy("io.test.v", "1.0.1", good), "reinstall it every hour"},
		"manifest id":      {legacy("io.test.other", "1.0.0", good), `manifest id is "io.test.v"`},
		"binary pin":       {legacy("io.test.b", "1.0.0", s.publish("io.test.b", "1.0.0", nil, scriptBin, strings.Repeat("a", 64))), "pilotctl refuses to install it"},
		"missing":          {legacy("io.test.v", "1.0.0", variant{s.srv.URL + "/gone.tar.gz", good.BundleSHA}), "http 404"},
	} {
		got := testLinter(policy{}, false).lint(&catalogue{}, &catalogue{Apps: []entry{tc.e}})
		if !hasFinding(got, false, "", tc.want) {
			t.Errorf("%s: want a finding containing %q, got %+v", name, tc.want, got)
		}
	}
}

func TestUninspectableUpdateIsTreatedAsStateful(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.test.opaque"
	base := &catalogue{Apps: []entry{legacy(id, "1.0.0", variant{s.srv.URL + "/gone.tar.gz", strings.Repeat("b", 64)})}}
	head := &catalogue{Apps: []entry{legacy(id, "1.1.0", s.publish(id, "1.1.0", nil, scriptBin, ""))}}
	got := testLinter(policy{}, false).lint(base, head)
	if !hasFinding(got, false, "needs approval", "could not be inspected") {
		t.Fatalf("got %+v", got)
	}
}

// The committed catalogue and policy parse, list the known stateful apps, and
// produce no findings against themselves (nothing is touched).
func TestRepoCatalogueAndPolicy(t *testing.T) {
	l, err := newLinter(filepath.Join("..", "stateful-apps.json"), false, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"io.pilot.wallet", "io.pilot.smol", "io.pilot.agentphone", "io.pilot.bowmark", "io.pilot.orthogonal"} {
		if !contains(l.policy.StatefulApps, id) {
			t.Errorf("stateful-apps.json does not list %s", id)
		}
	}
	cat, err := loadCatalogue(filepath.Join("..", "catalogue.json"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cat.Apps) == 0 {
		t.Fatal("empty catalogue")
	}
	if got := l.lint(cat, cat); len(got) != 0 {
		t.Fatalf("unchanged catalogue produced findings: %+v", got)
	}
	// Offline, a bump of a listed app is still caught from the policy list.
	bumped := &catalogue{Apps: append([]entry(nil), cat.Apps...)}
	for i := range bumped.Apps {
		if bumped.Apps[i].ID == "io.pilot.wallet" {
			bumped.Apps[i].Version = "9.9.9"
		}
	}
	if got := l.lint(cat, bumped); !hasFinding(got, false, "needs approval", "io.pilot.wallet") {
		t.Fatalf("offline wallet bump: %+v", got)
	}
}

func TestReportFormats(t *testing.T) {
	var buf bytes.Buffer
	if code := report(&buf, []finding{{Warning: true, AppID: "a", Title: "t", Msg: "m"}}, true); code != 0 {
		t.Fatalf("warnings only: exit %d", code)
	}
	if !strings.Contains(buf.String(), "::warning file=catalogue/catalogue.json,title=t::m") {
		t.Fatalf("annotation: %q", buf.String())
	}
	buf.Reset()
	if code := report(&buf, []finding{{AppID: "a", Title: "t", Msg: "m"}}, false); code != 1 || !strings.Contains(buf.String(), "ERROR: [t] m") {
		t.Fatalf("error: exit %d, %q", code, buf.String())
	}
}

func TestLoadCatalogueOptionalBase(t *testing.T) {
	c, err := loadCatalogue("", true)
	if err != nil || len(c.Apps) != 0 {
		t.Fatalf("empty base: %v %v", c, err)
	}
	p := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err := loadCatalogue(p, true); err != nil || len(c.Apps) != 0 {
		t.Fatalf("empty base file: %v %v", c, err)
	}
}

// A bundle-less entry must be a well-formed rename tombstone, checked even
// when the PR does not touch it.
func TestTombstonesMustBeWellFormed(t *testing.T) {
	s := newBundleServer(t)
	target := legacy("io.test.new", "1.0.0", s.publish("io.test.new", "1.0.0", nil, scriptBin, ""))
	good := entry{ID: "io.test.old", RenamedTo: "io.test.new", Hidden: true, Publisher: "ed25519:old"}
	if got := testLinter(policy{}, false).lint(&catalogue{}, &catalogue{Apps: []entry{good, target}}); len(got) != 0 {
		t.Fatalf("valid tombstone: %+v", got)
	}
	for name, tc := range map[string]struct {
		apps []entry
		want string
	}{
		"no bundle, no rename": {[]entry{{ID: "io.test.old", Publisher: "ed25519:old"}}, "nothing can install it"},
		"target missing":       {[]entry{good}, `renamed_to "io.test.new" is not in the catalogue`},
		"chained":              {[]entry{good, {ID: "io.test.new", RenamedTo: "io.test.newer", Hidden: true, Publisher: "ed25519:x"}}, "renames are one hop"},
		"self":                 {[]entry{{ID: "io.test.old", RenamedTo: "io.test.old", Hidden: true, Publisher: "ed25519:old"}}, "names the entry itself"},
		"version":              {[]entry{{ID: "io.test.old", RenamedTo: "io.test.new", Hidden: true, Publisher: "ed25519:old", Version: "1.2.0"}, target}, "has no version"},
		"metadata":             {[]entry{{ID: "io.test.old", RenamedTo: "io.test.new", Hidden: true, Publisher: "ed25519:old", MetadataURL: "https://x/m.json"}, target}, "no metadata_url"},
		"not hidden":           {[]entry{{ID: "io.test.old", RenamedTo: "io.test.new", Publisher: "ed25519:old"}, target}, `"hidden": true`},
		"no publisher":         {[]entry{{ID: "io.test.old", RenamedTo: "io.test.new", Hidden: true}, target}, "keep the old publisher key"},
		"still has a bundle":   {[]entry{{ID: "io.test.old", RenamedTo: "io.test.new", Hidden: true, Publisher: "ed25519:old", BundleURL: target.BundleURL, BundleSHA: target.BundleSHA}, target}, "still publishes a bundle"},
	} {
		head := &catalogue{Apps: tc.apps}
		// base == head: the tombstone itself is untouched and still checked.
		if got := testLinter(policy{}, false).lint(head, head); !hasFinding(got, false, "bad rename tombstone", tc.want) {
			t.Errorf("%s: want a finding containing %q, got %+v", name, tc.want, got)
		}
	}
}

// A cli bundle published for a platform its install.json has no native tool
// for exits at every start there. io.pilot.smolmachines 1.2.0 shipped a
// darwin/amd64 bundle like that (upstream smolvm has no macOS x86_64 build).
func TestCLIBundleNeedsANativeToolForEachPublishedPlatform(t *testing.T) {
	s := newBundleServer(t)
	const id = "io.test.vm"
	installJSON := []byte(`{"schema":1,"app":"io.test.vm","version":"1.0.0","command":"smolvm","assets":[
		{"os":"darwin","arch":"arm64"},{"os":"linux","arch":"amd64"},{"os":"linux","arch":"arm64"}]}`)
	extra := map[string][]byte{"install.json": installJSON}
	e := entry{ID: id, Version: "1.0.0", Bundles: map[string]variant{
		"darwin/arm64": s.publishWith(id, "1.0.0", nil, machArm64, "", extra),
		"darwin/amd64": s.publishWith(id, "1.0.0", nil, machHeader(macho.CpuAmd64), "", extra),
		"linux/amd64":  s.publishWith(id, "1.0.0", nil, elfAmd64, "", extra),
		"linux/arm64":  s.publishWith(id, "1.0.0", nil, elfArm64, "", extra),
	}}
	e.BundleURL, e.BundleSHA = e.Bundles["linux/amd64"].BundleURL, e.Bundles["linux/amd64"].BundleSHA
	got := testLinter(policy{}, false).lint(&catalogue{}, &catalogue{Apps: []entry{e}})
	if len(errorsOf(got)) != 1 || !hasFinding(got, false, "no native tool", "darwin/amd64: install.json ships smolvm only for darwin/arm64, linux/amd64, linux/arm64") {
		t.Fatalf("got %+v", got)
	}
	delete(e.Bundles, "darwin/amd64")
	if got := testLinter(policy{}, false).lint(&catalogue{}, &catalogue{Apps: []entry{e}}); len(got) != 0 {
		t.Fatalf("every published platform has its tool: %+v", got)
	}
}
