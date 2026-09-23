// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// thinMachO64 is a minimal parseable 64-bit Mach-O header with no load commands.
func thinMachO64(cpu macho.Cpu) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], macho.Magic64)
	binary.LittleEndian.PutUint32(h[4:], uint32(cpu))
	binary.LittleEndian.PutUint32(h[12:], uint32(macho.TypeExec))
	return h
}

// fatMachO builds a universal Mach-O with one thin slice per cpu.
func fatMachO(cpus ...macho.Cpu) []byte {
	const align = 0x1000
	out := make([]byte, align*(len(cpus)+1))
	binary.BigEndian.PutUint32(out[0:], macho.MagicFat)
	binary.BigEndian.PutUint32(out[4:], uint32(len(cpus)))
	for i, cpu := range cpus {
		off := uint32(align * (i + 1))
		slice := thinMachO64(cpu)
		entry := out[8+20*i:]
		binary.BigEndian.PutUint32(entry[0:], uint32(cpu))
		binary.BigEndian.PutUint32(entry[8:], off)
		binary.BigEndian.PutUint32(entry[12:], uint32(len(slice)))
		binary.BigEndian.PutUint32(entry[16:], 12) // 2^12 alignment
		copy(out[off:], slice)
	}
	return out
}

// minimalPE builds a parseable PE image header for machine.
func minimalPE(machine uint16) []byte {
	b := make([]byte, 0x80+24)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x80)
	copy(b[0x80:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(b[0x84:], machine)
	return b
}

func writeBin(t *testing.T, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app")
	if err := os.WriteFile(p, body, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCheckFatOrPEPlatformUniversalMachO(t *testing.T) {
	t.Parallel()
	both := writeBin(t, fatMachO(macho.CpuAmd64, macho.CpuArm64))
	if err := checkFatOrPEPlatform(both, "darwin", "arm64"); err != nil {
		t.Fatalf("universal amd64+arm64 on darwin/arm64: %v", err)
	}
	if err := checkFatOrPEPlatform(both, "darwin", "amd64"); err != nil {
		t.Fatalf("universal amd64+arm64 on darwin/amd64: %v", err)
	}
	if err := checkFatOrPEPlatform(both, "linux", "arm64"); err == nil || !strings.Contains(err.Error(), "universal Mach-O/macOS") {
		t.Fatalf("universal Mach-O on linux: %v", err)
	}
	armOnly := writeBin(t, fatMachO(macho.CpuArm64))
	if err := checkFatOrPEPlatform(armOnly, "darwin", "amd64"); err == nil || !strings.Contains(err.Error(), "do not include host architecture amd64") {
		t.Fatalf("arm64-only universal on darwin/amd64: %v", err)
	}
}

func TestCheckFatOrPEPlatformPE(t *testing.T) {
	t.Parallel()
	exe := writeBin(t, minimalPE(pe.IMAGE_FILE_MACHINE_AMD64))
	if err := checkFatOrPEPlatform(exe, "windows", "amd64"); err != nil {
		t.Fatalf("PE amd64 on windows/amd64: %v", err)
	}
	for _, host := range [][2]string{{"linux", "amd64"}, {"darwin", "arm64"}} {
		if err := checkFatOrPEPlatform(exe, host[0], host[1]); err == nil || !strings.Contains(err.Error(), "PE/Windows") {
			t.Fatalf("PE on %s/%s: %v", host[0], host[1], err)
		}
	}
	if err := checkFatOrPEPlatform(exe, "windows", "arm64"); err == nil || !strings.Contains(err.Error(), "does not match host architecture arm64") {
		t.Fatalf("PE amd64 on windows/arm64: %v", err)
	}
}

func TestCheckFatOrPEPlatformLeavesOtherFormatsToThinCheck(t *testing.T) {
	t.Parallel()
	for name, body := range map[string][]byte{
		"script":     []byte("#!/bin/sh\necho hi\n"),
		"thin macho": thinMachO64(macho.CpuArm64),
		"java class": append([]byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x34}, make([]byte, 64)...),
		"unknown":    []byte("adapter-v1\n"),
	} {
		if err := checkFatOrPEPlatform(writeBin(t, body), "linux", "amd64"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// foreignBinary returns a native executable header for a platform that is
// not this host, and that platform's name.
func foreignBinary() ([]byte, string) {
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		return thinMachO64(macho.CpuArm64), "darwin/arm64"
	}
	elf := make([]byte, 64)
	copy(elf, "\x7fELF")
	elf[4], elf[5] = 2, 1 // 64-bit, little endian
	binary.LittleEndian.PutUint16(elf[18:], 62)
	return elf, "linux/amd64"
}

// TestAppStoreInstallRefusesForeignPlatformBinary drives the real CLI (the
// refusal exits non-zero) with a bundle shaped like wallet 0.3.3 on Linux: a
// correctly pinned binary for the wrong platform. The install must fail with
// platform_mismatch and leave the existing install and its state untouched.
func TestAppStoreInstallRefusesForeignPlatformBinary(t *testing.T) {
	root := isolateAppStoreTest(t)
	const id = "io.test.foreign"
	appDir := filepath.Join(root, id)
	good := writeVersionedBundle(t, id, "1.0.0", "v1")
	_ = captureStdout(t, func() { cmdAppStoreInstall([]string{good, "--local"}) })
	seedAppState(t, appDir)

	bad := writeVersionedBundle(t, id, "1.0.1", "v2")
	body, platform := foreignBinary()
	bin := filepath.Join(bad, "bin", "app")
	if err := os.WriteFile(bin, body, 0o755); err != nil {
		t.Fatal(err)
	}
	var mf map[string]any
	if err := json.Unmarshal([]byte(mustRead(t, filepath.Join(bad, "manifest.json"))), &mf); err != nil {
		t.Fatal(err)
	}
	mf["binary"].(map[string]any)["sha256"] = sha256File(bin)
	raw, _ := json.Marshal(mf)
	mustWrite(t, filepath.Join(bad, "manifest.json"), string(raw), 0o644)

	env := map[string]string{}
	for _, k := range []string{"PILOT_APPSTORE_ROOT", "PILOT_SOCKET", "PILOT_TELEMETRY_URL", "PILOT_APPSTORE_CATALOG_URL"} {
		env[k] = os.Getenv(k)
	}
	_, stderr, code := runCLI(t, []string{"--json", "appstore", "install", bad, "--local", "--force"}, env)
	if code == 0 {
		t.Fatalf("installing a %s binary on %s/%s succeeded", platform, runtime.GOOS, runtime.GOARCH)
	}
	var env2 map[string]any
	line := strings.TrimSpace(stderr[strings.LastIndex(strings.TrimSpace(stderr), "\n")+1:])
	if err := json.Unmarshal([]byte(line), &env2); err != nil {
		t.Fatalf("stderr is not a JSON error envelope: %v\n%s", err, stderr)
	}
	if env2["code"] != "platform_mismatch" {
		t.Fatalf("code = %v, want platform_mismatch\n%s", env2["code"], stderr)
	}
	msg, _ := env2["message"].(string)
	if !strings.Contains(msg, id) || !strings.Contains(msg, runtime.GOOS+"/"+runtime.GOARCH) {
		t.Errorf("message should name the app and the host platform: %q", msg)
	}
	if hint, _ := env2["hint"].(string); !strings.Contains(hint, "untouched") {
		t.Errorf("hint should say the existing install is untouched: %q", hint)
	}
	assertAppStateKept(t, appDir, "after a refused foreign-platform install")
	if m, _, err := readInstalledManifest(appDir); err != nil || m.AppVersion != "1.0.0" {
		t.Fatalf("installed app changed: %v, %v", m, err)
	}
}
