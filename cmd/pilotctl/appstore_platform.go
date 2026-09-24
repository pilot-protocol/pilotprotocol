// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// checkAppBinaryPlatform refuses an app binary that cannot run on this host,
// before anything is staged. validateHostExecutable (executable_platform.go)
// covers thin ELF and Mach-O images; this adds universal (fat) Mach-O and PE,
// which it lets through unchecked. Scripts and unrecognised adapter formats
// are still accepted and left to the OS.
//
// This is what stops a legacy single-`bundle_url` catalogue entry that ships
// one platform's binary (wallet 0.3.3 and cosift 0.1.2: darwin/arm64 Mach-O;
// generallegal 0.1.0: linux/amd64 ELF) from "installing successfully" on every
// other platform and then failing at spawn with an exec-format error.
func checkAppBinaryPlatform(path string) error {
	if err := checkFatOrPEPlatform(path, runtime.GOOS, runtime.GOARCH); err != nil {
		return err
	}
	return validateHostExecutable(path)
}

// checkFatOrPEPlatform checks universal Mach-O and PE images against
// goos/goarch. Any other format (thin ELF/Mach-O, scripts, unknown) returns nil
// for the thin-image check to handle.
func checkFatOrPEPlatform(path, goos, goarch string) error {
	if ff, err := macho.OpenFat(path); err == nil {
		defer ff.Close()
		var slices []string
		match := false
		for _, a := range ff.Arches {
			arch := machoCPUArch(a.Cpu)
			slices = append(slices, arch)
			if arch == goarch {
				match = true
			}
		}
		sort.Strings(slices)
		if goos != "darwin" {
			return fmt.Errorf("binary format is universal Mach-O/macOS (%s), host is %s/%s", strings.Join(slices, ", "), goos, goarch)
		}
		if !match {
			return fmt.Errorf("universal Mach-O slices (%s) do not include host architecture %s", strings.Join(slices, ", "), goarch)
		}
		return nil
	}
	if pf, err := pe.Open(path); err == nil {
		defer pf.Close()
		arch := peMachineArch(pf.Machine)
		if goos != "windows" {
			return fmt.Errorf("binary format is PE/Windows (%s), host is %s/%s", arch, goos, goarch)
		}
		if arch != goarch {
			return fmt.Errorf("PE machine %s does not match host architecture %s", arch, goarch)
		}
	}
	return nil
}

func machoCPUArch(cpu macho.Cpu) string {
	switch cpu {
	case macho.CpuAmd64:
		return "amd64"
	case macho.CpuArm64:
		return "arm64"
	case macho.Cpu386:
		return "386"
	case macho.CpuArm:
		return "arm"
	default:
		return fmt.Sprintf("cpu %#x", uint32(cpu))
	}
}

func peMachineArch(machine uint16) string {
	switch machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "amd64"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "arm64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "386"
	default:
		return fmt.Sprintf("machine %#x", machine)
	}
}

// checkBundleAssetsPlatform refuses a bundle whose install.json lists native
// tools but none for goos/goarch. A "cli" app's adapter is portable Go, so the
// binary check above passes, but at its first start the adapter stages the
// fronted tool from install.json and exits 1 when this host is not listed
// ("install assets: stage: no asset for darwin/amd64; available: ..."). The
// supervisor restarts it until the crash-loop limit suspends it, so the
// install "succeeds" and the app never runs. io.pilot.smolmachines 1.2.0 was
// published for darwin/amd64 like that (upstream smolvm has no macOS x86_64
// build). An install.json that does not parse, or lists no assets, is left to
// the app, as before.
func checkBundleAssetsPlatform(bundleDir, goos, goarch string) error {
	raw, err := os.ReadFile(filepath.Join(bundleDir, "install.json")) // #nosec G304 G703 -- install.json of the bundle being installed (the dir pilotctl unpacked, or the --local dir the operator named); only read and parsed
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read install.json: %w", err)
	}
	var spec struct {
		Command string `json:"command"`
		Assets  []struct {
			OS   string `json:"os"`
			Arch string `json:"arch"`
		} `json:"assets"`
	}
	if json.Unmarshal(raw, &spec) != nil || len(spec.Assets) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var avail []string
	for _, a := range spec.Assets {
		if a.OS == goos && a.Arch == goarch {
			return nil
		}
		if p := a.OS + "/" + a.Arch; !seen[p] {
			seen[p] = true
			avail = append(avail, p)
		}
	}
	sort.Strings(avail)
	tool := spec.Command
	if tool == "" {
		tool = "its native tool"
	}
	return fmt.Errorf("the bundle ships %s only for %s, not for %s/%s", tool, strings.Join(avail, ", "), goos, goarch)
}
