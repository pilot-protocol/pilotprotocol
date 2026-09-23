// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"debug/macho"
	"debug/pe"
	"fmt"
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
