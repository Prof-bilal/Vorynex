package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
)

// runDoctor reports the host's enforcement capabilities. It never guesses: it
// reports what is actually available so the operator knows which tier can be
// enforced (see docs/FAILURE_MODES.md — never claim a protection level the host
// cannot enforce).
func runDoctor() {
	fmt.Println("Vorynex — capability report")
	fmt.Printf("  os/arch       %s/%s\n", runtime.GOOS, runtime.GOARCH)

	if runtime.GOOS == "linux" {
		fmt.Printf("  kernel        %s\n", kernelRelease())
		abi := spawntime.LandlockABI()
		if abi > 0 {
			fmt.Printf("  landlock      ABI %d (Tier 0 filesystem + network available)\n", abi)
		} else {
			fmt.Printf("  landlock      unavailable (needs kernel 5.13+ with CONFIG_SECURITY_LANDLOCK)\n")
		}
		fmt.Printf("  lsm           %s\n", lsmList())
		caps := live.Detect()
		if caps.Available {
			fmt.Printf("  tier-1        available (eBPF-LSM: file-granular exec, live enforcement)\n")
		} else {
			reason := "unavailable"
			if len(caps.Reasons) > 0 {
				reason = caps.Reasons[0]
			}
			fmt.Printf("  tier-1        unavailable (%s)\n", reason)
		}
	}

	for _, tool := range []string{"bwrap", "docker", "strace"} {
		if path, err := exec.LookPath(tool); err == nil {
			fmt.Printf("  %-13s %s\n", tool, path)
		} else {
			fmt.Printf("  %-13s not found\n", tool)
		}
	}

	if runtime.GOOS == "linux" && spawntime.LandlockABI() == 0 {
		fmt.Println("\nverdict: enforcement unavailable — Vorynex will fail closed rather than run a workload unprotected")
	}
}

func kernelRelease() string {
	var u struct{ sysname, nodename, release [65]byte }
	// uname(2) via the syscall package keeps this dependency-free.
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	_ = u
	return "unknown"
}

func lsmList() string {
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "unknown (securityfs not mounted?)"
}
