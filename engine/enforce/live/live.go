// Package live implements Tier 1 live enforcement planning and capability
// detection for eBPF-LSM.
//
// Loading BPF programs requires CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN) and a
// kernel with CONFIG_BPF_LSM. This package reports honestly whether the host
// can enforce, derives the enforcement plan from a policy, and refuses to
// pretend when it cannot. The kernel loader itself is not part of this build:
// it must be validated with the required privileges, and an unverified
// privileged loader is worse than a clear refusal.
package live

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/vorynex/vorynex/engine/policy"
)

// Capabilities describes whether Tier 1 can be enforced on this host.
type Capabilities struct {
	Available       bool     `json:"available"`
	Kernel          string   `json:"kernel"`
	LSM             []string `json:"lsm"`
	HasBPFLSM       bool     `json:"has_bpf_lsm"`
	HasBTF          bool     `json:"has_btf"`
	HasCaps         bool     `json:"has_capabilities"`
	KernelAtLeast57 bool     `json:"kernel_at_least_5_7"`
	Reasons         []string `json:"reasons,omitempty"`
}

// Detect probes the running host.
func Detect() Capabilities { return detect("/") }

func detect(root string) Capabilities {
	c := Capabilities{Kernel: strings.TrimSpace(readFile(filepath.Join(root, "proc/sys/kernel/osrelease")))}

	if runtime.GOOS != "linux" {
		c.Reasons = append(c.Reasons, "Tier 1 is Linux-only")
		return c
	}

	if lsm := readFile(filepath.Join(root, "sys/kernel/security/lsm")); lsm != "" {
		c.LSM = strings.Split(strings.TrimSpace(lsm), ",")
	} else {
		c.Reasons = append(c.Reasons, "securityfs not mounted (/sys/kernel/security/lsm unreadable)")
	}
	c.HasBPFLSM = containsString(c.LSM, "bpf")
	if !c.HasBPFLSM {
		c.Reasons = append(c.Reasons, "bpf is not in the active LSM list (needs kernel 5.7+, CONFIG_BPF_LSM, lsm=...,bpf)")
	}

	if fileExists(filepath.Join(root, "sys/kernel/btf/vmlinux")) {
		c.HasBTF = true
	} else {
		c.Reasons = append(c.Reasons, "no BTF at /sys/kernel/btf/vmlinux (CO-RE unavailable)")
	}

	if major, minor, ok := parseKernel(c.Kernel); ok {
		c.KernelAtLeast57 = major > 5 || (major == 5 && minor >= 7)
		if !c.KernelAtLeast57 {
			c.Reasons = append(c.Reasons, fmt.Sprintf("kernel %d.%d is older than 5.7", major, minor))
		}
	} else {
		c.Reasons = append(c.Reasons, "cannot determine kernel version")
	}

	if caps, ok := readCapEff(filepath.Join(root, "proc/self/status")); ok {
		// CAP_SYS_ADMIN(21), or CAP_PERFMON(38) + CAP_BPF(39).
		c.HasCaps = hasCap(caps, 21) || (hasCap(caps, 38) && hasCap(caps, 39))
		if !c.HasCaps {
			c.Reasons = append(c.Reasons, "agent lacks CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN); run it with those capabilities")
		}
	} else {
		c.Reasons = append(c.Reasons, "cannot read the process capability set (/proc/self/status)")
	}

	c.Available = c.HasBPFLSM && c.HasBTF && c.HasCaps && c.KernelAtLeast57
	return c
}

// Hook is one piece of the live enforcement plan.
type Hook struct {
	Hook    string `json:"hook"`
	Purpose string `json:"purpose"`
	Rule    string `json:"rule"`
}

// Plan derives the eBPF-LSM hooks a policy needs. It is deterministic and does
// not require privileges, so it can be reviewed before anything is loaded.
func Plan(p policy.Policy) []Hook {
	var hooks []Hook

	for _, ex := range p.Process.Exec.Deny {
		hooks = append(hooks, Hook{Hook: "bprm_check_security", Purpose: "deny process execution", Rule: "deny exec " + ex})
	}
	if len(p.Process.Exec.Allow) > 0 {
		hooks = append(hooks, Hook{
			Hook:    "bprm_check_security",
			Purpose: "exec allowlist",
			Rule:    "allow only " + strings.Join(p.Process.Exec.Allow, ", "),
		})
	}

	if p.Filesystem.ProtectSecrets {
		hooks = append(hooks, Hook{
			Hook:    "file_open",
			Purpose: "protect secrets",
			Rule:    "deny opens of .env, *.pem, *.key, .ssh, .aws, .kube, .docker",
		})
	}
	for _, d := range p.Filesystem.Deny {
		hooks = append(hooks, Hook{Hook: "file_open", Purpose: "deny path", Rule: "deny open " + d})
	}

	hooks = append(hooks, Hook{
		Hook:    "socket_connect",
		Purpose: "block cloud metadata",
		Rule:    "deny connect to 169.254.169.254 and 169.254.170.2",
	})
	if len(p.Network.Allow) > 0 {
		hooks = append(hooks, Hook{
			Hook:    "socket_connect",
			Purpose: "egress allowlist",
			Rule:    "allow only resolved allowlist hosts: " + strings.Join(p.Network.Allow, ", "),
		})
	}

	hooks = append(hooks, Hook{
		Hook:    "capable",
		Purpose: "block privilege escalation",
		Rule:    "deny capability changes",
	})
	return hooks
}

// UnavailableError explains why Tier 1 cannot be enforced. It is never a silent
// fallback: the caller must report it.
type UnavailableError struct {
	Reasons []string
}

func (e *UnavailableError) Error() string {
	return "tier 1 unavailable: " + strings.Join(e.Reasons, "; ")
}

// Session is an attached, disarmed Tier 1 enforcement session.
type Session interface {
	// Arm targets one cgroup and denies one capability for it.
	Arm(cgroupID uint64, capability int) error
	// Disarm makes the attached program inert again.
	Disarm() error
	// Close detaches the program and releases resources.
	Close() error
}

// Attach loads the compiled BPF-LSM object and attaches it DISARMED. It fails
// honestly when the host cannot enforce or the object is missing.
func Attach(c Capabilities, bpfObject string) (Session, error) {
	if !c.Available {
		return nil, &UnavailableError{Reasons: c.Reasons}
	}
	if bpfObject == "" {
		return nil, &UnavailableError{Reasons: []string{
			"no BPF object supplied; build it with `make bpf` and pass its path",
		}}
	}
	return attachObject(bpfObject)
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == s {
			return true
		}
	}
	return false
}

func parseKernel(release string) (int, int, bool) {
	release = strings.TrimSpace(release)
	if i := strings.IndexAny(release, "-+"); i >= 0 {
		release = release[:i]
	}
	parts := strings.Split(release, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return major, minor, true
}

// readCapEff parses the CapEff mask from /proc/self/status.
func readCapEff(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		v, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

func hasCap(mask uint64, bit uint) bool {
	return mask&(1<<bit) != 0
}
