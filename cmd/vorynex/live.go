package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/policy"
)

// runLive implements `vorynex live status|plan|attach`.
func runLive(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vorynex live <status|plan|attach> [...]")
	}
	switch args[0] {
	case "status":
		return liveStatus()
	case "plan":
		return livePlan(args[1:])
	case "attach":
		return liveAttach(args[1:])
	default:
		return fmt.Errorf("unknown live subcommand %q (want status, plan, or attach)", args[0])
	}
}

func liveStatus() error {
	c := live.Detect()
	fmt.Println("Tier 1 (live enforcement)")
	fmt.Printf("  kernel        %s\n", c.Kernel)
	fmt.Printf("  lsm           %s\n", strings.Join(c.LSM, ","))
	fmt.Printf("  bpf-lsm       %v\n", c.HasBPFLSM)
	fmt.Printf("  btf           %v\n", c.HasBTF)
	fmt.Printf("  capabilities  %v\n", c.HasCaps)
	fmt.Printf("  available     %v\n", c.Available)
	if !c.Available {
		fmt.Println("  reasons:")
		for _, r := range c.Reasons {
			fmt.Printf("    - %s\n", r)
		}
		fmt.Println("\nFallback: Tier 0 spawn-time enforcement remains in effect.")
	}
	fmt.Println("\nBPF object: build with `make bpf` (engine/enforce/live/bpf/live.bpf.o).")
	return nil
}

func livePlan(args []string) error {
	var policyPath string
	for i := 0; i < len(args); i++ {
		if args[i] == "--policy" && i+1 < len(args) {
			i++
			policyPath = args[i]
		}
	}
	if policyPath == "" {
		return fmt.Errorf("--policy <file> is required")
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		return err
	}

	hooks := live.Plan(p)
	fmt.Printf("Tier 1 enforcement plan (%d hooks)\n\n", len(hooks))
	for _, h := range hooks {
		fmt.Printf("  %-22s %-26s %s\n", h.Hook, h.Purpose, h.Rule)
	}
	if !live.Detect().Available {
		fmt.Println("\nNote: Tier 1 is not available on this host, so this plan cannot be loaded here.")
		fmt.Println("      Tier 0 spawn-time enforcement still applies. See `vorynex live status`.")
	}
	return nil
}

// liveAttach loads the BPF object, attaches it disarmed, and (when a cgroup is
// given) arms it for that cgroup for a bounded time. It always disarms and
// detaches before returning.
func liveAttach(args []string) error {
	var object, cgroup, denyExec, denyOpen, blockConnect, pid string
	capability := -1
	seconds := 10
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--object":
			if i+1 < len(args) {
				i++
				object = args[i]
			}
		case "--cgroup":
			if i+1 < len(args) {
				i++
				cgroup = args[i]
			}
		case "--cap":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil {
					capability = n
				}
			}
		case "--deny-exec":
			if i+1 < len(args) {
				i++
				denyExec = args[i]
			}
		case "--deny-open":
			if i+1 < len(args) {
				i++
				denyOpen = args[i]
			}
		case "--block-connect":
			if i+1 < len(args) {
				i++
				blockConnect = args[i]
			}
		case "--pid":
			if i+1 < len(args) {
				i++
				pid = args[i]
			}
		case "--seconds":
			if i+1 < len(args) {
				i++
				if n, err := strconv.Atoi(args[i]); err == nil && n > 0 {
					seconds = n
				}
			}
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if object == "" {
		return fmt.Errorf("--object <path> is required; build it with `make bpf`")
	}

	caps := live.Detect()
	if !caps.Available {
		for _, r := range caps.Reasons {
			fmt.Fprintf(os.Stderr, "  - %s\n", r)
		}
		return fmt.Errorf("tier 1 unavailable on this host")
	}

	s, err := live.Attach(caps, object)
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Println("attached (disarmed)")

	if cgroup == "" {
		fmt.Println("no --cgroup given; detaching with no enforcement applied")
		return nil
	}

	id, err := resolveCgroupID(cgroup)
	if err != nil {
		return err
	}
	if pid != "" {
		if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(pid+"\n"), 0o644); err != nil {
			return fmt.Errorf("move pid %s into %s: %w", pid, cgroup, err)
		}
		fmt.Printf("moved pid %s into %s\n", pid, cgroup)
	}
	if err := s.Arm(id); err != nil {
		return err
	}
	fmt.Printf("armed for cgroup %d\n", id)

	denied := false
	if capability >= 0 {
		if err := s.DenyCapability(capability); err != nil {
			return err
		}
		fmt.Printf("  deny capability %d\n", capability)
		denied = true
	}
	if denyExec != "" {
		ino, err := live.InodeOf(denyExec)
		if err != nil {
			return err
		}
		if err := s.DenyExecInode(ino); err != nil {
			return err
		}
		fmt.Printf("  deny exec %s (inode %d)\n", denyExec, ino)
		denied = true
	}
	if denyOpen != "" {
		ino, err := live.InodeOf(denyOpen)
		if err != nil {
			return err
		}
		if err := s.DenyFileInode(ino); err != nil {
			return err
		}
		fmt.Printf("  deny open %s (inode %d)\n", denyOpen, ino)
		denied = true
	}
	if blockConnect != "" {
		ip, port, err := parseBlockTarget(blockConnect)
		if err != nil {
			return err
		}
		if err := s.BlockConnect(ip, port); err != nil {
			return err
		}
		fmt.Printf("  block connect to %s\n", blockConnect)
		denied = true
	}
	if !denied {
		fmt.Println("  armed but nothing denied (pass --cap or --deny-exec)")
	}

	fmt.Printf("running for %ds (Ctrl-C to stop early)\n", seconds)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	select {
	case <-time.After(time.Duration(seconds) * time.Second):
	case <-sig:
	}

	if err := s.Disarm(); err != nil {
		return err
	}
	fmt.Println("disarmed; detaching")
	return nil
}

func resolveCgroupID(arg string) (uint64, error) {
	if v, err := strconv.ParseUint(arg, 10, 64); err == nil {
		return v, nil
	}
	return live.CgroupID(arg)
}

// parseBlockTarget parses "ip" or "ip:port" into the map representation: a
// host-endian u32 of the four address octets, plus a host-order port (0 = any).
func parseBlockTarget(s string) (uint32, uint16, error) {
	host, portStr := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, portStr = h, p
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return 0, 0, fmt.Errorf("%q is not an IPv4 address", host)
	}
	var port uint16
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n < 0 || n > 65535 {
			return 0, 0, fmt.Errorf("%q is not a valid port", portStr)
		}
		port = uint16(n)
	}
	return binary.LittleEndian.Uint32(ip), port, nil
}
