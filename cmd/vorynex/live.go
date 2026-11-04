package main

import (
	"fmt"
	"os"
	"os/signal"
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
	var object, cgroup string
	capability := 21 // CAP_SYS_ADMIN
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
	if err := s.Arm(id, capability); err != nil {
		return err
	}
	fmt.Printf("armed: denying capability %d for cgroup %d\n", capability, id)
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
