package main

import (
	"fmt"
	"strings"

	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/policy"
)

// runLive implements `vorynex live status|plan`.
func runLive(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vorynex live <status|plan> [--policy <file>]")
	}
	switch args[0] {
	case "status":
		return liveStatus()
	case "plan":
		return livePlan(args[1:])
	default:
		return fmt.Errorf("unknown live subcommand %q (want status or plan)", args[0])
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
