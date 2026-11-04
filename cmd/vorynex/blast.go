package main

import (
	"encoding/json"
	"fmt"

	"github.com/vorynex/vorynex/engine/blastradius"
	"github.com/vorynex/vorynex/engine/policy"
)

// runBlast prints the blast radius for a policy: what a compromised workload
// could reach, and which danger classes are contained.
func runBlast(args []string) error {
	var policyPath, workload, mode string
	var jsonOut bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--workload":
			if i+1 < len(args) {
				i++
				workload = args[i]
			}
		case "--mode":
			if i+1 < len(args) {
				i++
				mode = args[i]
			}
		case "--json":
			jsonOut = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if policyPath == "" {
		return fmt.Errorf("--policy <file> is required")
	}

	p, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	report := blastradius.FromPolicy(p, workload, mode)

	if jsonOut {
		b, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Blast radius: %s (mode %s)\n", report.Workload, report.Mode)
	fmt.Printf("If this workload were compromised right now:\n\n")

	fmt.Printf("REACHABLE (%d)\n", len(report.Reachable))
	if len(report.Reachable) == 0 {
		fmt.Println("  (none)")
	}
	for _, r := range report.Reachable {
		fmt.Printf("  ! %-8s %-34s %s\n", r.Kind, r.Target, r.Via)
	}

	fmt.Printf("\nCONTAINED (%d)\n", len(report.Contained))
	for _, c := range report.Contained {
		fmt.Printf("  ✓ %-24s %s\n", c.Class, c.Reason)
	}

	if len(report.Warnings) > 0 {
		fmt.Printf("\nWARNINGS (%d)\n", len(report.Warnings))
		for _, w := range report.Warnings {
			fmt.Printf("  ! %s\n", w)
		}
	}
	return nil
}
