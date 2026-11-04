package main

import (
	"encoding/json"
	"fmt"

	"github.com/vorynex/vorynex/engine/blastradius"
	"github.com/vorynex/vorynex/engine/policy"
)

// runBlast prints the blast radius for a policy: what a compromised workload
// could reach, and which danger classes are contained. With --compare it prints
// the difference between the two policies.
func runBlast(args []string) error {
	var policyPath, workload, mode, compare string
	var jsonOut bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--compare":
			if i+1 < len(args) {
				i++
				compare = args[i]
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

	if compare != "" {
		p2, err := policy.Load(compare)
		if err != nil {
			return err
		}
		report2 := blastradius.FromPolicy(p2, workload, mode)
		diff := blastradius.Diff(report, report2)
		if jsonOut {
			b, _ := json.MarshalIndent(diff, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("Blast radius diff: %s\n  before: %s\n  after:  %s\n\n", report.Workload, policyPath, compare)
		fmt.Printf("REACHABLE added (%d)\n", len(diff.ReachableAdded))
		for _, r := range diff.ReachableAdded {
			fmt.Printf("  + %-8s %s\n", r.Kind, r.Target)
		}
		fmt.Printf("REACHABLE removed (%d)\n", len(diff.ReachableRemoved))
		for _, r := range diff.ReachableRemoved {
			fmt.Printf("  - %-8s %s\n", r.Kind, r.Target)
		}
		fmt.Printf("CONTAINED added (%d)\n", len(diff.ContainedAdded))
		for _, c := range diff.ContainedAdded {
			fmt.Printf("  + %s\n", c.Class)
		}
		fmt.Printf("CONTAINED removed (%d)\n", len(diff.ContainedRemoved))
		for _, c := range diff.ContainedRemoved {
			fmt.Printf("  - %s\n", c.Class)
		}
		return nil
	}

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
