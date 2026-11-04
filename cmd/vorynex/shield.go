package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/cve"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/shield"
)

// runShield implements `vorynex shield`: propose containment for a CVE, validate
// it deterministically, and simulate it against recorded traffic.
func runShield(args []string) error {
	var lockPath, osvPath, kevPath, policyPath, eventsPath, out, workload string
	var jsonOut bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--lockfile":
			if i+1 < len(args) {
				i++
				lockPath = args[i]
			}
		case "--osv":
			if i+1 < len(args) {
				i++
				osvPath = args[i]
			}
		case "--kev":
			if i+1 < len(args) {
				i++
				kevPath = args[i]
			}
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--events":
			if i+1 < len(args) {
				i++
				eventsPath = args[i]
			}
		case "--out":
			if i+1 < len(args) {
				i++
				out = args[i]
			}
		case "--workload":
			if i+1 < len(args) {
				i++
				workload = args[i]
			}
		case "--json":
			jsonOut = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if lockPath == "" || osvPath == "" {
		return fmt.Errorf("usage: vorynex shield --lockfile <package-lock.json> --osv <file> [--kev <file>] [--policy <base.yaml>] [--events <events.jsonl>] [--out <candidate.yaml>] [--workload <name>] [--json]")
	}
	if workload == "" {
		workload = "workload"
	}

	pkgs, err := readLockfile(lockPath)
	if err != nil {
		return err
	}
	af, err := os.Open(osvPath)
	if err != nil {
		return err
	}
	advisories, err := cve.ParseOSV(af)
	af.Close()
	if err != nil {
		return err
	}
	var kevSet map[string]bool
	if kevPath != "" {
		kf, err := os.Open(kevPath)
		if err != nil {
			return err
		}
		kevSet, err = cve.ParseKEV(kf)
		kf.Close()
		if err != nil {
			return err
		}
	}

	matches := cve.Correlate(workload, pkgs, advisories, kevSet)
	if len(matches) == 0 {
		fmt.Printf("Emergency Shield: %s\n\nNo affected packages matched; nothing to contain.\n", workload)
		return nil
	}

	base := policy.Policy{}
	if policyPath != "" {
		base, err = policy.Load(policyPath)
		if err != nil {
			return err
		}
	}

	cand := shield.Propose(base, matches)
	problems := shield.Validate(base, cand.Policy)

	var events []audit.Event
	if eventsPath != "" {
		var hostID string
		events, hostID, err = readTraceEvents(eventsPath)
		if err != nil {
			return err
		}
		_ = hostID
	}
	sim := shield.Simulate(base, cand.Policy, events)
	verdict := shield.Decide(problems, sim)

	if jsonOut {
		payload := map[string]any{
			"workload": workload,
			"matches":  matches,
			"candidate": map[string]any{
				"added":  cand.Added,
				"hints":  cand.Hints,
				"policy": cand.Policy,
			},
			"problems":   problems,
			"simulation": sim,
			"verdict":    verdict,
		}
		b, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("Emergency Shield: %s\n\n", workload)
	for _, m := range matches {
		fixed := m.Fixed
		if fixed == "" {
			fixed = "unknown"
		}
		id := m.Advisory.ID
		if len(m.Advisory.Aliases) > 0 {
			id += " (" + join(m.Advisory.Aliases) + ")"
		}
		fmt.Printf("Affected: %s  %s %s -> fixed %s\n", id, m.Package.Name, m.Package.Version, fixed)
	}

	fmt.Printf("\nProposed containment (%d changes):\n", len(cand.Added))
	for _, a := range cand.Added {
		fmt.Printf("  + %s\n", a)
	}
	if len(cand.Hints) > 0 {
		fmt.Println("\nHints:")
		for _, h := range cand.Hints {
			fmt.Printf("  - %s\n", h)
		}
	}

	if len(problems) > 0 {
		fmt.Println("\nValidation: FAILED")
		for _, p := range problems {
			fmt.Printf("  ! %s\n", p)
		}
	} else {
		fmt.Println("\nValidation: PASS")
	}

	fmt.Printf("Simulation: %d events, %d newly contained, %d benign breakages, %d coverage gaps\n",
		sim.Events, len(sim.NewDangerous), len(sim.NewBenign), len(sim.CoverageGaps))
	for _, b := range sim.NewBenign {
		fmt.Printf("  ! would break: %s %s (%s)\n", b.Kind, b.Target, b.Reason)
	}
	for _, g := range sim.CoverageGaps {
		fmt.Printf("  ~ not covered: %s\n", g)
	}

	fmt.Printf("\nVerdict: %s\n", verdict)
	if verdict == shield.VerdictApproved {
		fmt.Println("Next: apply in OBSERVE mode, confirm it fires only on attack traffic, then protect.")
	}

	if out != "" {
		data, err := cand.Policy.Marshal()
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, data, 0o600); err != nil {
			return err
		}
		fmt.Printf("\nCandidate written to %s\n", out)
	}

	fmt.Println("\nMitigation is not a patch. Upgrade the affected package.")
	return nil
}

func join(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
