package main

import (
	"context"
	"fmt"

	"github.com/vorynex/vorynex/engine/telemetry"
)

// runRollout implements `vorynex rollout pull|status`.
//
// The control plane stages a desired mode (and optional policy); the agent
// pulls it and persists it locally. Vorynex never silently restarts or
// reconfigures a customer's process: the supervisor converges to the desired
// state with `vorynex protect` / `vorynex exec` on its own schedule.
func runRollout(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vorynex rollout <pull|status> [...]")
	}
	switch args[0] {
	case "pull":
		return rolloutPull(args[1:])
	case "status":
		return rolloutStatus()
	default:
		return fmt.Errorf("unknown rollout subcommand %q (want pull or status)", args[0])
	}
}

func rolloutPull(args []string) error {
	var endpoint, token, dir string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--endpoint":
			if i+1 < len(args) {
				i++
				endpoint = args[i]
			}
		case "--token":
			if i+1 < len(args) {
				i++
				token = args[i]
			}
		case "--dir":
			if i+1 < len(args) {
				i++
				dir = args[i]
			}
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}
	if dir == "" {
		dir = telemetry.DefaultDir()
	}
	hostID, err := telemetry.LoadOrCreateHostID(dir)
	if err != nil {
		return err
	}
	client := telemetry.NewClient(endpoint, token)
	if ht := telemetry.LoadHostToken(dir); ht != "" {
		client.SetToken(ht)
	}
	ctx := context.Background()

	rs, ok, err := client.Desired(ctx, hostID)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Printf("no desired state staged for %s\n", hostID)
		return nil
	}

	prev := telemetry.LoadDesired(dir)
	if err := telemetry.SaveDesired(dir, rs.Revision, rs.Mode, rs.PolicyYAML); err != nil {
		return err
	}
	fmt.Printf("desired state: revision %d, mode %s\n", rs.Revision, rs.Mode)
	if rs.Revision == prev.Revision {
		fmt.Println("already up to date; nothing changed")
		return nil
	}
	if rs.PolicyYAML != "" {
		path := dir + "/desired.policy.yaml"
		fmt.Printf("policy written to %s\n", path)
		if rs.Mode == "protect" || rs.Mode == "lockdown" {
			fmt.Println("supervisor: launch the workload under this policy, e.g.")
			fmt.Printf("  vorynex exec --policy %s -- <command...>\n", path)
		}
	}
	return nil
}

func rolloutStatus() error {
	dir := telemetry.DefaultDir()
	d := telemetry.LoadDesired(dir)
	if d.Revision == 0 && d.Mode == "" {
		fmt.Println("no desired state pulled yet (run `vorynex rollout pull --endpoint <url>`)")
		return nil
	}
	fmt.Printf("desired revision %d\n", d.Revision)
	fmt.Printf("desired mode     %s\n", d.Mode)
	if d.Policy != "" {
		fmt.Printf("desired policy   %d bytes (desired.policy.yaml)\n", len(d.Policy))
	} else {
		fmt.Println("desired policy   none")
	}
	return nil
}
