package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/discovery"
	"github.com/vorynex/vorynex/engine/enforce/live"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/state"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// runConnect is the one-command onboarding path: it reports what the host can
// enforce, discovers the workload, optionally enrolls with the control plane,
// and records a baseline in observe mode.
//
// It never enters protect. Every line it prints comes from discovery or a real
// probe; if data is missing it says "unknown" rather than inventing a tick.
func runConnect(args []string) error {
	var workload, endpoint, token string
	var cmd []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--workload":
			if i+1 >= len(args) {
				return fmt.Errorf("--workload requires a value")
			}
			i++
			workload = args[i]
		case "--endpoint":
			if i+1 >= len(args) {
				return fmt.Errorf("--endpoint requires a value")
			}
			i++
			endpoint = args[i]
		case "--token":
			if i+1 >= len(args) {
				return fmt.Errorf("--token requires a value")
			}
			i++
			token = args[i]
		case "--":
			cmd = args[i+1:]
			i = len(args)
		default:
			return fmt.Errorf("unknown flag %q (usage: vorynex connect [--workload <name>] [--endpoint <url>] [--token <t>] [-- <command...>])", args[i])
		}
	}

	dir := telemetry.DefaultDir()
	hostID, err := telemetry.LoadOrCreateHostID(dir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	abi := spawntime.LandlockABI()
	caps := live.Detect()

	// --- discovery (best effort: Docker may not be present) -----------------
	var rep *discovery.Report
	var discoveryErr error
	containers, derr := discovery.NodeWorkloads(ctx)
	if derr != nil {
		containers, derr = discovery.ListRunning(ctx)
	}
	if derr != nil {
		discoveryErr = derr
	} else if len(containers) > 0 {
		c, perr := pickWorkload(containers, workload)
		switch {
		case perr == nil:
			if r, err := discovery.BuildReport(ctx, c); err == nil {
				rep = &r
				if workload == "" {
					workload = c.Name()
				}
			} else {
				discoveryErr = err
			}
		case len(containers) > 1 && workload == "":
			printWorkloadList(containers)
			return fmt.Errorf("multiple workloads found; re-run with --workload <name>")
		default:
			discoveryErr = perr
		}
	}

	// --- optional enrollment -------------------------------------------------
	hostToken := telemetry.LoadHostToken(dir)
	issuedNow := false
	if endpoint != "" {
		client := telemetry.NewClient(endpoint, token)
		if hostToken == "" {
			hostname, _ := os.Hostname()
			issued, err := client.Enroll(ctx, hostID, hostname)
			if err != nil {
				return fmt.Errorf("enroll with %s: %w", endpoint, err)
			}
			if issued != "" {
				if err := telemetry.SaveHostToken(dir, issued); err != nil {
					return err
				}
				hostToken = issued
				issuedNow = true
			}
		}
		if _, err := state.SetControlPlane(endpoint); err != nil {
			return err
		}
	}

	// --- baseline (only if a command was given) ------------------------------
	var baseline string
	var observed int
	var workloadCode int
	if len(cmd) > 0 {
		path, events, code, err := observeCommand(cmd)
		if err != nil {
			return err
		}
		baseline, observed, workloadCode = path, len(events), code
		if _, err := state.SetBaseline(path); err != nil {
			return err
		}
	}

	if _, err := state.SetMode(state.ModeObserve); err != nil {
		return err
	}
	if workload != "" {
		if _, err := state.SetWorkload(workload); err != nil {
			return err
		}
	}
	_ = state.Journal(state.JournalEntry{
		Event:  "connect",
		Mode:   state.ModeObserve,
		Detail: strings.TrimSpace(workload + " " + endpoint),
	})

	printConnectReport(hostID, workload, rep, discoveryErr, abi, caps, endpoint, issuedNow, hostToken != "", baseline, observed)
	if workloadCode != 0 {
		fmt.Fprintf(os.Stderr, "\nnote: the observed command exited with code %d; the baseline is still recorded.\n", workloadCode)
	}
	return nil
}

// pickWorkload matches by exact id, id prefix, or container name.
func pickWorkload(containers []discovery.Container, want string) (discovery.Container, error) {
	if want == "" {
		if len(containers) == 1 {
			return containers[0], nil
		}
		return discovery.Container{}, fmt.Errorf("%d workloads found", len(containers))
	}
	for _, c := range containers {
		if c.ID == want || strings.HasPrefix(c.ID, want) || c.Name() == strings.TrimPrefix(want, "/") {
			return c, nil
		}
	}
	return discovery.Container{}, fmt.Errorf("no workload matches %q", want)
}

func printWorkloadList(containers []discovery.Container) {
	fmt.Println("Workloads found:")
	for _, c := range containers {
		fmt.Printf("  %-28s %s  (%s)\n", c.Name(), c.Image, discovery.Runtime(c))
	}
}

func printConnectReport(hostID, workload string, rep *discovery.Report, discoveryErr error, abi int, caps live.Capabilities, endpoint string, issuedNow, hasToken bool, baseline string, observed int) {
	fmt.Printf("Vorynex connect — %s\n\n", hostID)

	if abi > 0 {
		fmt.Printf("  ✓ platform       landlock ABI %d · tier 0 available\n", abi)
	} else {
		fmt.Println("  ✗ platform       no Landlock (needs kernel 5.13+ with CONFIG_SECURITY_LANDLOCK)")
	}
	if caps.Available {
		fmt.Println("  ✓ tier 1         eBPF-LSM available (live enforcement)")
	} else {
		reason := "unavailable"
		if len(caps.Reasons) > 0 {
			reason = caps.Reasons[0]
		}
		fmt.Printf("  · tier 1         %s\n", reason)
	}

	if rep == nil {
		if discoveryErr != nil {
			fmt.Printf("  · workload       unknown — Docker discovery failed: %v\n", discoveryErr)
		} else {
			fmt.Println("  · workload       none found (no Node workloads running in Docker)")
		}
	} else {
		fmt.Printf("  ✓ workload       %s · %s · image %s", rep.Name, rep.Runtime, rep.Image)
		if rep.User != "" {
			fmt.Printf(" · user %s", rep.User)
		}
		fmt.Println()
		if rep.Privileged {
			fmt.Println("  ⚠ privileged     container runs privileged")
		}
		if rep.ReadonlyRootfs {
			fmt.Println("  ✓ root fs        read-only")
		}
		if len(rep.WritablePaths) > 0 {
			fmt.Printf("  ✓ writable       %s\n", strings.Join(rep.WritablePaths, ", "))
		}
		if len(rep.ReadOnlyPaths) > 0 {
			fmt.Printf("  · read-only      %s\n", strings.Join(rep.ReadOnlyPaths, ", "))
		}
		if len(rep.SensitiveMounts) > 0 {
			var names []string
			for _, m := range rep.SensitiveMounts {
				names = append(names, fmt.Sprintf("%s (%s)", m.Destination, m.Reason))
			}
			fmt.Printf("  ⚠ sensitive      %s\n", strings.Join(names, ", "))
		}
		if len(rep.SecretEnvNames) > 0 {
			fmt.Printf("  ⚠ secret env     %s (names only, values never read)\n", strings.Join(rep.SecretEnvNames, ", "))
		}
		if rep.NetworkMode != "" {
			fmt.Printf("  · network        %s\n", rep.NetworkMode)
		}
		if len(rep.Warnings) > 0 {
			fmt.Printf("  ⚠ warnings       %d — %s\n", len(rep.Warnings), strings.Join(rep.Warnings, "; "))
		}
	}

	switch {
	case endpoint == "":
		fmt.Println("  · control plane  not configured (local-first; pass --endpoint to enroll)")
	case issuedNow:
		fmt.Printf("  ✓ control plane  enrolled with %s (per-host token stored)\n", endpoint)
	case hasToken:
		fmt.Printf("  ✓ control plane  using stored per-host token for %s\n", endpoint)
	default:
		fmt.Printf("  · control plane  %s (no host token — auth may be disabled there)\n", endpoint)
	}

	if baseline != "" {
		fmt.Printf("  ✓ baseline       %d events recorded at %s\n", observed, baseline)
	} else {
		fmt.Println("  · baseline       not measured yet")
	}
	fmt.Printf("  mode            observe (nothing enforced)\n")

	fmt.Println()
	if baseline == "" {
		fmt.Println("next: record a baseline, then review it:")
		fmt.Println("  vorynex connect -- <your start command>     (or attach to a running workload)")
		fmt.Println("  vorynex policy generate --from <events.jsonl> --out policy.yaml")
	} else {
		fmt.Println("next:")
		fmt.Printf("  vorynex policy generate --from %s --out policy.yaml\n", baseline)
		fmt.Println("  vorynex protect --from <events.jsonl> -- <your start command>")
	}
	fmt.Println("Nothing was enforced. `vorynex status` shows the current posture.")
}
