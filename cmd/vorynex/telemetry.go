package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/vorynex/vorynex/engine/telemetry"
)

// runTelemetry implements `vorynex telemetry status|export`.
func runTelemetry(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vorynex telemetry <status|export> [...]")
	}
	dir := telemetry.DefaultDir()
	switch args[0] {
	case "status":
		return telemetryStatus(dir)
	case "export":
		return telemetryExport(dir, args[1:])
	default:
		return fmt.Errorf("unknown telemetry subcommand %q", args[0])
	}
}

func telemetryStatus(dir string) error {
	hostID, err := telemetry.LoadOrCreateHostID(dir)
	if err != nil {
		return err
	}
	spool, err := telemetry.OpenSpool(telemetry.DefaultSpoolPath(), 0)
	if err != nil {
		return err
	}
	records, err := spool.ReadAfter(0)
	if err != nil {
		return err
	}
	cursor := telemetry.LoadCursor(dir)
	pending := 0
	for _, r := range records {
		if r.Seq > cursor {
			pending++
		}
	}
	fmt.Printf("host id        %s\n", hostID)
	fmt.Printf("spool          %s\n", spool.Path())
	fmt.Printf("buffered       %d records\n", len(records))
	fmt.Printf("cursor         %d\n", cursor)
	fmt.Printf("pending export %d records\n", pending)
	if tok := telemetry.LoadHostToken(dir); tok != "" {
		fmt.Printf("host token     stored (%d chars)\n", len(tok))
	} else {
		fmt.Println("host token     none (issued at enrollment when auth is enabled)")
	}
	return nil
}

func telemetryExport(dir string, args []string) error {
	var endpoint, token, policyPath, hostTokenFlag string
	once := false
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
		case "--host-token":
			if i+1 < len(args) {
				i++
				hostTokenFlag = args[i]
			}
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--once":
			once = true
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if endpoint == "" {
		return fmt.Errorf("--endpoint is required")
	}

	hostID, err := telemetry.LoadOrCreateHostID(dir)
	if err != nil {
		return err
	}
	client := telemetry.NewClient(endpoint, token)
	ctx := context.Background()

	// Prefer a per-host token: the admin token is only needed to enroll (or to
	// adopt a rotated token explicitly).
	hostToken := telemetry.LoadHostToken(dir)
	if hostTokenFlag != "" {
		if err := telemetry.SaveHostToken(dir, hostTokenFlag); err != nil {
			return err
		}
		hostToken = hostTokenFlag
		fmt.Printf("stored per-host token for %s\n", hostID)
	}
	if hostToken == "" {
		hostname, _ := os.Hostname()
		issued, err := client.Enroll(ctx, hostID, hostname)
		if err != nil {
			return err
		}
		if issued != "" {
			if err := telemetry.SaveHostToken(dir, issued); err != nil {
				return err
			}
			hostToken = issued
			fmt.Printf("stored per-host token for %s\n", hostID)
		}
		fmt.Printf("enrolled %s at %s\n", hostID, endpoint)
	} else {
		fmt.Printf("using stored per-host token for %s\n", hostID)
	}
	client.SetToken(hostToken)

	// Best-effort: converge the local desired state so a supervisor can apply a
	// staged rollout. Failure here never blocks telemetry.
	if rs, ok, err := client.Desired(ctx, hostID); err == nil && ok {
		prev := telemetry.LoadDesired(dir)
		if err := telemetry.SaveDesired(dir, rs.Revision, rs.Mode, rs.PolicyYAML); err == nil && rs.Revision != prev.Revision {
			fmt.Printf("desired state updated: revision %d, mode %s\n", rs.Revision, rs.Mode)
		}
	}

	if policyPath != "" {
		data, err := os.ReadFile(policyPath)
		if err != nil {
			return err
		}
		if err := client.UploadPolicy(ctx, hostID, data); err != nil {
			return fmt.Errorf("upload policy %s: %w", policyPath, err)
		}
		fmt.Printf("uploaded policy %s\n", policyPath)
	}

	spool, err := telemetry.OpenSpool(telemetry.DefaultSpoolPath(), 0)
	if err != nil {
		return err
	}
	for {
		cursor := telemetry.LoadCursor(dir)
		newCursor, sent, err := client.Export(ctx, spool, hostID, cursor)
		if err != nil {
			if once {
				return err
			}
			fmt.Fprintf(os.Stderr, "export paused (will retry): %v\n", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if sent > 0 {
			if err := telemetry.SaveCursor(dir, newCursor); err != nil {
				return err
			}
			fmt.Printf("exported %d records (cursor %d)\n", sent, newCursor)
		}
		if once {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}
