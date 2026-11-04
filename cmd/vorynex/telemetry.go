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
	return nil
}

func telemetryExport(dir string, args []string) error {
	var endpoint, token, policyPath string
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
	hostname, _ := os.Hostname()
	client := telemetry.NewClient(endpoint, token)
	ctx := context.Background()
	if err := client.Enroll(ctx, hostID, hostname); err != nil {
		return err
	}
	fmt.Printf("enrolled %s at %s\n", hostID, endpoint)

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
