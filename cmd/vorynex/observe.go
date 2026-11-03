package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/profiler"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// runObserve runs a workload with NO enforcement, records every file/exec/network
// access to a JSONL event bus, and reports what Protect mode would have blocked.
func runObserve(args []string) error {
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i >= len(args) {
		return fmt.Errorf("usage: vorynex observe -- <command...>")
	}
	cmd := args[i+1:]
	if len(cmd) == 0 {
		return fmt.Errorf("no command after `--`")
	}

	f, path, err := audit.OpenTrace()
	if err != nil {
		return err
	}
	logger := audit.New(f)

	fmt.Fprintln(os.Stderr, "vorynex observe: recording (no enforcement)")
	code, runErr := audit.Trace(cmd, os.Environ(), os.Stdin, os.Stdout, os.Stderr, logger)
	closeErr := f.Close()
	if runErr != nil {
		return runErr
	}
	if closeErr != nil {
		return closeErr
	}

	ef, err := os.Open(path)
	if err != nil {
		return err
	}
	events, err := audit.ReadEvents(ef)
	ef.Close()
	if err != nil {
		return err
	}

	// A single observe run: a capability seen twice is a candidate; a one-off is
	// kept observing. Never-promote classes are excluded regardless.
	prof := profiler.Build([][]audit.Event{events}, profiler.Options{MinSessions: 1, MinCount: 2})
	blocked := profiler.WouldBlock(events)

	// Stream observed events into the local telemetry spool. This is
	// local-first: the exporter drains it separately (docs/FAILURE_MODES.md).
	if spool, err := telemetry.OpenSpool(telemetry.DefaultSpoolPath(), 0); err == nil {
		for _, e := range events {
			_ = spool.Append(e)
		}
	}

	printObserveReport(path, len(events), prof, blocked)

	if code != 0 {
		os.Exit(code)
	}
	return nil
}

func printObserveReport(path string, eventCount int, prof profiler.Profile, blocked []profiler.Blocked) {
	fmt.Printf("\nObserved %d events across %d session(s).\n", eventCount, prof.Sessions)
	fmt.Printf("Event bus (JSONL): %s\n", path)

	fmt.Printf("\nCapabilities (%d):\n", len(prof.Capabilities))
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "  DECISION\tKIND\tTARGET\tCOUNT\tNOTE")
	for _, c := range prof.Capabilities {
		fmt.Fprintf(w, "  %s\t%s\t%s\t%d\t%s\n", c.Decision, c.Kind, c.Target, c.Count, c.Reason)
	}
	w.Flush()

	fmt.Printf("\nWould-have-blocked under Protect: %d\n", len(blocked))
	const max = 20
	for i, b := range blocked {
		if i >= max {
			fmt.Printf("  ... and %d more\n", len(blocked)-max)
			break
		}
		fmt.Printf("  %s  %s %s  (%s)\n", b.Time.Format("15:04:05"), b.Kind, b.Target, b.Reason)
	}

	fmt.Printf("\nSummary: %d promotable, %d observe-only, %d never-promote.\n",
		prof.Summary.Promotable, prof.Summary.ObserveOnly, prof.Summary.NeverPromote)
	fmt.Println("\nNothing was enforced. Review, then run `vorynex protect`.")
}
