package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/vorynex/vorynex/engine/discovery"
)

// runDiscover lists the workloads Vorynex can protect, and with --details
// classifies what each one can reach (writable paths, sensitive mounts, secret
// environment variable names, network exposure).
func runDiscover(args []string) error {
	details := false
	for _, a := range args {
		if a == "--details" || a == "-v" {
			details = true
		}
	}

	ctx := context.Background()
	containers, err := discovery.ListRunning(ctx)
	if err != nil {
		return err
	}
	if len(containers) == 0 {
		fmt.Println("no running containers found")
		return nil
	}

	fmt.Printf("%d running container(s):\n\n", len(containers))
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tRUNTIME\tIMAGE\tSTATUS")
	for _, c := range containers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.Name(), discovery.Runtime(c), c.Image, c.Status)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	if !details {
		return nil
	}

	for _, c := range containers {
		report, err := discovery.BuildReport(ctx, c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%s: %v\n", c.Name(), err)
			continue
		}
		printReport(report)
	}
	return nil
}

func printReport(r discovery.Report) {
	fmt.Printf("\n%s  (%s, %s)\n", r.Name, r.Runtime, r.Image)
	if r.User != "" {
		fmt.Printf("  user              %s\n", r.User)
	}
	fmt.Printf("  network mode      %s\n", orNone(r.NetworkMode))
	fmt.Printf("  readonly rootfs   %v\n", r.ReadonlyRootfs)
	fmt.Printf("  published ports   %s\n", portsString(r.PublishedPorts))

	if len(r.WritablePaths) > 0 {
		fmt.Printf("  writable paths    %v\n", r.WritablePaths)
	}
	if len(r.ReadOnlyPaths) > 0 {
		fmt.Printf("  read-only paths   %v\n", r.ReadOnlyPaths)
	}
	if len(r.SecretEnvNames) > 0 {
		fmt.Printf("  secret env names  %v  (names only; values never read)\n", r.SecretEnvNames)
	}
	for _, m := range r.SensitiveMounts {
		fmt.Printf("  ! sensitive mount %s <- %s (%s)\n", m.Destination, m.Source, m.Reason)
	}
	for _, warn := range r.Warnings {
		fmt.Printf("  ! %s\n", warn)
	}
}

func portsString(ports []discovery.Port) string {
	if len(ports) == 0 {
		return "none"
	}
	var out []string
	for _, p := range ports {
		if p.PublicPort != 0 {
			out = append(out, fmt.Sprintf("%d->%d/%s", p.PublicPort, p.PrivatePort, p.Type))
		} else {
			out = append(out, fmt.Sprintf("%d/%s", p.PrivatePort, p.Type))
		}
	}
	return fmt.Sprint(out)
}

func orNone(s string) string {
	if s == "" {
		return "default (bridge)"
	}
	return s
}
