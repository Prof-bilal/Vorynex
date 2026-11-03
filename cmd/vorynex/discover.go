package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/vorynex/vorynex/engine/discovery"
)

// runDiscover lists the workloads Vorynex can protect on this host.
func runDiscover() error {
	containers, err := discovery.ListRunning(context.Background())
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
	return w.Flush()
}
