// Command vorynex is the Vorynex agent CLI.
//
// Milestone 1 scaffold: the command surface is defined here, but enforcement
// (Tier 0 spawn-time, Tier 1 live) is not implemented yet. Commands that are
// not yet available say so rather than pretending to protect a workload.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1-dev"

const usage = `vorynex — managed runtime security for web applications

Usage:
  vorynex <command> [arguments]

Commands:
  connect     Connect this host and discover the application (Milestone 2)
  observe     Profile the workload without enforcing (Milestone 3)
  protect     Enable high-confidence enforcement (Milestone 4)
  status      Show current mode, effective policy, and recent events
  trace       Show a human-readable attack trace
  doctor      Report platform + enforcement capabilities
  version     Print the version

Enforcement is not implemented in this build. See docs/ARCHITECTURE.md.`

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Println(usage)
		return
	}
	switch args[0] {
	case "version", "--version", "-v":
		fmt.Printf("vorynex %s\n", version)
	case "help", "--help", "-h":
		fmt.Println(usage)
	case "doctor":
		fmt.Println("capability reporting not implemented yet (Milestone 1)")
	default:
		fmt.Fprintf(os.Stderr, "vorynex: %q is not implemented in this build\n", args[0])
		fmt.Fprintln(os.Stderr, "run `vorynex help` for the command surface")
		os.Exit(2)
	}
}
