// Command vorynex is the Vorynex agent CLI.
//
// Tier 0 enforcement (spawn-time, Landlock) is implemented for `vorynex exec`,
// which launches a workload under a least-privilege runtime boundary. The
// remaining commands are not implemented yet and say so rather than pretending
// to protect a workload.
package main

import (
	"fmt"
	"os"

	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/policy"
)

const version = "0.0.1-dev"

const usage = `vorynex — managed runtime security for web applications

Usage:
  vorynex <command> [arguments]

Commands:
  exec        Launch a workload under a Tier 0 (spawn-time) boundary
                vorynex exec --policy <file> -- <command...>
  discover    List running containers and their detected runtime
                --details to classify writable paths, sensitive mounts, secrets
  doctor      Report platform + enforcement capabilities
  connect     Connect this host and discover the application (Milestone 2)
  observe     Profile a workload with no enforcement (records what Protect would block)
                vorynex observe -- <command...>
  policy      Generate a reviewable, signable policy from observed behavior
                vorynex policy generate --from <events.jsonl> [--out <file>]
  protect     Enable high-confidence enforcement (Milestone 4)
  status      Show current mode, effective policy, and recent events
  trace       Show a human-readable attack trace
  version     Print the version

See docs/ARCHITECTURE.md.`

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
	case "exec":
		if err := runExec(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "doctor":
		runDoctor()
	case "discover":
		if err := runDiscover(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "observe":
		if err := runObserve(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "policy":
		if err := runPolicy(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "vorynex: %q is not implemented in this build\n", args[0])
		fmt.Fprintln(os.Stderr, "run `vorynex help` for the command surface")
		os.Exit(2)
	}
}

// runExec parses `--policy <file> -- <command...>`, loads the policy, and
// launches the command under the spawn-time boundary. On success it never
// returns: the process image is replaced by the workload.
func runExec(args []string) error {
	var policyPath string
	i := 0
	for i < len(args) && args[i] != "--" {
		switch args[i] {
		case "--policy":
			if i+1 >= len(args) {
				return fmt.Errorf("--policy requires a value")
			}
			policyPath = args[i+1]
			i += 2
		default:
			return fmt.Errorf("unknown flag %q (want --policy <file> -- <command...>)", args[i])
		}
	}
	if i >= len(args) {
		return fmt.Errorf("missing `--` before the command")
	}
	cmd := args[i+1:]
	if policyPath == "" {
		return fmt.Errorf("--policy is required")
	}
	if len(cmd) == 0 {
		return fmt.Errorf("no command after `--`")
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	return spawntime.Run(cmd, p)
}
