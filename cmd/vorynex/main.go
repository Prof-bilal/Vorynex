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

// Stamped at build time: -X main.version=... -X main.commit=... -X main.date=...
// (see `make release`). The defaults keep `go run` and `go test` working.
var (
	version = "0.0.1-dev"
	commit  = ""
	date    = ""
)

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
  telemetry   status | export --endpoint <url> [--token <t>] [--once]
  protect     Enable high-confidence enforcement from an observe baseline, apply
              the policy the control plane staged, or turn protection off
                vorynex protect --from <events.jsonl> -- <command...>
                vorynex protect --from-desired [--pubkey <hex|file>] [-- <command...>]
                vorynex protect --off
  run         Supervise a workload under a policy and roll back if it never
              becomes healthy
                vorynex run --policy <file> [--health <url|cmd>] -- <command...>
  status      Show current mode, effective policy, and recent events
  trace       Show a human-readable attack trace
                vorynex trace [--from <events.jsonl>] [--workload <id>] [--all] [--json]
  blast-radius  Show what a compromised workload could reach, from a policy
                vorynex blast-radius --policy <file> [--workload <name>] [--json]
  cve         Correlate known vulnerabilities with a workload's packages
                vorynex cve scan --lockfile <package-lock.json> --osv <file> [--kev <file>]
  shield      Propose, validate, and simulate CVE containment
                vorynex shield --lockfile <package-lock.json> --osv <file> [--events <events.jsonl>]
  live        Tier 1 capability status and enforcement plan
                vorynex live status | vorynex live plan --policy <file>
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
		if len(args) > 1 && args[1] == "--json" {
			fmt.Printf("{\"version\":%q,\"commit\":%q,\"date\":%q}\n", version, commit, date)
			return
		}
		fmt.Printf("vorynex %s\n", version)
		if commit != "" || date != "" {
			fmt.Printf("  commit %s  built %s\n", orUnknown(commit), orUnknown(date))
		}
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
	case "telemetry":
		if err := runTelemetry(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "trace":
		if err := runTrace(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "blast-radius":
		if err := runBlast(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "cve":
		if err := runCve(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "shield":
		if err := runShield(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "protect":
		if err := runProtect(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "connect":
		if err := runConnect(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := runStatus(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "run":
		if err := runRun(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "live":
		if err := runLive(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	case "rollout":
		if err := runRollout(args[1:]); err != nil {
			fmt.Fprintf(os.Stderr, "vorynex: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "vorynex: %q is not implemented in this build\n", args[0])
		fmt.Fprintln(os.Stderr, "run `vorynex help` for the command surface")
		os.Exit(2)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// runExec parses `--policy <file> -- <command...>`, loads the policy, and
// launches the command under the spawn-time boundary. On success it never
// returns: the process image is replaced by the workload.
func runExec(args []string) error {
	var policyPath, sigPath, keySpec string
	i := 0
	for i < len(args) && args[i] != "--" {
		switch args[i] {
		case "--policy":
			if i+1 >= len(args) {
				return fmt.Errorf("--policy requires a value")
			}
			policyPath = args[i+1]
			i += 2
		case "--sig":
			if i+1 >= len(args) {
				return fmt.Errorf("--sig requires a value")
			}
			sigPath = args[i+1]
			i += 2
		case "--pubkey":
			if i+1 >= len(args) {
				return fmt.Errorf("--pubkey requires a value")
			}
			keySpec = args[i+1]
			i += 2
		default:
			return fmt.Errorf("unknown flag %q (want --policy <file> [--sig <file> --pubkey <hex|file>] -- <command...>)", args[i])
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
	if (sigPath == "") != (keySpec == "") {
		return fmt.Errorf("--sig and --pubkey must be given together")
	}
	if sigPath != "" {
		keyID, err := verifyDetached(policyPath, sigPath, keySpec)
		if err != nil {
			return fmt.Errorf("refusing to run: %w", err)
		}
		fmt.Fprintf(os.Stderr, "policy signature verified (key %s)\n", keyID)
	}
	p, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	return spawntime.Run(cmd, p)
}
