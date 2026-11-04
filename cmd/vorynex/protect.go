package main

import (
	"fmt"
	"os"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/policygen"
	"github.com/vorynex/vorynex/engine/profiler"
)

// runProtect generates a high-confidence policy from an observe baseline and
// launches the workload under Tier 0 (Landlock). It closes observe -> protect in
// one command.
func runProtect(args []string) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	var flagArgs, cmd []string
	if sep >= 0 {
		flagArgs, cmd = args[:sep], args[sep+1:]
	} else {
		flagArgs = args
	}

	var from, out string
	for i := 0; i < len(flagArgs); i++ {
		switch flagArgs[i] {
		case "--from":
			if i+1 < len(flagArgs) {
				i++
				from = flagArgs[i]
			}
		case "--out":
			if i+1 < len(flagArgs) {
				i++
				out = flagArgs[i]
			}
		default:
			return fmt.Errorf("unknown flag %q", flagArgs[i])
		}
	}
	if from == "" {
		return fmt.Errorf("usage: vorynex protect --from <events.jsonl> [--out <file>] -- <command...>")
	}
	if len(cmd) == 0 {
		return fmt.Errorf("no command after `--`")
	}

	events, _, err := readTraceEvents(from)
	if err != nil {
		return err
	}
	prof := profiler.Build([][]audit.Event{events}, profiler.Options{MinSessions: 1, MinCount: 2})
	res := policygen.Generate(prof, policygen.DefaultOptions())
	data, err := res.Policy.Marshal()
	if err != nil {
		return err
	}
	path := out
	if path == "" {
		f, err := os.CreateTemp("", "vorynex-policy-*.yaml")
		if err != nil {
			return err
		}
		path = f.Name()
		if _, err := f.Write(data); err != nil {
			f.Close()
			return err
		}
		f.Close()
	} else if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}

	printGenSummary(res)
	fmt.Fprintf(os.Stderr, "policy written to %s; launching under Tier 0 (Landlock)\n", path)
	return spawntime.Run(cmd, res.Policy)
}
