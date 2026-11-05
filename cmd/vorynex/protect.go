package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/enforce/spawntime"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/policygen"
	"github.com/vorynex/vorynex/engine/profiler"
	"github.com/vorynex/vorynex/engine/state"
	"github.com/vorynex/vorynex/engine/telemetry"
)

// runProtect turns an observe baseline into an enforced posture.
//
//	vorynex protect --from <events.jsonl> [--out <file>] -- <command...>
//	vorynex protect --from-desired [--pubkey <hex|file>] [-- <command...>]
//	vorynex protect --off
//
// Every transition snapshots the previous posture, so --off restores it exactly.
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

	var from, out, pubkey string
	var off, fromDesired bool
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
		case "--pubkey":
			if i+1 < len(flagArgs) {
				i++
				pubkey = flagArgs[i]
			}
		case "--off":
			off = true
		case "--from-desired":
			fromDesired = true
		default:
			return fmt.Errorf("unknown flag %q", flagArgs[i])
		}
	}

	switch {
	case off:
		if len(cmd) > 0 {
			return fmt.Errorf("--off does not take a command")
		}
		return protectOff()
	case fromDesired:
		return protectFromDesired(pubkey, cmd)
	case from != "":
		if len(cmd) == 0 {
			return fmt.Errorf("no command after `--`")
		}
		return protectFromBaseline(from, out, cmd)
	default:
		return fmt.Errorf("usage: vorynex protect --from <events.jsonl> [--out <file>] -- <command...>\n       vorynex protect --from-desired [--pubkey <hex|file>] [-- <command...>]\n       vorynex protect --off")
	}
}

// protectOff restores the posture that was captured before the last transition.
func protectOff() error {
	st := state.Load()
	if st.Mode == state.ModeObserve && !state.CanRevert() {
		fmt.Println("Already in observe mode; nothing to restore.")
		return nil
	}
	next, err := state.Revert()
	if err != nil {
		return err
	}
	_ = state.Journal(state.JournalEntry{
		Event:  "protect-off",
		Mode:   next.Mode,
		Detail: "restored the previous posture",
	})

	fmt.Printf("Protection off. Mode: %s", next.Mode)
	if next.PolicyPath != "" {
		fmt.Printf(" · policy %s", next.PolicyPath)
	} else {
		fmt.Print(" · no policy")
	}
	fmt.Println()
	fmt.Println("Restart the workload for the change to take effect — Vorynex never restarts it for you.")
	return nil
}

// protectFromDesired applies the policy the control plane staged, verifying it
// against the pinned trust root when one is supplied.
func protectFromDesired(pubkey string, cmd []string) error {
	dir := telemetry.DefaultDir()
	desired := telemetry.LoadDesired(dir)
	if desired.Revision == 0 && desired.Policy == "" {
		return fmt.Errorf("no desired state staged; run `vorynex rollout pull --endpoint <url>` first")
	}
	if desired.Policy == "" {
		return fmt.Errorf("desired revision %d carries no policy", desired.Revision)
	}

	path := filepath.Join(dir, "desired.policy.yaml")
	if err := os.WriteFile(path, []byte(desired.Policy), 0o600); err != nil {
		return err
	}

	if pubkey != "" {
		sig := path + ".sig"
		if _, err := os.Stat(sig); err != nil {
			return fmt.Errorf("a trust root was provided but %s is missing; refusing to apply an unsigned staged policy", sig)
		}
		keyID, err := verifyDetached(path, sig, pubkey)
		if err != nil {
			return err
		}
		fmt.Printf("signature verified (key %s)\n", keyID)
	}

	mode := state.Mode(desired.Mode)
	if !state.Valid(mode) {
		mode = state.ModeProtect
	}
	sha, err := state.Digest(path)
	if err != nil {
		return err
	}
	st, err := state.BeginTransition(mode, path, sha)
	if err != nil {
		return err
	}
	_ = state.Journal(state.JournalEntry{
		Event:  "protect-desired",
		Mode:   st.Mode,
		Detail: fmt.Sprintf("revision %d · %s", desired.Revision, path),
	})

	fmt.Printf("applied staged policy revision %d · mode %s\n  policy %s\n", desired.Revision, st.Mode, path)
	if len(cmd) == 0 {
		fmt.Println("\nnext: run the workload under the supervisor so a failure can roll back:")
		fmt.Printf("  vorynex run --policy %s -- <command...>\n", path)
		return nil
	}

	p, err := policy.Load(path)
	if err != nil {
		return err
	}
	return spawntime.Run(cmd, p)
}

// protectFromBaseline generates a policy from observed traffic, records the
// transition, and launches the workload under it.
func protectFromBaseline(from, out string, cmd []string) error {
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
	sha, err := state.Digest(path)
	if err != nil {
		return err
	}
	st, err := state.BeginTransition(state.ModeProtect, path, sha)
	if err != nil {
		return err
	}
	_ = state.Journal(state.JournalEntry{Event: "protect", Mode: st.Mode, Detail: path})

	fmt.Fprintf(os.Stderr, "policy %s · mode %s; launching under Tier 0 (Landlock)\n", path, st.Mode)
	if err := spawntime.Run(cmd, res.Policy); err != nil {
		return err
	}
	return nil
}
