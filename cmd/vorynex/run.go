package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/state"
)

// runRun supervises a workload under a policy and rolls back if it never becomes
// healthy. A false positive is a security incident, so the safe default is to
// restore the previous posture rather than leave a broken app enforcing.
//
//	vorynex run --policy <file> [--sig <file> --pubkey <hex|file>]
//	            [--health <url|command>] [--health-interval 2s]
//	            [--health-timeout 40s] [--health-consecutive 2] -- <command...>
func runRun(args []string) error {
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

	var policyPath, sigPath, pubkey, health string
	interval := 2 * time.Second
	timeout := 40 * time.Second
	consecutive := 2

	for i := 0; i < len(flagArgs); i++ {
		switch flagArgs[i] {
		case "--policy":
			if i+1 < len(flagArgs) {
				i++
				policyPath = flagArgs[i]
			}
		case "--sig":
			if i+1 < len(flagArgs) {
				i++
				sigPath = flagArgs[i]
			}
		case "--pubkey":
			if i+1 < len(flagArgs) {
				i++
				pubkey = flagArgs[i]
			}
		case "--health":
			if i+1 < len(flagArgs) {
				i++
				health = flagArgs[i]
			}
		case "--health-interval":
			if i+1 < len(flagArgs) {
				i++
				if d, err := time.ParseDuration(flagArgs[i]); err == nil && d > 0 {
					interval = d
				}
			}
		case "--health-timeout":
			if i+1 < len(flagArgs) {
				i++
				if d, err := time.ParseDuration(flagArgs[i]); err == nil && d > 0 {
					timeout = d
				}
			}
		case "--health-consecutive":
			if i+1 < len(flagArgs) {
				i++
				if n, err := strconv.Atoi(flagArgs[i]); err == nil && n > 0 {
					consecutive = n
				}
			}
		default:
			return fmt.Errorf("unknown flag %q", flagArgs[i])
		}
	}

	if policyPath == "" || len(cmd) == 0 {
		return fmt.Errorf("usage: vorynex run --policy <file> [--health <url|cmd>] -- <command...>")
	}
	if (sigPath == "") != (pubkey == "") {
		return fmt.Errorf("--sig and --pubkey must be given together")
	}
	if sigPath != "" {
		keyID, err := verifyDetached(policyPath, sigPath, pubkey)
		if err != nil {
			return fmt.Errorf("refusing to run: %w", err)
		}
		fmt.Fprintf(os.Stderr, "policy signature verified (key %s)\n", keyID)
	}

	if _, err := policy.Load(policyPath); err != nil {
		return err
	}
	sha, err := state.Digest(policyPath)
	if err != nil {
		return err
	}
	st, err := state.BeginTransition(state.ModeProtect, policyPath, sha)
	if err != nil {
		return err
	}
	_ = state.Journal(state.JournalEntry{Event: "run", Mode: st.Mode, Detail: policyPath})
	fmt.Fprintf(os.Stderr, "supervising under %s (mode %s)\n", policyPath, st.Mode)

	// The supervisor stays unsandboxed so it can kill and roll back; the child
	// is `vorynex exec`, which applies Landlock and replaces itself with the app.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := append([]string{"exec", "--policy", policyPath, "--"}, cmd...)
	child := exec.Command(self, childArgs...)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		return fmt.Errorf("start workload: %w", err)
	}

	done := make(chan struct{})
	exit := make(chan error, 1)
	go func() {
		exit <- child.Wait()
		close(done)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		select {
		case <-sigCh:
			terminate(child, done)
		case <-done:
		}
	}()

	if health != "" {
		if err := waitHealthy(health, interval, timeout, consecutive); err != nil {
			fmt.Fprintf(os.Stderr, "health check failed: %v\nrolling back\n", err)
			terminate(child, done)
			if _, rerr := state.Revert(); rerr != nil {
				return rerr
			}
			_ = state.Journal(state.JournalEntry{Event: "rollback", Mode: state.ModeObserve, Detail: err.Error()})
			return fmt.Errorf("rolled back to observe — the workload never became healthy under the policy")
		}
		fmt.Fprintln(os.Stderr, "health check passed; policy stays applied")
	}

	if err := <-exit; err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return fmt.Errorf("workload exited: %v", err)
		}
		return err
	}
	_ = state.Journal(state.JournalEntry{Event: "run-exit", Mode: st.Mode, Detail: "workload exited 0"})
	return nil
}

// waitHealthy polls until `consecutive` checks pass or the timeout elapses.
func waitHealthy(spec string, interval, timeout time.Duration, consecutive int) error {
	if consecutive < 1 {
		consecutive = 1
	}
	deadline := time.Now().Add(timeout)
	passed := 0
	var last error
	for time.Now().Before(deadline) {
		if err := checkHealth(spec); err != nil {
			passed = 0
			last = err
		} else {
			passed++
			if passed >= consecutive {
				return nil
			}
		}
		time.Sleep(interval)
	}
	if last == nil {
		last = fmt.Errorf("timed out after %s", timeout)
	}
	return last
}

// checkHealth accepts either an http(s) URL or a shell command.
func checkHealth(spec string) error {
	if strings.HasPrefix(spec, "http://") || strings.HasPrefix(spec, "https://") {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, spec, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			return fmt.Errorf("GET %s returned %d", spec, resp.StatusCode)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/bin/sh", "-c", spec).CombinedOutput()
	if err != nil {
		return fmt.Errorf("health command failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// terminate asks politely, then insists. It never calls Wait — the supervisor
// owns the single Wait and closes done when the child is reaped.
func terminate(cmd *exec.Cmd, done <-chan struct{}) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
	}
}
