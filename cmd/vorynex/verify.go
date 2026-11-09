package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/verify"
)

// runVerify launches the workload under a candidate policy, drives a corpus of
// legitimate workflows at it, and exits 2 (DO NOT ENFORCE) unless every required
// workflow passes and every declared feature is covered. It changes no state.
//
//	vorynex verify --policy <file> --corpus <file> --base <url> [--trace] -- <command...>
func runVerify(args []string) error {
	var policyPath, corpusPath, base string
	trace := false
	ready := 20 * time.Second
	i := 0
	for i < len(args) && args[i] != "--" {
		if args[i] == "--trace" {
			trace = true
			i++
			continue
		}
		if i+1 >= len(args) {
			return fmt.Errorf("%s requires a value", args[i])
		}
		switch args[i] {
		case "--policy":
			policyPath = args[i+1]
		case "--corpus":
			corpusPath = args[i+1]
		case "--base":
			base = args[i+1]
		case "--ready-timeout":
			d, err := time.ParseDuration(args[i+1])
			if err != nil {
				return err
			}
			ready = d
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
		i += 2
	}
	if i >= len(args) || len(args[i+1:]) == 0 || policyPath == "" || corpusPath == "" || base == "" {
		return fmt.Errorf("usage: vorynex verify --policy <file> --corpus <file> --base <url> [--ready-timeout 20s] -- <command...>")
	}
	cmd := args[i+1:]

	p, err := policy.Load(policyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		return err
	}
	var corpus verify.Corpus
	if err := json.Unmarshal([]byte(os.ExpandEnv(string(raw))), &corpus); err != nil {
		return fmt.Errorf("corpus: %w", err)
	}

	// Capability gate first: a rule the backend cannot enforce as written is a
	// reason not to enforce, before any request is sent.
	if abs, err := exec.LookPath(cmd[0]); err == nil {
		abs, _ = filepath.Abs(abs)
		for _, b := range policy.BroadExecGrants(abs, p.Process.Exec.Allow, p.Process.Exec.Deny) {
			fmt.Printf("Backend capability: NOT ENFORCEABLE AS WRITTEN\n  %v\nDecision: DO NOT ENFORCE\n", b)
			os.Exit(2)
		}
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := append([]string{"exec", "--policy", policyPath, "--"}, cmd...)
	name := self
	tracePath := ""
	if trace {
		// Requested explicitly, so a missing strace is an error, not a silent skip.
		st, err := exec.LookPath("strace")
		if err != nil {
			return fmt.Errorf("--trace needs strace on PATH: %w", err)
		}
		tf, err := os.CreateTemp("", "vorynex-verify-strace-*")
		if err != nil {
			return err
		}
		tf.Close()
		defer os.Remove(tf.Name())
		tracePath = tf.Name()
		childArgs = append([]string{"-f", "-qq", "-e", "trace=execve,openat,connect", "-o", tracePath, self}, childArgs...)
		name = st
	}
	child := exec.Command(name, childArgs...)
	child.Stdout, child.Stderr = os.Stderr, os.Stderr
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		return err
	}
	defer func() {
		_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		_, _ = child.Process.Wait()
	}()

	deadline := time.Now().Add(ready)
	for {
		if resp, err := http.Get(base + "/health"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		if time.Now().After(deadline) {
			fmt.Println("Decision: DO NOT ENFORCE\n  - the workload never became healthy under this policy (startup false positive)")
			os.Exit(2)
		}
		time.Sleep(100 * time.Millisecond)
	}

	rep := verify.Run(base, corpus)
	fmt.Print(rep.Format())
	if trace {
		// Stop the workload first so strace flushes its file.
		_ = syscall.Kill(-child.Process.Pid, syscall.SIGKILL)
		_, _ = child.Process.Wait()
		d, err := verify.Denials(tracePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trace: %v\n", err)
		} else {
			fmt.Print(verify.FormatDenials(d))
		}
	}
	if !rep.Ready() {
		os.Exit(2)
	}
	return nil
}
