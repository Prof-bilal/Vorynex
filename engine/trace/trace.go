// Package trace turns low-level audit events into plain-English containment
// stories: what the workload tried, under which policy, and what happened.
//
// Events from strace carry no ingress request, so a trace never invents an HTTP
// hop. When the trace includes fork/exec records, a trace names the real process
// lineage (e.g. "node -> /bin/bash") and is marked "exact"; otherwise it falls
// back to the syscall event alone and is marked "inferred".
package trace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/profiler"
)

// Hop is one step in the rendered chain.
type Hop struct {
	Label  string `json:"label"`
	Kind   string `json:"kind"`   // workload | action | target
	Status string `json:"status"` // running | attempt | denied | would-deny
}

// Trace is one containment story.
type Trace struct {
	ID          string    `json:"id"`
	Time        time.Time `json:"time"`
	Workload    string    `json:"workload"`
	HostID      string    `json:"host_id,omitempty"`
	Path        []Hop     `json:"path"`
	Attempt     string    `json:"attempt"`
	Policy      string    `json:"policy"`
	Result      string    `json:"result"` // DENIED | WOULD_DENY
	Behavior    string    `json:"behavior"`
	Reason      string    `json:"reason,omitempty"`
	Confidence  string    `json:"confidence"` // inferred | exact
	NextActions []string  `json:"next_actions"`
}

// Results.
const (
	ResultDenied    = "DENIED"
	ResultWouldDeny = "WOULD_DENY"
)

// Build derives traces from audit events. Contained events become DENIED
// traces; dangerous access that was not enforced (observe mode) becomes
// WOULD_DENY. Harmless failed syscalls (e.g. ENOENT) are ignored.
func Build(events []audit.Event, hostID, workload string) []Trace {
	name := workload
	if name == "" {
		name = hostID
	}
	if name == "" {
		name = "workload"
	}

	parents, prog := processTree(events)

	var out []Trace
	for _, e := range events {
		kind, target, dangerous, why := profiler.Classify(e)
		if !dangerous || target == "" {
			continue
		}
		result := ResultWouldDeny
		if !e.Allowed && permissionDenied(e.Reason) {
			result = ResultDenied
		}
		chain := lineage(e, parents, prog)
		attempt := name + " → " + target
		confidence := "inferred"
		if len(chain) > 0 {
			attempt = strings.Join(append(append([]string{}, chain...), target), " → ")
			confidence = "exact"
		}
		out = append(out, Trace{
			ID:       id(hostID, name, e),
			Time:     e.Timestamp,
			Workload: name,
			HostID:   hostID,
			Path: []Hop{
				{Label: name, Kind: "workload", Status: "running"},
				{Label: actionVerb(e.Action), Kind: "action", Status: "attempt"},
				{Label: target, Kind: "target", Status: statusFor(result)},
			},
			Attempt:     attempt,
			Policy:      policyFor(kind),
			Result:      result,
			Behavior:    behaviorFor(why),
			Reason:      e.Reason,
			Confidence:  confidence,
			NextActions: nextActions(kind, why),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// processTree reconstructs parent links and per-pid program images from clone,
// fork, and execve events, so a trace can name the lineage that reached a
// dangerous call.
func processTree(events []audit.Event) (parents map[int]int, prog map[int]string) {
	parents = map[int]int{}
	prog = map[int]string{}
	ordered := append([]audit.Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })
	for _, e := range ordered {
		switch e.Action {
		case "clone", "clone3", "fork", "vfork":
			if e.PID <= 0 {
				continue
			}
			if child, err := strconv.Atoi(strings.TrimSpace(e.Result)); err == nil && child > 0 {
				parents[child] = e.PID
			}
		case "execve", "execveat":
			if e.PID > 0 && strings.HasPrefix(e.Resource, "/") {
				prog[e.PID] = e.Resource
			}
		}
	}
	return parents, prog
}

// lineage returns the process chain that reached e, root first, excluding the
// dangerous target itself. It is empty when the trace carries no fork/exec
// evidence, which keeps the trace honest ("inferred").
func lineage(e audit.Event, parents map[int]int, prog map[int]string) []string {
	var rev []string
	seen := map[int]bool{}
	pid := e.PID
	if e.Action != "execve" && e.Action != "execveat" {
		if p, ok := prog[pid]; ok {
			rev = append(rev, p)
			seen[pid] = true
		}
	}
	for hops := 0; hops < 8; hops++ {
		parent, ok := parents[pid]
		if !ok || seen[parent] {
			break
		}
		seen[parent] = true
		if p, ok := prog[parent]; ok {
			rev = append(rev, p)
		}
		pid = parent
	}
	chain := make([]string, 0, len(rev))
	for i := len(rev) - 1; i >= 0; i-- {
		if len(chain) > 0 && chain[len(chain)-1] == rev[i] {
			continue // collapse "node → node"
		}
		chain = append(chain, rev[i])
	}
	if len(chain) > 6 {
		chain = chain[len(chain)-6:]
	}
	return chain
}

func id(hostID, workload string, e audit.Event) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s", hostID, workload, e.Timestamp.UTC().Format(time.RFC3339Nano), e.Action, e.Resource)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func permissionDenied(reason string) bool {
	return strings.Contains(reason, "EACCES") || strings.Contains(reason, "EPERM")
}

func statusFor(result string) string {
	if result == ResultDenied {
		return "denied"
	}
	return "would-deny"
}

func actionVerb(action string) string {
	switch action {
	case "execve", "execveat":
		return "exec"
	case "connect":
		return "connect"
	case "open", "openat", "openat2", "creat", "stat", "newfstatat", "access", "readlink":
		if policy.WriteAction(action) {
			return "write"
		}
		return "read"
	}
	return action
}

func policyFor(kind string) string {
	switch kind {
	case string(profiler.KindExec):
		return "process.exec"
	case string(profiler.KindRead):
		return "filesystem.read"
	case string(profiler.KindWrite):
		return "filesystem.write"
	case string(profiler.KindConnect):
		return "network.connect"
	}
	return "runtime.boundary"
}

func behaviorFor(why string) string {
	switch why {
	case "shell execution":
		return "shell execution"
	case "secret path":
		return "credential access"
	case "cloud metadata endpoint":
		return "cloud metadata access"
	case "raw IP egress":
		return "arbitrary egress"
	}
	if why == "" {
		return "unexpected access"
	}
	return why
}

func nextActions(kind, why string) []string {
	switch why {
	case "shell execution":
		return []string{
			"Review the request that reached this workload",
			"Fix the command-injection sink",
			"Keep the rule",
		}
	case "secret path":
		return []string{
			"Rotate any credentials this workload can reach",
			"Move secrets to a secret manager",
			"Keep the rule",
		}
	case "cloud metadata endpoint":
		return []string{
			"Require IMDSv2 with a hop limit where possible",
			"Keep the rule",
		}
	case "raw IP egress":
		return []string{
			"Add the legitimate destination to network.allow",
			"Keep the rule",
		}
	}
	if kind == string(profiler.KindWrite) {
		return []string{"Confirm this path is not user-controlled", "Keep the rule"}
	}
	return []string{"Review the access", "Keep the rule"}
}
