// Package trace turns low-level audit events into plain-English containment
// stories: what the workload tried, under which policy, and what happened.
//
// Events from strace carry no process lineage or ingress request, so a trace is
// marked "inferred": it renders from the syscall event alone rather than
// inventing an HTTP hop or a parent process it cannot prove.
package trace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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
			Attempt:     name + " → " + target,
			Policy:      policyFor(kind),
			Result:      result,
			Behavior:    behaviorFor(why),
			Reason:      e.Reason,
			Confidence:  "inferred",
			NextActions: nextActions(kind, why),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
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
