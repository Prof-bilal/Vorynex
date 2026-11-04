// Package shield implements Emergency Shield: turn a CVE match into a candidate
// containment policy, validate it deterministically, and simulate it against
// recorded traffic before anything is enforced.
//
// AI may propose; the validation and simulation here are deterministic. A
// candidate is never applied automatically.
package shield

import (
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/cve"
	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/profiler"
)

var shellDenies = []string{"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash"}
var downloadDenies = []string{"/usr/bin/curl", "/usr/bin/wget"}
var pathDenies = []string{"/var/run/docker.sock", "/etc/shadow"}

var metadataHosts = map[string]bool{"169.254.169.254": true, "169.254.170.2": true}

// Candidate is a proposed containment policy plus what changed.
type Candidate struct {
	Policy policy.Policy `json:"policy"`
	Added  []string      `json:"added"`
	Hints  []string      `json:"hints,omitempty"`
}

// Propose builds a candidate containment policy from CVE matches and a base
// policy. It only ever adds denies and safe defaults; it never grants anything.
func Propose(base policy.Policy, matches []cve.Match) Candidate {
	cand := deepCopy(base)
	cand.Version = 1
	cand.Filesystem.ProtectSecrets = true

	added := map[string]bool{}
	addDeny := func(p string) {
		if !contains(cand.Filesystem.Deny, p) {
			cand.Filesystem.Deny = append(cand.Filesystem.Deny, p)
			added["filesystem.deny "+p] = true
		}
	}
	addExecDeny := func(p string) {
		if !contains(cand.Process.Exec.Deny, p) {
			cand.Process.Exec.Deny = append(cand.Process.Exec.Deny, p)
			added["process.exec.deny "+p] = true
		}
	}

	if !base.Filesystem.ProtectSecrets {
		added["filesystem.protect_secrets = true"] = true
	}
	for _, p := range pathDenies {
		addDeny(p)
	}
	for _, p := range shellDenies {
		addExecDeny(p)
	}
	for _, p := range downloadDenies {
		addExecDeny(p)
	}

	// Behavior hints from advisory text (informational, not enforcement).
	var hints []string
	for _, m := range matches {
		s := strings.ToLower(m.Advisory.Summary)
		switch {
		case strings.Contains(s, "remote code execution"), strings.Contains(s, "rce"), strings.Contains(s, "command injection"):
			hints = append(hints, m.Advisory.ID+": likely code execution -> shell/download exec denied")
		case strings.Contains(s, "ssrf"), strings.Contains(s, "server-side request"):
			hints = append(hints, m.Advisory.ID+": likely SSRF -> cloud metadata remains denied; egress stays allowlist-only")
		case strings.Contains(s, "path traversal"), strings.Contains(s, "directory traversal"):
			hints = append(hints, m.Advisory.ID+": likely path traversal -> secret paths protected")
		case strings.Contains(s, "deserialization"):
			hints = append(hints, m.Advisory.ID+": likely deserialization -> exec denied")
		}
	}

	sort.Strings(cand.Filesystem.Deny)
	sort.Strings(cand.Process.Exec.Deny)

	keys := make([]string, 0, len(added))
	for k := range added {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(hints)
	return Candidate{Policy: cand, Added: keys, Hints: hints}
}

// Validate checks a candidate deterministically. It returns the problems that
// make the candidate unsafe to apply; an empty slice means it passed.
func Validate(base, cand policy.Policy) []string {
	var problems []string

	if err := cand.Validate(); err != nil {
		problems = append(problems, "schema: "+err.Error())
	}
	for _, ex := range cand.Process.Exec.Allow {
		if isShell(ex) {
			problems = append(problems, "candidate grants a shell: "+ex)
		}
	}
	for _, h := range cand.Network.Allow {
		if metadataHosts[strings.ToLower(h)] {
			problems = append(problems, "candidate allowlists cloud metadata: "+h)
		}
	}
	for _, p := range append(append([]string{}, cand.Filesystem.Read...), cand.Filesystem.Write...) {
		if filepath.Clean(p) == "/" {
			problems = append(problems, "candidate grants the filesystem root")
		}
	}
	// No weakening: denies must be a superset, grants a subset.
	for _, d := range base.Filesystem.Deny {
		if !contains(cand.Filesystem.Deny, d) {
			problems = append(problems, "candidate drops an existing deny: "+d)
		}
	}
	for _, ex := range base.Process.Exec.Deny {
		if !contains(cand.Process.Exec.Deny, ex) {
			problems = append(problems, "candidate drops an existing exec deny: "+ex)
		}
	}
	for _, g := range allGrants(cand) {
		if !contains(allGrants(base), g) {
			problems = append(problems, "candidate adds a grant: "+g)
		}
	}
	return problems
}

// BlockedEvent is an event a candidate would deny.
type BlockedEvent struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Target    string    `json:"target"`
	Reason    string    `json:"reason"`
	Dangerous bool      `json:"dangerous"`
}

// Simulation is the result of replaying recorded events against a candidate.
type Simulation struct {
	NewDangerous []BlockedEvent `json:"new_dangerous"`
	NewBenign    []BlockedEvent `json:"new_benign"`
	CoverageGaps []string       `json:"coverage_gaps,omitempty"`
	Events       int            `json:"events"`
}

// Simulate replays events through the base and candidate policies. New denials
// of dangerous behavior are the point; new denials of anything else are
// breakage and block approval.
func Simulate(base, cand policy.Policy, events []audit.Event) Simulation {
	var sim Simulation
	sim.Events = len(events)
	for _, e := range events {
		baseOK, _ := allowedBy(base, e)
		candOK, reason := allowedBy(cand, e)
		kind, target, dangerous, why := profiler.Classify(e)
		if baseOK && !candOK {
			b := BlockedEvent{Time: e.Timestamp, Kind: kind, Target: target, Reason: reason, Dangerous: dangerous}
			if dangerous {
				sim.NewDangerous = append(sim.NewDangerous, b)
			} else {
				sim.NewBenign = append(sim.NewBenign, b)
			}
			continue
		}
		if dangerous && baseOK && candOK {
			sim.CoverageGaps = append(sim.CoverageGaps, fmt.Sprintf("%s %s (%s)", kind, target, why))
		}
	}
	return sim
}

// Verdict summarizes whether a candidate may proceed.
type Verdict string

const (
	VerdictApproved    Verdict = "approved"
	VerdictNeedsReview Verdict = "needs-review"
	VerdictRejected    Verdict = "rejected"
)

// Decide applies the gates: validation must pass; any benign breakage requires
// review; otherwise the candidate may proceed to observe.
func Decide(problems []string, sim Simulation) Verdict {
	if len(problems) > 0 {
		return VerdictRejected
	}
	if len(sim.NewBenign) > 0 {
		return VerdictNeedsReview
	}
	return VerdictApproved
}

// allowedBy approximates the tier-0 evaluator for simulation.
func allowedBy(p policy.Policy, e audit.Event) (bool, string) {
	switch {
	case e.Type == "network":
		host := hostOnly(e.Resource)
		if metadataHosts[host] {
			return false, "cloud metadata"
		}
		if len(p.Network.Allow) == 0 {
			return false, "egress allowlist empty"
		}
		if hostAllowed(p.Network.Allow, host) {
			return true, "network.allow"
		}
		return false, "not in network.allow"
	case e.Action == "execve" || e.Action == "execveat":
		if matches(p.Process.Exec.Deny, e.Resource) {
			return false, "process.exec.deny"
		}
		if len(p.Process.Exec.Allow) > 0 && !matches(p.Process.Exec.Allow, e.Resource) {
			return false, "not in process.exec.allow"
		}
		return true, "allowed"
	default:
		if !strings.HasPrefix(e.Resource, "/") {
			return true, "not a filesystem path"
		}
		if matches(p.Filesystem.Deny, e.Resource) {
			return false, "filesystem.deny"
		}
		if underAny(p.Filesystem.Write, e.Resource) {
			return true, "filesystem.write"
		}
		if underAny(p.Filesystem.Read, e.Resource) {
			return true, "filesystem.read"
		}
		return false, "deny by default"
	}
}

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(hostport)
}

func hostAllowed(allow []string, host string) bool {
	for _, a := range allow {
		a = strings.ToLower(a)
		if a == host {
			return true
		}
		if strings.HasPrefix(a, "*.") {
			suffix := a[1:]
			if strings.HasSuffix(host, suffix) && host != suffix[1:] {
				return true
			}
		}
	}
	return false
}

func underAny(dirs []string, path string) bool {
	path = filepath.Clean(path)
	for _, d := range dirs {
		d = filepath.Clean(d)
		if path == d {
			return true
		}
		rel, err := filepath.Rel(d, path)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func matches(list []string, path string) bool {
	for _, p := range list {
		if p == path {
			return true
		}
		if ok, _ := filepath.Match(p, path); ok {
			return true
		}
	}
	return false
}

func isShell(p string) bool {
	switch filepath.Base(p) {
	case "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "ash", "busybox":
		return true
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func allGrants(p policy.Policy) []string {
	var out []string
	out = append(out, p.Filesystem.Read...)
	out = append(out, p.Filesystem.Write...)
	out = append(out, p.Process.Exec.Allow...)
	out = append(out, p.Network.Allow...)
	return out
}

func deepCopy(p policy.Policy) policy.Policy {
	c := p
	c.Filesystem.Read = append([]string(nil), p.Filesystem.Read...)
	c.Filesystem.Write = append([]string(nil), p.Filesystem.Write...)
	c.Filesystem.Deny = append([]string(nil), p.Filesystem.Deny...)
	c.Network.Allow = append([]string(nil), p.Network.Allow...)
	c.Process.Exec.Allow = append([]string(nil), p.Process.Exec.Allow...)
	c.Process.Exec.Deny = append([]string(nil), p.Process.Exec.Deny...)
	return c
}
