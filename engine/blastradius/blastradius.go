// Package blastradius answers one question from real configuration:
//
//	If this application is compromised right now, what can the attacker reach?
//
// Every line is either reachable or contained, backed by a policy rule. There
// is no invented security score.
package blastradius

import (
	"path"
	"sort"
	"strings"

	"github.com/vorynex/vorynex/engine/policy"
)

// Resource is something an attacker could reach.
type Resource struct {
	Kind       string `json:"kind"` // network | path | process
	Target     string `json:"target"`
	Via        string `json:"via"`
	Confidence string `json:"confidence"` // exact | inferred
}

// Contained is a danger class that is not reachable.
type Contained struct {
	Class  string `json:"class"`
	Reason string `json:"reason"`
}

// Report is the blast radius for one workload.
type Report struct {
	Workload  string      `json:"workload"`
	Mode      string      `json:"mode"`
	Reachable []Resource  `json:"reachable"`
	Contained []Contained `json:"contained"`
	Warnings  []string    `json:"warnings,omitempty"`
}

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true,
}

var metadataHosts = map[string]bool{"169.254.169.254": true, "169.254.170.2": true}

// FromPolicy derives the report from an effective policy.
func FromPolicy(p policy.Policy, workload, mode string) Report {
	if workload == "" {
		workload = "workload"
	}
	if mode == "" {
		mode = "protect"
	}
	r := Report{Workload: workload, Mode: mode}
	seen := map[string]bool{}
	add := func(kind, target, via string) {
		if target == "" || seen[kind+"|"+target] {
			return
		}
		seen[kind+"|"+target] = true
		r.Reachable = append(r.Reachable, Resource{Kind: kind, Target: target, Via: via, Confidence: "exact"})
	}
	for _, h := range p.Network.Allow {
		add("network", h, "network.allow")
	}
	for _, w := range p.Filesystem.Write {
		add("path", w, "filesystem.write")
	}
	for _, rd := range p.Filesystem.Read {
		add("path", rd, "filesystem.read")
	}
	for _, ex := range p.Process.Exec.Allow {
		add("process", ex, "process.exec.allow")
	}

	contain := func(class, reason string) {
		r.Contained = append(r.Contained, Contained{Class: class, Reason: reason})
	}
	warn := func(s string) {
		for _, w := range r.Warnings {
			if w == s {
				return
			}
		}
		r.Warnings = append(r.Warnings, s)
	}

	// Egress is allowlist-only by construction in the tier-0 shim.
	contain("arbitrary egress", "only network.allow hosts are granted")
	contain("cloud metadata", "not allowlisted (169.254.169.254)")
	for _, h := range p.Network.Allow {
		if metadataHosts[h] {
			warn("cloud metadata endpoint is allowlisted")
		}
	}

	// Credentials.
	if p.Filesystem.ProtectSecrets || denyMatches(p, ".env") || denyMatches(p, "id_rsa") {
		contain("SSH & cloud credentials", "filesystem.deny / protect_secrets")
	} else {
		warn("no secret-path protection configured")
	}
	if denyMatches(p, "docker.sock") {
		contain("docker socket", "explicit deny")
	} else if anyContains(p.Filesystem.Write, "docker.sock") || anyContains(p.Filesystem.Read, "docker.sock") {
		warn("docker socket is granted")
	} else {
		contain("docker socket", "not granted")
	}

	// Host filesystem.
	if grantsRoot(p) {
		warn("filesystem grant includes /")
	} else {
		contain("host filesystem", "deny by default")
	}

	// Shell execution.
	if allowShell(p) {
		warn("a shell is allowlisted for execution")
	} else if denyShell(p) {
		contain("shell execution", "process.exec.deny")
	} else {
		contain("shell execution", "not allowlisted")
	}

	// Other containers ride on the docker socket.
	contain("other containers", "docker socket not granted")

	sort.Slice(r.Reachable, func(i, j int) bool {
		if r.Reachable[i].Kind != r.Reachable[j].Kind {
			return r.Reachable[i].Kind < r.Reachable[j].Kind
		}
		return r.Reachable[i].Target < r.Reachable[j].Target
	})
	sort.Slice(r.Contained, func(i, j int) bool { return r.Contained[i].Class < r.Contained[j].Class })
	return r
}

// DiffReport is the change in blast radius between two policies.
type DiffReport struct {
	ReachableAdded   []Resource  `json:"reachable_added,omitempty"`
	ReachableRemoved []Resource  `json:"reachable_removed,omitempty"`
	ContainedAdded   []Contained `json:"contained_added,omitempty"`
	ContainedRemoved []Contained `json:"contained_removed,omitempty"`
}

// Diff compares two reports. "Added" means present in after, absent in before.
func Diff(before, after Report) DiffReport {
	var d DiffReport
	br := map[string]Resource{}
	for _, r := range before.Reachable {
		br[r.Kind+"|"+r.Target] = r
	}
	ar := map[string]Resource{}
	for _, r := range after.Reachable {
		ar[r.Kind+"|"+r.Target] = r
	}
	for k, r := range ar {
		if _, ok := br[k]; !ok {
			d.ReachableAdded = append(d.ReachableAdded, r)
		}
	}
	for k, r := range br {
		if _, ok := ar[k]; !ok {
			d.ReachableRemoved = append(d.ReachableRemoved, r)
		}
	}
	bc := map[string]Contained{}
	for _, c := range before.Contained {
		bc[c.Class] = c
	}
	ac := map[string]Contained{}
	for _, c := range after.Contained {
		ac[c.Class] = c
	}
	for k, c := range ac {
		if _, ok := bc[k]; !ok {
			d.ContainedAdded = append(d.ContainedAdded, c)
		}
	}
	for k, c := range bc {
		if _, ok := ac[k]; !ok {
			d.ContainedRemoved = append(d.ContainedRemoved, c)
		}
	}
	sort.Slice(d.ReachableAdded, func(i, j int) bool { return d.ReachableAdded[i].Target < d.ReachableAdded[j].Target })
	sort.Slice(d.ReachableRemoved, func(i, j int) bool { return d.ReachableRemoved[i].Target < d.ReachableRemoved[j].Target })
	sort.Slice(d.ContainedAdded, func(i, j int) bool { return d.ContainedAdded[i].Class < d.ContainedAdded[j].Class })
	sort.Slice(d.ContainedRemoved, func(i, j int) bool { return d.ContainedRemoved[i].Class < d.ContainedRemoved[j].Class })
	return d
}

func denyMatches(p policy.Policy, substr string) bool {
	return anyContains(p.Filesystem.Deny, substr)
}

func anyContains(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}

func grantsRoot(p policy.Policy) bool {
	for _, w := range append(append([]string{}, p.Filesystem.Read...), p.Filesystem.Write...) {
		if w == "/" {
			return true
		}
	}
	return false
}

func allowShell(p policy.Policy) bool {
	for _, ex := range p.Process.Exec.Allow {
		if shellNames[path.Base(ex)] {
			return true
		}
	}
	return false
}

func denyShell(p policy.Policy) bool {
	for _, ex := range p.Process.Exec.Deny {
		if shellNames[path.Base(ex)] {
			return true
		}
	}
	return false
}
