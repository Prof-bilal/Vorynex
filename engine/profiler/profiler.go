// Package profiler derives an application's runtime behavior into capabilities
// with promotion decisions. It is the core of observe mode: run a workload with
// no enforcement, then decide what Vorynex *would* allow, deny, or keep
// watching.
//
// The rules are deterministic and conservative. The most dangerous behaviors
// (shell execution, secret reads, cloud-metadata and raw-IP egress) are
// "never-promote": they can never become an automatic allow rule, which is the
// primary defense against an attacker poisoning the learning phase.
package profiler

import (
	"net"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/policy"
)

// Kind classifies a capability.
type Kind string

const (
	KindRead    Kind = "fs.read"
	KindWrite   Kind = "fs.write"
	KindExec    Kind = "exec"
	KindConnect Kind = "net.connect"
)

// Decision is what the profiler recommends for a capability.
type Decision string

const (
	// Promote: safe to become an allow rule.
	Promote Decision = "promote"
	// Observe: not enough evidence yet; keep recording.
	Observe Decision = "observe"
	// Never: a dangerous class that must never be auto-promoted.
	Never Decision = "never-promote"
)

// Capability is one observed behavior.
type Capability struct {
	Kind     Kind
	Target   string
	Count    int
	Sessions int
	Decision Decision
	Reason   string
}

// Summary tallies the decisions.
type Summary struct {
	Promotable   int
	ObserveOnly  int
	NeverPromote int
}

// Profile is the result of observing one or more sessions.
type Profile struct {
	GeneratedAt  time.Time
	Sessions     int
	Capabilities []Capability
	Summary      Summary
}

// Options controls promotion thresholds. Defaults are conservative.
type Options struct {
	MinSessions int // distinct sessions a capability must appear in
	MinCount    int // total occurrences required
}

// DefaultOptions returns conservative thresholds: a capability must appear in
// at least two sessions. Callers observing a single session can lower this.
func DefaultOptions() Options { return Options{MinSessions: 2, MinCount: 1} }

var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"csh": true, "tcsh": true, "fish": true, "ash": true, "busybox": true,
}

var metadataHosts = map[string]bool{
	"169.254.169.254": true, // AWS/Azure/GCP IMDS
	"169.254.170.2":   true, // ECS task metadata
}

var secretBasenames = map[string]bool{
	".env": true, "id_rsa": true, "id_ed25519": true, "credentials": true,
	".npmrc": true, ".pypirc": true, ".dockercfg": true, ".netrc": true,
	".pgpass": true, ".htpasswd": true,
}

var secretPathFragments = []string{"/.ssh/", "/.aws/", "/.kube/", "/.docker/", "/.gnupg/"}

// Build aggregates audit events (one slice per session) into a profile.
func Build(sessions [][]audit.Event, opts Options) Profile {
	type key struct {
		kind   Kind
		target string
	}
	counts := map[key]int{}
	perSession := map[key]map[int]bool{}
	reasons := map[key]string{}
	never := map[key]bool{}

	for i, events := range sessions {
		for _, e := range events {
			kind, target, ok := classify(e)
			if !ok {
				continue
			}
			k := key{kind, target}
			safe, reason := danger(e)
			// A failed *safe* access is not a capability, but a dangerous
			// attempt is recorded regardless (it must never be promoted).
			if safe && !e.Allowed {
				continue
			}
			counts[k]++
			if perSession[k] == nil {
				perSession[k] = map[int]bool{}
			}
			perSession[k][i] = true
			if !safe {
				never[k] = true
				reasons[k] = reason
			}
		}
	}

	p := Profile{GeneratedAt: time.Now().UTC(), Sessions: len(sessions)}
	for k, count := range counts {
		c := Capability{
			Kind:     k.kind,
			Target:   k.target,
			Count:    count,
			Sessions: len(perSession[k]),
		}
		switch {
		case never[k]:
			c.Decision = Never
			c.Reason = reasons[k]
		case c.Sessions >= opts.MinSessions && c.Count >= opts.MinCount:
			c.Decision = Promote
		default:
			c.Decision = Observe
			c.Reason = "not enough evidence"
		}
		switch c.Decision {
		case Promote:
			p.Summary.Promotable++
		case Observe:
			p.Summary.ObserveOnly++
		case Never:
			p.Summary.NeverPromote++
		}
		p.Capabilities = append(p.Capabilities, c)
	}
	sort.Slice(p.Capabilities, func(i, j int) bool {
		if p.Capabilities[i].Decision != p.Capabilities[j].Decision {
			return p.Capabilities[i].Decision > p.Capabilities[j].Decision
		}
		if p.Capabilities[i].Kind != p.Capabilities[j].Kind {
			return p.Capabilities[i].Kind < p.Capabilities[j].Kind
		}
		return p.Capabilities[i].Target < p.Capabilities[j].Target
	})
	return p
}

// Blocked is an event Protect mode would deny.
type Blocked struct {
	Time   time.Time
	Kind   Kind
	Target string
	Reason string
}

// WouldBlock returns the events that Protect mode would deny: the dangerous
// classes only, which is what makes observe output actionable.
func WouldBlock(events []audit.Event) []Blocked {
	var out []Blocked
	for _, e := range events {
		kind, target, ok := classify(e)
		if !ok {
			continue
		}
		if safe, reason := danger(e); !safe {
			out = append(out, Blocked{Time: e.Timestamp, Kind: kind, Target: target, Reason: reason})
		}
	}
	return out
}

// Classify exposes the event classifier for other packages (e.g. trace).
// dangerous is true for the never-promote classes; reason explains why.
func Classify(e audit.Event) (kind string, target string, dangerous bool, reason string) {
	k, t, ok := classify(e)
	if !ok {
		return "", "", false, ""
	}
	safe, why := danger(e)
	return string(k), t, !safe, why
}

func classify(e audit.Event) (Kind, string, bool) {
	switch {
	case e.Type == "network":
		host := hostOnly(e.Resource)
		if host == "" {
			return "", "", false
		}
		return KindConnect, e.Resource, true
	case e.Action == "execve" || e.Action == "execveat":
		if !strings.HasPrefix(e.Resource, "/") {
			return "", "", false
		}
		return KindExec, e.Resource, true
	default:
		if !strings.HasPrefix(e.Resource, "/") {
			return "", "", false
		}
		// System/runtime paths are provided by the sandbox itself; recording
		// them as capabilities only adds noise.
		if policy.RuntimePath(e.Resource) {
			return "", "", false
		}
		if policy.WriteAction(e.Action) {
			return KindWrite, e.Resource, true
		}
		switch e.Action {
		case "open", "openat", "openat2", "creat", "access", "faccessat", "faccessat2",
			"stat", "lstat", "newfstatat", "statx", "readlink", "readlinkat":
			return KindRead, e.Resource, true
		}
		return "", "", false
	}
}

// danger reports whether an event is in a never-promote class, with a reason.
func danger(e audit.Event) (safe bool, reason string) {
	switch {
	case e.Type == "network":
		host := hostOnly(e.Resource)
		if metadataHosts[host] {
			return false, "cloud metadata endpoint"
		}
		if net.ParseIP(host) != nil {
			return false, "raw IP egress"
		}
		return true, ""
	case e.Action == "execve" || e.Action == "execveat":
		if shellNames[path.Base(e.Resource)] {
			return false, "shell execution"
		}
		return true, ""
	default:
		if isSecretPath(e.Resource) {
			return false, "secret path"
		}
		return true, ""
	}
}

func isSecretPath(p string) bool {
	base := path.Base(p)
	if secretBasenames[base] {
		return true
	}
	if strings.HasPrefix(base, ".env.") {
		return true
	}
	if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") ||
		strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") {
		return true
	}
	for _, frag := range secretPathFragments {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
