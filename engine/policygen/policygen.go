// Package policygen turns an observed behavior profile into a deny-by-default
// Vorynex policy.
//
// Generation is deliberately conservative: only capabilities the profiler
// marked promotable become grants, and every never-promote capability (shell
// execution, secret-path reads, cloud-metadata / raw-IP egress) becomes an
// explicit deny. Nothing observed is trusted implicitly.
package policygen

import (
	"net"
	"sort"

	"github.com/vorynex/vorynex/engine/policy"
	"github.com/vorynex/vorynex/engine/profiler"
)

// SchemaVersion is the policy schema version written by generated policies.
const SchemaVersion = 1

// Options controls generation.
type Options struct {
	// ProtectSecrets enables the built-in high-confidence secret filename
	// protection within granted trees.
	ProtectSecrets bool
}

// DefaultOptions returns safe defaults.
func DefaultOptions() Options { return Options{ProtectSecrets: true} }

// Result is a generated policy plus the decisions behind it, so a human can
// review what was granted and denied before applying it.
type Result struct {
	Policy policy.Policy
	// Denied lists never-promote capabilities turned into explicit denies,
	// with the reason they were excluded.
	Denied []DeniedCapability
	// Review lists capabilities observed but deliberately not granted
	// (executables other than the workload, network destinations).
	Review []profiler.Capability
}

// DeniedCapability is a never-promote capability recorded as a deny.
type DeniedCapability struct {
	Kind   profiler.Kind
	Target string
	Reason string
}

// Generate builds a policy from an observed profile.
func Generate(prof profiler.Profile, opts Options) Result {
	p := policy.Policy{Version: SchemaVersion, Filesystem: policy.Filesystem{ProtectSecrets: opts.ProtectSecrets}}

	seen := map[string]bool{}
	addRead := func(s string) { p.Filesystem.Read = addUnique(p.Filesystem.Read, s, seen) }
	addWrite := func(s string) { p.Filesystem.Write = addUnique(p.Filesystem.Write, s, seen) }
	addExec := func(s string) { p.Process.Exec.Allow = addUnique(p.Process.Exec.Allow, s, seen) }
	addDeny := func(s string) { p.Filesystem.Deny = addUnique(p.Filesystem.Deny, s, seen) }
	addExecDeny := func(s string) { p.Process.Exec.Deny = addUnique(p.Process.Exec.Deny, s, seen) }
	addHost := func(s string) { p.Network.Allow = addUnique(p.Network.Allow, s, seen) }

	var denied []DeniedCapability
	var review []profiler.Capability
	for _, c := range prof.Capabilities {
		if c.Decision == profiler.Never {
			denied = append(denied, DeniedCapability{Kind: c.Kind, Target: c.Target, Reason: c.Reason})
			switch c.Kind {
			case profiler.KindExec:
				addExecDeny(c.Target)
			case profiler.KindRead, profiler.KindWrite:
				addDeny(c.Target)
			}
			continue
		}
		if c.Decision == profiler.Review {
			review = append(review, c)
			continue
		}
		if c.Decision != profiler.Promote {
			continue
		}
		switch c.Kind {
		case profiler.KindRead:
			addRead(c.Target)
		case profiler.KindWrite:
			addWrite(c.Target)
		case profiler.KindExec:
			addExec(c.Target)
		case profiler.KindConnect:
			if host := hostOnly(c.Target); host != "" {
				addHost(host)
			}
		}
	}

	sort.Strings(p.Filesystem.Read)
	sort.Strings(p.Filesystem.Write)
	sort.Strings(p.Filesystem.Deny)
	sort.Strings(p.Process.Exec.Allow)
	sort.Strings(p.Process.Exec.Deny)
	sort.Strings(p.Network.Allow)

	return Result{Policy: p, Denied: denied, Review: review}
}

func addUnique(list []string, s string, seen map[string]bool) []string {
	if s == "" || seen[s] {
		return list
	}
	seen[s] = true
	return append(list, s)
}

func hostOnly(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
