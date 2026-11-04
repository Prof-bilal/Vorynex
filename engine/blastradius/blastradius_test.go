package blastradius

import (
	"testing"

	"github.com/vorynex/vorynex/engine/policy"
)

func containsClass(r Report, class string) bool {
	for _, c := range r.Contained {
		if c.Class == class {
			return true
		}
	}
	return false
}

func containsTarget(r Report, target string) bool {
	for _, x := range r.Reachable {
		if x.Target == target {
			return true
		}
	}
	return false
}

func TestFromPolicy(t *testing.T) {
	p := policy.Policy{
		Filesystem: policy.Filesystem{
			Read:           []string{"/app"},
			Write:          []string{"/app/uploads"},
			Deny:           []string{"/app/.env"},
			ProtectSecrets: true,
		},
		Network: policy.Network{Allow: []string{"api.stripe.com"}},
		Process: policy.Process{Exec: policy.ExecRules{Deny: []string{"/bin/bash", "/usr/bin/sh"}}},
	}
	r := FromPolicy(p, "payments", "protect")

	if !containsTarget(r, "api.stripe.com") || !containsTarget(r, "/app/uploads") {
		t.Errorf("reachable missing expected resources: %+v", r.Reachable)
	}
	for _, class := range []string{"host filesystem", "shell execution", "cloud metadata", "arbitrary egress", "SSH & cloud credentials", "docker socket"} {
		if !containsClass(r, class) {
			t.Errorf("contained missing %q: %+v", class, r.Contained)
		}
	}
	if len(r.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", r.Warnings)
	}
}

func TestRiskyPolicyWarns(t *testing.T) {
	p := policy.Policy{
		Filesystem: policy.Filesystem{Read: []string{"/"}},
		Network:    policy.Network{Allow: []string{"169.254.169.254"}},
		Process:    policy.Process{Exec: policy.ExecRules{Allow: []string{"/bin/bash"}}},
	}
	r := FromPolicy(p, "risky", "observe")
	if len(r.Warnings) == 0 {
		t.Fatal("expected warnings for a risky policy")
	}
	if containsClass(r, "host filesystem") {
		t.Error("host filesystem should not be contained when / is granted")
	}
}
