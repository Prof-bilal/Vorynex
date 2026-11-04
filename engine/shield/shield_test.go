package shield

import (
	"testing"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/cve"
	"github.com/vorynex/vorynex/engine/policy"
)

func TestProposeAndValidate(t *testing.T) {
	base := policy.Policy{Filesystem: policy.Filesystem{Read: []string{"/app"}}}
	matches := []cve.Match{{Advisory: cve.Advisory{ID: "GHSA-1", Summary: "Remote code execution in next"}}}
	c := Propose(base, matches)

	if !c.Policy.Filesystem.ProtectSecrets {
		t.Error("protect_secrets should be enabled")
	}
	if len(c.Policy.Process.Exec.Deny) == 0 {
		t.Error("expected exec denies")
	}
	if len(c.Policy.Filesystem.Read) != 1 || c.Policy.Filesystem.Read[0] != "/app" {
		t.Errorf("grants must not change: %v", c.Policy.Filesystem.Read)
	}
	if len(c.Hints) == 0 {
		t.Error("expected a behavior hint for RCE")
	}
	if problems := Validate(base, c.Policy); len(problems) != 0 {
		t.Errorf("candidate should validate: %v", problems)
	}
}

func TestValidateRejects(t *testing.T) {
	if problems := Validate(policy.Policy{}, policy.Policy{
		Process: policy.Process{Exec: policy.ExecRules{Allow: []string{"/bin/bash"}}},
	}); len(problems) == 0 {
		t.Error("candidate granting a shell must be rejected")
	}
	if problems := Validate(policy.Policy{}, policy.Policy{
		Network: policy.Network{Allow: []string{"169.254.169.254"}},
	}); len(problems) == 0 {
		t.Error("candidate allowlisting metadata must be rejected")
	}
	base := policy.Policy{Filesystem: policy.Filesystem{Deny: []string{"/x"}}}
	if problems := Validate(base, policy.Policy{}); len(problems) == 0 {
		t.Error("candidate dropping a deny must be rejected")
	}
}

func TestSimulateAndDecide(t *testing.T) {
	base := policy.Policy{Filesystem: policy.Filesystem{Read: []string{"/app"}}}
	cand := Propose(base, nil).Policy

	events := []audit.Event{
		{Type: "file", Action: "execve", Resource: "/bin/bash", Allowed: true},
		{Type: "file", Action: "openat", Resource: "/app/server.js", Allowed: true},
	}
	sim := Simulate(base, cand, events)
	if len(sim.NewDangerous) != 1 {
		t.Errorf("expected 1 newly contained dangerous event, got %+v", sim.NewDangerous)
	}
	if len(sim.NewBenign) != 0 {
		t.Errorf("unexpected benign breakage: %+v", sim.NewBenign)
	}
	if Decide(nil, sim) != VerdictApproved {
		t.Error("expected approved")
	}

	benignEvents := []audit.Event{{Type: "file", Action: "execve", Resource: "/usr/bin/curl", Allowed: true}}
	sim2 := Simulate(base, cand, benignEvents)
	if len(sim2.NewBenign) != 1 {
		t.Fatalf("expected benign breakage, got %+v", sim2.NewBenign)
	}
	if Decide(nil, sim2) != VerdictNeedsReview {
		t.Error("benign breakage must require review")
	}
	if Decide([]string{"schema error"}, sim) != VerdictRejected {
		t.Error("validation problems must reject")
	}
}
