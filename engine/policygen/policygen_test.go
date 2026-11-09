package policygen

import (
	"testing"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/profiler"
)

func ev(typ, action, resource string) audit.Event {
	return audit.Event{Type: typ, Action: action, Resource: resource, Allowed: true}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestGenerate(t *testing.T) {
	events := []audit.Event{
		ev("file", "execve", "/usr/bin/node"), // promotable (seen twice)
		ev("file", "execve", "/usr/bin/node"),
		ev("file", "execve", "/usr/bin/bash"), // never-promote
		ev("file", "openat", "/app/server.js"),
		ev("file", "openat", "/app/server.js"),
		ev("file", "openat", "/app/.env"), // never-promote (secret)
		ev("network", "connect", "api.stripe.com:443"),
		ev("network", "connect", "api.stripe.com:443"),
		ev("network", "connect", "169.254.169.254:80"), // never-promote (metadata)
	}
	prof := profiler.Build([][]audit.Event{events}, profiler.Options{MinSessions: 1, MinCount: 2})
	res := Generate(prof, DefaultOptions())
	p := res.Policy

	if p.Version != SchemaVersion {
		t.Errorf("version = %d, want %d", p.Version, SchemaVersion)
	}
	if !contains(p.Filesystem.Read, "/app/server.js") {
		t.Errorf("read grants missing /app/server.js: %v", p.Filesystem.Read)
	}
	if !contains(p.Process.Exec.Allow, "/usr/bin/node") {
		t.Errorf("exec allow missing node: %v", p.Process.Exec.Allow)
	}
	if !contains(p.Process.Exec.Deny, "/usr/bin/bash") {
		t.Errorf("exec deny missing bash: %v", p.Process.Exec.Deny)
	}
	if contains(p.Process.Exec.Allow, "/usr/bin/bash") {
		t.Errorf("shell must never be granted: %v", p.Process.Exec.Allow)
	}
	if contains(p.Network.Allow, "169.254.169.254") {
		t.Errorf("metadata must never be allowlisted: %v", p.Network.Allow)
	}
	if contains(p.Network.Allow, "api.stripe.com") {
		t.Errorf("observed destinations need review, never auto-granted: %v", p.Network.Allow)
	}
	foundReview := false
	for _, r := range res.Review {
		foundReview = foundReview || r.Target == "api.stripe.com:443" || r.Target == "api.stripe.com"
	}
	if !foundReview {
		t.Errorf("api.stripe.com should be listed for review: %+v", res.Review)
	}
	if !contains(p.Filesystem.Deny, "/app/.env") {
		t.Errorf("secret path must be denied: %v", p.Filesystem.Deny)
	}
	if !p.Filesystem.ProtectSecrets {
		t.Errorf("ProtectSecrets should be enabled by default")
	}
	if err := p.Validate(); err != nil {
		t.Errorf("generated policy failed validation: %v", err)
	}
	if len(res.Denied) != 3 {
		t.Errorf("denied capabilities = %d, want 3 (shell, secret, metadata): %+v", len(res.Denied), res.Denied)
	}
	if _, err := p.Marshal(); err != nil {
		t.Errorf("generated policy did not marshal: %v", err)
	}
}
