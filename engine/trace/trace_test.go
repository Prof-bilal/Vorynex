package trace

import (
	"testing"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
)

func TestBuildDeniedAndWouldDeny(t *testing.T) {
	now := time.Now()
	events := []audit.Event{
		{Type: "file", Action: "execve", Resource: "/bin/bash", Allowed: false, Reason: "-1 EACCES (Permission denied)", Timestamp: now},
		{Type: "network", Action: "connect", Resource: "169.254.169.254:80", Allowed: true, Timestamp: now.Add(-time.Second)},
		{Type: "file", Action: "openat", Resource: "/app/server.js", Allowed: true, Timestamp: now},
		{Type: "file", Action: "openat", Resource: "/app/missing.mo", Allowed: false, Reason: "-1 ENOENT (No such file or directory)", Timestamp: now},
	}
	traces := Build(events, "host_1", "payments")
	if len(traces) != 2 {
		t.Fatalf("want 2 traces, got %d: %+v", len(traces), traces)
	}

	// Newest first: the shell exec (now) precedes the metadata connect (-1s).
	first := traces[0]
	if first.Result != ResultDenied {
		t.Errorf("shell: result = %q, want DENIED", first.Result)
	}
	if first.Behavior != "shell execution" {
		t.Errorf("shell: behavior = %q", first.Behavior)
	}
	if first.Policy != "process.exec" {
		t.Errorf("shell: policy = %q", first.Policy)
	}
	if len(first.Path) != 3 || first.Path[2].Status != "denied" {
		t.Errorf("shell: path = %+v", first.Path)
	}
	if first.Confidence != "inferred" {
		t.Errorf("confidence = %q", first.Confidence)
	}

	second := traces[1]
	if second.Result != ResultWouldDeny {
		t.Errorf("metadata: result = %q, want WOULD_DENY", second.Result)
	}
	if second.Behavior != "cloud metadata access" {
		t.Errorf("metadata: behavior = %q", second.Behavior)
	}

	// IDs are stable across rebuilds.
	again := Build(events, "host_1", "payments")
	if again[0].ID != first.ID {
		t.Errorf("id not stable: %q vs %q", again[0].ID, first.ID)
	}
}

func TestBuildIgnoresHarmless(t *testing.T) {
	events := []audit.Event{
		{Type: "file", Action: "openat", Resource: "/app/server.js", Allowed: true},
		{Type: "file", Action: "openat", Resource: "/app/missing.mo", Allowed: false, Reason: "-1 ENOENT"},
	}
	if got := Build(events, "h", "w"); len(got) != 0 {
		t.Fatalf("expected no traces, got %+v", got)
	}
}
