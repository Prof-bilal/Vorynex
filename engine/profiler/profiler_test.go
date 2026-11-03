package profiler

import (
	"testing"
	"time"

	"github.com/vorynex/vorynex/engine/audit"
)

func ev(typ, action, resource string) audit.Event {
	return audit.Event{Type: typ, Action: action, Resource: resource, Allowed: true, Timestamp: time.Now()}
}

func TestNeverPromoteClasses(t *testing.T) {
	events := []audit.Event{
		ev("file", "execve", "/usr/bin/bash"),
		ev("file", "openat", "/app/.env"),
		ev("file", "openat", "/home/u/.ssh/id_rsa"),
		ev("network", "connect", "169.254.169.254:80"),
		ev("network", "connect", "1.2.3.4:4444"),
	}
	for _, e := range events {
		if safe, _ := danger(e); safe {
			t.Errorf("expected %s %s to be dangerous", e.Action, e.Resource)
		}
		if _, _, ok := classify(e); !ok {
			t.Errorf("expected %s %s to classify", e.Action, e.Resource)
		}
	}
}

func TestSafeCapabilities(t *testing.T) {
	for _, e := range []audit.Event{
		ev("file", "execve", "/usr/bin/node"),
		ev("file", "openat", "/app/server.js"),
		ev("network", "connect", "api.stripe.com:443"),
	} {
		if safe, reason := danger(e); !safe {
			t.Errorf("expected %s %s safe, got %q", e.Action, e.Resource, reason)
		}
	}
}

func TestPromotionThreshold(t *testing.T) {
	session := []audit.Event{ev("file", "openat", "/app/server.js")}
	// one session, default requires two -> observe only
	p := Build([][]audit.Event{session}, DefaultOptions())
	if len(p.Capabilities) != 1 {
		t.Fatalf("want 1 capability, got %d", len(p.Capabilities))
	}
	if p.Capabilities[0].Decision != Observe {
		t.Errorf("single session: want observe, got %s", p.Capabilities[0].Decision)
	}
	// two sessions -> promote
	p = Build([][]audit.Event{session, session}, DefaultOptions())
	if p.Capabilities[0].Decision != Promote {
		t.Errorf("two sessions: want promote, got %s", p.Capabilities[0].Decision)
	}
	if p.Summary.Promotable != 1 {
		t.Errorf("summary promotable = %d, want 1", p.Summary.Promotable)
	}
}

func TestPoisoningDefense(t *testing.T) {
	// An attacker shells out during observe: it must never become promotable,
	// even across many sessions.
	attack := []audit.Event{ev("file", "execve", "/bin/sh")}
	p := Build([][]audit.Event{attack, attack, attack, attack}, DefaultOptions())
	if p.Capabilities[0].Decision != Never {
		t.Fatalf("shell execution promoted across sessions: %s", p.Capabilities[0].Decision)
	}
	if p.Summary.NeverPromote != 1 {
		t.Errorf("summary never = %d, want 1", p.Summary.NeverPromote)
	}
}

func TestWouldBlock(t *testing.T) {
	events := []audit.Event{
		ev("file", "openat", "/app/server.js"),
		ev("file", "execve", "/bin/bash"),
		ev("network", "connect", "169.254.169.254:80"),
	}
	blocked := WouldBlock(events)
	if len(blocked) != 2 {
		t.Fatalf("want 2 blocked, got %d", len(blocked))
	}
	for _, b := range blocked {
		if b.Reason == "" {
			t.Errorf("blocked event missing reason: %+v", b)
		}
	}
}
