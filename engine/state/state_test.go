package state

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	if got := Load(); got.Mode != "" {
		t.Fatalf("fresh state = %+v, want zero", got)
	}

	if _, err := SetMode(ModeProtect); err != nil {
		t.Fatal(err)
	}
	if got := Load().Mode; got != ModeProtect {
		t.Fatalf("mode = %q, want protect", got)
	}
	if _, err := SetMode(Mode("nonsense")); err == nil {
		t.Fatal("invalid mode should be rejected")
	}
	if got := Load().Mode; got != ModeProtect {
		t.Fatalf("invalid write changed mode to %q", got)
	}

	if _, err := SetWorkload("api"); err != nil {
		t.Fatal(err)
	}
	if _, err := SetControlPlane("http://127.0.0.1:8787"); err != nil {
		t.Fatal(err)
	}
	if _, err := SetBaseline("/tmp/baseline.jsonl"); err != nil {
		t.Fatal(err)
	}
	got := Load()
	if got.Workload != "api" || got.ControlPlane != "http://127.0.0.1:8787" || got.BaselinePath != "/tmp/baseline.jsonl" {
		t.Fatalf("state = %+v", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Fatal("UpdatedAt was not set")
	}
}

func TestSetPolicyRecordsDigest(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := []byte("version: 1\nfilesystem:\n  deny: [/app/.env]\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := SetPolicy(path); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	got := Load()
	if got.PolicyPath != path || got.PolicySHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("policy state = %+v", got)
	}

	if _, err := SetPolicy(""); err != nil {
		t.Fatal(err)
	}
	if got := Load(); got.PolicyPath != "" || got.PolicySHA256 != "" {
		t.Fatalf("clearing policy left %+v", got)
	}

	if _, err := SetPolicy(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("missing policy should be an error")
	}
}

func TestJournalAppendsAndReads(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	if _, err := ReadJournal(0); err != nil {
		t.Fatal(err)
	}
	for _, e := range []JournalEntry{
		{Event: "connect", Mode: ModeObserve, Detail: "baseline recorded"},
		{Event: "mode", Mode: ModeProtect, Detail: "policy applied"},
	} {
		if err := Journal(e); err != nil {
			t.Fatal(err)
		}
	}
	all, err := ReadJournal(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].Event != "connect" || all[1].Mode != ModeProtect {
		t.Fatalf("journal = %+v", all)
	}
	last, err := ReadJournal(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(last) != 1 || last[0].Event != "mode" {
		t.Fatalf("tail = %+v", last)
	}
}

func TestTransitionAndRevert(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())

	// Fresh host: observe, no policy.
	if _, err := SetMode(ModeObserve); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(p, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := Digest(p)
	if err != nil {
		t.Fatal(err)
	}

	// Transition to protect snapshots the observe posture.
	if _, err := BeginTransition(ModeProtect, p, sha); err != nil {
		t.Fatal(err)
	}
	s := Load()
	if s.Mode != ModeProtect || s.PolicyPath != p || s.PreviousMode != ModeObserve {
		t.Fatalf("after transition: %+v", s)
	}
	if !CanRevert() {
		t.Fatal("CanRevert = false after a transition")
	}

	// Revert restores observe and clears the snapshot.
	if _, err := Revert(); err != nil {
		t.Fatal(err)
	}
	s = Load()
	if s.Mode != ModeObserve || s.PolicyPath != "" || s.PreviousMode != "" {
		t.Fatalf("after revert: %+v", s)
	}
	if CanRevert() {
		t.Fatal("CanRevert = true after revert")
	}

	// Reverting with no snapshot still lands on observe, never on an empty mode.
	if _, err := Revert(); err != nil {
		t.Fatal(err)
	}
	if s := Load(); s.Mode != ModeObserve {
		t.Fatalf("revert without snapshot left mode %q", s.Mode)
	}
}

func TestLoadIgnoresCorruptState(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(Path(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Load(); got.Mode != "" {
		t.Fatalf("corrupt state returned %+v, want zero", got)
	}
}
