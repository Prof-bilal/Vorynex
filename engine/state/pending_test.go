package state

import (
	"os"
	"os/exec"
	"testing"
)

func isolate(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
}

func TestRecoverRevertsWhenSupervisorDied(t *testing.T) {
	isolate(t)
	if _, err := BeginTransition(ModeProtect, "/old.yaml", "oldsha"); err != nil {
		t.Fatal(err)
	}
	// A supervisor that has already exited.
	c := exec.Command("true")
	c.Run()
	Update(func(s *State) {
		s.PreviousMode, s.PreviousPolicyPath, s.PreviousPolicySHA = ModeProtect, "/old.yaml", "oldsha"
	})
	Update(func(s *State) {
		s.Mode, s.PolicyPath = ModeProtect, "/bad.yaml"
		s.Pending = &Pending{SupervisorPID: c.Process.Pid, SupervisorStart: "1"}
	})
	did, err := Recover()
	if err != nil || !did {
		t.Fatalf("recover did=%v err=%v", did, err)
	}
	if s := Load(); s.PolicyPath != "/old.yaml" || s.Pending != nil {
		t.Fatalf("not reverted: %+v", s)
	}
}

func TestRecoverIgnoresLiveSupervisorAndCommit(t *testing.T) {
	isolate(t)
	BeginSupervised(ModeProtect, "/new.yaml", "sha") // this test process is the live supervisor
	if did, _ := Recover(); did {
		t.Fatal("recovered a live supervisor's transition")
	}
	if err := Commit(); err != nil {
		t.Fatal(err)
	}
	if s := Load(); s.Pending != nil || s.PolicyPath != "/new.yaml" {
		t.Fatalf("commit should keep the policy and clear pending: %+v", s)
	}
}

func TestRecoverDefeatsPIDReuse(t *testing.T) {
	isolate(t)
	BeginSupervised(ModeProtect, "/new.yaml", "sha")
	// Same PID (alive) but a different start time: a different process.
	Update(func(s *State) { s.Pending.SupervisorStart = "not-our-start-time" })
	if did, _ := Recover(); !did {
		t.Fatal("a recycled PID must not keep a transition alive")
	}
}

func TestRecoverKillsLeftoverWorkload(t *testing.T) {
	isolate(t)
	w := exec.Command("sleep", "30")
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	BeginSupervised(ModeProtect, "/new.yaml", "sha")
	SetPendingWorkload(w.Process.Pid)
	Update(func(s *State) { s.Pending.SupervisorStart = "dead" })
	if did, _ := Recover(); !did {
		t.Fatal("expected recovery")
	}
	if err := w.Wait(); err == nil {
		t.Fatal("workload should have been killed")
	}
	_ = os.Getpid
}
