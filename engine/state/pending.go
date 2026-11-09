package state

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Pending marks a transition that has been applied but not yet verified. It is
// written together with the new posture and cleared by Commit once the policy
// has proven itself. If the supervisor dies in between, nothing is left to
// revert, so the next agent start does it (Recover).
type Pending struct {
	SupervisorPID   int    `json:"supervisor_pid"`
	SupervisorStart string `json:"supervisor_start"` // /proc start ticks: defeats PID reuse
	WorkloadPID     int    `json:"workload_pid,omitempty"`
	WorkloadStart   string `json:"workload_start,omitempty"`
}

// BeginSupervised is BeginTransition plus a Pending marker for this process,
// applied in one atomic state write so there is no window where the new policy
// is recorded without a way to recover it.
func BeginSupervised(m Mode, policyPath, policySHA string) (State, error) {
	if !Valid(m) {
		return Load(), fmt.Errorf("invalid mode %q", m)
	}
	pid := os.Getpid()
	start, _ := procStart(pid)
	return Update(func(s *State) {
		s.PreviousMode, s.PreviousPolicyPath, s.PreviousPolicySHA = s.Mode, s.PolicyPath, s.PolicySHA256
		s.Mode, s.PolicyPath, s.PolicySHA256 = m, policyPath, policySHA
		s.Pending = &Pending{SupervisorPID: pid, SupervisorStart: start}
	})
}

// SetWorkload records the supervised child so Recover can stop it if it is
// still running after the supervisor is gone.
func SetPendingWorkload(pid int) error {
	start, _ := procStart(pid)
	_, err := Update(func(s *State) {
		if s.Pending != nil {
			s.Pending.WorkloadPID, s.Pending.WorkloadStart = pid, start
		}
	})
	return err
}

// Commit clears the pending marker: the policy is verified and stays applied.
// The previous-posture snapshot is kept so `protect --off` still restores it.
func Commit() error {
	_, err := Update(func(s *State) { s.Pending = nil })
	return err
}

// Recover reverts an unverified transition whose supervisor no longer exists and
// stops its workload if that is still running. It reports whether it acted. It
// is a no-op while the supervisor is alive, so a healthy run is never disturbed.
func Recover() (bool, error) {
	s := Load()
	if s.Pending == nil || alive(s.Pending.SupervisorPID, s.Pending.SupervisorStart) {
		return false, nil
	}
	p := *s.Pending
	if p.WorkloadPID > 0 && alive(p.WorkloadPID, p.WorkloadStart) {
		_ = syscall.Kill(p.WorkloadPID, syscall.SIGKILL)
	}
	if _, err := Revert(); err != nil { // Revert clears Pending with the snapshot
		return false, err
	}
	_, _ = Update(func(s *State) { s.Pending = nil })
	_ = Journal(JournalEntry{Event: "recovered", Mode: Load().Mode,
		Detail: fmt.Sprintf("supervisor %d died before the policy was verified; reverted", p.SupervisorPID)})
	return true, nil
}

// alive is true only for the same process: a recycled PID has a different start time.
func alive(pid int, start string) bool {
	cur, ok := procStart(pid)
	return ok && (start == "" || cur == start)
}

// procStart returns field 22 (starttime) of /proc/<pid>/stat.
func procStart(pid int) (string, bool) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", false
	}
	// comm (field 2) may contain spaces/parens: parse after the last ')'.
	rest := string(b[strings.LastIndexByte(string(b), ')')+1:])
	f := strings.Fields(rest)
	if len(f) < 20 {
		return "", false
	}
	return f[19], true // fields after comm start at field 3, so starttime (22) is index 19
}
