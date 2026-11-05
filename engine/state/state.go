// Package state persists the agent's local operating state: which mode the host
// is in, which policy is active, and where the observe baseline lives.
//
// It is the single source of truth for `vorynex status` and for rollback, and it
// never depends on the control plane being reachable — a cloud outage must not
// change or hide the local posture.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vorynex/vorynex/engine/telemetry"
)

// Mode is the host's enforcement posture.
type Mode string

const (
	ModeObserve  Mode = "observe"
	ModeProtect  Mode = "protect"
	ModeLockdown Mode = "lockdown"
)

// Valid reports whether m is a known mode.
func Valid(m Mode) bool {
	switch m {
	case ModeObserve, ModeProtect, ModeLockdown:
		return true
	}
	return false
}

// State is the persisted operating state.
type State struct {
	Mode         Mode      `json:"mode"`
	PolicyPath   string    `json:"policy_path,omitempty"`
	PolicySHA256 string    `json:"policy_sha256,omitempty"`
	BaselinePath string    `json:"baseline_path,omitempty"`
	ControlPlane string    `json:"control_plane,omitempty"`
	Workload     string    `json:"workload,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`

	// Previous posture, kept so `protect --off` restores the exact prior state.
	// One level is enough for rollback; the journal holds the full history.
	PreviousMode       Mode   `json:"previous_mode,omitempty"`
	PreviousPolicyPath string `json:"previous_policy_path,omitempty"`
	PreviousPolicySHA  string `json:"previous_policy_sha256,omitempty"`
}

// Digest returns the SHA-256 of a policy file.
func Digest(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read policy %s: %w", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// BeginTransition snapshots the current posture, then records the new one.
func BeginTransition(m Mode, policyPath, policySHA string) (State, error) {
	if !Valid(m) {
		return Load(), fmt.Errorf("invalid mode %q", m)
	}
	return Update(func(s *State) {
		s.PreviousMode = s.Mode
		s.PreviousPolicyPath = s.PolicyPath
		s.PreviousPolicySHA = s.PolicySHA256
		s.Mode = m
		s.PolicyPath = policyPath
		s.PolicySHA256 = policySHA
	})
}

// CanRevert reports whether a previous posture was snapshotted.
func CanRevert() bool {
	return Load().PreviousMode != ""
}

// Revert restores the snapshotted posture and clears the snapshot. Reverting
// with no snapshot (first ever protect) falls back to observe with no policy.
func Revert() (State, error) {
	return Update(func(s *State) {
		s.Mode = s.PreviousMode
		if s.Mode == "" {
			s.Mode = ModeObserve
		}
		s.PolicyPath = s.PreviousPolicyPath
		s.PolicySHA256 = s.PreviousPolicySHA
		s.PreviousMode = ""
		s.PreviousPolicyPath = ""
		s.PreviousPolicySHA = ""
	})
}

// Dir is the agent state directory (shared with telemetry so there is one place
// to look and one place to clean).
func Dir() string { return telemetry.DefaultDir() }

// Path is the state file path.
func Path() string { return filepath.Join(Dir(), "state.json") }

// Load returns the persisted state, or a zero value when none exists yet. A
// corrupt file is reported as zero state rather than crashing the agent.
func Load() State {
	b, err := os.ReadFile(Path())
	if err != nil {
		return State{}
	}
	var s State
	if json.Unmarshal(b, &s) != nil {
		return State{}
	}
	return s
}

// Save writes the state atomically, owner-only.
func Save(s State) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	s.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(Dir(), "state-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, Path())
}

// Update applies fn to the current state and saves it.
func Update(fn func(*State)) (State, error) {
	s := Load()
	fn(&s)
	return s, Save(s)
}

// SetMode records the posture.
func SetMode(m Mode) (State, error) {
	if !Valid(m) {
		return Load(), fmt.Errorf("invalid mode %q", m)
	}
	return Update(func(s *State) { s.Mode = m })
}

// SetPolicy records the active policy and its digest. An empty path clears it.
func SetPolicy(path string) (State, error) {
	digest := ""
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return Load(), fmt.Errorf("read policy %s: %w", path, err)
		}
		sum := sha256.Sum256(b)
		digest = hex.EncodeToString(sum[:])
	}
	return Update(func(s *State) {
		s.PolicyPath = path
		s.PolicySHA256 = digest
	})
}

// SetBaseline records the observe trace used as the baseline.
func SetBaseline(path string) (State, error) {
	return Update(func(s *State) { s.BaselinePath = path })
}

// SetControlPlane records the control-plane URL used for enrollment.
func SetControlPlane(url string) (State, error) {
	return Update(func(s *State) { s.ControlPlane = url })
}

// SetWorkload records the workload name or container.
func SetWorkload(name string) (State, error) {
	return Update(func(s *State) { s.Workload = name })
}

// JournalEntry is one state transition, kept as an append-only audit trail.
type JournalEntry struct {
	Time   time.Time `json:"time"`
	Event  string    `json:"event"`
	Mode   Mode      `json:"mode,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// JournalPath is the append-only transition log.
func JournalPath() string { return filepath.Join(Dir(), "journal.jsonl") }

// Journal appends one entry.
func Journal(e JournalEntry) error {
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(JournalPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// ReadJournal returns up to limit entries (0 = all), oldest first.
func ReadJournal(limit int) ([]JournalEntry, error) {
	b, err := os.ReadFile(JournalPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []JournalEntry
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var e JournalEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}
