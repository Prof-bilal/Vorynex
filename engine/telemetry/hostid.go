package telemetry

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// DefaultDir is the agent's local state directory.
func DefaultDir() string {
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "vorynex")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".local", "state", "vorynex")
}

// DefaultSpoolPath is the local telemetry event bus.
func DefaultSpoolPath() string { return filepath.Join(DefaultDir(), "telemetry.jsonl") }

// LoadOrCreateHostID returns a stable, locally-generated host identity.
func LoadOrCreateHostID(dir string) (string, error) {
	path := filepath.Join(dir, "hostid")
	if b, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := "host_" + hex.EncodeToString(buf)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0o600); err != nil {
		return "", err
	}
	return id, nil
}

// LoadCursor returns the last exported sequence number (0 if none).
func LoadCursor(dir string) uint64 {
	b, err := os.ReadFile(filepath.Join(dir, "telemetry.cursor"))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// SaveCursor persists the last exported sequence number.
func SaveCursor(dir string, seq uint64) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "telemetry.cursor"),
		[]byte(strconv.FormatUint(seq, 10)+"\n"), 0o600)
}

// LoadHostToken returns the per-host token issued at enrollment (empty if none).
func LoadHostToken(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "hosttoken"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// SaveHostToken persists a per-host token, owner-only.
func SaveHostToken(dir, token string) error {
	if token == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "hosttoken"), []byte(token+"\n"), 0o600)
}

// Desired is the locally persisted desired rollout state.
type Desired struct {
	Revision int
	Mode     string
	Policy   string
}

// SaveDesired persists the desired rollout state the agent pulled.
func SaveDesired(dir string, rev int, mode, policy string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "desired.mode"), []byte(mode+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "desired.revision"), []byte(strconv.Itoa(rev)+"\n"), 0o600); err != nil {
		return err
	}
	if policy != "" {
		if err := os.WriteFile(filepath.Join(dir, "desired.policy.yaml"), []byte(policy), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// LoadDesired reads the desired rollout state (zero value when none was pulled).
func LoadDesired(dir string) Desired {
	d := Desired{}
	if b, err := os.ReadFile(filepath.Join(dir, "desired.mode")); err == nil {
		d.Mode = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "desired.revision")); err == nil {
		d.Revision, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "desired.policy.yaml")); err == nil {
		d.Policy = string(b)
	}
	return d
}
