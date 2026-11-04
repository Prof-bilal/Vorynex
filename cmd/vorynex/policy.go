package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/policygen"
	"github.com/vorynex/vorynex/engine/profiler"
)

// runPolicy implements `vorynex policy generate`.
func runPolicy(args []string) error {
	if len(args) == 0 || args[0] != "generate" {
		return fmt.Errorf("usage: vorynex policy generate --from <events.jsonl> [--from <events2.jsonl>...] [--min-sessions N] [--out <file>] [--sign-key <file>]")
	}
	var froms []string
	var out, signKey string
	minSessions := 0
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--from":
			if i+1 < len(rest) {
				i++
				froms = append(froms, rest[i])
			}
		case "--out":
			if i+1 < len(rest) {
				i++
				out = rest[i]
			}
		case "--sign-key":
			if i+1 < len(rest) {
				i++
				signKey = rest[i]
			}
		case "--min-sessions":
			if i+1 < len(rest) {
				i++
				if n, err := strconv.Atoi(rest[i]); err == nil {
					minSessions = n
				}
			}
		default:
			return fmt.Errorf("unknown flag %q", rest[i])
		}
	}
	if len(froms) == 0 {
		return fmt.Errorf("--from <events.jsonl> is required")
	}

	// Each --from is one independent session. A capability must appear in
	// MinSessions of them to be promotable; provenance is the session count.
	sessions := make([][]audit.Event, 0, len(froms))
	for _, from := range froms {
		events, _, err := readTraceEvents(from)
		if err != nil {
			return fmt.Errorf("read %s: %w", from, err)
		}
		sessions = append(sessions, events)
	}
	if minSessions <= 0 {
		if len(sessions) > 1 {
			minSessions = 2
		} else {
			minSessions = 1
		}
	}

	prof := profiler.Build(sessions, profiler.Options{MinSessions: minSessions, MinCount: 1})
	res := policygen.Generate(prof, policygen.DefaultOptions())
	data, err := res.Policy.Marshal()
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "aggregated %d session(s), min-sessions %d\n", len(sessions), minSessions)

	if out == "" {
		fmt.Print(string(data))
		printGenSummary(res)
		return nil
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", out)
	printGenSummary(res)

	if signKey != "" {
		keyID, err := signPolicyFile(out, data, signKey)
		if err != nil {
			return err
		}
		fmt.Printf("signed: key %s -> %s.sig\n", keyID, out)
	}
	return nil
}

func printGenSummary(res policygen.Result) {
	p := res.Policy
	fmt.Printf("generated policy: %d read, %d write, %d exec-allow, %d fs-deny, %d exec-deny, %d hosts; %d never-promote denied\n",
		len(p.Filesystem.Read), len(p.Filesystem.Write), len(p.Process.Exec.Allow),
		len(p.Filesystem.Deny), len(p.Process.Exec.Deny), len(p.Network.Allow), len(res.Denied))
	for _, d := range res.Denied {
		fmt.Printf("  denied %s %s  (%s)\n", d.Kind, d.Target, d.Reason)
	}
}

// signPolicyFile signs data with an Ed25519 key stored at keyPath (a 32-byte hex
// seed), creating the key if it does not exist. It writes a detached signature
// to <out>.sig and returns a short key id.
func signPolicyFile(out string, data []byte, keyPath string) (string, error) {
	seed, err := loadOrCreateSeed(keyPath)
	if err != nil {
		return "", err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, data)
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	keyID := hex.EncodeToString(sum[:])[:16]

	if err := os.WriteFile(out+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o600); err != nil {
		return "", err
	}
	return keyID, nil
}

func loadOrCreateSeed(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		trimmed := strings.TrimSpace(string(b))
		if raw, err := hex.DecodeString(trimmed); err == nil && len(raw) == ed25519.SeedSize {
			return raw, nil
		}
		if len(b) == ed25519.SeedSize {
			return b, nil
		}
		return nil, fmt.Errorf("signing key %s must be a %d-byte seed (hex or raw)", path, ed25519.SeedSize)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return seed, nil
}
