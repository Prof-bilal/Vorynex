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

	"github.com/vorynex/vorynex/engine/audit"
	"github.com/vorynex/vorynex/engine/policygen"
	"github.com/vorynex/vorynex/engine/profiler"
)

// runPolicy implements `vorynex policy <generate|verify|pubkey>`.
func runPolicy(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vorynex policy <generate|verify|pubkey> [...]")
	}
	switch args[0] {
	case "generate":
		return policyGenerate(args[1:])
	case "verify":
		return policyVerify(args[1:])
	case "pubkey":
		return policyPubkey(args[1:])
	default:
		return fmt.Errorf("unknown policy subcommand %q (want generate, verify, or pubkey)", args[0])
	}
}

// policyVerify checks a detached signature against the trust root.
func policyVerify(args []string) error {
	var policyPath, sigPath, keySpec string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--policy":
			if i+1 < len(args) {
				i++
				policyPath = args[i]
			}
		case "--sig":
			if i+1 < len(args) {
				i++
				sigPath = args[i]
			}
		case "--pubkey":
			if i+1 < len(args) {
				i++
				keySpec = args[i]
			}
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if policyPath == "" || sigPath == "" || keySpec == "" {
		return fmt.Errorf("usage: vorynex policy verify --policy <file> --sig <file> --pubkey <hex|file>")
	}
	keyID, err := verifyDetached(policyPath, sigPath, keySpec)
	if err != nil {
		return err
	}
	fmt.Printf("signature valid (key %s)\n", keyID)
	return nil
}

// policyPubkey prints the public key for a signing seed, so it can be pinned as
// the trust root on agents.
func policyPubkey(args []string) error {
	var keyPath string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--key":
			if i+1 < len(args) {
				i++
				keyPath = args[i]
			}
		default:
			return fmt.Errorf("unknown flag %q", args[i])
		}
	}
	if keyPath == "" {
		return fmt.Errorf("usage: vorynex policy pubkey --key <seed-file>")
	}
	seed, err := readSeed(keyPath)
	if err != nil {
		return err
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Printf("public key  %s\n", hex.EncodeToString(pub))
	fmt.Printf("fingerprint %s\n", fingerprint(pub))
	fmt.Println("\nPin this on agents as the trust root; they refuse policies that do not verify.")
	return nil
}

func policyGenerate(args []string) error {
	var froms []string
	var out, signKey string
	minSessions := 0
	rest := args
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
	if seed, err := readSeed(path); err == nil {
		return seed, nil
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
