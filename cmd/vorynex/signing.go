package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// readSeed reads an Ed25519 seed (32 bytes) from a file, hex or raw.
func readSeed(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(b))
	if raw, err := hex.DecodeString(trimmed); err == nil && len(raw) == ed25519.SeedSize {
		return raw, nil
	}
	if len(b) == ed25519.SeedSize {
		return b, nil
	}
	return nil, fmt.Errorf("signing key %s must be a %d-byte seed (hex or raw)", path, ed25519.SeedSize)
}

// loadPublicKey accepts a 32-byte hex public key, or a path to a file holding
// one. The fingerprint is the first 16 hex chars of SHA-256 over the key.
func loadPublicKey(spec string) (ed25519.PublicKey, string, error) {
	raw := strings.TrimSpace(spec)
	if b, err := os.ReadFile(spec); err == nil {
		raw = strings.TrimSpace(string(b))
	}
	key, err := hex.DecodeString(raw)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("public key must be a %d-byte hex string or a file containing one", ed25519.PublicKeySize)
	}
	sum := sha256.Sum256(key)
	return ed25519.PublicKey(key), hex.EncodeToString(sum[:])[:16], nil
}

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// verifyDetached checks a base64 Ed25519 signature over the policy file against
// the trust root. It returns the signer's key fingerprint.
func verifyDetached(policyPath, sigPath, keySpec string) (string, error) {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return "", err
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigRaw)))
	if err != nil {
		return "", fmt.Errorf("signature %s must be base64: %w", sigPath, err)
	}
	pub, keyID, err := loadPublicKey(keySpec)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(pub, data, sig) {
		return keyID, fmt.Errorf("signature is NOT valid for %s (key %s)", policyPath, keyID)
	}
	return keyID, nil
}
