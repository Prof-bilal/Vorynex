package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBroadExecGrants(t *testing.T) {
	root := t.TempDir()
	mk := func(rel string, mode os.FileMode) string {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte("x"), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	exclusive := mk("helpers/ping", 0o755)
	shared := mk("bin/ping", 0o755)
	mk("bin/sh", 0o755)
	mk("bin/readme.txt", 0o644) // not executable: does not widen the grant
	launch := mk("app/node", 0o755)
	mk("app/npm", 0o755) // the launch directory is always granted; exempt

	if got := BroadExecGrants(launch, []string{exclusive}, nil); len(got) != 0 {
		t.Fatalf("exclusive directory flagged: %v", got)
	}
	got := BroadExecGrants(launch, []string{shared}, nil)
	if len(got) != 1 || len(got[0].Others) != 1 || filepath.Base(got[0].Others[0]) != "sh" {
		t.Fatalf("shared directory not flagged correctly: %+v", got)
	}
	if got := BroadExecGrants(launch, []string{shared}, []string{shared}); len(got) != 0 {
		t.Fatalf("denied entry should be ignored: %v", got)
	}
	if got := BroadExecGrants(launch, []string{launch}, nil); len(got) != 0 {
		t.Fatalf("launch binary must be exempt: %v", got)
	}
}
