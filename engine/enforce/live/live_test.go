package live

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vorynex/vorynex/engine/policy"
)

func fakeRoot(t *testing.T, lsm, capEff string, withBTF bool) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc/sys/kernel/osrelease", "6.8.0-31-generic\n")
	write("sys/kernel/security/lsm", lsm)
	write("proc/self/status", "Name:\ttest\nCapEff:\t"+capEff+"\n")
	if withBTF {
		write("sys/kernel/btf/vmlinux", "btf")
	}
	return root
}

func TestDetectAvailable(t *testing.T) {
	root := fakeRoot(t, "lockdown,capability,landlock,yama,bpf", "000000c000000000", true)
	c := detect(root)
	if !c.Available {
		t.Fatalf("expected available: %+v", c)
	}
	if !c.HasBPFLSM || !c.HasBTF || !c.HasCaps || !c.KernelAtLeast57 {
		t.Fatalf("unexpected capabilities: %+v", c)
	}
}

func TestDetectWithoutBPFLSM(t *testing.T) {
	root := fakeRoot(t, "lockdown,capability,landlock,yama", "000000c000000000", true)
	c := detect(root)
	if c.Available {
		t.Fatal("expected unavailable without bpf in the LSM list")
	}
	if len(c.Reasons) == 0 {
		t.Fatal("expected a reason")
	}
}

func TestDetectWithoutCaps(t *testing.T) {
	root := fakeRoot(t, "lockdown,capability,landlock,yama,bpf", "0000000000000000", true)
	c := detect(root)
	if c.HasCaps {
		t.Fatal("expected no capabilities")
	}
	if c.Available {
		t.Fatal("expected unavailable without CAP_BPF")
	}
}

func TestPlan(t *testing.T) {
	p := policy.Policy{
		Filesystem: policy.Filesystem{Deny: []string{"/app/.env"}, ProtectSecrets: true},
		Network:    policy.Network{Allow: []string{"api.stripe.com"}},
		Process:    policy.Process{Exec: policy.ExecRules{Deny: []string{"/bin/bash"}}},
	}
	hooks := Plan(p)
	if len(hooks) == 0 {
		t.Fatal("expected hooks")
	}
	seen := map[string]bool{}
	for _, h := range hooks {
		seen[h.Hook] = true
		if h.Rule == "" || h.Purpose == "" {
			t.Errorf("incomplete hook: %+v", h)
		}
	}
	for _, want := range []string{"bprm_check_security", "file_open", "socket_connect", "capable"} {
		if !seen[want] {
			t.Errorf("plan missing hook %q: %+v", want, hooks)
		}
	}
}

func TestAttachFailsHonestly(t *testing.T) {
	if err := Attach(Capabilities{Available: false, Reasons: []string{"no bpf"}}, ""); err == nil {
		t.Fatal("expected an error when unavailable")
	}
	if err := Attach(Capabilities{Available: true}, ""); err == nil {
		t.Fatal("expected an error when no BPF object is supplied")
	}
	if err := Attach(Capabilities{Available: true}, "/tmp/live.bpf.o"); err == nil {
		t.Fatal("expected an error while the loader is not shipped")
	}
}
