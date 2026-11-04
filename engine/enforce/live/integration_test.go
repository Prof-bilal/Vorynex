//go:build integration && linux

package live

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTier1Enforcement validates every live hook end to end. Requires root and
// a compiled BPF object:
//
//	make bpf-test
//
// Safety: programs attach DISARMED and are only armed for a dedicated test
// cgroup. A process outside that cgroup must be unaffected while armed.
func TestTier1Enforcement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF/CAP_PERFMON) to load BPF-LSM programs")
	}
	object := os.Getenv("VORYNEX_BPF_OBJECT")
	if object == "" {
		object = "bpf/live.bpf.o"
	}
	if _, err := os.Stat(object); err != nil {
		t.Skipf("BPF object not built (%v); run `make bpf`", err)
	}
	caps := Detect()
	if !caps.Available {
		t.Skipf("tier 1 unavailable: %v", caps.Reasons)
	}

	dir := filepath.Join("/sys/fs/cgroup", "vorynex-test-"+strconv.Itoa(os.Getpid()))
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}
	defer os.Remove(dir)

	id, err := CgroupID(dir)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	t.Logf("target cgroup id = %d", id)

	const trueBin = "/bin/true"
	trueInode, err := InodeOf(trueBin)
	if err != nil {
		t.Fatalf("inode of %s: %v", trueBin, err)
	}

	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretInode, err := InodeOf(secret)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Attach(caps, object)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer s.Close()

	// ---- disarmed: nothing denied ----
	if _, err := runIn(dir, trueBin); err != nil {
		t.Fatalf("disarmed: exec should succeed inside the cgroup: %v", err)
	}
	if _, err := runOutside(trueBin); err != nil {
		t.Fatalf("disarmed: exec should succeed outside the cgroup: %v", err)
	}

	if err := s.Arm(id); err != nil {
		t.Fatalf("arm: %v", err)
	}

	// ---- file-granular exec denial ----
	if err := s.DenyExecInode(trueInode); err != nil {
		t.Fatalf("deny exec inode: %v", err)
	}
	if _, err := runIn(dir, trueBin); err == nil {
		t.Fatal("armed: exec of the denied inode should be blocked inside the cgroup")
	} else {
		t.Logf("exec denied inside the cgroup as expected: %v", err)
	}
	if _, err := runOutside(trueBin); err != nil {
		t.Fatalf("armed: a process outside the cgroup must be unaffected: %v", err)
	}
	if err := s.DenyExecInode(0); err != nil {
		t.Fatal(err)
	}
	if _, err := runIn(dir, trueBin); err != nil {
		t.Fatalf("exec should work again after clearing the deny: %v", err)
	}
	t.Log("exec denial works and is cgroup-scoped")

	// ---- path-based file denial ----
	if err := s.DenyFileInode(secretInode); err != nil {
		t.Fatalf("deny file inode: %v", err)
	}
	if _, err := runIn(dir, "cat "+secret); err == nil {
		t.Fatal("armed: opening the denied file should be blocked inside the cgroup")
	} else {
		t.Logf("file open denied inside the cgroup as expected: %v", err)
	}
	if _, err := runOutside("cat " + secret); err != nil {
		t.Fatalf("armed: the file must be readable outside the cgroup: %v", err)
	}
	if err := s.DenyFileInode(0); err != nil {
		t.Fatal(err)
	}
	if _, err := runIn(dir, "cat "+secret); err != nil {
		t.Fatalf("file should be readable again after clearing the deny: %v", err)
	}
	t.Log("file denial works and is cgroup-scoped")

	// ---- egress denial ----
	ip := binary.LittleEndian.Uint32([]byte{127, 0, 0, 1})
	if err := s.BlockConnect(ip, 9); err != nil {
		t.Fatalf("block connect: %v", err)
	}
	out, err := runIn(dir, `/usr/bin/bash -c 'echo > /dev/tcp/127.0.0.1/9'`)
	if err == nil || !strings.Contains(out, "Operation not permitted") {
		t.Fatalf("armed: connect should be denied with EPERM, got err=%v out=%q", err, out)
	}
	t.Logf("connect denied inside the cgroup as expected: %s", strings.TrimSpace(out))
	out, _ = runOutside(`/usr/bin/bash -c 'echo > /dev/tcp/127.0.0.1/9'`)
	if strings.Contains(out, "Operation not permitted") {
		t.Fatalf("armed: a connect outside the cgroup must not be denied: %q", out)
	}
	if err := s.BlockConnect(0, 0); err != nil {
		t.Fatal(err)
	}
	t.Log("egress denial works and is cgroup-scoped")

	// ---- capability denial ----
	if err := s.DenyCapability(21); err != nil { // CAP_SYS_ADMIN
		t.Fatalf("deny capability: %v", err)
	}
	if _, err := runIn(dir, "/usr/bin/unshare -m true"); err == nil {
		t.Fatal("armed: unshare(CLONE_NEWNS) should be denied inside the cgroup")
	} else {
		t.Logf("capability denied inside the cgroup as expected: %v", err)
	}
	if _, err := runOutside("/usr/bin/unshare -m true"); err != nil {
		t.Fatalf("armed: another cgroup must be unaffected: %v", err)
	}
	if err := s.DenyCapability(0); err != nil {
		t.Fatal(err)
	}
	if _, err := runIn(dir, "/usr/bin/unshare -m true"); err != nil {
		t.Fatalf("capability should work again after clearing the deny: %v", err)
	}
	t.Log("capability denial works and is cgroup-scoped")

	// ---- no-workload-kill ----
	workload := exec.Command("/bin/sh", "-c", fmt.Sprintf("echo $$ > %s/cgroup.procs && exec sleep 5", dir))
	if err := workload.Start(); err != nil {
		t.Fatalf("start workload: %v", err)
	}
	defer workload.Process.Kill()
	time.Sleep(100 * time.Millisecond)
	if err := workload.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("workload was killed while armed: %v", err)
	}
	t.Log("a running workload stays alive while enforcement is armed")

	// ---- disarm restores everything ----
	if err := s.Disarm(); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	if _, err := runIn(dir, trueBin); err != nil {
		t.Fatalf("disarmed: exec should succeed: %v", err)
	}
	t.Log("disarm restores behavior")
}

func runIn(cgroupDir, command string) (string, error) {
	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec %s", cgroupDir, command)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, string(out))
	}
	return string(out), nil
}

func runOutside(command string) (string, error) {
	out, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%v: %s", err, string(out))
	}
	return string(out), nil
}
