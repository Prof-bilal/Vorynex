//go:build integration && linux

package live

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

// TestLSMCapabilityEnforcement validates the live tier end to end. It requires
// root and a compiled BPF object:
//
//	sudo -E go test -tags integration -run TestLSMCapability -v ./engine/enforce/live/
//
// Safety: the program is attached DISARMED and only ever armed for a dedicated
// test cgroup. A process outside that cgroup must be unaffected while armed.
func TestLSMCapabilityEnforcement(t *testing.T) {
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

	const capSysAdmin = 21

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

	s, err := Attach(caps, object)
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	defer s.Close()

	// Disarmed: capability checks are unaffected inside and outside the cgroup.
	if err := unshareIn(dir); err != nil {
		t.Fatalf("disarmed: unshare should succeed inside the cgroup: %v", err)
	}
	if err := unshareOutside(); err != nil {
		t.Fatalf("disarmed: unshare should succeed outside the cgroup: %v", err)
	}

	// Armed: CAP_SYS_ADMIN is denied for the target cgroup only.
	if err := s.Arm(id, capSysAdmin); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if err := unshareIn(dir); err == nil {
		t.Fatal("armed: unshare should have been denied in the target cgroup")
	} else {
		t.Logf("armed: denied as expected: %v", err)
	}
	if err := unshareOutside(); err != nil {
		t.Fatalf("armed: a process outside the cgroup must be unaffected: %v", err)
	}

	// Disarmed: enforcement stops.
	if err := s.Disarm(); err != nil {
		t.Fatalf("disarm: %v", err)
	}
	if err := unshareIn(dir); err != nil {
		t.Fatalf("disarmed: unshare should succeed again: %v", err)
	}
}

func unshareIn(cgroupDir string) error {
	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec /usr/bin/unshare -m true", cgroupDir)
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}

func unshareOutside() error {
	out, err := exec.Command("/usr/bin/unshare", "-m", "true").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(out))
	}
	return nil
}
