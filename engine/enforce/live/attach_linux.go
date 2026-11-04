//go:build linux

package live

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type session struct {
	coll   *ebpf.Collection
	lnk    link.Link
	armed  *ebpf.Map
	target *ebpf.Map
	denied *ebpf.Map
}

func attachObject(path string) (Session, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load BPF object %s: %w", path, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create BPF collection (need CAP_BPF/CAP_PERFMON): %w", err)
	}

	prog := coll.Programs["deny_cap"]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program deny_cap not found in %s", path)
	}
	lnk, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attach LSM program: %w", err)
	}

	s := &session{
		coll:   coll,
		lnk:    lnk,
		armed:  coll.Maps["armed"],
		target: coll.Maps["target_cgroup"],
		denied: coll.Maps["denied_cap"],
	}
	if s.armed == nil || s.target == nil || s.denied == nil {
		s.Close()
		return nil, fmt.Errorf("required maps missing from %s", path)
	}
	return s, nil
}

// Arm targets cgroupID and denies capability for it. The program is inert for
// every other cgroup.
func (s *session) Arm(cgroupID uint64, capability int) error {
	if err := s.target.Put(uint32(0), cgroupID); err != nil {
		return fmt.Errorf("set target cgroup: %w", err)
	}
	if err := s.denied.Put(uint32(0), uint32(capability)); err != nil {
		return fmt.Errorf("set denied capability: %w", err)
	}
	if err := s.armed.Put(uint32(0), uint64(1)); err != nil {
		return fmt.Errorf("arm: %w", err)
	}
	return nil
}

func (s *session) Disarm() error {
	return s.armed.Put(uint32(0), uint64(0))
}

func (s *session) Close() error {
	if s.lnk != nil {
		s.lnk.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

// CgroupID returns the id that bpf_get_current_cgroup_id() reports for a cgroup
// directory. cgroup v2 exposes it as cgroup.id on newer kernels; otherwise the
// kernfs file handle carries it (first 8 bytes, little-endian).
func CgroupID(path string) (uint64, error) {
	if b, err := os.ReadFile(filepath.Join(path, "cgroup.id")); err == nil {
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			return v, nil
		}
	}
	h, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, fmt.Errorf("get cgroup id for %s: %w", path, err)
	}
	b := h.Bytes()
	if len(b) < 8 {
		return 0, fmt.Errorf("cgroup handle for %s is %d bytes, want >= 8", path, len(b))
	}
	return binary.LittleEndian.Uint64(b[:8]), nil
}
