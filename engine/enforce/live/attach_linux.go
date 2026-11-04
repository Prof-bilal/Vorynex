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

var programs = []string{"deny_cap", "deny_exec", "deny_open", "deny_connect"}

type session struct {
	coll        *ebpf.Collection
	links       []link.Link
	armed       *ebpf.Map
	target      *ebpf.Map
	deniedCap   *ebpf.Map
	deniedInode *ebpf.Map
	deniedFile  *ebpf.Map
	blockedIP   *ebpf.Map
	blockedPort *ebpf.Map
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

	s := &session{
		coll:        coll,
		armed:       coll.Maps["armed"],
		target:      coll.Maps["target_cgroup"],
		deniedCap:   coll.Maps["denied_cap"],
		deniedInode: coll.Maps["denied_inode"],
		deniedFile:  coll.Maps["denied_file_inode"],
		blockedIP:   coll.Maps["blocked_ip"],
		blockedPort: coll.Maps["blocked_port"],
	}
	if s.armed == nil || s.target == nil || s.deniedCap == nil || s.deniedInode == nil ||
		s.deniedFile == nil || s.blockedIP == nil || s.blockedPort == nil {
		coll.Close()
		return nil, fmt.Errorf("required maps missing from %s", path)
	}

	for _, name := range programs {
		prog := coll.Programs[name]
		if prog == nil {
			s.Close()
			return nil, fmt.Errorf("program %s not found in %s", name, path)
		}
		l, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("attach %s: %w", name, err)
		}
		s.links = append(s.links, l)
	}
	return s, nil
}

func (s *session) Arm(cgroupID uint64) error {
	if err := s.target.Put(uint32(0), cgroupID); err != nil {
		return fmt.Errorf("set target cgroup: %w", err)
	}
	if err := s.armed.Put(uint32(0), uint64(1)); err != nil {
		return fmt.Errorf("arm: %w", err)
	}
	return nil
}

func (s *session) DenyCapability(capability int) error {
	return s.deniedCap.Put(uint32(0), uint32(capability))
}

func (s *session) DenyExecInode(inode uint64) error {
	return s.deniedInode.Put(uint32(0), inode)
}

func (s *session) DenyFileInode(inode uint64) error {
	return s.deniedFile.Put(uint32(0), inode)
}

func (s *session) BlockConnect(ip uint32, port uint16) error {
	if err := s.blockedIP.Put(uint32(0), ip); err != nil {
		return fmt.Errorf("set blocked ip: %w", err)
	}
	if err := s.blockedPort.Put(uint32(0), uint32(port)); err != nil {
		return fmt.Errorf("set blocked port: %w", err)
	}
	return nil
}

func (s *session) Disarm() error {
	return s.armed.Put(uint32(0), uint64(0))
}

func (s *session) Close() error {
	for _, l := range s.links {
		l.Close()
	}
	if s.coll != nil {
		s.coll.Close()
	}
	return nil
}

// InodeOf returns the inode number of path.
func InodeOf(path string) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return st.Ino, nil
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
