//go:build linux

package spawntime

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock filesystem access rights (uapi/linux/landlock.h). Bits above the
// running kernel's ABI must not be set in handled_access_fs, or the ruleset
// is rejected; see fsMaskFor.
const (
	accExecute    uint64 = 1 << 0
	accWriteFile  uint64 = 1 << 1
	accReadFile   uint64 = 1 << 2
	accReadDir    uint64 = 1 << 3
	accRemoveDir  uint64 = 1 << 4
	accRemoveFile uint64 = 1 << 5
	accMakeChar   uint64 = 1 << 6
	accMakeDir    uint64 = 1 << 7
	accMakeReg    uint64 = 1 << 8
	accMakeSock   uint64 = 1 << 9
	accMakeFifo   uint64 = 1 << 10
	accMakeBlock  uint64 = 1 << 11
	accMakeSym    uint64 = 1 << 12
	accRefer      uint64 = 1 << 13 // ABI >= 2
	accTruncate   uint64 = 1 << 14 // ABI >= 3
)

// Landlock network access rights.
const accNetConnectTCP uint64 = 1 << 0 // ABI >= 4

const (
	ruleTypePathBeneath uint32 = 1
	ruleTypeNetPort     uint32 = 2
	createRulesetVer    uint32 = 1 // LANDLOCK_CREATE_RULESET_VERSION
)

// LandlockABI reports the kernel's Landlock ABI version, or 0 if Landlock is
// unavailable. It is used by `vorynex doctor` and capability gating.
func LandlockABI() int {
	abi, err := landlockABI()
	if err != nil {
		return 0
	}
	return abi
}

// landlockABI returns the kernel's Landlock ABI version, or an error if
// Landlock is unavailable.
func landlockABI() (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, uintptr(createRulesetVer))
	if errno != 0 {
		return 0, fmt.Errorf("landlock unavailable (need kernel 5.13+ with CONFIG_SECURITY_LANDLOCK): %w", errno)
	}
	return int(r), nil
}

// fsMaskFor returns the set of filesystem access rights this shim handles for
// a given ABI. Any handled right that no rule grants is denied.
func fsMaskFor(abi int) uint64 {
	mask := accExecute | accWriteFile | accReadFile | accReadDir |
		accRemoveDir | accRemoveFile | accMakeChar | accMakeDir |
		accMakeReg | accMakeSock | accMakeFifo | accMakeBlock | accMakeSym
	if abi >= 2 {
		mask |= accRefer
	}
	if abi >= 3 {
		mask |= accTruncate
	}
	return mask
}

func landlockCreateRuleset(attr unsafe.Pointer, size uintptr, flags uint32) (int, error) {
	r, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(attr), size, uintptr(flags))
	if errno != 0 {
		return -1, errno
	}
	return int(r), nil
}

// landlockAddRule adds a rule. Note the syscall signature is
// (ruleset_fd, rule_type, rule_attr, flags) — there is no size argument; the
// attribute size is implied by rule_type.
func landlockAddRule(fd int, ruleType uint32, attr unsafe.Pointer) error {
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(fd), uintptr(ruleType), uintptr(attr), 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func landlockRestrictSelf(fd int) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(fd), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// addPathRule grants access on path (recursively, via LANDLOCK_RULE_PATH_BENEATH).
func addPathRule(rulesetFD int, path string, access uint64) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	// Landlock rejects READ_DIR on a non-directory, so drop it for files.
	if !info.IsDir() {
		access &^= accReadDir
	}

	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer unix.Close(fd)

	// struct landlock_path_beneath_attr is packed: u64 allowed_access, s32 parent_fd.
	var attr [12]byte
	binary.NativeEndian.PutUint64(attr[0:8], access)
	binary.NativeEndian.PutUint32(attr[8:12], uint32(fd))
	if err := landlockAddRule(rulesetFD, ruleTypePathBeneath, unsafe.Pointer(&attr[0])); err != nil {
		return fmt.Errorf("add landlock rule for %q: %w", path, err)
	}
	return nil
}
