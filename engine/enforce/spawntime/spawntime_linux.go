//go:build linux

// Package spawntime implements Vorynex's Tier 0 enforcement: a workload is
// launched under a kernel-enforced least-privilege boundary (Landlock) that
// restricts filesystem access, executable spawning, and outbound TCP. Unlike
// bubblewrap it needs no privileges and works inside a container, which is why
// it is the default spawn-time primitive.
//
// The boundary is applied to the current thread (Landlock is per-thread and
// inherited across fork/exec), then the process is replaced by the workload.
// Everything the workload subsequently does is confined, including any child
// process it spawns.
package spawntime

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/vorynex/vorynex/engine/envfilter"
	"github.com/vorynex/vorynex/engine/policy"
)

// readOnlyRuntime are the system trees a dynamically linked workload needs to
// read. Note they are deliberately *subdirectories*, never /usr or /bin: a
// Landlock rule on a directory is inherited by everything beneath it, and a
// directory rule that lacks EXECUTE blocks execution for its whole subtree. A
// rule on /usr would therefore make every binary under /usr unexecutable,
// including the workload's own runtime.
var readOnlyRuntime = []string{"/usr/lib", "/usr/lib64", "/usr/share", "/lib", "/lib64", "/etc", "/proc"}

// Run applies the policy's runtime boundary and then replaces the current
// process with cmd. cmd[0] must exist; it is resolved via LookPath.
func Run(cmd []string, p policy.Policy) error {
	if len(cmd) == 0 {
		return fmt.Errorf("spawntime: no command")
	}
	abs, err := exec.LookPath(cmd[0])
	if err != nil {
		return fmt.Errorf("spawntime: resolve %q: %w", cmd[0], err)
	}
	abs, err = absPath(abs)
	if err != nil {
		return err
	}
	argv := append([]string{abs}, cmd[1:]...)

	// Landlock and no_new_privs are per-thread; pin this goroutine's OS thread
	// and exec from it so the workload inherits the boundary.
	runtime.LockOSThread()
	if err := restrict(p, abs); err != nil {
		return err
	}

	env := os.Environ()
	if len(p.Env.Allow) > 0 {
		env = envfilter.FilterDenied(env, p.EnvAllowlist(), p.EnvDenylist())
	}
	return syscall.Exec(abs, argv, env)
}

func absPath(path string) (string, error) {
	if path == "" || path[0] == '/' {
		return path, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return wd + "/" + path, nil
}

// restrict builds and applies the Landlock ruleset. It must be called on a
// locked OS thread.
func restrict(p policy.Policy, exePath string) error {
	abi, err := landlockABI()
	if err != nil {
		return err
	}
	if abi < 1 {
		return fmt.Errorf("spawntime: landlock ABI %d is unsupported", abi)
	}

	fsMask := fsMaskFor(abi)
	netMask := uint64(0)
	if abi >= 4 {
		// Handle TCP connect so every outbound connection is denied unless a
		// rule allows the port. No port rules are added yet, so all outbound
		// TCP is denied. (Host-based allowlisting is a later milestone.)
		netMask = accNetConnectTCP
	}

	var attr []byte
	if netMask != 0 {
		attr = make([]byte, 16)
		binary.NativeEndian.PutUint64(attr[0:8], fsMask)
		binary.NativeEndian.PutUint64(attr[8:16], netMask)
	} else {
		attr = make([]byte, 8)
		binary.NativeEndian.PutUint64(attr[0:8], fsMask)
	}

	fd, err := landlockCreateRuleset(unsafe.Pointer(&attr[0]), uintptr(len(attr)), 0)
	if err != nil {
		return fmt.Errorf("spawntime: create landlock ruleset: %w", err)
	}
	defer unix.Close(fd)

	read := accReadFile | accReadDir
	write := read | accWriteFile | accRemoveFile | accRemoveDir |
		accMakeReg | accMakeDir | accMakeSym | accMakeFifo | accMakeSock
	if abi >= 2 {
		write |= accRefer
	}
	if abi >= 3 {
		write |= accTruncate
	}

	for _, dir := range readOnlyRuntime {
		if isDir(dir) {
			if err := addPathRule(fd, dir, read); err != nil {
				return err
			}
		}
	}
	if isDir("/dev") {
		if err := addPathRule(fd, "/dev", read|accWriteFile); err != nil {
			return err
		}
	}

	for _, path := range p.Filesystem.Read {
		if err := addPathRule(fd, path, read); err != nil {
			return err
		}
	}
	for _, path := range p.Filesystem.Write {
		if err := addPathRule(fd, path, write); err != nil {
			return err
		}
	}

	// Executable control: grant READ|EXECUTE on the workload's directory AND on
	// its ELF interpreter's directory (e.g. /lib64). Executing a dynamically
	// linked binary requires EXECUTE on both; granting only the binary's own
	// directory leaves the interpreter non-executable and execve fails EACCES.
	// Everything else stays non-executable, so shells and system binaries that
	// live elsewhere cannot be run.
	for _, dir := range execDirs(exePath, p.Process.Exec.Allow, p.Process.Exec.Deny) {
		if err := addPathRule(fd, dir, read|accExecute); err != nil {
			return err
		}
	}

	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("spawntime: set no_new_privs: %w", err)
	}
	if err := landlockRestrictSelf(fd); err != nil {
		return fmt.Errorf("spawntime: enforce landlock ruleset: %w", err)
	}
	return nil
}

// execDirs returns the directories whose EXECUTE grant makes a binary runnable:
// the binary's own directory AND the directory of its ELF interpreter, because
// executing a dynamically linked binary requires EXECUTE on both. The root
// directory is skipped (granting EXECUTE on "/" would make everything
// executable).
func execDirs(exePath string, allow, deny []string) []string {
	seen := make(map[string]bool)
	var out []string
	addDir := func(d string) {
		if d == "" || d == "/" || d == "." || seen[d] {
			return
		}
		seen[d] = true
		out = append(out, d)
	}
	addBin := func(p string) {
		addDir(filepath.Dir(p))
		for _, d := range interpreterDirs(p) {
			addDir(d)
		}
	}
	addBin(exePath)
	for _, a := range allow {
		if !isDenied(a, deny) {
			addBin(a)
		}
	}
	return out
}

func isDenied(path string, deny []string) bool {
	for _, d := range deny {
		if d == path {
			return true
		}
	}
	return false
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
