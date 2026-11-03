//go:build linux

package spawntime

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// interpreterDirs returns the directories that must be granted EXECUTE so that
// path's ELF interpreter can run.
//
// This matters for Landlock: executing a dynamically linked binary requires
// EXECUTE on the binary *and* on its interpreter (e.g.
// /lib64/ld-linux-x86-64.so.2). Granting EXECUTE only on the binary's own
// directory leaves the interpreter non-executable and execve fails with EACCES.
//
// The interpreter path is often a symlink chain (on Ubuntu
// /lib64/ld-linux-x86-64.so.2 is a symlink into /usr/lib/x86_64-linux-gnu), and
// Landlock rules match the resolved hierarchy, so we grant both the literal
// directory and the symlink-resolved directory.
func interpreterDirs(path string) []string {
	interp := interpreterPath(path)
	if interp == "" {
		return nil
	}
	dirs := []string{filepath.Dir(interp)}
	if real, err := filepath.EvalSymlinks(interp); err == nil {
		if d := filepath.Dir(real); d != dirs[0] {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// interpreterPath returns the ELF program interpreter (PT_INTERP) string for
// path, or "" if it cannot be determined (e.g. a static binary).
func interpreterPath(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	hdr := make([]byte, 64)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return ""
	}
	if string(hdr[0:4]) != "\x7fELF" || hdr[4] != 2 { // 64-bit only
		return ""
	}
	phoff := int64(binary.LittleEndian.Uint64(hdr[32:40]))
	phentsize := int(binary.LittleEndian.Uint16(hdr[54:56]))
	phnum := int(binary.LittleEndian.Uint16(hdr[56:58]))
	if phentsize < 56 || phnum <= 0 || phnum > 512 {
		return ""
	}
	for i := 0; i < phnum; i++ {
		ph := make([]byte, phentsize)
		if _, err := f.ReadAt(ph, phoff+int64(i*phentsize)); err != nil {
			return ""
		}
		if binary.LittleEndian.Uint32(ph[0:4]) != 3 { // PT_INTERP
			continue
		}
		off := binary.LittleEndian.Uint64(ph[8:16])
		size := binary.LittleEndian.Uint64(ph[32:40])
		if size == 0 || size > 4096 {
			return ""
		}
		buf := make([]byte, size)
		if _, err := f.ReadAt(buf, int64(off)); err != nil {
			return ""
		}
		interp := strings.TrimRight(string(buf), "\x00")
		if !filepath.IsAbs(interp) {
			return ""
		}
		return interp
	}
	return ""
}
