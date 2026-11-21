package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// BroadGrant describes an exec allow entry that the Tier 0 backend cannot
// enforce at the granularity the policy states. Landlock grants EXECUTE per
// directory, so allowing /usr/bin/ping also allows every other executable in
// /usr/bin (including sh). Others lists what else becomes runnable.
type BroadGrant struct {
	Allow  string
	Dir    string
	Others []string
}

func (b BroadGrant) Error() string {
	shown := b.Others
	more := ""
	if len(shown) > 5 {
		shown, more = shown[:5], fmt.Sprintf(" and %d more", len(b.Others)-5)
	}
	return fmt.Sprintf("process.exec.allow %q cannot be enforced per file by Tier 0 (Landlock grants execute per directory): "+
		"it would also make %d other executables in %s runnable (%s%s). "+
		"Put the binary in a directory that contains only it, or set VORYNEX_ACCEPT_BROAD_EXEC=1 to accept the wider grant knowingly",
		b.Allow, len(b.Others), b.Dir, strings.Join(shown, ", "), more)
}

// BroadExecGrants returns every allow entry whose directory also contains other
// executables. launch is the workload's own binary: its directory is always
// granted, so it is exempt. Entries that are also denied are ignored.
func BroadExecGrants(launch string, allow, deny []string) []BroadGrant {
	var out []BroadGrant
	launchDir := filepath.Dir(launch)
	for _, a := range allow {
		dir := filepath.Dir(a)
		if dir == launchDir || contains(deny, a) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		var others []string
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if full == a {
				continue
			}
			// Stat follows symlinks: a link to an executable is executable.
			if info, err := os.Stat(full); err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 {
				others = append(others, full)
			}
		}
		if len(others) > 0 {
			sort.Strings(others)
			out = append(out, BroadGrant{Allow: a, Dir: dir, Others: others})
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
