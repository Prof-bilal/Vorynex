//go:build !linux

package spawntime

import (
	"fmt"

	"github.com/vorynex/vorynex/engine/policy"
)

// Run is unavailable off Linux: Tier 0 enforcement uses Landlock (and, later,
// seccomp), which are Linux primitives. Vorynex fails closed rather than
// launch a workload unprotected.
func Run(cmd []string, p policy.Policy) error {
	return fmt.Errorf("spawntime: Tier 0 enforcement is Linux-only in this build")
}
