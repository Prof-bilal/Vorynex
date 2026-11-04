//go:build !linux

package live

import "fmt"

func attachObject(string) (Session, error) {
	return nil, &UnavailableError{Reasons: []string{"Tier 1 is Linux-only"}}
}

// CgroupID is Linux-only.
func CgroupID(string) (uint64, error) {
	return 0, fmt.Errorf("tier 1 is Linux-only")
}
