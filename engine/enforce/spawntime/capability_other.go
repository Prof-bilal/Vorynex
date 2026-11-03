//go:build !linux

package spawntime

// LandlockABI reports 0: Landlock is a Linux feature.
func LandlockABI() int { return 0 }
