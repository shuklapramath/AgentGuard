//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	securityfsDir     = "/sys/kernel/security"
	securityfsLSMPath = "/sys/kernel/security/lsm"
)

func lsmFileReadable() bool {
	f, err := os.Open(securityfsLSMPath)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

// ensureSecurityfs mounts securityfs if /sys/kernel/security/lsm is not readable.
// Does not enable BPF LSM. EBUSY = already mounted.
func ensureSecurityfs() error {
	if lsmFileReadable() {
		return nil
	}
	if err := os.MkdirAll(securityfsDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", securityfsDir, err)
	}
	err := unix.Mount("securityfs", securityfsDir, "securityfs", 0, "")
	if err != nil && err != unix.EBUSY {
		return fmt.Errorf("mount securityfs: %w", err)
	}
	if !lsmFileReadable() {
		return fmt.Errorf("securityfs unmounted: %s still not readable", securityfsLSMPath)
	}
	return nil
}
