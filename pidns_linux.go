//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func currentPidns() (dev, ino uint64, err error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, 0, fmt.Errorf("stat /proc/self/ns/pid: %w", err)
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}
