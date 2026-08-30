//go:build !linux

package main

import "fmt"

func currentPidns() (dev, ino uint64, err error) {
	return 0, 0, fmt.Errorf("pid ns: linux only")
}
