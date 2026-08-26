//go:build !linux

package main

import "os/exec"

func setChildCredential(_ *exec.Cmd, _ *launchIdentity) {
	// eBPF launch is Linux-only; identity drop is a no-op elsewhere.
}
