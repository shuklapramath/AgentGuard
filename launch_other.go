//go:build !linux

package main

import "os/exec"

func setChildCredential(_ *exec.Cmd, _ *launchIdentity) {
	// eBPF launch is Linux-only; identity drop is a no-op elsewhere.
}

func enableChildPtrace(_ *exec.Cmd) {}

func waitChildPtraceStop(_ int) error { return nil }

func detachChildPtrace(_ int) error { return nil }
