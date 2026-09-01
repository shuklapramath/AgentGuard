//go:build linux

package main

import (
	"fmt"
	"os/exec"
	"syscall"
)

func setChildCredential(cmd *exec.Cmd, id *launchIdentity) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    id.Uid,
			Gid:    id.Gid,
			Groups: id.Groups,
		},
	}
}

func enableChildPtrace(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true
}

func waitChildPtraceStop(pid int) error {
	var ws syscall.WaitStatus
	for {
		_, err := syscall.Wait4(pid, &ws, 0, nil)
		if err != nil {
			return fmt.Errorf("wait ptrace stop: %w", err)
		}
		if ws.Stopped() {
			return nil
		}
		if ws.Exited() || ws.Signaled() {
			return fmt.Errorf("child exited before ptrace stop: status=%v", ws)
		}
	}
}

func detachChildPtrace(pid int) error {
	if err := syscall.PtraceDetach(pid); err != nil {
		return fmt.Errorf("ptrace detach: %w", err)
	}
	return nil
}
