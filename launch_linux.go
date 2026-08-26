//go:build linux

package main

import (
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
