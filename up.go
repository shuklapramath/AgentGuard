package main

import (
	"fmt"
	"os"
	"os/exec"
)

func cmdUp(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}

	image := os.Getenv("AGENTGUARD_IMAGE")
	if image == "" {
		image = "agentguard:runtime"
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not on PATH")
	}

	args := []string{
		"run", "-it", "--rm",
		"--privileged",
		"--cap-add=CAP_BPF",
		"--cap-add=CAP_PERFMON",
		"--cap-add=CAP_SYS_ADMIN",
		"--cap-add=CAP_NET_ADMIN",
		"-v", cwd + ":/workspace",
		"-v", "/sys/kernel/btf:/sys/kernel/btf:ro",
		"-v", "/sys/kernel/debug:/sys/kernel/debug",
		"-w", "/workspace",
		"-e", "AGENTGUARD_POLICY=/workspace/policies/default.yaml",
		image,
		"bash",
	}

	cmd := exec.Command(docker, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
