package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

func cmdUp(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}

	image := os.Getenv("AGENTGUARD_IMAGE")
	if image == "" {
		image = "ghcr.io/shuklapramath/agentguard:latest"
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	docker, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("docker not on PATH")
	}

	info := exec.Command(docker, "info")
	info.Stdout = io.Discard
	info.Stderr = io.Discard
	if err := info.Run(); err != nil {
		return fmt.Errorf("docker is not usable (%v)\nStart Docker or Colima, then retry. Use sudo if the docker socket is root-only.", err)
	}

	policy := filepath.Join(cwd, "policies", "default.yaml")
	st, err := os.Stat(policy)
	if err != nil {
		return fmt.Errorf("missing %s; run: agentguard init", policy)
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory; run: agentguard init", policy)
	}

	localDir, claudeDir, err := ensureUpRuntimeDirs()
	if err != nil {
		return err
	}

	key, err := readAnthropicAPIKey()
	if err != nil {
		return err
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
		"-v", localDir + ":/home/ubuntu/.local",
		"-v", claudeDir + ":/home/ubuntu/.claude",
		"-w", "/workspace",
		"-e", "AGENTGUARD_POLICY=/workspace/policies/default.yaml",
	}
	if key != "" {
		args = append(args, "-e", "ANTHROPIC_API_KEY="+key)
	}
	args = append(args, image, "bash")

	cmd := exec.Command(docker, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
