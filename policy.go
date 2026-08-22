package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	_ "embed"
)

//go:embed policies/default.yaml.example
var defaultPolicyTemplate []byte

// policyFlag is set by parseAgentGuardArgs from --policy / --policy=.
var policyFlag string

// apiPolicyPath is the absolute policy path chosen at startup (for /api/policies).
var apiPolicyPath string

var policySearchNames = []string{
	"policies/default.yaml",
	".agentguard/default.yaml",
}

// resolvePolicyPath finds or creates the policy file.
//
// Order:
//  1. explicit (--policy) — must exist; never auto-create
//  2. AGENTGUARD_POLICY — must exist; never auto-create
//  3. walk cwd upward for policies/default.yaml or .agentguard/default.yaml
//  4. create ./policies/default.yaml from the embedded starter
func resolvePolicyPath(explicit string) (path string, created bool, err error) {
	if explicit != "" {
		abs, err := filepath.Abs(explicit)
		if err != nil {
			return "", false, fmt.Errorf("resolve --policy path: %w", err)
		}
		if err := requireRegularFile(abs); err != nil {
			return "", false, fmt.Errorf("policy file not found: %s (from --policy): %w", abs, err)
		}
		return abs, false, nil
	}

	if env := os.Getenv("AGENTGUARD_POLICY"); env != "" {
		abs, err := filepath.Abs(env)
		if err != nil {
			return "", false, fmt.Errorf("resolve AGENTGUARD_POLICY: %w", err)
		}
		if err := requireRegularFile(abs); err != nil {
			return "", false, fmt.Errorf("policy file not found: %s (from AGENTGUARD_POLICY): %w", abs, err)
		}
		return abs, false, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", false, fmt.Errorf("get working directory: %w", err)
	}
	start, err := filepath.Abs(cwd)
	if err != nil {
		return "", false, fmt.Errorf("resolve working directory: %w", err)
	}

	if found, ok := findPolicyWalkingUp(start); ok {
		return found, false, nil
	}

	createdPath, err := createStarterPolicy(start)
	if err != nil {
		return "", false, err
	}
	return createdPath, true, nil
}

func requireRegularFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.IsDir() {
		return errors.New("path is a directory")
	}
	return nil
}

func findPolicyWalkingUp(start string) (string, bool) {
	dir := start
	for {
		for _, rel := range policySearchNames {
			candidate := filepath.Join(dir, rel)
			if err := requireRegularFile(candidate); err == nil {
				return candidate, true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// createStarterPolicy writes cwd/policies/default.yaml from the embedded template.
// Never overwrites an existing file.
func createStarterPolicy(cwd string) (string, error) {
	dir := filepath.Join(cwd, "policies")
	path := filepath.Join(dir, "default.yaml")

	if err := requireRegularFile(path); err == nil {
		return path, nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create policies directory: %w", err)
	}
	chownToSudoUser(dir)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return path, nil
		}
		return "", fmt.Errorf("create policy file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(defaultPolicyTemplate); err != nil {
		return "", fmt.Errorf("write policy file: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close policy file: %w", err)
	}

	chownToSudoUser(path)
	return path, nil
}

func chownToSudoUser(path string) {
	uidStr := os.Getenv("SUDO_UID")
	gidStr := os.Getenv("SUDO_GID")
	if uidStr == "" || gidStr == "" {
		return
	}
	uid, err1 := strconv.Atoi(uidStr)
	gid, err2 := strconv.Atoi(gidStr)
	if err1 != nil || err2 != nil {
		return
	}
	_ = os.Chown(path, uid, gid)
}