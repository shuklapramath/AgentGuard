package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func agentGuardHostDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".agentguard"), nil
}

func ensureUpRuntimeDirs() (localDir, claudeDir string, err error) {
	root, err := agentGuardHostDir()
	if err != nil {
		return "", "", err
	}
	localDir = filepath.Join(root, "runtime", ".local")
	claudeDir = filepath.Join(root, "runtime", ".claude")
	if err := os.MkdirAll(localDir, 0755); err != nil {
		return "", "", fmt.Errorf("create %s: %w", localDir, err)
	}
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		return "", "", fmt.Errorf("create %s: %w", claudeDir, err)
	}
	return localDir, claudeDir, nil
}

func anthropicKeyPath() (string, error) {
	root, err := agentGuardHostDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "anthropic_key"), nil
}

func readAnthropicAPIKey() (string, error) {
	if v := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")); v != "" {
		return v, nil
	}
	path, err := anthropicKeyPath()
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	key := strings.TrimSpace(string(b))
	if key == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return key, nil
}

func writeAnthropicAPIKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("empty key")
	}
	root, err := agentGuardHostDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return fmt.Errorf("create %s: %w", root, err)
	}
	path := filepath.Join(root, "anthropic_key")
	if err := os.WriteFile(path, []byte(key+"\n"), 0600); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	_ = os.Chmod(path, 0600)
	return nil
}
