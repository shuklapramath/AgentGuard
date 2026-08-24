package main

import (
	"os"
	"path/filepath"
)

const defaultStateDir = "/tmp/agentguard"

var (
	agentGuardLogDir  string
	agentGuardLogPath string
	violationStoreDir string
	activeSessionPath string
	agentGuardDBPath  string
)

// initStateDirs sets IPC/log/db paths from AGENTGUARD_STATE_DIR.
// Must run at the start of main so hook and enforcer use the same root.
func initStateDirs() {
	root := os.Getenv("AGENTGUARD_STATE_DIR")
	if root == "" {
		root = defaultStateDir
	}
	root = filepath.Clean(root)

	agentGuardLogDir = root
	agentGuardLogPath = filepath.Join(root, "agentguard.log")
	violationStoreDir = filepath.Join(root, "violations")
	activeSessionPath = filepath.Join(root, "active_session")
	agentGuardDBPath = filepath.Join(root, "agentguard.db")
}
