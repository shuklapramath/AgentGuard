package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const agentGuardVersion = "0.1.0"

// parseAgentGuardArgs strips global flags from os.Args and returns a slice
// shaped like os.Args (argv[0] = program name) for launch/attach parsing.
//
// Supported globals:
//
//	--verbose / -v
//	--policy PATH
//	--policy=PATH
//	-h / --help  (rewritten as the "help" command)
func parseAgentGuardArgs() []string {
	out := make([]string, 0, len(os.Args))
	out = append(out, os.Args[0])

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--verbose" || a == "-v":
			verbose = true

		case a == "--policy":
			if i+1 >= len(args) {
				log.Fatal("--policy requires a file path")
			}
			policyFlag = args[i+1]
			i++

		case strings.HasPrefix(a, "--policy="):
			policyFlag = strings.TrimPrefix(a, "--policy=")
			if policyFlag == "" {
				log.Fatal("--policy requires a file path")
			}

		case a == "-h" || a == "--help":
			out = append(out, "help")

		default:
			out = append(out, a)
		}
	}
	return out
}

// dispatchCLI handles light commands that must not load BPF or require root.
// Returns true if main should return (command fully handled).
// Returns false to fall through to runEnforcer.
func dispatchCLI(args []string) bool {
	if len(args) < 2 {
		return false
	}
	cmd := args[1]
	rest := args[2:]

	switch cmd {
	case "help":
		printUsage()
		return true

	case "version":
		fmt.Printf("agentguard %s\n", agentGuardVersion)
		return true

	case "init":
		if err := cmdInit(rest); err != nil {
			fmt.Fprintf(os.Stderr, "agentguard init: %v\n", err)
			os.Exit(1)
		}
		return true

	case "doctor":
		if err := cmdDoctor(rest); err != nil {
			fmt.Fprintf(os.Stderr, "agentguard doctor: %v\n", err)
			os.Exit(1)
		}
		return true

	case "hook":
		runHook() // never returns
		return true

	case "login":
		if err := cmdLogin(rest); err != nil {
			fmt.Fprintf(os.Stderr, "agentguard login: %v\n", err)
			os.Exit(1)
		}
		return true

	case "up":
		if err := cmdUp(rest); err != nil {
			fmt.Fprintf(os.Stderr, "agentguard up: %v\n", err)
			os.Exit(1)
		}
		return true

	case "run":
		// Rewrite to the shape runEnforcer already understands:
		//   agentguard run -- claude  →  agentguard -- claude
		//   agentguard run <pid>      →  agentguard <pid>
		rewritten := append([]string{args[0]}, rest...)
		runEnforcer(rewritten)
		return true

	case "--":
		return false

	default:
		if _, err := strconv.Atoi(cmd); err == nil {
			return false // attach mode
		}
		fmt.Fprintf(os.Stderr, "agentguard: unknown command %q\n\n", cmd)
		printUsage()
		os.Exit(2)
		return true
	}
}

func cmdInit(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	policyPath, err := createStarterPolicy(cwd)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", policyPath)

	hookCmd, err := hookCommand()
	if err != nil {
		return fmt.Errorf("resolve hook command: %w", err)
	}

	home, err := initTargetHome()
	if err != nil {
		return fmt.Errorf("resolve home for hooks: %w", err)
	}
	userSettings := filepath.Join(home, ".claude", "settings.json")
	if err := mergeClaudeHooks(userSettings, hookCmd); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", userSettings)

	projSettings := filepath.Join(cwd, ".claude", "settings.json")
	if err := mergeClaudeHooks(projSettings, hookCmd); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", projSettings)

	fmt.Printf("Hook command: %s\n", hookCmd)
	fmt.Println("Restart Claude if it is running, then: sudo agentguard -- claude")
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `AgentGuard — kernel-enforced agent supervisor

Usage:
  sudo agentguard [flags] -- <agent> [args...]   Load eBPF as root; start <agent> as SUDO_USER
  sudo agentguard [flags] <pid>                 Attach to an existing PID
  sudo agentguard [flags] run -- <agent> [...]  Same as launch
  sudo agentguard [flags] run <pid>             Same as attach

  agentguard init                               Policy YAML + Claude hooks in YOUR ~/.claude
  agentguard doctor                             Check kernel, policy, launch home, hooks
  agentguard hook                               Claude Code hook (do not run by hand)
  agentguard login                              Write ~/.agentguard/anthropic_key (stdin, not argv)
  agentguard up                                 Docker shell (privileged + BTF); runtime persisted under ~/.agentguard/runtime; then: sudo agentguard -- claude
  agentguard version
  agentguard help

Under sudo, Claude uses /home/$SUDO_USER/.claude — not /root/.claude.
Hooks must exec: %s hook
Do not edit /root/.claude when you launched via sudo from your account.

Flags (before the command):
  -v, --verbose          Verbose logging
  --policy <path>        Explicit policy file (must exist)
  -h, --help             Show this help

Env:
  AGENTGUARD_POLICY      Explicit policy file (must exist)
  AGENTGUARD_STATE_DIR   IPC/log/db root (default /tmp/agentguard)
  AGENTGUARD_IMAGE       Image for agentguard up (default ghcr.io/shuklapramath/agentguard:latest)
  ANTHROPIC_API_KEY      Passed into up (overrides ~/.agentguard/anthropic_key)

Examples:
  agentguard login
  agentguard init
  agentguard up
  sudo agentguard -- claude
  sudo agentguard -- /usr/bin/claude
  sudo agentguard --policy ./policies/default.yaml -- claude
`, installedAgentguard)
}
