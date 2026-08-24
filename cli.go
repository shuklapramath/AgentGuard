package main

import (
	"fmt"
	"log"
	"os"
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

	case "up":
		fmt.Fprintln(os.Stderr, "agentguard up: not implemented yet (Phase 3 — Docker image)")
		fmt.Fprintln(os.Stderr, "On Linux, run: sudo agentguard -- <agent>")
		os.Exit(2)
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
	path, err := createStarterPolicy(cwd)
	if err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", path)
	fmt.Println("Edit this file, then run: sudo agentguard -- <agent>")
	return nil
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `AgentGuard — kernel-enforced agent supervisor

Usage:
  sudo agentguard [flags] -- <agent> [args...]   Launch and supervise an agent
  sudo agentguard [flags] <pid>                 Attach to an existing PID
  sudo agentguard [flags] run -- <agent> [...]  Same as launch (explicit)
  sudo agentguard [flags] run <pid>             Same as attach (explicit)

  agentguard init                               Create policies/default.yaml
  agentguard doctor                             Check environment / policy
  agentguard hook                               Claude Code hook entrypoint
  agentguard up                                 (coming soon) Docker secure env
  agentguard version
  agentguard help

Flags (before the command):
  -v, --verbose          Verbose logging
  --policy <path>        Explicit policy file (must exist)
  -h, --help             Show this help

Env:
  AGENTGUARD_POLICY      Explicit policy file (must exist)
  AGENTGUARD_STATE_DIR   IPC/log/db root (default /tmp/agentguard)

Examples:
  agentguard init
  sudo agentguard -- /home/ebpf/.local/bin/claude
  sudo agentguard --policy ./policies/default.yaml -- claude
`)
}
