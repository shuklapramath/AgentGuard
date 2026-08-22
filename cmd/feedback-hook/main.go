package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	agentGuardDir     = "/tmp/agentguard"
	violationStoreDir = "/tmp/agentguard/violations"
	activeSessionPath = "/tmp/agentguard/active_session"
)

type HookInput struct {
	SessionID     string `json:"session_id"`
	ToolName      string `json:"tool_name"`
	HookEventName string `json:"hook_event_name"`
}

type PendingViolation struct {
	Reason     string `json:"reason"`
	PolicyType uint8  `json:"policy_type"`
	Path       string `json:"path"`
}

// Claude Code PostToolUse / PostToolUseFailure JSON (exit 0).
type hookOutput struct {
	SystemMessage      string             `json:"systemMessage,omitempty"`
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

func main() {
	// Never abort the whole hook just because debug logging failed — that
	// previously caused exit 0 with empty stdout, so Claude got no feedback.
	debugLog := openDebugLog()
	defer debugLog.Close()

	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0)
	}

	var input HookInput
	if err := json.Unmarshal(stdinData, &input); err != nil {
		os.Exit(0)
	}

	sessionID := strings.TrimSpace(input.SessionID)
	hookEvent := strings.TrimSpace(input.HookEventName)

	fmt.Fprintf(debugLog, "[HOOK] Hook spawned. Session ID: %s, Event: %s, Tool: %s\n",
		sessionID, hookEvent, input.ToolName)

	// Cursor and Claude Code share this binary. Cursor uses lowercase
	// "postToolUse" + tool Shell; Claude Code uses PascalCase
	// "PostToolUse"/"PostToolUseFailure" (Bash, Fetch, WebFetch, …).
	// Ignore Cursor so it cannot overwrite active_session or steal IPC.
	if isCursorHook(hookEvent, input.ToolName) {
		fmt.Fprintf(debugLog, "[HOOK] Ignoring Cursor hook event=%q tool=%q\n", hookEvent, input.ToolName)
		os.Exit(0)
	}

	// SOLUTION #1: PreToolUse hook - pre-register session ID before tool executes
	// This ensures active_session is set BEFORE violations occur during tool execution
	if isPreToolUseEvent(hookEvent) {
		if sessionID != "" {
			_ = os.MkdirAll(agentGuardDir, 0777)
			_ = os.Chmod(agentGuardDir, 0777)
			if err := os.WriteFile(activeSessionPath, []byte(sessionID), 0666); err != nil {
				fmt.Fprintf(debugLog, "[HOOK] PreToolUse: failed to pre-register session: %v\n", err)
			} else {
				_ = os.Chmod(activeSessionPath, 0666)
				fmt.Fprintf(debugLog, "[HOOK] PreToolUse: SUCCESS - pre-registered session %s before tool execution\n", sessionID)
			}
		}
		// PreToolUse doesn't look for violations, just pre-registers the session
		os.Exit(0)
	}

	// PostToolUse/PostToolUseFailure: register session AND deliver violations
	if sessionID != "" {
		_ = os.MkdirAll(agentGuardDir, 0777)
		_ = os.Chmod(agentGuardDir, 0777)
		if err := os.WriteFile(activeSessionPath, []byte(sessionID), 0666); err != nil {
			fmt.Fprintf(debugLog, "[HOOK] PostTool: failed to write active_session: %v\n", err)
		} else {
			_ = os.Chmod(activeSessionPath, 0666)
			fmt.Fprintf(debugLog, "[HOOK] PostTool: registered active_session -> %s\n", activeSessionPath)
		}
	}

	// Claude Code often reports failed Bash/Fetch (e.g. proxy 403) as
	// PostToolUse — not PostToolUseFailure. Deliver on both when a pending
	// violation exists; no-op when there is none (successful tools stay quiet).
	canonicalEvent := normalizeHookEvent(hookEvent)
	if canonicalEvent == "" {
		fmt.Fprintf(debugLog, "[HOOK] Ignoring unsupported hook event %q\n", hookEvent)
		os.Exit(0)
	}
	hookEvent = canonicalEvent

	path := filepath.Join(violationStoreDir, sessionID+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		latest := filepath.Join(violationStoreDir, "latest.json")
		data, err = os.ReadFile(latest)
		if err != nil {
			fmt.Fprintf(debugLog, "[HOOK] No violation found for session %s (expected for successful tools)\n", sessionID)
			os.Exit(0) // no pending violation
		}
		path = latest
		fmt.Fprintf(debugLog, "[HOOK] Using fallback latest.json\n")
	}

	var v PendingViolation
	if err := json.Unmarshal(data, &v); err != nil {
		os.Exit(0)
	}
	reason := strings.TrimSpace(v.Reason)
	if reason == "" {
		os.Exit(0)
	}

	// Consume both mirrors so the next hook cannot re-deliver stale text.
	os.Remove(path)
	if sessionID != "" {
		os.Remove(filepath.Join(violationStoreDir, sessionID+".json"))
	}
	os.Remove(filepath.Join(violationStoreDir, "latest.json"))

	msg := "[SECURITY SYSTEM]: " + reason
	out := hookOutput{
		SystemMessage: msg,
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:     hookEvent,
			AdditionalContext: msg,
		},
	}
	payload, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintf(debugLog, "[HOOK] marshal hook output: %v\n", err)
		os.Exit(0)
	}

	fmt.Fprintf(debugLog, "[HOOK] DELIVERING violation feedback for %s\n", hookEvent)
	os.Stdout.Write(payload)
	os.Stdout.Write([]byte("\n"))
	os.Exit(0)
}

// openDebugLog prefers the AgentGuard IPC dir (world-writable). On failure it
// falls back to stderr so the hook can still deliver feedback on stdout.
func openDebugLog() *os.File {
	candidates := []string{
		filepath.Join(agentGuardDir, "hook-debug.log"),
		"/tmp/hook-debug.log",
	}
	for _, path := range candidates {
		_ = os.MkdirAll(filepath.Dir(path), 0777)
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			continue
		}
		_ = os.Chmod(path, 0666)
		return f
	}
	return os.Stderr
}

// isCursorHook reports Cursor agent invocations that must not touch IPC.
// Claude Code sends PascalCase PostToolUse / PostToolUseFailure.
func isCursorHook(event, tool string) bool {
	if tool == "Shell" {
		return true
	}
	switch event {
	case "postToolUse", "postToolUseFailure":
		return true
	default:
		return false
	}
}

// isPreToolUseEvent detects the PreToolUse hook event.
// Solution #1: Pre-register session ID before tool execution to ensure
// active_session file exists when violations occur during tool execution.
func isPreToolUseEvent(event string) bool {
	switch strings.TrimSpace(event) {
	case "PreToolUse":
		return true
	default:
		return false
	}
}

// normalizeHookEvent maps Claude Code event names to the JSON hookEventName
// values. Empty string => ignore this invocation.
func normalizeHookEvent(event string) string {
	switch strings.TrimSpace(event) {
	case "PostToolUse":
		return "PostToolUse"
	case "PostToolUseFailure":
		return "PostToolUseFailure"
	case "":
		// Default: treat as failure path so a bare invoke can still deliver.
		return "PostToolUseFailure"
	default:
		// Reject Cursor lowercase / unknown events (defense in depth).
		return ""
	}
}
