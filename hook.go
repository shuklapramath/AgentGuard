package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// runHook is the Claude Code / Cursor hook entrypoint (agentguard hook).
// It always exits; it must not load BPF or print AgentGuard banners to stdout.
func runHook() {
	debugLog := openHookDebugLog()
	defer debugLog.Close()

	stdinData, err := io.ReadAll(os.Stdin)
	if err != nil {
		os.Exit(0)
	}

	var input hookInput
	if err := json.Unmarshal(stdinData, &input); err != nil {
		os.Exit(0)
	}

	sessionID := strings.TrimSpace(input.SessionID)
	hookEvent := strings.TrimSpace(input.HookEventName)

	fmt.Fprintf(debugLog, "[HOOK] Hook spawned. Session ID: %s, Event: %s, Tool: %s\n",
		sessionID, hookEvent, input.ToolName)

	if isCursorHook(hookEvent, input.ToolName) {
		fmt.Fprintf(debugLog, "[HOOK] Ignoring Cursor hook event=%q tool=%q\n", hookEvent, input.ToolName)
		os.Exit(0)
	}

	if isPreToolUseEvent(hookEvent) {
		if sessionID != "" {
			_ = os.MkdirAll(agentGuardLogDir, 0777)
			_ = os.Chmod(agentGuardLogDir, 0777)
			if err := os.WriteFile(activeSessionPath, []byte(sessionID), 0666); err != nil {
				fmt.Fprintf(debugLog, "[HOOK] PreToolUse: failed to pre-register session: %v\n", err)
			} else {
				_ = os.Chmod(activeSessionPath, 0666)
				fmt.Fprintf(debugLog, "[HOOK] PreToolUse: SUCCESS - pre-registered session %s before tool execution\n", sessionID)
			}
		}
		os.Exit(0)
	}

	if sessionID != "" {
		_ = os.MkdirAll(agentGuardLogDir, 0777)
		_ = os.Chmod(agentGuardLogDir, 0777)
		if err := os.WriteFile(activeSessionPath, []byte(sessionID), 0666); err != nil {
			fmt.Fprintf(debugLog, "[HOOK] PostTool: failed to write active_session: %v\n", err)
		} else {
			_ = os.Chmod(activeSessionPath, 0666)
			fmt.Fprintf(debugLog, "[HOOK] PostTool: registered active_session -> %s\n", activeSessionPath)
		}
	}

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
			os.Exit(0)
		}
		path = latest
		fmt.Fprintf(debugLog, "[HOOK] Using fallback latest.json\n")
	}

	var v hookPendingViolation
	if err := json.Unmarshal(data, &v); err != nil {
		os.Exit(0)
	}
	reason := strings.TrimSpace(v.Reason)
	if reason == "" {
		os.Exit(0)
	}

	os.Remove(path)
	if sessionID != "" {
		os.Remove(filepath.Join(violationStoreDir, sessionID+".json"))
	}
	os.Remove(filepath.Join(violationStoreDir, "latest.json"))

	msg := "[SECURITY SYSTEM]: " + reason
	out := hookJSONOutput{
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
	_, _ = os.Stdout.Write(payload)
	_, _ = os.Stdout.Write([]byte("\n"))
	os.Exit(0)
}

type hookInput struct {
	SessionID     string `json:"session_id"`
	ToolName      string `json:"tool_name"`
	HookEventName string `json:"hook_event_name"`
}

type hookPendingViolation struct {
	Reason     string `json:"reason"`
	PolicyType uint8  `json:"policy_type"`
	Path       string `json:"path"`
}

type hookJSONOutput struct {
	SystemMessage      string             `json:"systemMessage,omitempty"`
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

func openHookDebugLog() *os.File {
	candidates := []string{
		filepath.Join(agentGuardLogDir, "hook-debug.log"),
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

func isPreToolUseEvent(event string) bool {
	return strings.TrimSpace(event) == "PreToolUse"
}

func normalizeHookEvent(event string) string {
	switch strings.TrimSpace(event) {
	case "PostToolUse":
		return "PostToolUse"
	case "PostToolUseFailure":
		return "PostToolUseFailure"
	case "":
		return "PostToolUseFailure"
	default:
		return ""
	}
}
