package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const installedAgentguard = "/usr/local/bin/agentguard"

func initTargetHome() (string, error) {
	if os.Geteuid() == 0 {
		id, err := sudoLaunchIdentity()
		if err != nil {
			return "", err
		}
		if id != nil {
			return id.Home, nil
		}
	}
	return os.UserHomeDir()
}

// hookCommand is the string Claude settings should exec.
// Prefer the installed binary so `./agentguard init` from a git tree does not
// rewrite hooks to a repo-local path.
func hookCommand() (string, error) {
	if st, err := os.Stat(installedAgentguard); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
		return installedAgentguard + " hook", nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return self + " hook", nil
}

func mergeClaudeHooks(settingsPath, hookCmd string) error {
	dir := filepath.Dir(settingsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	chownToSudoUser(dir)

	raw := map[string]json.RawMessage{}
	if b, err := os.ReadFile(settingsPath); err == nil && len(b) > 0 {
		if err := json.Unmarshal(b, &raw); err != nil {
			return fmt.Errorf("parse %s: %w", settingsPath, err)
		}
	}

	var hooks map[string][]hookMatcher
	if h, ok := raw["hooks"]; ok {
		if err := json.Unmarshal(h, &hooks); err != nil {
			return fmt.Errorf("parse hooks in %s: %w", settingsPath, err)
		}
	}
	if hooks == nil {
		hooks = map[string][]hookMatcher{}
	}

	entry := hookEntry{Type: "command", Command: hookCmd}
	for _, ev := range []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"} {
		hooks[ev] = upsertAgentGuardHook(hooks[ev], entry)
	}

	hb, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	raw["hooks"] = hb

	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	if err := os.WriteFile(settingsPath, out, 0644); err != nil {
		return err
	}
	chownToSudoUser(settingsPath)
	return nil
}

type hookMatcher struct {
	Matcher string      `json:"matcher"`
	Hooks   []hookEntry `json:"hooks"`
}

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

func upsertAgentGuardHook(existing []hookMatcher, entry hookEntry) []hookMatcher {
	replaced := false
	for i := range existing {
		if existing[i].Matcher != "*" && existing[i].Matcher != "" {
			continue
		}
		for j := range existing[i].Hooks {
			if isAgentGuardHookCmd(existing[i].Hooks[j].Command) {
				existing[i].Hooks[j] = entry
				replaced = true
			}
		}
		if existing[i].Matcher == "" {
			existing[i].Matcher = "*"
		}
	}
	if replaced {
		return existing
	}
	return append(existing, hookMatcher{Matcher: "*", Hooks: []hookEntry{entry}})
}

func isAgentGuardHookCmd(cmd string) bool {
	s := strings.TrimSpace(cmd)
	return strings.Contains(s, "agentguard-hook") ||
		strings.HasSuffix(s, "agentguard hook") ||
		strings.Contains(s, "/agentguard hook")
}
