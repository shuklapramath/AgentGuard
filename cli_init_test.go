package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCmdInitWritesPolicyOnly(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := cmdInit(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "policies", "default.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".claude")); err == nil {
		t.Fatal("init without --claude must not write $PWD/.claude")
	}
	if _, err := os.Stat(filepath.Join(dir, ".codex")); err == nil {
		t.Fatal("init without --codex must not write $PWD/.codex")
	}
}

func TestParseInitFlags(t *testing.T) {
	claude, codex, err := parseInitFlags(nil)
	if err != nil || claude || codex {
		t.Fatalf("empty: claude=%v codex=%v err=%v", claude, codex, err)
	}
	claude, codex, err = parseInitFlags([]string{"--claude"})
	if err != nil || !claude || codex {
		t.Fatalf("--claude: claude=%v codex=%v err=%v", claude, codex, err)
	}
	claude, codex, err = parseInitFlags([]string{"--codex"})
	if err != nil || claude || !codex {
		t.Fatalf("--codex: claude=%v codex=%v err=%v", claude, codex, err)
	}
	claude, codex, err = parseInitFlags([]string{"--claude", "--codex"})
	if err != nil || !claude || !codex {
		t.Fatalf("both: claude=%v codex=%v err=%v", claude, codex, err)
	}
	if _, _, err := parseInitFlags([]string{"--cursor"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if _, _, err := parseInitFlags([]string{"foo"}); err == nil {
		t.Fatal("expected error for extra arg")
	}
}

func TestMergeCodexHooks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "hooks.json")
	if err := mergeCodexHooks(p, "/usr/local/bin/agentguard hook"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var wrap struct {
		Description string                   `json:"description"`
		Hooks       map[string][]hookMatcher `json:"hooks"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		t.Fatal(err)
	}
	if wrap.Description == "" {
		t.Fatal("expected description")
	}
	if _, ok := wrap.Hooks["PostToolUseFailure"]; ok {
		t.Fatal("Codex hooks must not install PostToolUseFailure")
	}
	for _, ev := range []string{"PreToolUse", "PostToolUse"} {
		if len(wrap.Hooks[ev]) == 0 {
			t.Fatalf("missing %s", ev)
		}
	}
}
