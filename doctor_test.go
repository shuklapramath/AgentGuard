package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorCheckHookSettings(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing", func(t *testing.T) {
		res := doctorCheckHookSettings(filepath.Join(dir, "nope.json"), claudeHookEvents)
		if !res.missing || res.ok {
			t.Fatalf("expected missing, got %+v", res)
		}
	})

	t.Run("old trampoline", func(t *testing.T) {
		p := writeSettings(t, dir, "old.json", "/home/u/.local/bin/agentguard-hook")
		res := doctorCheckHookSettings(p, claudeHookEvents)
		if !res.oldHook || res.ok {
			t.Fatalf("expected oldHook, got %+v", res)
		}
	})

	t.Run("new hook", func(t *testing.T) {
		p := writeSettings(t, dir, "new.json", "/usr/local/bin/agentguard hook")
		res := doctorCheckHookSettings(p, claudeHookEvents)
		if !res.ok || res.command != "/usr/local/bin/agentguard hook" {
			t.Fatalf("expected ok with installed hook, got %+v", res)
		}
	})

	t.Run("mixed old and new", func(t *testing.T) {
		p := filepath.Join(dir, "mixed.json")
		if err := os.WriteFile(p, []byte(`{
			"hooks": {
				"PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}],
				"PostToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"/home/u/.local/bin/agentguard-hook"}]}],
				"PostToolUseFailure": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}]
			}
		}`), 0644); err != nil {
			t.Fatal(err)
		}
		res := doctorCheckHookSettings(p, claudeHookEvents)
		if !res.oldHook || res.ok {
			t.Fatalf("expected oldHook when any event still uses agentguard-hook, got %+v", res)
		}
	})

	t.Run("missing PostToolUse", func(t *testing.T) {
		p := filepath.Join(dir, "partial.json")
		if err := os.WriteFile(p, []byte(`{
			"hooks": {
				"PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}],
				"PostToolUseFailure": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}]
			}
		}`), 0644); err != nil {
			t.Fatal(err)
		}
		res := doctorCheckHookSettings(p, claudeHookEvents)
		if res.ok || res.oldHook || res.missing {
			t.Fatalf("expected detail fail for missing event, got %+v", res)
		}
		if res.detail != "missing agentguard hook on PostToolUse" {
			t.Fatalf("detail=%q", res.detail)
		}
	})

	t.Run("codex without PostToolUseFailure", func(t *testing.T) {
		p := filepath.Join(dir, "codex.json")
		if err := os.WriteFile(p, []byte(`{
			"hooks": {
				"PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}],
				"PostToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/agentguard hook"}]}]
			}
		}`), 0644); err != nil {
			t.Fatal(err)
		}
		res := doctorCheckHookSettings(p, codexHookEvents)
		if !res.ok {
			t.Fatalf("Codex file without PostToolUseFailure should be ok, got %+v", res)
		}
		res = doctorCheckHookSettings(p, claudeHookEvents)
		if res.ok || res.missing || res.oldHook {
			t.Fatalf("same file must fail Claude check (missing Failure), got %+v", res)
		}
	})
}

func TestIsAgentGuardHookSubcommand(t *testing.T) {
	if isAgentGuardHookSubcommand("/home/u/.local/bin/agentguard-hook") {
		t.Fatal("old trampoline must not count as the hook subcommand")
	}
	if !isAgentGuardHookSubcommand("/usr/local/bin/agentguard hook") {
		t.Fatal("installed hook subcommand should match")
	}
	if !isAgentGuardHookSubcommand("/home/ebpf/AgentGuard/agentguard hook") {
		t.Fatal("repo-path hook subcommand should match")
	}
}

func writeSettings(t *testing.T, dir, name, cmd string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	body := `{
  "hooks": {
    "PostToolUse": [{"matcher": "*","hooks": [{"type": "command","command": "` + cmd + `"}]}],
    "PostToolUseFailure": [{"matcher": "*","hooks": [{"type": "command","command": "` + cmd + `"}]}],
    "PreToolUse": [{"matcher": "*","hooks": [{"type": "command","command": "` + cmd + `"}]}]
  }
}`
	if err := os.WriteFile(p, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}
