package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteReadAnthropicAPIKeyRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "")

	const want = "sk-ant-test-key"
	if err := writeAnthropicAPIKey(want); err != nil {
		t.Fatal(err)
	}
	path, err := anthropicKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("key file perm = %o, want 0600", st.Mode().Perm())
	}

	got, err := readAnthropicAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("read %q, want %q", got, want)
	}
}

func TestReadAnthropicAPIKeyEnvWinsOverFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "")

	if err := writeAnthropicAPIKey("from-file"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "from-env")

	got, err := readAnthropicAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-env" {
		t.Fatalf("read %q, want from-env", got)
	}
}

func TestReadAnthropicAPIKeyEmptyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "")

	path := filepath.Join(home, ".agentguard", "anthropic_key")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := readAnthropicAPIKey()
	if err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("expected empty-file error, got %v", err)
	}
}

func TestReadAnthropicAPIKeyMissingFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("ANTHROPIC_API_KEY", "")

	got, err := readAnthropicAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("read %q, want empty", got)
	}
}

func TestCmdLoginRejectsArgs(t *testing.T) {
	err := cmdLogin([]string{"sk-ant-x"})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("expected unexpected arguments, got %v", err)
	}
}
