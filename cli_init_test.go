package main

import (
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
}

func TestParseInitFlags(t *testing.T) {
	claude, err := parseInitFlags(nil)
	if err != nil || claude {
		t.Fatalf("empty: claude=%v err=%v", claude, err)
	}
	claude, err = parseInitFlags([]string{"--claude"})
	if err != nil || !claude {
		t.Fatalf("--claude: claude=%v err=%v", claude, err)
	}
	if _, err := parseInitFlags([]string{"--cursor"}); err == nil {
		t.Fatal("expected error for unknown flag")
	}
	if _, err := parseInitFlags([]string{"foo"}); err == nil {
		t.Fatal("expected error for extra arg")
	}
}
