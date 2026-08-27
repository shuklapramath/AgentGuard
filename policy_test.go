package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindPolicyPathDoesNotCreate(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	path, err := findPolicyPath("")
	if err != nil {
		t.Fatal(err)
	}

	created := filepath.Join(dir, "policies", "default.yaml")
	if _, err := os.Stat(created); !os.IsNotExist(err) {
		t.Fatalf("findPolicyPath must not create YAML: %v", err)
	}
	if path == created {
		t.Fatalf("findPolicyPath reported the cwd path it must not create: %q", path)
	}
}

func TestFindPolicyPathFindsCwd(t *testing.T) {
	dir := t.TempDir()
	polDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(polDir, 0755); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(polDir, "default.yaml")
	if err := os.WriteFile(want, []byte("test: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(want)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	got, err := findPolicyPath("")
	if err != nil {
		t.Fatal(err)
	}
	if got != abs {
		t.Fatalf("got %q, want %q", got, abs)
	}
}
