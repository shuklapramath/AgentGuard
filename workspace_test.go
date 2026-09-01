package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathStartsWithBoundary(t *testing.T) {
	if !pathStartsWith("/workspace", "/workspace") {
		t.Fatal("exact workspace must match")
	}
	if !pathStartsWith("/workspace/foo", "/workspace") {
		t.Fatal("child of workspace must match")
	}
	if pathStartsWith("/workspace-evil", "/workspace") {
		t.Fatal("/workspace must not match /workspace-evil")
	}
	if pathStartsWith("/workspace.bak", "/workspace") {
		t.Fatal("/workspace must not match /workspace.bak")
	}
	if pathStartsWith("/usrfoo", "/usr") {
		t.Fatal("/usr must not match /usrfoo")
	}
	if !pathStartsWith("/usr/bin/cat", "/usr") {
		t.Fatal("/usr must match /usr/bin/cat")
	}
	if pathStartsWith("/work", "/workspace") {
		t.Fatal("shorter path must not match")
	}
}

func TestDangerousAllowPrefix(t *testing.T) {
	home := "/home/ubuntu"
	if !isDangerousAllowPrefix("/", home) {
		t.Fatal("/ must be refused")
	}
	if !isDangerousAllowPrefix("/home", home) {
		t.Fatal("/home must be refused")
	}
	if !isDangerousAllowPrefix("/home/ubuntu", home) {
		t.Fatal("$HOME must be refused")
	}
	if isDangerousAllowPrefix("/usr", home) {
		t.Fatal("/usr must be allowed")
	}
	if isDangerousAllowPrefix("/home/ubuntu/.claude", home) {
		t.Fatal("~/.claude must be allowed")
	}
}

func TestResolveWorkspaceRootCwd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	got, err := resolveWorkspaceRoot("")
	if err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		want, err = filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveWorkspaceRootRejectsSlash(t *testing.T) {
	if _, err := resolveWorkspaceRoot("/"); err == nil {
		t.Fatal("expected error for workspace /")
	}
}

func TestResolveAllowPrefixesRejectsHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveAllowPrefixes([]string{home}, nil)
	if err == nil {
		t.Fatal("expected error for $HOME as allow prefix")
	}
}

func TestResolveAllowPrefixesHomeSuffix(t *testing.T) {
	got, err := resolveAllowPrefixes([]string{"/usr"}, []string{".claude"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d prefixes, want 2: %v", len(got), got)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	wantHome := filepath.Join(home, ".claude")
	if real, err := filepath.EvalSymlinks(wantHome); err == nil {
		wantHome = real
	}
	foundUsr, foundClaude := false, false
	for _, p := range got {
		if p == "/usr" {
			foundUsr = true
		}
		if p == wantHome {
			foundClaude = true
		}
	}
	if !foundUsr || !foundClaude {
		t.Fatalf("got %v, want /usr and %s", got, wantHome)
	}
}

func TestLoadAllPoliciesWorkspace(t *testing.T) {
	pf, err := loadPolicies("policies/default.yaml.example")
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, wp, _, _ := loadAllPolicies(pf)
	if wp == nil {
		t.Fatal("expected workspace_confinement from starter YAML")
	}
	if wp.Root == "" {
		t.Fatal("empty workspace root")
	}
	if len(wp.AllowPrefixes) < 10 {
		t.Fatalf("too few allow prefixes: %v", wp.AllowPrefixes)
	}
	for _, p := range wp.AllowPrefixes {
		if p == "/" || p == "/home" {
			t.Fatalf("dangerous prefix loaded: %q", p)
		}
	}
}

func TestLoadEnforcerSpec(t *testing.T) {
	spec, err := loadEnforcer()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"check_file_open", "check_path_unlink", "check_path_rename"} {
		if spec.Programs[name] == nil {
			t.Fatalf("missing program %s", name)
		}
	}
	for _, name := range []string{"workspace_root", "allowed_path_prefixes"} {
		if spec.Maps[name] == nil {
			t.Fatalf("missing map %s", name)
		}
	}
	if spec.Variables["enforce_workspace"] == nil {
		t.Fatal("missing variable enforce_workspace")
	}
}
