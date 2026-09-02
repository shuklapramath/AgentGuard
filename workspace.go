package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	maxAllowPrefixSlots = 25
	maxWorkspaceRootLen = 255 // d_path path_len is capped at MAX_PATH_LEN-1
)

type WorkspacePolicy struct {
	PolicyID      uint32
	Feedback      string
	Root          string
	AllowPrefixes []string
}

// pathStartsWith is the userspace twin of BPF path_starts_with_*: prefix match
// with a '/' boundary so "/workspace" does not match "/workspace-evil".
func pathStartsWith(path, prefix string) bool {
	if prefix == "" || len(path) < len(prefix) {
		return false
	}
	if path[:len(prefix)] != prefix {
		return false
	}
	if len(path) == len(prefix) {
		return true
	}
	return path[len(prefix)] == '/'
}

func resolveWorkspaceRoot(explicit string) (string, error) {
	p := strings.TrimSpace(explicit)
	if p == "" || p == "." {
		var err error
		p, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("workspace cwd: %w", err)
		}
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("workspace abs: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	out := filepath.Clean(real)
	if len(out) > maxWorkspaceRootLen {
		return "", fmt.Errorf("workspace path %q exceeds %d bytes", out, maxWorkspaceRootLen)
	}
	if out == "/" {
		return "", fmt.Errorf("workspace root cannot be /")
	}
	return out, nil
}

func agentHomeDir() (string, error) {
	id, err := sudoLaunchIdentity()
	if err != nil {
		return "", err
	}
	if id != nil && id.Home != "" {
		return id.Home, nil
	}
	return os.UserHomeDir()
}

func isDangerousAllowPrefix(p, home string) bool {
	if p == "/" || p == "/home" {
		return true
	}
	if home != "" && p == filepath.Clean(home) {
		return true
	}
	return false
}

func resolveOnePrefix(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("empty allow prefix")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		real = abs
	}
	out := filepath.Clean(real)
	if len(out) > bpfPatternKeySize {
		return "", fmt.Errorf("allow prefix %q exceeds %d bytes", out, bpfPatternKeySize)
	}
	return out, nil
}

func resolveAllowPrefixes(prefixes, homeSuffixes []string) ([]string, error) {
	home, err := agentHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home for allow_home_suffixes: %w", err)
	}

	out := make([]string, 0, len(prefixes)+len(homeSuffixes))
	seen := make(map[string]struct{})

	add := func(p string) error {
		if isDangerousAllowPrefix(p, home) {
			return fmt.Errorf("allow prefix %q would disable confinement (refusing /, /home, and $HOME)", p)
		}
		if _, ok := seen[p]; ok {
			return nil
		}
		seen[p] = struct{}{}
		out = append(out, p)
		return nil
	}

	for _, raw := range prefixes {
		p, err := resolveOnePrefix(raw)
		if err != nil {
			return nil, err
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}

	for _, suf := range homeSuffixes {
		s := strings.TrimSpace(suf)
		s = strings.TrimPrefix(s, "/")
		if s == "" {
			return nil, fmt.Errorf("empty allow_home_suffixes entry")
		}
		if filepath.IsAbs(strings.TrimSpace(suf)) {
			return nil, fmt.Errorf("allow_home_suffixes %q must be relative to $HOME", suf)
		}
		joined := filepath.Join(home, s)
		p, err := resolveOnePrefix(joined)
		if err != nil {
			return nil, err
		}
		if err := add(p); err != nil {
			return nil, err
		}
	}

	if len(out) > maxAllowPrefixSlots {
		return nil, fmt.Errorf("too many allow prefixes: %d > %d", len(out), maxAllowPrefixSlots)
	}
	return out, nil
}

// workspaceRootEntryBPF must match struct workspace_root_entry in enforcer.bpf.c.
type workspaceRootEntryBPF struct {
	Prefix    [256]byte
	PrefixLen uint32
	PolicyID  uint32
}

func applyWorkspaceRoot(m *ebpf.Map, wp *WorkspacePolicy) error {
	var ent workspaceRootEntryBPF
	idx := uint32(0)
	if wp == nil {
		return m.Update(&idx, &ent, ebpf.UpdateAny)
	}
	if len(wp.Root) == 0 || len(wp.Root) > maxWorkspaceRootLen {
		return fmt.Errorf("invalid workspace root length %d", len(wp.Root))
	}
	copy(ent.Prefix[:], wp.Root)
	ent.PrefixLen = uint32(len(wp.Root))
	ent.PolicyID = wp.PolicyID
	if err := m.Update(&idx, &ent, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("load workspace root %q: %w", wp.Root, err)
	}
	log.Printf("	-> workspace root policy=%d prefix=%q", wp.PolicyID, wp.Root)
	return nil
}

func applyAllowPrefixes(m *ebpf.Map, wp *WorkspacePolicy) error {
	for i := uint32(0); i < maxAllowPrefixSlots; i++ {
		empty := pathPatternEntryBPF{}
		if err := m.Update(&i, &empty, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear allow prefix slot %d: %w", i, err)
		}
	}
	if wp == nil {
		return nil
	}
	log.Printf("[+] Loading %d workspace allow prefixes...", len(wp.AllowPrefixes))
	for i, p := range wp.AllowPrefixes {
		if len(p) > bpfPatternKeySize {
			return fmt.Errorf("allow prefix %q exceeds %d bytes", p, bpfPatternKeySize)
		}
		var ent pathPatternEntryBPF
		copy(ent.Pattern[:], p)
		ent.PolicyID = wp.PolicyID
		ent.PatternLen = uint8(len(p))
		idx := uint32(i)
		if err := m.Update(&idx, &ent, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load allow prefix %q: %w", p, err)
		}
		log.Printf("	-> slot=%d policy=%d prefix=%q", i, wp.PolicyID, p)
	}
	return nil
}

func applyWorkspacePolicy(objs *enforcerObjects, wp *WorkspacePolicy) error {
	on := wp != nil
	if err := objs.EnforceWorkspace.Set(boolToU8(on)); err != nil {
		return fmt.Errorf("set enforce_workspace: %w", err)
	}
	if err := applyWorkspaceRoot(objs.WorkspaceRoot, wp); err != nil {
		return err
	}
	if err := applyAllowPrefixes(objs.AllowedPathPrefixes, wp); err != nil {
		return err
	}
	if on {
		log.Printf("[+] workspace confinement ON root=%s prefixes=%d", wp.Root, len(wp.AllowPrefixes))
	} else {
		log.Printf("[+] workspace confinement OFF")
	}
	return nil
}
