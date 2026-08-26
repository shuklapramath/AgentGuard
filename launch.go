package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

type launchIdentity struct {
	User    string
	Home    string
	Uid     uint32
	Gid     uint32
	Groups  []uint32
	PathPre string
}

// sudoLaunchIdentity is set when AgentGuard is root via sudo.
// Nil means do not change the child (already the invoking user, or a root shell).
func sudoLaunchIdentity() (*launchIdentity, error) {
	if os.Geteuid() != 0 {
		return nil, nil
	}
	name := strings.TrimSpace(os.Getenv("SUDO_USER"))
	if name == "" || name == "root" {
		return nil, nil
	}

	uid := os.Getenv("SUDO_UID")
	gid := os.Getenv("SUDO_GID")
	if uid == "" || gid == "" {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("lookup SUDO_USER %q: %w", name, err)
		}
		uid, gid = u.Uid, u.Gid
	}

	uidN, err1 := strconv.ParseUint(uid, 10, 32)
	gidN, err2 := strconv.ParseUint(gid, 10, 32)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("parse SUDO_UID/SUDO_GID: %v %v", err1, err2)
	}

	home := ""
	if u, err := user.LookupId(strconv.FormatUint(uidN, 10)); err == nil {
		home = u.HomeDir
		if u.Username != "" {
			name = u.Username
		}
	}
	if home == "" {
		home = "/home/" + name
	}

	groups := []uint32{uint32(gidN)}
	if u, err := user.Lookup(name); err == nil {
		if ids, err := u.GroupIds(); err == nil {
			seen := map[uint32]bool{uint32(gidN): true}
			for _, s := range ids {
				n, err := strconv.ParseUint(s, 10, 32)
				if err != nil {
					continue
				}
				g := uint32(n)
				if !seen[g] {
					groups = append(groups, g)
					seen[g] = true
				}
			}
		}
	}

	return &launchIdentity{
		User:    name,
		Home:    home,
		Uid:     uint32(uidN),
		Gid:     uint32(gidN),
		Groups:  groups,
		PathPre: filepath.Join(home, ".local", "bin"),
	}, nil
}

func applyLaunchIdentity(cmd *exec.Cmd, id *launchIdentity, extraEnv []string) {
	if id == nil {
		cmd.Env = append(os.Environ(), extraEnv...)
		return
	}

	setChildCredential(cmd, id)

	env := filterEnv(os.Environ(), []string{
		"HOME", "USER", "LOGNAME", "USERNAME",
		"MAIL", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME",
		"XDG_CONFIG_HOME", "XDG_DATA_HOME",
		"SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND",
	})
	env = append(env,
		"HOME="+id.Home,
		"USER="+id.User,
		"LOGNAME="+id.User,
		"USERNAME="+id.User,
		"XDG_RUNTIME_DIR=/run/user/"+strconv.FormatUint(uint64(id.Uid), 10),
	)
	env = rewritePATH(env, id.PathPre)
	cmd.Env = append(env, extraEnv...)
}

func resolveAgentPath(bin string, id *launchIdentity) string {
	if id == nil || filepath.IsAbs(bin) {
		return bin
	}
	cand := filepath.Join(id.PathPre, bin)
	if st, err := os.Stat(cand); err == nil && !st.IsDir() && st.Mode()&0111 != 0 {
		return cand
	}
	return bin
}

func filterEnv(in, dropKeys []string) []string {
	drop := make(map[string]bool, len(dropKeys))
	for _, k := range dropKeys {
		drop[k] = true
	}
	out := make([]string, 0, len(in))
	for _, e := range in {
		k, _, _ := strings.Cut(e, "=")
		if drop[k] {
			continue
		}
		out = append(out, e)
	}
	return out
}

func rewritePATH(env []string, prefix string) []string {
	const def = "/usr/local/bin:/usr/bin:/bin"
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			p := strings.TrimPrefix(e, "PATH=")
			env[i] = "PATH=" + prefix + ":" + p
			return env
		}
	}
	return append(env, "PATH="+prefix+":"+def)
}
