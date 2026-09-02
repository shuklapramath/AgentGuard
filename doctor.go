package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func cmdDoctor(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}

	fmt.Printf("agentguard doctor %s\n", agentGuardVersion)
	fmt.Printf("os=%s arch=%s euid=%d\n\n", runtime.GOOS, runtime.GOARCH, os.Geteuid())

	ok := true
	claudeHome := ""
	checkHooks := false

	if os.Geteuid() == 0 {
		id, err := sudoLaunchIdentity()
		if err != nil {
			fmt.Printf("[FAIL] launch identity: %v\n", err)
			ok = false
		} else if id != nil {
			fmt.Printf("[OK]   sudo → agent should run as %s uid=%d HOME=%s\n",
				id.User, id.Uid, id.Home)
			fmt.Printf("       Claude would use %s\n", filepath.Join(id.Home, ".claude"))
			claudeHome = id.Home
			checkHooks = true
		} else {
			fmt.Printf("[FAIL] euid=0 and no SUDO_USER; Claude will use /root/.claude; hooks in ~/.claude will be ignored\n")
			ok = false
		}
	} else {
		fmt.Printf("[INFO] not root; launch identity drop applies only under sudo\n")
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Printf("[FAIL] home directory: %v\n", err)
			ok = false
		} else {
			claudeHome = home
			checkHooks = true
		}
	}

	path, err := findPolicyPath(policyFlag)
	switch {
	case err != nil:
		fmt.Printf("[FAIL] policy: %v\n", err)
		ok = false
	case path == "":
		fmt.Printf("[INFO] no policy in this directory (run: agentguard init)\n")
	default:
		fmt.Printf("[OK]   policy (found): %s\n", path)
	}

	st, err := os.Stat(agentGuardLogDir)
	switch {
	case err != nil && os.IsNotExist(err):
		fmt.Printf("[INFO] state dir %s not created yet (created at runtime)\n", agentGuardLogDir)
	case err != nil:
		fmt.Printf("[WARN] state dir %s: %v\n", agentGuardLogDir, err)
	default:
		id, _ := sudoLaunchIdentity()
		if os.Geteuid() == 0 && id != nil {
			mode := st.Mode().Perm()
			if mode&0002 == 0 && mode&0070 == 0 {
				fmt.Printf("[WARN] %s mode %o — user-run hook may not be able to write (want 0777)\n",
					agentGuardLogDir, mode)
			} else {
				fmt.Printf("[OK]   state dir %s mode %o\n", agentGuardLogDir, mode)
			}
		} else {
			fmt.Printf("[OK]   state dir: %s\n", agentGuardLogDir)
		}
	}
	if os.Getenv("AGENTGUARD_STATE_DIR") != "" {
		fmt.Printf("       from AGENTGUARD_STATE_DIR\n")
	} else {
		fmt.Printf("       default (/tmp/agentguard)\n")
	}

	btf := "/sys/kernel/btf/vmlinux"
	if st, err := os.Stat(btf); err != nil {
		if runtime.GOOS != "linux" {
			fmt.Printf("[INFO] BTF: %s not readable on this host (%v)\n", btf, err)
			fmt.Println("       Enforcement runs inside: agentguard up")
		} else {
			fmt.Printf("[FAIL] BTF: %s not readable (%v)\n", btf, err)
			ok = false
		}
	} else {
		fmt.Printf("[OK]   BTF: %s (%d bytes)\n", btf, st.Size())
	}

	if runtime.GOOS != "linux" {
		fmt.Printf("[INFO] securityfs: checked inside agentguard up (Linux VM)\n")
	} else {
		if !doctorReportSecurityfs() {
			ok = false
		}
	}

	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		if runtime.GOOS != "linux" {
			fmt.Printf("[INFO] /proc/cmdline: %v\n", err)
			fmt.Println("       AgentGuard enforcement requires Linux (or Colima/Docker Linux VM).")
		} else {
			fmt.Printf("[WARN] /proc/cmdline: %v (are you on Linux?)\n", err)
		}
	} else {
		s := string(cmdline)
		if strings.Contains(s, "bpf") {
			fmt.Printf("[OK]   cmdline mentions bpf (LSM likely enabled)\n")
		} else {
			fmt.Printf("[WARN] cmdline has no 'bpf' token — check CONFIG_BPF_LSM / lsm=bpf\n")
			fmt.Printf("       cmdline: %s\n", strings.TrimSpace(s))
		}
	}

	if dpath, err := exec.LookPath("docker"); err != nil {
		if runtime.GOOS != "linux" {
			fmt.Printf("[FAIL] docker: not on PATH (required for agentguard up)\n")
			ok = false
		} else {
			fmt.Printf("[INFO] docker: not on PATH\n")
		}
	} else {
		fmt.Printf("[INFO] docker: %s\n", dpath)
		info := exec.Command("docker", "info")
		info.Stdout = io.Discard
		info.Stderr = io.Discard
		if err := info.Run(); err != nil {
			if runtime.GOOS != "linux" {
				fmt.Printf("[FAIL] docker info failed: %v\n", err)
				ok = false
			} else {
				fmt.Printf("[WARN] docker info failed: %v\n", err)
			}
		} else {
			fmt.Printf("[OK]   docker daemon reachable\n")
		}
	}
	if path, err := exec.LookPath("colima"); err != nil {
		fmt.Printf("[INFO] colima: not on PATH\n")
	} else {
		fmt.Printf("[INFO] colima: %s\n", path)
	}

	if checkHooks {
		settingsPath := filepath.Join(claudeHome, ".claude", "settings.json")
		res := doctorCheckHookSettings(settingsPath, claudeHookEvents)
		switch {
		case res.ok:
			fmt.Printf("[OK]   Claude hooks: %s\n", res.command)
			fmt.Printf("       file: %s\n", settingsPath)
		case res.missing:
			fmt.Printf("[INFO] Claude settings not found: %s\n", settingsPath)
			fmt.Printf("       optional: agentguard init --claude  (kernel still enforces without hooks)\n")
		case res.oldHook:
			fmt.Printf("[FAIL] Claude hooks still call agentguard-hook: %s\n", settingsPath)
			ok = false
		default:
			fmt.Printf("[FAIL] Claude hooks in %s: %s\n", settingsPath, res.detail)
			ok = false
		}

		codexPath := filepath.Join(claudeHome, ".codex", "hooks.json")
		cres := doctorCheckHookSettings(codexPath, codexHookEvents)
		switch {
		case cres.ok:
			fmt.Printf("[OK]   Codex hooks: %s\n", cres.command)
			fmt.Printf("       file: %s\n", codexPath)
		case cres.missing:
			fmt.Printf("[INFO] Codex hooks not found: %s\n", codexPath)
			fmt.Printf("       optional: agentguard init --codex  (kernel still enforces without hooks)\n")
		case cres.oldHook:
			fmt.Printf("[FAIL] Codex hooks still call agentguard-hook: %s\n", codexPath)
			ok = false
		default:
			fmt.Printf("[FAIL] Codex hooks in %s: %s\n", codexPath, cres.detail)
			ok = false
		}
	}

	installedOK := false
	if st, err := os.Stat(installedAgentguard); err != nil || st.IsDir() || st.Mode()&0111 == 0 {
		fmt.Printf("[FAIL] installed binary missing: %s\n", installedAgentguard)
		ok = false
	} else {
		fmt.Printf("[OK]   installed binary: %s\n", installedAgentguard)
		installedOK = true
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Printf("[WARN] executable path: %v\n", err)
	} else {
		selfResolved := resolvePath(self)
		fmt.Printf("[OK]   binary: %s\n", selfResolved)
		if installedOK {
			instResolved := resolvePath(installedAgentguard)
			if selfResolved == instResolved {
				fmt.Printf("[OK]   doctor binary is the installed agentguard\n")
			} else {
				fmt.Printf("[WARN] doctor is %s; Claude hooks use %s hook — reinstall if hook code changed\n",
					selfResolved, installedAgentguard)
			}
		}
	}

	fmt.Println()
	if !ok {
		fmt.Println("doctor: some checks failed")
		os.Exit(1)
	}
	fmt.Println("doctor: ok")
	return nil
}

var (
	claudeHookEvents = []string{"PreToolUse", "PostToolUse", "PostToolUseFailure"}
	codexHookEvents  = []string{"PreToolUse", "PostToolUse"}
)

type hookCheckResult struct {
	ok      bool
	missing bool
	oldHook bool
	command string
	detail  string
}

func doctorCheckHookSettings(settingsPath string, need []string) hookCheckResult {
	b, err := os.ReadFile(settingsPath)
	if err != nil {
		return hookCheckResult{missing: true, detail: err.Error()}
	}
	var wrap struct {
		Hooks map[string][]hookMatcher `json:"hooks"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return hookCheckResult{detail: "invalid JSON: " + err.Error()}
	}

	var sawOld bool
	var hookCmd string
	var missing []string
	for _, ev := range need {
		found := false
		for _, m := range wrap.Hooks[ev] {
			for _, h := range m.Hooks {
				c := strings.TrimSpace(h.Command)
				if strings.Contains(c, "agentguard-hook") {
					sawOld = true
				}
				if isAgentGuardHookSubcommand(c) {
					found = true
					if hookCmd == "" {
						hookCmd = c
					}
				}
			}
		}
		if !found {
			missing = append(missing, ev)
		}
	}
	if sawOld {
		return hookCheckResult{oldHook: true, detail: "still uses agentguard-hook"}
	}
	if len(missing) > 0 {
		return hookCheckResult{detail: "missing agentguard hook on " + strings.Join(missing, ", ")}
	}
	return hookCheckResult{ok: true, command: hookCmd}
}

// isAgentGuardHookSubcommand is the live hook: `agentguard hook`, not the old trampoline.
func isAgentGuardHookSubcommand(cmd string) bool {
	s := strings.TrimSpace(cmd)
	if s == "" || strings.Contains(s, "agentguard-hook") {
		return false
	}
	return strings.HasSuffix(s, "agentguard hook") || strings.Contains(s, "/agentguard hook")
}

func doctorReportSecurityfs() bool {
	if !lsmFileReadable() {
		if os.Geteuid() == 0 {
			if err := ensureSecurityfs(); err != nil {
				fmt.Printf("[WARN] securityfs unmounted: %v\n", err)
				fmt.Println("       empty /sys/kernel/security is not proof BPF LSM is off")
				return true
			}
		} else {
			fmt.Printf("[WARN] securityfs unmounted: %s not readable\n", securityfsLSMPath)
			fmt.Println("       not proof BPF LSM is off; agentguard up / sudo agentguard will try to mount")
			return true
		}
	}

	body, err := os.ReadFile(securityfsLSMPath)
	if err != nil {
		fmt.Printf("[WARN] securityfs unmounted: %s not readable (%v)\n", securityfsLSMPath, err)
		fmt.Println("       empty /sys/kernel/security is not proof BPF LSM is off")
		return true
	}
	list := strings.TrimSpace(string(body))
	if lsmListHasBPF(list) {
		fmt.Printf("[OK]   LSM list contains bpf: %s\n", list)
		return true
	}
	fmt.Printf("[FAIL] bpf is not in the LSM list: %s\n", list)
	fmt.Println("       securityfs is mounted; do not remount; do not write /sys/kernel/security/lsm")
	fmt.Println("       boot the guest with bpf in lsm= (kernel cmdline) and restart Colima / the VM")
	return false
}

func resolvePath(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}
