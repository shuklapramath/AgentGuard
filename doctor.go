package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func cmdDoctor(rest []string) error {
	if len(rest) > 0 {
		return fmt.Errorf("unexpected arguments: %v", rest)
	}

	fmt.Printf("agentguard doctor %s\n", agentGuardVersion)
	fmt.Printf("os=%s arch=%s\n\n", runtime.GOOS, runtime.GOARCH)

	ok := true

	path, created, err := resolvePolicyPath(policyFlag)
	if err != nil {
		fmt.Printf("[FAIL] policy: %v\n", err)
		ok = false
	} else {
		note := "found"
		if created {
			note = "created starter"
		}
		fmt.Printf("[OK]   policy (%s): %s\n", note, path)
	}

	btf := "/sys/kernel/btf/vmlinux"
	if st, err := os.Stat(btf); err != nil {
		fmt.Printf("[FAIL] BTF: %s not readable (%v)\n", btf, err)
		ok = false
	} else {
		fmt.Printf("[OK]   BTF: %s (%d bytes)\n", btf, st.Size())
	}

	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		fmt.Printf("[WARN] /proc/cmdline: %v (are you on Linux?)\n", err)
		if runtime.GOOS != "linux" {
			fmt.Println("       AgentGuard enforcement requires Linux (or Colima/Docker Linux VM).")
			ok = false
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

	if path, err := exec.LookPath("docker"); err != nil {
		fmt.Printf("[INFO] docker: not on PATH\n")
	} else {
		fmt.Printf("[INFO] docker: %s\n", path)
		if err := exec.Command("docker", "info").Run(); err != nil {
			fmt.Printf("[WARN] docker info failed: %v\n", err)
		} else {
			fmt.Printf("[OK]   docker daemon reachable\n")
		}
	}
	if path, err := exec.LookPath("colima"); err != nil {
		fmt.Printf("[INFO] colima: not on PATH\n")
	} else {
		fmt.Printf("[INFO] colima: %s\n", path)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Printf("[WARN] executable path: %v\n", err)
	} else {
		fmt.Printf("[OK]   binary: %s\n", self)
		fmt.Printf("       Claude hook command should be: %s hook\n", self)
	}

	fmt.Println()
	if !ok {
		fmt.Println("doctor: some checks failed")
		os.Exit(1)
	}
	fmt.Println("doctor: ok")
	return nil
}
