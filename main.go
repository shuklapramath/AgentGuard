package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go monitor monitor.bpf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go enforcer enforcer.bpf.c

// verbose enables ultra-noisy per-event JSON and full SSL request dumps in the log file.
var verbose bool

// agentGuardLogFile is the durable log sink; after launch-mode Claude starts we
// point log.SetOutput exclusively here so the shared TTY stays clean.
var agentGuardLogFile *os.File

// initAgentGuardLog sends the standard library logger (and thus all log.Printf
// across main/proxy/socks/db) to a file. During startup we also mirror to stderr
// so operators see progress; call quietAgentGuardLogs() before handing the TTY
// to Claude in launch mode.
func initAgentGuardLog() (*os.File, error) {
	if err := os.MkdirAll(agentGuardLogDir, 0777); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	_ = os.Chmod(agentGuardLogDir, 0777)
	f, err := os.OpenFile(agentGuardLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	agentGuardLogFile = f
	log.SetOutput(io.MultiWriter(f, os.Stderr))
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	fmt.Fprintf(os.Stderr, "AgentGuard: logging to %s\n", agentGuardLogPath)
	if verbose {
		fmt.Fprintf(os.Stderr, "AgentGuard: verbose event logging enabled\n")
	}
	log.Printf("=== AgentGuard log started (verbose=%v) ===", verbose)
	return f, nil
}

// quietAgentGuardLogs stops mirroring to stderr so Claude's TUI is undisturbed.
func quietAgentGuardLogs() {
	if agentGuardLogFile == nil {
		return
	}
	log.SetOutput(agentGuardLogFile)
	fmt.Fprintf(os.Stderr, "AgentGuard: TTY quiet — follow logs with: tail -f %s\n", agentGuardLogPath)
	log.Printf("=== TTY quiet mode (logs file-only) ===")
}

type NamedPattern struct {
	Pattern  string
	PolicyID uint32
}

type PendingViolation struct {
	Reason      string `json:"reason"`
	PolicyType  uint8  `json:"policy_type"`
	Path        string `json:"path"`
	TimestampNs uint64 `json:"timestamp_ns"`
}

type Event struct {
	TimestampNs uint64
	Pid         uint32
	Ppid        uint32
	Comm        [16]byte
	EventType   uint8
	FileName    [256]byte
	Daddr       [4]byte
	Dport       uint16
	Command     [256]byte
	PolicyType  uint32
}

type OutputEvent struct {
	TimestampNs uint64 `json:"timestamp_ns"`
	Pid         uint32 `json:"pid"`
	Ppid        uint32 `json:"ppid,omitempty"`
	Comm        string `json:"comm"`
	EventType   string `json:"event_type"`
	FileName    string `json:"filename,omitempty"`
	DestIP      string `json:"dest_ip,omitempty"`
	DestPort    uint16 `json:"dest_port,omitempty"`
	Command     string `json:"command,omitempty"`
}

type ProcessNode struct {
	Pid      uint32
	Ppid     uint32
	Comm     string
	Children []*ProcessNode
	Events   []OutputEvent
}

type ViolationEvent struct {
	TimestampNs   uint64
	Pid           uint32
	PolicyType    uint32
	TypedComm     [16]byte
	CanonicalPath [256]byte
	Detail        [256]byte
}

type AgentPolicy struct {
	Description string `yaml:"description"`
	BlockOn     struct {
		PathPatterns    []string `yaml:"path_patterns"`
		CommandPatterns []string `yaml:"command_patterns"`
		AllowedHosts    []string `yaml:"allowed_hosts"`
		AllowedPorts    []string `yaml:"allowed_ports"`
		//DestinationNotIn []string `yaml:"destination_not_in"`
	} `yaml:"block_on"`
	Egress        string `yaml:"egress"`
	AllowLocalDNS bool   `yaml:"allow_local_dns"`

	Proxy struct {
		Listen          string `yaml:"listen"`
		RequireSNIMatch bool   `yaml:"require_sni_match"`
		AllowIPLiterals bool   `yaml:"allow_ip_literals"`
	} `yaml:"proxy"`

	Feedback string `yaml:"feedback"`
}

type PolicyKind int

const (
	KindPath PolicyKind = iota
	KindNetwork
	KindCommand
)

type ResolvedPolicy struct {
	Name     string
	Kind     PolicyKind
	ID       uint32
	Feedback string
}

type PolicyFile struct {
	Policies map[string]AgentPolicy `yaml:"policies"`
}

var (
	policyByID = make(map[uint32]ResolvedPolicy)

	sessionIDByPid = make(map[uint32]string)
	sessionMutex   sync.Mutex

	tree    = make(map[uint32]*ProcessNode)
	rootPID uint32
)

func loadAllPolicies(pf *PolicyFile) (
	pathPatterns []NamedPattern,
	commandPatterns []NamedPattern,
	proxyPolicy *ProxyPolicy,
	enforceNetwork bool,
	allowLocalDNS bool,
) {
	var nextID uint32 = 1

	names := make([]string, 0, len(pf.Policies))
	for name := range pf.Policies {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		p := pf.Policies[name]
		id := nextID
		nextID++

		switch {
		case len(p.BlockOn.PathPatterns) > 0:
			policyByID[id] = ResolvedPolicy{Name: name, Kind: KindPath, ID: id, Feedback: p.Feedback}
			for _, pattern := range p.BlockOn.PathPatterns {
				clean := strings.TrimPrefix(pattern, "**/")
				pathPatterns = append(pathPatterns, NamedPattern{Pattern: clean, PolicyID: id})
			}
		case len(p.BlockOn.AllowedHosts) > 0:
			policyByID[id] = ResolvedPolicy{Name: name, Kind: KindNetwork, ID: id, Feedback: p.Feedback}
			portMap := make(map[int]bool)
			for _, portStr := range p.BlockOn.AllowedPorts {
				portVal, err := strconv.Atoi(portStr)
				if err != nil {
					log.Printf("⚠️ Ignoring invalid allowed port %q: %v", portStr, err)
					continue
				}
				portMap[portVal] = true
			}
			proxyPolicy = &ProxyPolicy{
				PolicyID:       id,
				Feedback:       p.Feedback,
				AllowedHosts:   p.BlockOn.AllowedHosts,
				AllowedPorts:   portMap,
				AllowIPLiteral: p.Proxy.AllowIPLiterals,
			}
			enforceNetwork = p.Egress == "proxy_only"
			allowLocalDNS = p.AllowLocalDNS

		case len(p.BlockOn.CommandPatterns) > 0:
			policyByID[id] = ResolvedPolicy{Name: name, Kind: KindCommand, ID: id, Feedback: p.Feedback}
			for _, pattern := range p.BlockOn.CommandPatterns {
				bare := coarseReduceCommand(pattern)
				commandPatterns = append(commandPatterns, NamedPattern{Pattern: bare, PolicyID: id})
			}
		}
	}
	return
}

func coarseReduceCommand(pattern string) string {
	fields := strings.Fields(pattern)
	if len(fields) == 0 {
		return pattern
	}
	first := fields[0]
	// if it's a full path like /usr/bin/rm, keep as-is; otherwise it's a bare command like "mkfs"
	if strings.HasPrefix(first, "/") {
		return first
	}
	return first // "rm - rf /*" -> "rm"
}

func loadPolicies(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

func writePendingViolation(sessionID string, v PendingViolation) error {
	if sessionID == "" {
		return fmt.Errorf("empty session id")
	}
	if err := os.MkdirAll(violationStoreDir, 0777); err != nil {
		return err
	}
	_ = os.Chmod(violationStoreDir, 0777)

	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	// Session-scoped file the feedback-hook looks up by Claude's session_id.
	path := filepath.Join(violationStoreDir, sessionID+".json")
	if err := os.WriteFile(path, data, 0666); err != nil {
		return err
	}
	// Linux does not update mode on overwrite of an existing file — force it.
	_ = os.Chmod(path, 0666)

	// Mirror for hook fallback when session ids briefly disagree.
	latest := filepath.Join(violationStoreDir, "latest.json")
	if err := os.WriteFile(latest, data, 0666); err != nil {
		return err
	}
	_ = os.Chmod(latest, 0666)
	return nil
}

// Retrieve SessionID for a given PID
func getSessionIDForPID(pid uint32) string {
	sessionMutex.Lock()
	defer sessionMutex.Unlock()
	return sessionIDByPid[pid]
}

// resolveSessionID picks the session id used to key violation IPC files.
// Priority: Claude hook ground truth (active_session, UUID-shaped only) →
// exact PID SSL map → agent root PID (tools/children inherit enforcement
// but not always the map). Non-UUID junk in active_session (e.g. test
// leftovers) must not win over the PID map.
// SOLUTION #1: Retries reading active_session with small delay to handle
// race condition where PreToolUse hook may still be writing it.
func resolveSessionID(pid uint32) string {
	// Retry reading active_session up to 3 times with short delays
	// This handles race conditions where PreToolUse hook just wrote it
	for attempt := 0; attempt < 3; attempt++ {
		if b, err := os.ReadFile(activeSessionPath); err == nil {
			if s := strings.TrimSpace(string(b)); isHookSessionID(s) {
				return s
			}
		}
		if attempt < 2 {
			// Small delay before retry (10ms)
			select {
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	if s := getSessionIDForPID(pid); s != "" {
		return s
	}
	if rootPID != 0 {
		if s := getSessionIDForPID(rootPID); s != "" {
			return s
		}
	}
	return ""
}

// isHookSessionID accepts Claude Code / Cursor session UUIDs only.
func isHookSessionID(s string) bool {
	if len(s) < 36 {
		return false
	}
	// xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	return true
}

func formatFeedbackReason(policyType uint32, path string) string {
	policy, exists := policyByID[policyType]
	if !exists {
		// Fallback if the kernel sends a policy ID we don't recognize
		return "Action blocked by security policy."
	}

	// Check if the reason string has a '%s' placeholder for the path
	if strings.Contains(policy.Feedback, "%s") {
		return fmt.Sprintf(policy.Feedback, path)
	}

	// If no placeholder, just return the static string
	return policy.Feedback
}

func policyNameForID(policyID uint32) string {
	if p, exists := policyByID[policyID]; exists {
		return p.Name
	}
	return "unknown_policy"
}

func getOrCreateNode(pid uint32) *ProcessNode {
	if node, ok := tree[pid]; ok {
		return node
	}
	node := &ProcessNode{Pid: pid}
	tree[pid] = node
	return node
}

func parseCString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		return string(b) //No null byte found, return the whole thing
	}
	return string(b[:idx]) // Slice off the null byte and everything after it
}

const (
	maxPathPatternSlots    = 16
	maxCommandPatternSlots = 16
	bpfPatternKeySize      = 64
)

// pathPatternEntryBPF must match struct path_pattern_entry in enforcer.bpf.c.
type pathPatternEntryBPF struct {
	Pattern    [bpfPatternKeySize]byte
	PolicyID   uint32
	PatternLen uint8
	_          [3]byte
}

// normalizePathSuffix turns YAML patterns into exact path suffixes for BPF.
// ".env" -> "/.env", "id_rsa" -> "/id_rsa", "/abs" stays "/abs".
func normalizePathSuffix(pattern string) (string, error) {
	p := strings.TrimSpace(strings.TrimPrefix(pattern, "**/"))
	if p == "" {
		return "", fmt.Errorf("empty path pattern")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > bpfPatternKeySize {
		return "", fmt.Errorf("path pattern %q exceeds %d bytes", p, bpfPatternKeySize)
	}
	return p, nil
}

// applyPathPatterns loads path suffix rules into blocked_path_patterns (ARRAY).
func applyPathPatterns(m *ebpf.Map, patterns []NamedPattern) error {
	if len(patterns) > maxPathPatternSlots {
		return fmt.Errorf("too many path patterns: %d > %d", len(patterns), maxPathPatternSlots)
	}

	log.Printf("[+] Loading %d path suffix rules...", len(patterns))

	for i := uint32(0); i < maxPathPatternSlots; i++ {
		empty := pathPatternEntryBPF{}
		if err := m.Update(&i, &empty, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear path slot %d: %w", i, err)
		}
	}

	for i, p := range patterns {
		suffix, err := normalizePathSuffix(p.Pattern)
		if err != nil {
			return fmt.Errorf("policy=%d: %w", p.PolicyID, err)
		}

		var ent pathPatternEntryBPF
		copy(ent.Pattern[:], suffix)
		ent.PolicyID = p.PolicyID
		ent.PatternLen = uint8(len(suffix))

		idx := uint32(i)
		if err := m.Update(&idx, &ent, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load path pattern %q: %w", suffix, err)
		}
		log.Printf("	-> slot=%d policy=%d suffix=%q", i, p.PolicyID, suffix)
	}
	return nil
}

// normalizeCommandSuffix turns YAML command names into a basename suffix.
// "rm", "/usr/bin/rm", "/bin/rm" -> "/rm".
func normalizeCommandSuffix(pattern string) (string, error) {
	p := strings.TrimSpace(pattern)
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", fmt.Errorf("empty command pattern")
	}
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	if p == "" {
		return "", fmt.Errorf("empty command basename")
	}
	return normalizePathSuffix(p)
}

// applyCommandPatterns loads basename suffix rules into blocked_command_patterns (ARRAY).
func applyCommandPatterns(m *ebpf.Map, patterns []NamedPattern) error {
	suffixes := make([]NamedPattern, 0, len(patterns))
	seen := make(map[string]struct{})
	for _, p := range patterns {
		suffix, err := normalizeCommandSuffix(p.Pattern)
		if err != nil {
			return fmt.Errorf("policy=%d: %w", p.PolicyID, err)
		}
		if _, dup := seen[suffix]; dup {
			continue
		}
		seen[suffix] = struct{}{}
		suffixes = append(suffixes, NamedPattern{Pattern: suffix, PolicyID: p.PolicyID})
	}

	if len(suffixes) > maxCommandPatternSlots {
		return fmt.Errorf("too many command patterns: %d > %d", len(suffixes), maxCommandPatternSlots)
	}

	log.Printf("[+] Loading %d command basename suffix rules...", len(suffixes))

	for i := uint32(0); i < maxCommandPatternSlots; i++ {
		empty := pathPatternEntryBPF{}
		if err := m.Update(&i, &empty, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("clear command slot %d: %w", i, err)
		}
	}

	for i, p := range suffixes {
		var ent pathPatternEntryBPF
		copy(ent.Pattern[:], p.Pattern)
		ent.PolicyID = p.PolicyID
		ent.PatternLen = uint8(len(p.Pattern))

		idx := uint32(i)
		if err := m.Update(&idx, &ent, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("load command pattern %q: %w", p.Pattern, err)
		}
		log.Printf("	-> slot=%d policy=%d suffix=%q", i, p.PolicyID, p.Pattern)
	}
	return nil
}

func main() {
	initStateDirs()
	args := parseAgentGuardArgs()
	if len(args) < 2 {
		printUsage()
		os.Exit(2)
	}
	if dispatchCLI(args) {
		return
	}
	runEnforcer(args)
}

// runEnforcer is the heavy path: load BPF, apply policies, launch or attach.
func runEnforcer(args []string) {
	logFile, err := initAgentGuardLog()
	if err != nil {
		fmt.Fprintf(os.Stderr, "AgentGuard: failed to init log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	if self, err := os.Executable(); err == nil {
		hookBinaryPath = self + " hook"
	} else {
		hookBinaryPath = "agentguard hook"
	}

	// --- INITIALIZE TIME ANCHOR & DATABASE
	initTimeAnchor()
	initDB(agentGuardDBPath)
	apiStartedAt = time.Now()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}
	if err := ensureSecurityfs(); err != nil {
		log.Printf("securityfs unmounted: %v (empty /sys/kernel/security is not proof BPF LSM is off)", err)
	} else if lsmFileReadable() {
		body, err := os.ReadFile(securityfsLSMPath)
		if err != nil {
			log.Printf("securityfs: %s not readable after mount: %v", securityfsLSMPath, err)
		} else {
			list := strings.TrimSpace(string(body))
			if lsmListHasBPF(list) {
				log.Printf("LSM list contains bpf: %s", list)
			} else {
				log.Fatalf("bpf is not in the LSM list: %s (securityfs is mounted; do not remount; do not write %s; boot the guest with lsm=...,bpf and restart the VM)", list, securityfsLSMPath)
			}
		}
	}
	pidnsDev, pidnsIno, err := currentPidns()
	if err != nil {
		log.Fatalf("pid ns: %v", err)
	}
	log.Printf("pid ns dev=%d ino=%d (tracked_pids keys use this namespace)", pidnsDev, pidnsIno)

	monSpec, err := loadMonitor()
	if err != nil {
		log.Fatal(err)
	}
	if err := monSpec.Variables["pidns_dev"].Set(pidnsDev); err != nil {
		log.Fatalf("failed to set monitor pidns_dev: %v", err)
	}
	if err := monSpec.Variables["pidns_ino"].Set(pidnsIno); err != nil {
		log.Fatalf("failed to set monitor pidns_ino: %v", err)
	}
	objs := monitorObjects{}
	if err := monSpec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	policyPath, created, err := resolvePolicyPath(policyFlag)
	if err != nil {
		log.Fatalf("failed to resolve policy: %v", err)
	}
	apiPolicyPath = policyPath
	if created {
		log.Printf("AgentGuard: created %s (starter policy — edit to customize)", policyPath)
	} else {
		log.Printf("AgentGuard: using policy %s", policyPath)
	}

	pf, err := loadPolicies(policyPath)
	if err != nil {
		log.Fatalf("failed to load policies: %v", err)
	}

	// Call new function to get seperated lists here
	credentialPatterns, commandPatterns, proxyPolicy, enforceNetwork, allowLocalDNS := loadAllPolicies(pf)

	// Blind the proxy listener now (if configured) so we know its real port
	// before freezing the enforcer's .rodata.
	var proxyServer *ProxyServer
	var proxyAddrHost uint32
	var proxyPortHost uint16
	if proxyPolicy != nil {
		listenAddr := "127.0.0.1:0"
		proxyServer, err = NewProxyServer(proxyPolicy, listenAddr)
		if proxyServer != nil {
			apiProxyAddr = proxyServer.Addr()
		}
		if err != nil {
			log.Fatalf("failed to start proxy: %v", err)
		}
		proxyAddrHost = 0x7f000001 // 127.0.0.1
		proxyPortHost = uint16(proxyServer.port)
		log.Printf("🔒 Proxy listening on %s (token issued)", proxyServer.Addr())
	}

	dnsAddrHost := uint32(0x7f000035) // 127.0.0.53, systemd-resolved default
	var networkPolicyID uint32
	if proxyPolicy != nil {
		networkPolicyID = proxyPolicy.PolicyID
	}

	// --- Load enforcer with .rodata constants frozen in via RewriteConstants.
	// (Verify `loadEnforcer` matches generated file's spec-loader name.)
	enforcerSpec, err := loadEnforcer()
	if err != nil {
		log.Fatalf("failed to load enforcer spec: %v", err)
	}

	if err := enforcerSpec.Variables["proxy_addr_host"].Set(proxyAddrHost); err != nil {
		log.Fatalf("failed to set proxy_addr_host: %v", err)
	}
	if err := enforcerSpec.Variables["proxy_port_host"].Set(proxyPortHost); err != nil {
		log.Fatalf("failed to set proxy_port_host: %v", err)
	}
	if err := enforcerSpec.Variables["dns_addr_host"].Set(dnsAddrHost); err != nil {
		log.Fatalf("failed to set dns_addr_host: %v", err)
	}
	if err := enforcerSpec.Variables["network_policy_id"].Set(networkPolicyID); err != nil {
		log.Fatalf("failed to set network_policy_id: %v", err)
	}
	if err := enforcerSpec.Variables["pidns_dev"].Set(pidnsDev); err != nil {
		log.Fatalf("failed to set enforcer pidns_dev: %v", err)
	}
	if err := enforcerSpec.Variables["pidns_ino"].Set(pidnsIno); err != nil {
		log.Fatalf("failed to set enforcer pidns_ino: %v", err)
	}

	enforcerObjs := enforcerObjects{}
	if err := enforcerSpec.LoadAndAssign(&enforcerObjs, &ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tracked_pids": objs.TrackedPids,
		},
	}); err != nil {
		log.Fatal(err)
	}
	defer enforcerObjs.Close()

	if err := enforcerObjs.EnforceNetwork.Set(boolToU8(enforceNetwork)); err != nil {
		log.Printf("⚠️ failed to set enforce_network: %v", err)
	}
	if err := enforcerObjs.AllowLocalDns.Set(boolToU8(allowLocalDNS)); err != nil {
		log.Printf("⚠️ failed to set allow_local_dns: %v", err)
	}

	// Push file-path suffixes into blocked_path_patterns (ARRAY of path_pattern_entry).
	if err := applyPathPatterns(enforcerObjs.BlockedPathPatterns, credentialPatterns); err != nil {
		log.Fatalf("failed to load credential path patterns: %v", err)
	}

	// Push command basename suffixes into blocked_command_patterns (ARRAY).
	if err := applyCommandPatterns(enforcerObjs.BlockedCommandPatterns, commandPatterns); err != nil {
		log.Fatalf("failed to load command patterns: %v", err)
	}

	if proxyServer != nil {
		log.Printf("🔑 Proxy auth token: %s", proxyServer.Token())
		log.Printf("🔒 Proxy listening on %s", proxyServer.Addr())
		go proxyServer.Serve()
	}

	var (
		targetPID int
		//targetPath string
		agentCmd *exec.Cmd // nil in attach-PID mode
	)

	switch {
	case len(args) >= 3 && args[1] == "--":
		// Launch mode: sudo ./agentguard [--verbose] -- /home/ebpf/.local/bin/claude ...
		if proxyServer == nil {
			log.Fatal("launch mode requires exfiltration_prevention / proxy policy")
		}
		proxyURL := fmt.Sprintf("http://user:%s@%s", proxyServer.Token(), proxyServer.Addr())

		id, idErr := sudoLaunchIdentity()
		if idErr != nil {
			log.Fatalf("launch identity: %v", idErr)
		}
		if id == nil && os.Geteuid() == 0 {
			log.Printf("WARNING: running as root without SUDO_USER — agent will use /root/.claude")
		}

		agentPath := resolveAgentPath(args[2], id)
		agentCmd = exec.Command(agentPath, args[3:]...)
		applyLaunchIdentity(agentCmd, id, []string{
			"HTTP_PROXY=" + proxyURL,
			"HTTPS_PROXY=" + proxyURL,
			"http_proxy=" + proxyURL,
			"https_proxy=" + proxyURL,
			"NO_PROXY=127.0.0.1,localhost,::1",
			"no_proxy=127.0.0.1,localhost,::1",
		})
		agentCmd.Stdin = os.Stdin
		agentCmd.Stdout = os.Stdout
		agentCmd.Stderr = os.Stderr

		// Hand the TTY to Claude: stop mirroring AgentGuard logs to stderr.
		quietAgentGuardLogs()

		if err := agentCmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start agent: %v\n", err)
			log.Fatalf("failed to start agent: %v", err)
		}
		targetPID = agentCmd.Process.Pid
		if id != nil {
			log.Printf("🚀 launched agent pid=%d uid=%d user=%s home=%s path=%s via proxy %s",
				targetPID, id.Uid, id.User, id.Home, agentPath, proxyServer.Addr())
		} else {
			log.Printf("🚀 launched agent pid=%d via proxy %s", targetPID, proxyServer.Addr())
		}

	case len(args) >= 2:
		// Debug attach mode (old behavior)
		targetPID, err = strconv.Atoi(args[1])
		if err != nil {
			log.Fatal("Invalid pid: ", err)
		}
		//targetPath, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", targetPID))
		log.Printf("tracking existing pid %d", targetPID)

	default:
		printUsage()
		os.Exit(2)
	}

	if err := objs.TrackedPids.Update(uint32(targetPID), uint8(1), 0); err != nil {
		log.Fatal("failed to add pid to map:", err)
	}
	apiTrackedPids = objs.TrackedPids
	log.Printf("tracking pid %d\n", targetPID)

	rootPID = uint32(targetPID)
	root := getOrCreateNode(rootPID)
	root.Comm = "root"

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.HandleOpenat, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpOpen.Close()

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.HandleExit, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpExit.Close()

	tpConnect, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.HandleConnect, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpConnect.Close()

	tpFork, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: objs.HandleFork,
	})
	if err != nil {
		log.Fatal("attach raw_tp/sched_process_fork: ", err)
	}
	defer tpFork.Close()

	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer tpExecve.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatal(err)
	}
	defer rd.Close()

	lsmLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcerObjs.CheckFileOpen,
	})
	if err != nil {
		log.Fatal("attaching LSM hook failed:", err)
	}
	defer lsmLink.Close()

	lsmConnectLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcerObjs.CheckSocketConnect,
	})
	if err != nil {
		log.Fatalf("Failed to attach socket_connect LSM hook:  %v", err)
	}
	defer lsmConnectLink.Close()

	// UDP sendmsg exfiltration path
	lsmSendmsgLink, err := link.AttachLSM(link.LSMOptions{Program: enforcerObjs.CheckSocketSendmsg})
	if err != nil {
		log.Fatalf("Failed to attach socket_sendmsg LSM hook: %v", err)
	}
	defer lsmSendmsgLink.Close()

	// raw-socket creation
	lsmSocketCreateLink, err := link.AttachLSM(link.LSMOptions{Program: enforcerObjs.CheckSocketCreate})
	if err != nil {
		log.Fatalf("Failed to attach socket_create LSM hook: %v", err)
	}
	defer lsmSocketCreateLink.Close()

	// Anti -rm -rf hook
	lsmExecLink, err := link.AttachLSM(link.LSMOptions{
		Program: enforcerObjs.CheckExec,
	})
	if err != nil {
		log.Fatalf("Failed to attach bprm_check_security LSM hook: %v", err)
	}
	defer lsmExecLink.Close()

	// Plug go into the other end of the pipe so it can start catching the reports
	violationReader, err := ringbuf.NewReader(enforcerObjs.Violations)
	if err != nil {
		log.Fatalf("Failed to open violations ring buffer: %v", err)
	}
	defer violationReader.Close()

	go func() {
		var vEvent ViolationEvent
		for {
			// Wait for a violation event from the kernel
			record, err := violationReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return // Program is exiting
				}
				log.Printf("Error reading from violations ringbuf: %v", err)
				continue
			}

			// Decode the raw bytes into our Go struct
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &vEvent); err != nil {
				log.Printf("Failed to parse violation event: %v", err)
				continue
			}

			// Clean up the string using the helper function from earlier
			cleanPath := parseCString(vEvent.Detail[:])

			// Updated alert to show the process name that attempted the bad command
			cleanComm := parseCString(vEvent.TypedComm[:])

			// Step 4
			log.Printf("[STEP 4 CONFIRMED] Kernel LSM fired! Received ViolationEvent for PID %d on target %s\n", vEvent.Pid, cleanPath)

			// High-priority alert (log file only — keeps Claude TTY clean)
			log.Printf("🚨 SECURITY VIOLATION BLOCKED 🚨")
			log.Printf("PID: %d | Policy Type: %d | Process: %s | Target: %s",
				vEvent.Pid, vEvent.PolicyType, cleanComm, cleanPath)

			// Resolve session for IPC (hook active_session → PID map → rootPID)
			// SOLUTION #1: PreToolUse hook pre-registers session ID in active_session file
			// before tools execute, so this resolution has the best chance of finding it
			reason := formatFeedbackReason(vEvent.PolicyType, cleanPath)
			sessionID := resolveSessionID(vEvent.Pid)
			feedbackSent := false
			if sessionID != "" {
				err := writePendingViolation(sessionID, PendingViolation{
					Reason:      reason,
					PolicyType:  uint8(vEvent.PolicyType),
					Path:        cleanPath,
					TimestampNs: vEvent.TimestampNs,
				})
				if err != nil {
					log.Printf("❌ Failed to write IPC violation file for session %s: %v", sessionID, err)
				} else {
					feedbackSent = true
					log.Printf("[STEP 5 CONFIRMED] ✅ Violation written for session %s (will be delivered by feedback hook)", sessionID)
				}
			} else {
				log.Printf("⚠️ Violation caught for PID %d, but no Session ID mapped yet.", vEvent.Pid)
			}

			recordViolation(vEvent.Pid, vEvent.PolicyType, cleanComm, cleanPath,
				reason, sessionID, "lsm", vEvent.TimestampNs, feedbackSent)
		}
	}()

	// --- Graceful shutdown for the long-lived proxy: SIGINT/SIGTERM now close
	// the proxy listener cleanly via context cacellation.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		<-ctx.Done()
		if proxyServer != nil {
			proxyServer.Close()
		}
		if agentCmd != nil && agentCmd.Process != nil {
			_ = agentCmd.Process.Signal(syscall.SIGTERM)
		}
	}()

	log.Println("listening for events...")

	apiAddr := os.Getenv("AGENTGUARD_API_ADDR")
	go serveAPI(apiAddr)

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Println("read error:", err)
				return
			}
			var e Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
				log.Println("decode error:", err)
				continue
			}
			//log.Printf("pid=%d comm=%s time=%d\n", e.Pid, string(bytes.TrimRight(e.Comm[:], "\x00")), e.TimestampNs)

			out := OutputEvent{
				TimestampNs: e.TimestampNs,
				Pid:         e.Pid,
				Comm:        parseCString(e.Comm[:]),
			}

			switch e.EventType {
			case 1:
				out.EventType = "file_open"
				//out.FileName = string(bytes.Trim(e.FileName[:], "\x00"))
				out.FileName = parseCString(e.FileName[:])
			case 2:
				out.EventType = "connect"
				out.DestIP = net.IP(e.Daddr[:]).String()
				out.DestPort = e.Dport
			case 3:
				out.EventType = "exec"
				out.FileName = parseCString(e.FileName[:])
				out.Command = parseCString(e.Command[:])
				node := getOrCreateNode(e.Pid)
				node.Comm = out.FileName

			case 4:
				out.EventType = "fork"
				out.Ppid = e.Ppid
				child := getOrCreateNode(e.Pid)
				child.Ppid = e.Ppid
				parent := getOrCreateNode(e.Ppid)
				parent.Children = append(parent.Children, child)
			}

			// record every event
			node := getOrCreateNode(e.Pid)
			if node.Comm == "" {
				node.Comm = out.Comm
			}
			node.Events = append(node.Events, out) // Add the complete output

			data, _ := json.Marshal(out)
			if verbose {
				log.Println(string(data))
			}
		}
	}()

	if agentCmd != nil {
		err := agentCmd.Wait()
		if err != nil {
			log.Printf("agent exited: %v", err)
		}
	} else {
		<-ctx.Done()
	}
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
