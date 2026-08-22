package main
import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	//"path/filepath"
	"strconv"
	"strings"
	"time"
	"github.com/cilium/ebpf"
)
const (
	defaultAPIAddr = "127.0.0.1:7432"
	hookBinaryPath = "/home/ebpf/.local/bin/agentguard-hook"
)

var (
	apiStartedAt  time.Time
	apiTrackedPids *ebpf.Map
	apiProxyAddr  string
)

type apiResponse struct {
	OK bool `json:"ok"`
	Data interface{} `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOK(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Data: data})
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiResponse{OK : false, Error: msg})
}

func serveAPI(addr string){
	if addr == "" {
		addr = defaultAPIAddr
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handleHealth)
	mux.HandleFunc("GET /api/events", handleEvents)
	mux.HandleFunc("GET /api/violations", handleViolations)
	mux.HandleFunc("GET /api/policies", handlePolicies)
	mux.HandleFunc("GET /api/agents", handleAgents)
	mux.HandleFunc("GET /api/feedback/status", handleFeedbackStatus)

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("🌐 API listening on http://%s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("⚠️ API server: %v", err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request){
	writeOK(w, map[string]interface{}{
		"status":	"ok",
		"uptime_sec" : int(time.Since(apiStartedAt).Seconds()),
		"root_pid": rootPID,
		"proxy_addr": apiProxyAddr,
		"db_path": agentGuardDBPath,
		"db_ready": db != nil,
	})
}

func parseLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n <= 0 {
		return 50
	}
	if n > 500 {
		return 500
	}
	return n
}

func parsePIDQuery(r * http.Request) (*uint32, error) {
	s := strings.TrimSpace(r.URL.Query().Get("pid"))
	if s == ""{
		return nil, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	pid := uint32(n)
	return &pid, nil
}

func handleEvents(w http.ResponseWriter, r *http.Request){
	pid, err := parsePIDQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid pid")
		return
	}
	rows, err := queryEvents(pid, false, parseLimit(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, rows)
}

func handleViolations(w http.ResponseWriter, r *http.Request){
	pid, err := parsePIDQuery(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid pid")
		return
	}
	rows, err := queryEvents(pid, true, parseLimit(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeOK(w, rows)
}

func kindName(k PolicyKind) string {
	switch k {
	case KindPath:
		return "path"
	case KindNetwork:
		return "network"
	case KindCommand:
		return "command"
	default:
		return "unknown"
	}
}

func handlePolicies(w http.ResponseWriter, r *http.Request) {
	if apiPolicyPath == "" {
		writeErr(w, http.StatusInternalServerError, "policy path not set")
		return
	}
	pf, err := loadPolicies(apiPolicyPath)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	idByName := make(map[string]ResolvedPolicy)
	for _, p := range policyByID {
		idByName[p.Name] = p
	}
	out := make([]map[string]interface{}, 0, len(pf.Policies))
	for name, pol := range pf.Policies {
		item := map[string]interface{} {
			"name": 			name,
			"description": 		pol.Description,
			"feedback": 		pol.Feedback,
			"path_patterns": 	pol.BlockOn.PathPatterns,
			"command_patterns": pol.BlockOn.CommandPatterns,
			"allowed_hosts": 	pol.BlockOn.AllowedHosts,
			"allowed_ports": 	pol.BlockOn.AllowedPorts,
			"egress": 			pol.Egress,
			"allow_local_dns": 	pol.AllowLocalDNS,
		}
		if rp, ok := idByName[name]; ok {
			item["id"] = rp.ID
			item["kind"] = kindName(rp.Kind)
		}
		out = append(out, item)
	}
	writeOK(w, out)
}

type agentInfo struct {
	Pid  		uint32 `json:"pid"`
	Comm 		string `json:"comm"`
	Ppid 		uint32 `json:"ppid,omitempty"`
	SessionID 	string `json:"session_id,omitempty"`
	IsRoot 		bool   `json:"is_root"`
}

func handleAgents(w http.ResponseWriter, r *http.Request) {
	if apiTrackedPids == nil {
		writeErr(w, http.StatusServiceUnavailable, "tracked_pids map not ready")
	}
	it := apiTrackedPids.Iterate()
	var pid uint32
	var one uint8
	var agents []agentInfo
	for it.Next(&pid, &one) {
		a := agentInfo{Pid : pid, IsRoot: pid == rootPID}
		if node, ok := tree[pid]; ok {
			a.Comm = node.Comm
			a.Ppid = node.Ppid
		}
		sessionMutex.Lock()
		a.SessionID = sessionIDByPid[pid]
		sessionMutex.Unlock()
		agents = append(agents, a)
	}
	if err := it.Err(); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if agents == nil {
		agents = []agentInfo{}
	}
	writeOK(w, agents)
}

func handleFeedbackStatus(w http.ResponseWriter, r *http.Request){
	pending := 0
	if ents, err := os.ReadDir(violationStoreDir); err == nil {
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				pending++
			}
		}
	}
	session := ""
	if b, err := os.ReadFile(activeSessionPath); err == nil {
		session = strings.TrimSpace(string(b))
	}
	st, err := os.Stat(hookBinaryPath)
	hookOK := err == nil && st.Size() > 0 && st.Size() < 8*1024*1024 // enforcer is ~14MB

	last, _ := lastBlockedEvent()
	writeOK(w, map[string]interface{}{
		"hook_path":    			hookBinaryPath,
		"hook_ok":    		  		hookOK,
		"active_session": 			session,
		"pending_violation_files":  pending,
		"last_blocked": 			last,
	})
}