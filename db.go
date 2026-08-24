package main

import (
	"database/sql"
	"log"
	"time"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

var (
	db				*sql.DB
	bootTimeAnchor	time.Time
	ktimeAnchorNs	uint64
)

// --- TIME TRANSLATION ---

func initTimeAnchor() {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	ktimeAnchorNs = uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
	bootTimeAnchor = time.Now()
}

func ktimeToWallClock(ktimeNs uint64) time.Time {
	deltaNs := int64(ktimeNs) - int64(ktimeAnchorNs)
	return bootTimeAnchor.Add(time.Duration(deltaNs))
}

// monotonicNowNs returns CLOCK_MONOTONIC time in nanoseconds - the same
// clock bpf_ktime_get_ns() uses in the kernel. PendingViolation.TimestampNs
// must be stamped with this, not time.Now(), or a network violation's
// timestamp won't correspond to the kernel-reported one.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// --- DATABASE SETUP ---

func initDB(path string) {
	if path == "" {
		path = agentGuardDBPath
	}
	if err := os.MkdirAll(agentGuardLogDir, 0755); err != nil {
		log.Fatalf("failed to create db dir: %v", err)
	}

	var err error
	db, err = sql.Open("sqlite", path)
	if err != nil {
		log.Fatalf("failed to open sqlite db: %v", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		log.Printf("⚠️ sqlite WAL: %v", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		log.Printf("⚠️ sqlite busy_timeout: %v", err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp TEXT NOT NULL,
		agent_pid INTEGER NOT NULL,
		agent_name TEXT,
		event_type TEXT NOT NULL,
		path TEXT,
		destination TEXT, 
		command TEXT,
		action TEXT NOT NULL,
		policy_violated TEXT,
		feedback_sent INTEGER NOT NULL DEFAULT 0,
		payload TEXT NOT NULL DEFAULT '{}'
	);
	CREATE INDEX IF NOT EXISTS idx_events_pid ON events(agent_pid);
	CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
	CREATE INDEX IF NOT EXISTS idex_events_ts ON events(timestamp);
	`
	if _,err := db.Exec(schema); err != nil {
		log.Fatalf("failed to create schema: %v", err)
	}

	// Existing DBs created before payload existed. 
	_, _ = db.Exec(`ALTER TABLE events ADD COLUMN payload TEXT NOT NULL DEFAULT '{}'`)
}

// --- DATABASE INSERTER ---

type DBEvent struct {
	Timestamp		time.Time
	AgentPid		uint32
	AgentName		string
	EventType		string
	Path			*string
	Destination		*string
	Command			*string
	Action			string
	PolicyViolated	*string
	FeedbackSent	bool
	Payload			string
}

type auditPayload struct {
	Timestamp		string	`json:"timestamp"`
	Pid				uint32	`json:"pid"`
	Comm 			string	`json:"comm"`
	EventType		string	`json:"event_type"`
	Action			string	`json:"action"`
	Policy 			string	`json:"policy"`
	PolicyID		uint32 	`json:"policy_id"`
	Path 			*string	`json:"path"`
	Destination 	*string	`json:"destination"`
	Command 		*string	`json:"command"`
	Reason  		string	`json:"reason"`
	FeedbackSent	bool	`json:"feedback_sent"`
	SessionID		string	`json:"session_id"`
	Source			string	`json:"source"`
}

type EventRow struct {
	ID				int64 			`json:"id"`
	Timestamp		string  		`json:"timestamp"`
	AgentPid		uint32 			`json:"agent_pid"`
	AgentName		string 			`json:"agent_name"`
	EventType		string 			`json:"event_type"`
	Path			*string 		`json:"path"`
	Destination		*string 		`json:"destination"`
	Command			*string 		`json:"command"`
	Action			string 			`json:"action"`
	PolicyViolated	*string 		`json:"policy_violated"`
	FeedbackSent	bool			`json:"feedback_sent"`
	Payload			json.RawMessage `json:"payload"`
}

func nullStr(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	s := ns.String
	return &s
}

func queryEvents(filterPid *uint32, blockedOnly bool, limit int) ([]EventRow, error){
	if db == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	if limit <= 0{
		limit = 50
	}
	q := `SELECT id, timestamp, agent_pid, agent_name, event_type, path, destination, command, action, policy_violated, feedback_sent, payload FROM events`
	var where []string
	var args []any 
	if filterPid != nil {
		where = append(where, "agent_pid = ?")
		args = append(args, *filterPid)
	}
	if blockedOnly {
		where = append(where, "action = 'blocked'")
	}
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]EventRow, 0)
	for rows.Next() {
		var e EventRow
		var path, dest, cmd, pol, payload sql.NullString
		var sent int
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.AgentPid, &e.AgentName, &e.EventType, &path, &dest, &cmd, &e.Action, &pol, &sent, &payload); err != nil {
			return nil, err
		}
		e.Path = nullStr(path)
		e.Destination = nullStr(dest)
		e.Command = nullStr(cmd)
		e.PolicyViolated = nullStr(pol)
		e.FeedbackSent = sent != 0
		if payload.Valid && payload.String != "" {
			e.Payload = json.RawMessage(payload.String)
		} else {
			e.Payload = json.RawMessage(`{}`)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func lastBlockedEvent() (*EventRow, error) {
	rows, err := queryEvents(nil, true, 1)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

func insertEvent(e DBEvent) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("db not initialized")
	}
	res, err := db.Exec(
		`INSERT INTO events (timestamp, agent_pid, agent_name, event_type, path, destination, command, action, policy_violated, feedback_sent, payload)
		VALUES	(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Timestamp.UTC().Format(time.RFC3339),
		e.AgentPid, e.AgentName, e.EventType, e.Path, e.Destination, e.Command, e.Action, e.PolicyViolated, e.FeedbackSent, e.Payload,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func eventTypeForPolicy(id uint32) string {
	p, ok := policyByID[id]
	if !ok {
		return "violation"
	}
	switch p.Kind {
	case KindPath:
		return "file_open"
	case KindNetwork:
		return "connect"
	case KindCommand:
		return "exec"
	default:
		return "violation"
	}
}

// recordViolation writes one audit row for an LSM or proxy deny.
// Call this even when sessionID is empty - IPC is seperate.
func recordViolation(pid uint32, policyID uint32, comm, target, reason, sessionID, source string, tsNs uint64, feedbackSent bool) {
	if db == nil {
		return
	}
	policyName := policyNameForID(policyID)
	eventType := eventTypeForPolicy(policyID)
	ts := ktimeToWallClock(tsNs)

	var pathPtr, destPtr, cmdPtr *string
	switch eventType {
	case "connect":
		destPtr = strPtr(target)
	case "exec":
		pathPtr = strPtr(target)
		cmdPtr = strPtr(target)
	default:
		pathPtr = strPtr(target)
	}

	pl := auditPayload{
		Timestamp: 		ts.UTC().Format(time.RFC3339),
		Pid: 			pid,
		Comm: 			comm,
		EventType: 		eventType,
		Action: 		"blocked",
		Policy: 		policyName,
		PolicyID: 		policyID,
		Path:  			pathPtr, 
		Destination: 	destPtr,
		Command: 		cmdPtr,
		Reason:  		reason,
		FeedbackSent: 	feedbackSent,
		SessionID: 		sessionID,
		Source: 		source,
	}
	raw, err := json.Marshal(pl)
	if err != nil {
		log.Printf("⚠️ audit json: %v", err)
		raw = []byte("{}")
	}

	_, err = insertEvent(DBEvent{
		Timestamp:  	ts,
		AgentPid: 	 	pid,
		AgentName: 	 	"claude-code",
		EventType: 	 	eventType,
		Path: 			pathPtr,
		Destination: 	destPtr,
		Command: 		cmdPtr,
		Action: 		"blocked",
		PolicyViolated: &policyName,
		FeedbackSent: 	feedbackSent,
		Payload: 		string(raw),
	})
	if err != nil{
		log.Printf("⚠️ Failed to write audit log to DB: %v", err)
	}
}