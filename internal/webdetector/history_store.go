package webdetector

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
	_ "modernc.org/sqlite"
)

type HistoryEvent struct {
	ID      int64                  `json:"id"`
	TsUnix  int64                  `json:"ts_unix"`
	TsUTC   string                 `json:"ts_utc,omitempty"`
	Type    string                 `json:"event_type"`
	Host    string                 `json:"host,omitempty"`
	IP      string                 `json:"ip,omitempty"`
	Mode    string                 `json:"mode,omitempty"`
	Reason  string                 `json:"reason,omitempty"`
	Score   float64                `json:"score,omitempty"`
	UniqIP  int                    `json:"uniq_ip,omitempty"`
	RPS     float64                `json:"rps,omitempty"`
	Status  int                    `json:"status_code,omitempty"`
	TTLSec  int                    `json:"ttl_sec,omitempty"`
	Payload map[string]interface{} `json:"payload,omitempty"`
}

type HistoryStats struct {
	Path          string `json:"path"`
	Events        int    `json:"events"`
	UniqueHosts   int    `json:"unique_hosts"`
	UniqueIPs     int    `json:"unique_ips"`
	SizeBytes     int64  `json:"size_bytes"`
	RetentionDays int    `json:"retention_days"`
	PruneEverySec int64  `json:"prune_every_sec"`
}

type HistorySummary struct {
	FromUnix int64 `json:"from_unix"`
	ToUnix   int64 `json:"to_unix"`

	TotalEvents int `json:"total_events"`

	ChallengeIssued          int `json:"challenge_issued"`
	ChallengeSolved          int `json:"challenge_solved"`
	ChallengeExpiredUnsolved int `json:"challenge_expired_unsolved"`
	ChallengeEscalated       int `json:"challenge_escalated_block"`

	BlockTriggers int `json:"block_triggers"`
	WAFObserved   int `json:"waf_observed"`
	Suspicious    int `json:"suspicious"`
}

type HistoryStore struct {
	mu sync.Mutex

	path          string
	retentionDays int
	pruneEvery    time.Duration
	lastPrune     time.Time
	db            *sql.DB
}

func NewHistoryStore(path string, retentionDays int, pruneEvery time.Duration) (*HistoryStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("history path required")
	}
	if retentionDays <= 0 {
		retentionDays = 30
	}
	if pruneEvery <= 0 {
		pruneEvery = 10 * time.Minute
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	existed := fileExists(path)
	wasSQLite, err := isSQLiteFile(path)
	if err != nil {
		return nil, err
	}
	if existed && !wasSQLite {
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove old non-sqlite history file %s: %w", path, err)
		}
		logging.Logf("[webdetector][history] removed old non-sqlite history file: %s", path)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite history db %s: %w", path, err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set sqlite journal_mode WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA synchronous=NORMAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set sqlite synchronous NORMAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set sqlite busy_timeout: %w", err)
	}
	if err := ensureHistorySchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &HistoryStore{path: path, retentionDays: retentionDays, pruneEvery: pruneEvery, db: db}
	if !existed || !wasSQLite {
		logging.Logf("[webdetector][history] created sqlite db: %s", path)
	}
	logging.Logf("[webdetector][history] using sqlite db: %s", path)
	return s, nil
}

func (s *HistoryStore) Close() {
	if s == nil || s.db == nil {
		return
	}
	_ = s.db.Close()
}

func ensureHistorySchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS history_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    mode TEXT,
    reason TEXT,
    score REAL,
    uniq_ip INTEGER,
    rps REAL,
    status_code INTEGER,
    ttl_sec INTEGER,
    payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_history_events_ts ON history_events(ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_history_events_type_ts ON history_events(event_type, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_history_events_host_ts ON history_events(host, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_history_events_ip_ts ON history_events(ip, ts_unix DESC);
CREATE INDEX IF NOT EXISTS idx_history_events_reason_ts ON history_events(reason, ts_unix DESC);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("init history sqlite schema: %w", err)
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func isSQLiteFile(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()
	hdr := make([]byte, 16)
	n, err := f.Read(hdr)
	if err != nil && n == 0 {
		return false, nil
	}
	return string(hdr[:n]) == "SQLite format 3\x00", nil
}

func (s *HistoryStore) Append(ev HistoryEvent) {
	if s == nil || s.db == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if ev.TsUnix == 0 {
		ev.TsUnix = time.Now().Unix()
	}
	payloadJSON := ""
	if ev.Payload != nil {
		if b, err := json.Marshal(ev.Payload); err == nil {
			payloadJSON = string(b)
		}
	}

	res, err := s.db.Exec(`
INSERT INTO history_events
(ts_unix, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ev.TsUnix, ev.Type, ev.Host, ev.IP, ev.Mode, ev.Reason, ev.Score, ev.UniqIP, ev.RPS, ev.Status, ev.TTLSec, payloadJSON,
	)
	if err != nil {
		logging.Logf("[webdetector][history] sqlite append failed: %v", err)
		return
	}
	if id, err := res.LastInsertId(); err == nil {
		ev.ID = id
	}
	s.pruneIfNeededLocked(time.Now())
}

func (s *HistoryStore) pruneIfNeededLocked(now time.Time) {
	if now.Sub(s.lastPrune) < s.pruneEvery {
		return
	}
	s.lastPrune = now
	if _, err := s.pruneLocked(s.retentionDays); err != nil {
		logging.Logf("[webdetector][history] sqlite prune failed: %v", err)
	}
}

func (s *HistoryStore) readAllLocked() ([]HistoryEvent, error) {
	rows, err := s.db.Query(`
SELECT id, ts_unix, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json
FROM history_events
ORDER BY ts_unix DESC, id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHistoryRows(rows)
}

func (s *HistoryStore) QueryEvents(host, ip, typ string, limit int) ([]HistoryEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}

	clauses := make([]string, 0, 3)
	args := make([]interface{}, 0, 4)
	if host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, host)
	}
	if ip != "" {
		clauses = append(clauses, "ip = ?")
		args = append(args, ip)
	}
	if typ != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, typ)
	}

	q := `SELECT id, ts_unix, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json FROM history_events`
	if len(clauses) > 0 {
		q += " WHERE " + strings.Join(clauses, " AND ")
	}
	q += " ORDER BY ts_unix DESC, id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHistoryRows(rows)
}

func (s *HistoryStore) Summarize(host, ip string, hours int) (HistorySummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hours <= 0 {
		hours = 24
	}
	to := time.Now().Unix()
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	r := HistorySummary{FromUnix: from, ToUnix: to}

	clauses := []string{"ts_unix >= ?", "ts_unix <= ?"}
	args := []interface{}{from, to}
	if host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, host)
	}
	if ip != "" {
		clauses = append(clauses, "ip = ?")
		args = append(args, ip)
	}

	rows, err := s.db.Query(`
SELECT event_type, COUNT(*)
FROM history_events
WHERE `+strings.Join(clauses, " AND ")+`
GROUP BY event_type`, args...)
	if err != nil {
		return r, err
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		var n int
		if err := rows.Scan(&typ, &n); err != nil {
			return r, err
		}
		r.TotalEvents += n
		switch typ {
		case "challenge_issued":
			r.ChallengeIssued = n
		case "challenge_solved":
			r.ChallengeSolved = n
		case "challenge_expired_unsolved":
			r.ChallengeExpiredUnsolved = n
		case "challenge_escalated_block":
			r.ChallengeEscalated = n
		case "block_trigger", "waf_block_trigger":
			r.BlockTriggers += n
		case "waf_observed", "waf_observe":
			r.WAFObserved += n
		case "suspicious":
			r.Suspicious = n
		}
	}
	return r, rows.Err()
}

func (s *HistoryStore) pruneLocked(days int) (int64, error) {
	if days <= 0 {
		days = s.retentionDays
	}
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	res, err := s.db.Exec(`DELETE FROM history_events WHERE ts_unix > 0 AND ts_unix < ?`, cut)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) // best-effort
	_, _ = s.db.Exec(`VACUUM`)
	return n, nil
}

func (s *HistoryStore) Prune(days int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(days)
}

func (s *HistoryStore) Truncate() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int64
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM history_events`).Scan(&n)
	if _, err := s.db.Exec(`DELETE FROM history_events`); err != nil {
		return 0, err
	}
	_, _ = s.db.Exec(`DELETE FROM sqlite_sequence WHERE name='history_events'`)
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	_, _ = s.db.Exec(`VACUUM`)
	return n, nil
}

func (s *HistoryStore) Stats() (HistoryStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var events, uniqueHosts, uniqueIPs int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM history_events`).Scan(&events); err != nil {
		return HistoryStats{}, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT host) FROM history_events WHERE host <> ''`).Scan(&uniqueHosts); err != nil {
		return HistoryStats{}, err
	}
	if err := s.db.QueryRow(`SELECT COUNT(DISTINCT ip) FROM history_events WHERE ip <> ''`).Scan(&uniqueIPs); err != nil {
		return HistoryStats{}, err
	}

	fi, _ := os.Stat(s.path)
	sz := int64(0)
	if fi != nil {
		sz = fi.Size()
	}
	if walInfo, err := os.Stat(s.path + "-wal"); err == nil && walInfo != nil {
		sz += walInfo.Size()
	}
	if shmInfo, err := os.Stat(s.path + "-shm"); err == nil && shmInfo != nil {
		sz += shmInfo.Size()
	}

	return HistoryStats{Path: s.path, Events: events, UniqueHosts: uniqueHosts, UniqueIPs: uniqueIPs, SizeBytes: sz, RetentionDays: s.retentionDays, PruneEverySec: int64(s.pruneEvery.Seconds())}, nil
}

func (s *HistoryStore) String() string {
	return fmt.Sprintf("history(sqlite path=%s retention_days=%d prune_every=%s)", s.path, s.retentionDays, s.pruneEvery)
}

func scanHistoryRows(rows *sql.Rows) ([]HistoryEvent, error) {
	out := make([]HistoryEvent, 0, 128)
	for rows.Next() {
		var ev HistoryEvent
		var payloadJSON sql.NullString
		if err := rows.Scan(&ev.ID, &ev.TsUnix, &ev.Type, &ev.Host, &ev.IP, &ev.Mode, &ev.Reason, &ev.Score, &ev.UniqIP, &ev.RPS, &ev.Status, &ev.TTLSec, &payloadJSON); err != nil {
			return nil, err
		}
		if ev.TsUnix > 0 {
			ev.TsUTC = time.Unix(ev.TsUnix, 0).UTC().Format(time.RFC3339)
		}
		if payloadJSON.Valid && strings.TrimSpace(payloadJSON.String) != "" {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(payloadJSON.String), &m); err == nil {
				ev.Payload = m
			}
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

