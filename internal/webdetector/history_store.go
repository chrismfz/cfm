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
	MaxRows       int    `json:"max_rows,omitempty"`
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

// WAFRuleHit is a single row from WAFByRule — one WAF rule and its hit count.
type WAFRuleHit struct {
	Rule  string `json:"rule"`
	Count int    `json:"count"`
}

// VhostOverview is the combined per-vhost security summary for the
// "Security Overview" panel tab.
type VhostOverview struct {
	Host     string `json:"host"`
	Hours    int    `json:"hours"`
	FromUnix int64  `json:"from_unix"`
	ToUnix   int64  `json:"to_unix"`
	// Challenge stats
	ChallengeIssued int     `json:"challenge_issued"`
	ChallengeSolved int     `json:"challenge_solved"`
	SolveRatePct    float64 `json:"solve_rate_pct"`
	// WAF stats
	WAFHits    int          `json:"waf_hits"`
	TopWAFRule string       `json:"top_waf_rule,omitempty"`
	WAFByRule  []WAFRuleHit `json:"waf_by_rule"`
}

type HistoryStore struct {
	mu sync.Mutex

	path          string
	retentionDays int
	pruneEvery    time.Duration
	maxRows       int
	lastPrune     time.Time
	db            *sql.DB

	// Background pruner. Prune is done on its own ticker goroutine so that
	// a slow DELETE cannot block Append (and, by extension, the bridge HTTP
	// handlers that feed Append from OnTrigger / InjectObserved).
	prunerOnce sync.Once
	prunerStop chan struct{}
	prunerDone chan struct{}
}

// NewHistoryStore opens (or creates) the sqlite history DB. maxRows is a
// hard row cap enforced by the pruner in addition to the time retention
// (newest rows kept; <=0 disables the cap) — sqlite handles millions of
// rows fine, but an unbounded table on a busy box grows into hundreds of
// MB that every maintenance pass (VACUUM, checkpoint) then has to chew.
func NewHistoryStore(path string, retentionDays int, pruneEvery time.Duration, maxRows int) (*HistoryStore, error) {
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
	// Cap the WAL file: without a limit, a checkpoint reuses but never
	// shrinks it — combined with VACUUM-through-WAL this once left a WAL
	// as large as the DB itself (~400MB) sitting on disk permanently.
	if _, err := db.Exec(`PRAGMA journal_size_limit=67108864;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("set sqlite journal_size_limit: %w", err)
	}
	if err := ensureHistorySchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &HistoryStore{
		path:          path,
		retentionDays: retentionDays,
		pruneEvery:    pruneEvery,
		maxRows:       maxRows,
		db:            db,
		prunerStop:    make(chan struct{}),
		prunerDone:    make(chan struct{}),
	}
	go s.prunerLoop()
	if !existed || !wasSQLite {
		logging.Logf("[webdetector][history] created sqlite db: %s", path)
	}
	logging.Logf("[webdetector][history] using sqlite db: %s", path)
	return s, nil
}

// prunerLoop runs retention deletes on its own ticker. Runs under s.mu so
// reads/writes see a consistent view, but crucially does NOT block Append
// callers for the full ticker period — only for the duration of one DELETE.
func (s *HistoryStore) prunerLoop() {
	defer close(s.prunerDone)
	t := time.NewTicker(s.pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-s.prunerStop:
			return
		case <-t.C:
			s.mu.Lock()
			if _, err := s.pruneLocked(s.retentionDays); err != nil {
				logging.Logf("[webdetector][history] sqlite prune failed: %v", err)
			}
			s.lastPrune = time.Now()
			s.mu.Unlock()
		}
	}
}

func (s *HistoryStore) Close() {
	if s == nil || s.db == nil {
		return
	}
	s.prunerOnce.Do(func() {
		if s.prunerStop != nil {
			close(s.prunerStop)
		}
		if s.prunerDone != nil {
			<-s.prunerDone
		}
	})
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

CREATE TABLE IF NOT EXISTS waf_inspected (
    hour_unix INTEGER NOT NULL,
    host      TEXT    NOT NULL DEFAULT '',
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (hour_unix, host)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_waf_inspected_hour ON waf_inspected(hour_unix DESC);
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
	// Prune runs on its own ticker (see prunerLoop); Append never blocks on it.
}

// readWAFEventsSinceLocked returns waf_observe/waf_trigger events with
// ts_unix >= fromUnix, newest first (idx_history_events_type_ts).
// Caller must hold s.mu before calling.
//
// This MUST stay windowed and type-filtered in SQL: the WAF engine summary
// endpoint is polled every 10s by the dashboard's Security overview, and
// its predecessor (readAllLocked) read the WHOLE table — every event type,
// unbounded time. On a busy box (millions of rows) that was ~1.4 GB of
// allocations per call and pinned the daemon near 40% CPU for as long as a
// dashboard tab stayed open.
func (s *HistoryStore) readWAFEventsSinceLocked(fromUnix int64) ([]HistoryEvent, error) {
	rows, err := s.db.Query(`
SELECT id, ts_unix, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json
FROM history_events
WHERE event_type IN ('waf_observe', 'waf_trigger') AND ts_unix >= ?
ORDER BY ts_unix DESC, id DESC`, fromUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanHistoryRows(rows)
}

// CountWAFEventsSince returns the number of waf_observe + waf_trigger events
// with ts_unix >= fromUnix, node-wide. It is a COUNT(*) over the
// idx_history_events_type_ts index — far cheaper than readWAFEventsSinceLocked
// (which scans full rows into memory) — so it is safe to call on the
// health-snapshot collection path. Same event set + window as the WAF engine
// summary's total, so cfm_metrics.waf_events_1h reconciles with it.
func (s *HistoryStore) CountWAFEventsSince(fromUnix int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var n int
	err := s.db.QueryRow(`
SELECT COUNT(*) FROM history_events
WHERE event_type IN ('waf_observe', 'waf_trigger') AND ts_unix >= ?`, fromUnix).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
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

// CountEventsSince returns how many events of type typ landed in the last
// `hours` (default 24). Cheap COUNT(*) with the type+ts index — for at-a-glance
// KPI tiles (e.g. the dashboard ClamAV card's "infections 24h"). host/ip empty
// means box-wide; a non-empty host scopes the count.
func (s *HistoryStore) CountEventsSince(typ, host string, hours int) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	if hours <= 0 {
		hours = 24
	}
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()

	clauses := []string{"ts_unix >= ?"}
	args := []interface{}{from}
	if typ != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, typ)
	}
	if host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, host)
	}
	q := "SELECT COUNT(*) FROM history_events WHERE " + strings.Join(clauses, " AND ")
	var n int
	if err := s.db.QueryRow(q, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
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

// WAFByRule returns WAF hit counts grouped by rule name (stored in the reason
// column) for the given host and time window.
// host="" returns the global breakdown (admin view).
func (s *HistoryStore) WAFByRule(host string, hours int) ([]WAFRuleHit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if hours <= 0 {
		hours = 24
	}
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	clauses := []string{
		"event_type IN ('waf_observed','waf_observe','waf_trigger')",
		"ts_unix >= ?",
		"reason IS NOT NULL",
		"reason != ''",
	}
	args := []interface{}{from}
	if host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, host)
	}

	rows, err := s.db.Query(`
SELECT reason, COUNT(*) as cnt
FROM history_events
WHERE `+strings.Join(clauses, " AND ")+`
GROUP BY reason
ORDER BY cnt DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []WAFRuleHit
	for rows.Next() {
		var h WAFRuleHit
		if err := rows.Scan(&h.Rule, &h.Count); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	if out == nil {
		out = []WAFRuleHit{}
	}
	return out, rows.Err()
}

// RecordWAFInspected upserts an absolute count for the (hour_unix, host)
// tuple. Lua's maybe_flush_waf_insp pushes its full snapshot every minute;
// since each push carries the live shdict counter for the current hour,
// repeated upserts on the same row simply overwrite with the latest value.
//
// Multiple workers' independent counters cannot be summed by overwrite —
// but Lua's `incr` already accumulates across workers in shared dict, so
// the pushed `count` is already the union. Go just persists it.
func (s *HistoryStore) RecordWAFInspected(hourUnix int64, host string, count int) error {
	if s == nil || s.db == nil {
		return nil
	}
	if hourUnix <= 0 || count < 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
INSERT INTO waf_inspected (hour_unix, host, count)
VALUES (?, ?, ?)
ON CONFLICT(hour_unix, host) DO UPDATE SET count = excluded.count`,
		hourUnix, strings.TrimSpace(host), count)
	return err
}

// WAFHitsByRuleID returns trigger counts grouped by the waf_rule_id stored in
// payload_json. Reason-string aggregation (WAFByRule) is too coarse for the
// rollout-gate use case because several distinct rules share a reason family
// (e.g. all WAF_AUTH_BURST tags). Per-ID precision needs json_extract. Observe
// rows are deliberately excluded: a block that clears should_push emits both a
// trigger and an observation, and counting both would inflate rollout hit rates.
//
// Events emitted before PR A's rule-id plumbing have NULL/missing
// waf_rule_id and are excluded.
func (s *HistoryStore) WAFHitsByRuleID(host string, hours int) (map[int]int, error) {
	if s == nil || s.db == nil {
		return map[int]int{}, nil
	}
	if hours <= 0 {
		hours = 24
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	clauses := []string{
		"event_type = 'waf_trigger'",
		"ts_unix >= ?",
		"payload_json IS NOT NULL",
		"json_extract(payload_json, '$.waf_rule_id') IS NOT NULL",
	}
	args := []interface{}{from}
	if host != "" {
		clauses = append(clauses, "host = ?")
		args = append(args, host)
	}
	q := `SELECT CAST(json_extract(payload_json, '$.waf_rule_id') AS INTEGER) AS rid, COUNT(*)
FROM history_events
WHERE ` + strings.Join(clauses, " AND ") + `
GROUP BY rid`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int]int{}
	for rows.Next() {
		var rid, cnt int
		if err := rows.Scan(&rid, &cnt); err != nil {
			return nil, err
		}
		if rid > 0 {
			out[rid] = cnt
		}
	}
	return out, rows.Err()
}

// WAFInspected returns the total inspection count over the given window.
// host="" returns the global aggregate (the rows where host=”); a non-empty
// host filters to that vhost's per-host counts.
//
// Window is [now - hours*3600, now]; the table stores per-hour buckets so
// resolution is hourly.
func (s *HistoryStore) WAFInspected(host string, hours int) (int, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	if hours <= 0 {
		hours = 24
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()
	q := `SELECT COALESCE(SUM(count), 0) FROM waf_inspected WHERE hour_unix >= ? AND host = ?`
	var n int
	err := s.db.QueryRow(q, from, strings.TrimSpace(host)).Scan(&n)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// VhostOverviewQuery returns the combined security overview for a single vhost.
// Combines Summarize + WAFByRule in one DB-locked pass to avoid double locking.
func (s *HistoryStore) VhostOverviewQuery(host string, hours int) (VhostOverview, error) {
	if hours <= 0 {
		hours = 24
	}
	to := time.Now().Unix()
	from := time.Now().Add(-time.Duration(hours) * time.Hour).Unix()

	ov := VhostOverview{
		Host:     host,
		Hours:    hours,
		FromUnix: from,
		ToUnix:   to,
	}

	// Summary counts — reuse Summarize (acquires its own lock).
	sum, err := s.Summarize(host, "", hours)
	if err != nil {
		return ov, err
	}
	ov.ChallengeIssued = sum.ChallengeIssued
	ov.ChallengeSolved = sum.ChallengeSolved
	if sum.ChallengeIssued > 0 {
		ov.SolveRatePct = float64(sum.ChallengeSolved) / float64(sum.ChallengeIssued) * 100
	}

	// WAF breakdown — reuse WAFByRule (acquires its own lock).
	wafRows, err := s.WAFByRule(host, hours)
	if err != nil {
		return ov, err
	}
	ov.WAFByRule = wafRows
	for _, r := range wafRows {
		ov.WAFHits += r.Count
	}
	if len(wafRows) > 0 {
		ov.TopWAFRule = wafRows[0].Rule
	}

	return ov, nil
}

// pruneLocked enforces the time retention AND the row cap, then reclaims
// space. Order matters: deletes first, VACUUM only when the freelist is
// actually worth reclaiming (a full VACUUM rewrites the whole DB — running
// it on every hourly prune of a ~400MB DB was most of the history I/O),
// and the WAL checkpoint runs LAST so the WAL file is truncated after
// VACUUM's writes (the old checkpoint-then-VACUUM order left a WAL as
// large as the DB on disk).
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

	// Hard row cap (newest kept), independent of the time window: a traffic
	// burst must not balloon the DB while waiting out the retention days.
	// The subquery finds the id of the maxRows-th newest row; with fewer
	// rows than the cap it yields NULL and the DELETE is a no-op.
	if s.maxRows > 0 {
		if res2, err2 := s.db.Exec(`
DELETE FROM history_events WHERE id < (
  SELECT id FROM history_events ORDER BY id DESC LIMIT 1 OFFSET ?)`, s.maxRows-1); err2 == nil {
			if trimmed, _ := res2.RowsAffected(); trimmed > 0 {
				n += trimmed
				logging.Logf("[webdetector][history] row cap %d: trimmed %d oldest rows", s.maxRows, trimmed)
			}
		}
	}

	// VACUUM only when >=20%% of pages AND >=8MB are on the freelist.
	var pageCount, freeCount, pageSize int64
	_ = s.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount)
	_ = s.db.QueryRow(`PRAGMA freelist_count`).Scan(&freeCount)
	_ = s.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize)
	if pageCount > 0 && pageSize > 0 && freeCount*5 >= pageCount && freeCount*pageSize >= 8<<20 {
		_, _ = s.db.Exec(`VACUUM`)
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
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
	_, _ = s.db.Exec(`VACUUM`)
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
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

	return HistoryStats{
		Path: s.path, Events: events, UniqueHosts: uniqueHosts,
		UniqueIPs: uniqueIPs, SizeBytes: sz, RetentionDays: s.retentionDays,
		PruneEverySec: int64(s.pruneEvery.Seconds()),
		MaxRows:       s.maxRows,
	}, nil
}

func (s *HistoryStore) String() string {
	return fmt.Sprintf("history(sqlite path=%s retention_days=%d prune_every=%s)", s.path, s.retentionDays, s.pruneEvery)
}

// OldestEventUnix returns the oldest event timestamp actually retained in the
// store (0 when empty). Read views use it to answer "does the data really span
// the requested window?" — a 90-day query against a 30-day retention must be
// able to say so instead of silently returning partial counts.
func (s *HistoryStore) OldestEventUnix() int64 {
	if s == nil || s.db == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var min sql.NullInt64
	if err := s.db.QueryRow(`SELECT MIN(ts_unix) FROM history_events`).Scan(&min); err != nil || !min.Valid {
		return 0
	}
	return min.Int64
}

// RetentionDays returns the configured time retention (pruning horizon).
func (s *HistoryStore) RetentionDays() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retentionDays
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
