package webdetector

/*
#cgo LDFLAGS: -lsqlite3
#include <sqlite3.h>
#include <stdlib.h>

static int bind_text(sqlite3_stmt* stmt, int idx, const char* val) {
	return sqlite3_bind_text(stmt, idx, val, -1, SQLITE_TRANSIENT);
}
*/
import "C"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"
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
	Path        string `json:"path"`
	Events      int    `json:"events"`
	UniqueHosts int    `json:"unique_hosts"`
	UniqueIPs   int    `json:"unique_ips"`
	SizeBytes   int64  `json:"size_bytes"`
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

	db            *C.sqlite3
	path          string
	retentionDays int
	pruneEvery    time.Duration
	lastPrune     time.Time
}

func NewHistoryStore(path string, retentionDays int, pruneEvery time.Duration) (*HistoryStore, error) {
	if strings.TrimSpace(path) == "" {
		path = "/var/lib/cfm/webdetector-history.db"
	}
	if pruneEvery <= 0 {
		pruneEvery = time.Hour
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if err := migrateJSONLIfNeeded(path); err != nil {
		return nil, err
	}
	db, err := openSQLite(path)
	if err != nil {
		return nil, err
	}
	s := &HistoryStore{db: db, path: path, retentionDays: retentionDays, pruneEvery: pruneEvery}
	if err := s.initSchema(); err != nil {
		_ = closeSQLite(db)
		return nil, err
	}
	return s, nil
}

func openSQLite(path string) (*C.sqlite3, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	var db *C.sqlite3
	rc := C.sqlite3_open_v2(cpath, &db, C.SQLITE_OPEN_READWRITE|C.SQLITE_OPEN_CREATE|C.SQLITE_OPEN_FULLMUTEX, nil)
	if rc != C.SQLITE_OK {
		err := sqliteErr(db, rc)
		_ = closeSQLite(db)
		return nil, err
	}
	return db, nil
}

func closeSQLite(db *C.sqlite3) error {
	if db == nil {
		return nil
	}
	rc := C.sqlite3_close_v2(db)
	if rc != C.SQLITE_OK {
		return sqliteErr(db, rc)
	}
	return nil
}

func sqliteErr(db *C.sqlite3, rc C.int) error {
	if db == nil {
		return fmt.Errorf("sqlite error rc=%d", int(rc))
	}
	msg := C.sqlite3_errmsg(db)
	return fmt.Errorf("sqlite error rc=%d: %s", int(rc), C.GoString(msg))
}

func execSQL(db *C.sqlite3, q string) error {
	cq := C.CString(q)
	defer C.free(unsafe.Pointer(cq))
	var errMsg *C.char
	rc := C.sqlite3_exec(db, cq, nil, nil, &errMsg)
	if rc != C.SQLITE_OK {
		if errMsg != nil {
			msg := C.GoString(errMsg)
			C.sqlite3_free(unsafe.Pointer(errMsg))
			return fmt.Errorf("sqlite exec: %s", msg)
		}
		return sqliteErr(db, rc)
	}
	return nil
}

func prepareSQL(db *C.sqlite3, q string) (*C.sqlite3_stmt, error) {
	cq := C.CString(q)
	defer C.free(unsafe.Pointer(cq))
	var stmt *C.sqlite3_stmt
	rc := C.sqlite3_prepare_v2(db, cq, -1, &stmt, nil)
	if rc != C.SQLITE_OK {
		return nil, sqliteErr(db, rc)
	}
	return stmt, nil
}

func initHistorySchema(db *C.sqlite3) error {
	queries := []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA busy_timeout=5000;`,
		`CREATE TABLE IF NOT EXISTS history (
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
		);`,
		`CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts_unix);`,
		`CREATE INDEX IF NOT EXISTS idx_history_event_type ON history(event_type);`,
		`CREATE INDEX IF NOT EXISTS idx_history_host ON history(host);`,
		`CREATE INDEX IF NOT EXISTS idx_history_ip ON history(ip);`,
		`CREATE INDEX IF NOT EXISTS idx_history_reason ON history(reason);`,
	}
	for _, q := range queries {
		if err := execSQL(db, q); err != nil {
			return err
		}
	}
	return nil
}

func migrateJSONLIfNeeded(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Size() == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	header := make([]byte, 16)
	n, _ := f.Read(header)
	_ = f.Close()
	if n >= 16 && string(header) == "SQLite format 3\x00" {
		return nil
	}

	tmpDB := path + ".migrating"
	_ = os.Remove(tmpDB)
	db, err := openSQLite(tmpDB)
	if err != nil {
		return err
	}
	defer closeSQLite(db)
	if err := initHistorySchema(db); err != nil {
		return err
	}
	if err := execSQL(db, "BEGIN"); err != nil {
		return err
	}
	stmt, err := prepareSQL(db, `INSERT INTO history
		(ts_unix,event_type,host,ip,mode,reason,score,uniq_ip,rps,status_code,ttl_sec,payload_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = execSQL(db, "ROLLBACK")
		return err
	}
	defer C.sqlite3_finalize(stmt)
	old, err := os.Open(path)
	if err != nil {
		_ = execSQL(db, "ROLLBACK")
		return err
	}
	defer old.Close()
	scan := bufio.NewScanner(old)
	buf := make([]byte, 0, 1024*1024)
	scan.Buffer(buf, 16*1024*1024)
	for scan.Scan() {
		var ev HistoryEvent
		if err := json.Unmarshal(scan.Bytes(), &ev); err != nil {
			continue
		}
		if err := bindInsert(stmt, ev); err != nil {
			_ = execSQL(db, "ROLLBACK")
			return err
		}
		rc := C.sqlite3_step(stmt)
		if rc != C.SQLITE_DONE {
			_ = execSQL(db, "ROLLBACK")
			return sqliteErr(db, rc)
		}
		C.sqlite3_reset(stmt)
		C.sqlite3_clear_bindings(stmt)
	}
	if err := scan.Err(); err != nil {
		_ = execSQL(db, "ROLLBACK")
		return err
	}
	if err := execSQL(db, "COMMIT"); err != nil {
		return err
	}
	backup := path + ".jsonl.bak"
	_ = os.Remove(backup)
	if err := os.Rename(path, backup); err != nil {
		return err
	}
	if err := os.Rename(tmpDB, path); err != nil {
		_ = os.Rename(backup, path)
		return err
	}
	return nil
}

func (s *HistoryStore) initSchema() error { return initHistorySchema(s.db) }

func (s *HistoryStore) Close() {
	if s != nil {
		_ = closeSQLite(s.db)
	}
}

func bindInsert(stmt *C.sqlite3_stmt, ev HistoryEvent) error {
	if ev.TsUnix <= 0 {
		ev.TsUnix = time.Now().Unix()
	}
	payloadJSON := ""
	if len(ev.Payload) > 0 {
		if b, err := json.Marshal(ev.Payload); err == nil {
			payloadJSON = string(b)
		}
	}
	vals := []string{strings.TrimSpace(ev.Type), cleanHost(ev.Host), strings.TrimSpace(ev.IP), strings.TrimSpace(ev.Mode), strings.TrimSpace(ev.Reason), payloadJSON}
	if rc := C.sqlite3_bind_int64(stmt, 1, C.sqlite3_int64(ev.TsUnix)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind ts_unix failed")
	}
	for i, v := range vals {
		cv := C.CString(v)
		rc := C.bind_text(stmt, C.int(i+2), cv)
		C.free(unsafe.Pointer(cv))
		if rc != C.SQLITE_OK {
			return fmt.Errorf("bind text failed at %d", i+2)
		}
	}
	if rc := C.sqlite3_bind_double(stmt, 7, C.double(ev.Score)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind score failed")
	}
	if rc := C.sqlite3_bind_int(stmt, 8, C.int(ev.UniqIP)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind uniq_ip failed")
	}
	if rc := C.sqlite3_bind_double(stmt, 9, C.double(ev.RPS)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind rps failed")
	}
	if rc := C.sqlite3_bind_int(stmt, 10, C.int(ev.Status)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind status failed")
	}
	if rc := C.sqlite3_bind_int(stmt, 11, C.int(ev.TTLSec)); rc != C.SQLITE_OK {
		return fmt.Errorf("bind ttl failed")
	}
	return nil
}

func (s *HistoryStore) Append(ev HistoryEvent) {
	if s == nil || s.db == nil || strings.TrimSpace(ev.Type) == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stmt, err := prepareSQL(s.db, `INSERT INTO history
		(ts_unix,event_type,host,ip,mode,reason,score,uniq_ip,rps,status_code,ttl_sec,payload_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return
	}
	defer C.sqlite3_finalize(stmt)
	if err := bindInsert(stmt, ev); err != nil {
		return
	}
	if rc := C.sqlite3_step(stmt); rc != C.SQLITE_DONE {
		return
	}
	s.pruneIfNeededLocked(time.Now())
}

func (s *HistoryStore) pruneIfNeededLocked(now time.Time) {
	if s.retentionDays <= 0 {
		return
	}
	if !s.lastPrune.IsZero() && now.Sub(s.lastPrune) < s.pruneEvery {
		return
	}
	s.lastPrune = now
	_, _ = s.pruneLocked(s.retentionDays)
}

func (s *HistoryStore) readAllLocked() ([]HistoryEvent, error) {
	stmt, err := prepareSQL(s.db, `SELECT id, ts_unix, datetime(ts_unix,'unixepoch') AS ts_utc, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json FROM history ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(stmt)
	out := make([]HistoryEvent, 0, 1024)
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return nil, sqliteErr(s.db, rc)
		}
		ev := HistoryEvent{
			ID:     int64(C.sqlite3_column_int64(stmt, 0)),
			TsUnix: int64(C.sqlite3_column_int64(stmt, 1)),
			TsUTC:  colText(stmt, 2),
			Type:   colText(stmt, 3),
			Host:   colText(stmt, 4),
			IP:     colText(stmt, 5),
			Mode:   colText(stmt, 6),
			Reason: colText(stmt, 7),
			Score:  float64(C.sqlite3_column_double(stmt, 8)),
			UniqIP: int(C.sqlite3_column_int(stmt, 9)),
			RPS:    float64(C.sqlite3_column_double(stmt, 10)),
			Status: int(C.sqlite3_column_int(stmt, 11)),
			TTLSec: int(C.sqlite3_column_int(stmt, 12)),
		}
		if p := colText(stmt, 13); strings.TrimSpace(p) != "" {
			_ = json.Unmarshal([]byte(p), &ev.Payload)
		}
		out = append(out, ev)
	}
	return out, nil
}

func (s *HistoryStore) QueryEvents(host, ip, typ string, limit int) ([]HistoryEvent, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	host = cleanHost(host)
	ip = strings.TrimSpace(ip)
	typ = strings.TrimSpace(typ)
	s.mu.Lock()
	defer s.mu.Unlock()

	where := []string{"1=1"}
	args := []string{}
	if host != "" {
		where = append(where, "host=?")
		args = append(args, host)
	}
	if ip != "" {
		where = append(where, "ip=?")
		args = append(args, ip)
	}
	if typ != "" {
		where = append(where, "event_type=?")
		args = append(args, typ)
	}
	q := fmt.Sprintf(`SELECT id, ts_unix, datetime(ts_unix,'unixepoch') AS ts_utc, event_type, host, ip, mode, reason, score, uniq_ip, rps, status_code, ttl_sec, payload_json
		FROM history WHERE %s ORDER BY id DESC LIMIT ?`, strings.Join(where, " AND "))
	stmt, err := prepareSQL(s.db, q)
	if err != nil {
		return nil, err
	}
	defer C.sqlite3_finalize(stmt)
	idx := 1
	for _, a := range args {
		ca := C.CString(a)
		rc := C.bind_text(stmt, C.int(idx), ca)
		C.free(unsafe.Pointer(ca))
		if rc != C.SQLITE_OK {
			return nil, sqliteErr(s.db, rc)
		}
		idx++
	}
	if rc := C.sqlite3_bind_int(stmt, C.int(idx), C.int(limit)); rc != C.SQLITE_OK {
		return nil, sqliteErr(s.db, rc)
	}
	out := make([]HistoryEvent, 0, limit)
	for {
		rc := C.sqlite3_step(stmt)
		if rc == C.SQLITE_DONE {
			break
		}
		if rc != C.SQLITE_ROW {
			return nil, sqliteErr(s.db, rc)
		}
		ev := HistoryEvent{
			ID:     int64(C.sqlite3_column_int64(stmt, 0)),
			TsUnix: int64(C.sqlite3_column_int64(stmt, 1)),
			TsUTC:  colText(stmt, 2),
			Type:   colText(stmt, 3),
			Host:   colText(stmt, 4),
			IP:     colText(stmt, 5),
			Mode:   colText(stmt, 6),
			Reason: colText(stmt, 7),
			Score:  float64(C.sqlite3_column_double(stmt, 8)),
			UniqIP: int(C.sqlite3_column_int(stmt, 9)),
			RPS:    float64(C.sqlite3_column_double(stmt, 10)),
			Status: int(C.sqlite3_column_int(stmt, 11)),
			TTLSec: int(C.sqlite3_column_int(stmt, 12)),
		}
		if p := colText(stmt, 13); strings.TrimSpace(p) != "" {
			_ = json.Unmarshal([]byte(p), &ev.Payload)
		}
		out = append(out, ev)
	}
	return out, nil
}

func colText(stmt *C.sqlite3_stmt, col C.int) string {
	ptr := C.sqlite3_column_text(stmt, col)
	if ptr == nil {
		return ""
	}
	return C.GoString((*C.char)(unsafe.Pointer(ptr)))
}

func (s *HistoryStore) Summarize(host, ip string, hours int) (HistorySummary, error) {
	res := HistorySummary{}
	if s == nil || s.db == nil {
		return res, nil
	}
	if hours <= 0 {
		hours = 24
	}
	to := time.Now()
	from := to.Add(-time.Duration(hours) * time.Hour)
	res.FromUnix = from.Unix()
	res.ToUnix = to.Unix()
	host = cleanHost(host)
	ip = strings.TrimSpace(ip)
	s.mu.Lock()
	defer s.mu.Unlock()
	where := []string{"ts_unix BETWEEN ? AND ?"}
	args := []string{}
	if host != "" {
		where = append(where, "host=?")
		args = append(args, host)
	}
	if ip != "" {
		where = append(where, "ip=?")
		args = append(args, ip)
	}
	q := fmt.Sprintf(`SELECT
		COUNT(*),
		SUM(CASE WHEN event_type='challenge_issued' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='challenge_solved' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='challenge_expired_unsolved' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='challenge_escalated_block' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='block_trigger' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='waf_observe' THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_type='suspicious_snapshot' THEN 1 ELSE 0 END)
		FROM history WHERE %s`, strings.Join(where, " AND "))
	stmt, err := prepareSQL(s.db, q)
	if err != nil {
		return res, err
	}
	defer C.sqlite3_finalize(stmt)
	if rc := C.sqlite3_bind_int64(stmt, 1, C.sqlite3_int64(res.FromUnix)); rc != C.SQLITE_OK {
		return res, sqliteErr(s.db, rc)
	}
	if rc := C.sqlite3_bind_int64(stmt, 2, C.sqlite3_int64(res.ToUnix)); rc != C.SQLITE_OK {
		return res, sqliteErr(s.db, rc)
	}
	idx := 3
	for _, a := range args {
		ca := C.CString(a)
		rc := C.bind_text(stmt, C.int(idx), ca)
		C.free(unsafe.Pointer(ca))
		if rc != C.SQLITE_OK {
			return res, sqliteErr(s.db, rc)
		}
		idx++
	}
	if rc := C.sqlite3_step(stmt); rc != C.SQLITE_ROW {
		if rc == C.SQLITE_DONE {
			return res, nil
		}
		return res, sqliteErr(s.db, rc)
	}
	res.TotalEvents = int(C.sqlite3_column_int(stmt, 0))
	res.ChallengeIssued = int(C.sqlite3_column_int(stmt, 1))
	res.ChallengeSolved = int(C.sqlite3_column_int(stmt, 2))
	res.ChallengeExpiredUnsolved = int(C.sqlite3_column_int(stmt, 3))
	res.ChallengeEscalated = int(C.sqlite3_column_int(stmt, 4))
	res.BlockTriggers = int(C.sqlite3_column_int(stmt, 5))
	res.WAFObserved = int(C.sqlite3_column_int(stmt, 6))
	res.Suspicious = int(C.sqlite3_column_int(stmt, 7))
	return res, nil
}

func (s *HistoryStore) pruneLocked(days int) (int64, error) {
	cut := time.Now().Add(-time.Duration(days) * 24 * time.Hour).Unix()
	stmt, err := prepareSQL(s.db, `DELETE FROM history WHERE ts_unix < ?`)
	if err != nil {
		return 0, err
	}
	defer C.sqlite3_finalize(stmt)
	if rc := C.sqlite3_bind_int64(stmt, 1, C.sqlite3_int64(cut)); rc != C.SQLITE_OK {
		return 0, sqliteErr(s.db, rc)
	}
	if rc := C.sqlite3_step(stmt); rc != C.SQLITE_DONE {
		return 0, sqliteErr(s.db, rc)
	}
	n := int64(C.sqlite3_changes(s.db))
	_ = execSQL(s.db, `PRAGMA wal_checkpoint(TRUNCATE);`)
	return n, nil
}

func (s *HistoryStore) Prune(days int) (int64, error) {
	if s == nil || s.db == nil || days <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneLocked(days)
}

func (s *HistoryStore) Truncate() (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := execSQL(s.db, `DELETE FROM history`); err != nil {
		return 0, err
	}
	n := int64(C.sqlite3_changes(s.db))
	_ = execSQL(s.db, `VACUUM`)
	_ = execSQL(s.db, `PRAGMA wal_checkpoint(TRUNCATE);`)
	return n, nil
}

func (s *HistoryStore) Stats() (HistoryStats, error) {
	st := HistoryStats{}
	if s == nil || s.db == nil {
		return st, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st.Path = s.path
	stmt, err := prepareSQL(s.db, `SELECT COUNT(*), COUNT(DISTINCT host), COUNT(DISTINCT ip) FROM history`)
	if err != nil {
		return st, err
	}
	defer C.sqlite3_finalize(stmt)
	if rc := C.sqlite3_step(stmt); rc != C.SQLITE_ROW {
		return st, sqliteErr(s.db, rc)
	}
	st.Events = int(C.sqlite3_column_int(stmt, 0))
	st.UniqueHosts = int(C.sqlite3_column_int(stmt, 1))
	st.UniqueIPs = int(C.sqlite3_column_int(stmt, 2))
	if fi, err := os.Stat(s.path); err == nil {
		st.SizeBytes = fi.Size()
	}
	return st, nil
}

func (s *HistoryStore) String() string {
	if s == nil {
		return ""
	}
	return fmt.Sprintf("%s", s.path)
}
