// Package alerts is the node's alert store: every event the detectors hand the
// notifier (notify.Enqueue / notify.Emit) is recorded here, in SQLite, whether
// or not a mail/Slack channel is configured and whatever the dedupe, detector
// overrides or severity gates then decide to send. The notifier's JSONL file
// (/var/lib/cfm/notify.log.jsonl) stays the DELIVERY audit (one row per
// channel attempt, only when something was sent); this is the EVENT log the
// operator, cfm-web and the MCP tools query, filter and group.
//
// Writes never block a detector: Record queues the row for a single writer
// goroutine that inserts in batches, and a full queue drops (and counts) the
// row rather than waiting.
package alerts

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"

	_ "modernc.org/sqlite"
)

// DefaultPath is where Init opens the store. A var so tests never reach the
// live file (CLAUDE.md §5): SetPathForTest from a TestMain.
var DefaultPath = "/var/lib/cfm/alerts.db"

// SetPathForTest points DefaultPath at path and returns a func that restores it.
func SetPathForTest(path string) (restore func()) {
	prev := DefaultPath
	DefaultPath = path
	return func() { DefaultPath = prev }
}

const (
	// DefaultMaxAge and DefaultMaxRows bound the store: whichever is hit first.
	// 500k rows is ~150-250 MB on disk with samples; a busy node writes a few
	// tens of thousands of events a day, so the age limit is the usual one.
	DefaultMaxAge  = 30 * 24 * time.Hour
	DefaultMaxRows = 500000

	queueSize     = 8192
	batchSize     = 256
	flushInterval = 500 * time.Millisecond
	pruneInterval = 10 * time.Minute

	maxSamples     = 5
	maxSampleBytes = 2048
	maxFieldBytes  = 1024
)

// Delivery outcomes: what the notifier did with the event. Recorded so the
// store can answer "why didn't I get a mail for this?".
const (
	DeliveryNotified      = "notified"       // at least one channel accepted it
	DeliverySendFailed    = "send_failed"    // every channel it went to returned an error
	DeliveryNotifierOff   = "notifier_off"   // notifier disabled or its config failed to load
	DeliveryNoChannels    = "no_channels"    // enabled, but no channel matched
	DeliveryDeduped       = "deduped"        // same dedupe key inside its cooldown
	DeliveryMuted         = "muted"          // detector override notify=false
	DeliveryBelowSeverity = "below_severity" // detector override min_severity
	DeliveryQueueFull     = "queue_full"     // notifier queue was full; never reached Emit
)

// Record is one stored alert.
type Record struct {
	ID         int64             `json:"id"`
	TsUnix     int64             `json:"ts_unix"`
	Time       string            `json:"time"`
	Host       string            `json:"host,omitempty"`
	Category   string            `json:"category"`
	Kind       string            `json:"kind"`
	Severity   string            `json:"severity,omitempty"`
	IP         string            `json:"ip,omitempty"`
	Country    string            `json:"country,omitempty"`
	CountryISO string            `json:"country_iso,omitempty"`
	ASN        string            `json:"asn,omitempty"`
	ASNNum     int64             `json:"asn_num,omitempty"`
	PTR        string            `json:"ptr,omitempty"`
	Vhost      string            `json:"vhost,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Mode       string            `json:"mode,omitempty"`
	TTLSec     int64             `json:"ttl_sec,omitempty"`
	Count      int               `json:"count,omitempty"`
	Section    string            `json:"section,omitempty"`
	Delivery   string            `json:"delivery,omitempty"`
	EventID    string            `json:"event_id,omitempty"`
	Samples    []string          `json:"samples,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// Store is the SQLite-backed alert store.
type Store struct {
	path    string
	maxAge  time.Duration
	maxRows int
	db      *sql.DB // the writer's: inserts and prunes, one connection
	ro      *sql.DB // the readers': List, Summarize, Overview, Stats

	queue   chan Record
	flushCh chan chan struct{}
	dropped atomic.Int64
	written atomic.Int64

	stopOnce sync.Once
	stop     chan struct{}
	done     sync.WaitGroup
}

var (
	defaultMu sync.RWMutex
	defStore  *Store
)

// Init opens the store at DefaultPath with the default limits and installs it
// as the package default that Record and the API read. Safe to call once at
// startup; a failure leaves recording off (Record is then a no-op).
func Init() error {
	s, err := Open(DefaultPath, DefaultMaxAge, DefaultMaxRows)
	if err != nil {
		return err
	}
	SetDefault(s)
	return nil
}

// SetDefault installs s as the package default (nil uninstalls it) and returns
// the previous one. For Init and tests.
func SetDefault(s *Store) *Store {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	prev := defStore
	defStore = s
	return prev
}

// Default returns the installed store, or nil.
func Default() *Store {
	defaultMu.RLock()
	defer defaultMu.RUnlock()
	return defStore
}

// Add queues r on the default store. A no-op when no store is installed.
func Add(r Record) {
	if s := Default(); s != nil {
		s.Add(r)
	}
}

// Open opens (or creates) the store at path and starts its writer and pruner.
func Open(path string, maxAge time.Duration, maxRows int) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("alerts: path required")
	}
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	// The store holds every tenant's events (client IPs, vhosts, MySQL users,
	// log lines), so it is 0600 from the first byte: SQLite gives the -wal and
	// -shm files the database file's mode, so the file must exist with that
	// mode before SQLite creates it under the process umask.
	if err := createPrivate(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("alerts: open %s: %w", path, err)
	}
	// The writer's connection: one, so inserts and prunes serialise and the
	// pragmas below (per connection) stay applied.
	db.SetMaxOpenConns(1)
	for _, p := range []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA busy_timeout=5000;`,
		// cap the WAL: a checkpoint reuses but never shrinks it (see the
		// webdetector history store, where an uncapped WAL reached the DB's size)
		`PRAGMA journal_size_limit=67108864;`,
	} {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("alerts: %s: %w", p, err)
		}
	}
	if err := ensureSchema(db); err != nil {
		_ = db.Close()
		return nil, err
	}
	for _, p := range []string{path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600) // a store created by an earlier build under the umask
	}
	// The readers get their own small pool: in WAL mode they never block the
	// writer, so a slow 30-day query can't stall inserts and fill the queue.
	// query_only makes every reader connection refuse writes.
	ro, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: path,
		RawQuery: "_pragma=busy_timeout(5000)&_pragma=query_only(1)"}).String())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("alerts: open readers %s: %w", path, err)
	}
	ro.SetMaxOpenConns(4)
	s := &Store{
		path:    path,
		maxAge:  maxAge,
		maxRows: maxRows,
		db:      db,
		ro:      ro,
		queue:   make(chan Record, queueSize),
		flushCh: make(chan chan struct{}),
		stop:    make(chan struct{}),
	}
	s.done.Add(2)
	go s.writer()
	go s.pruner()
	logging.Logf("[alerts] using sqlite db: %s (max_age=%s max_rows=%d)", path, maxAge, maxRows)
	return s, nil
}

// Close flushes the queued rows and closes the database.
func (s *Store) Close() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stop)
		s.done.Wait()
		_ = s.ro.Close()
		_ = s.db.Close()
	})
}

// Shutdown flushes and closes the default store and uninstalls it. For the
// daemon's exit path: rows still queued are written, not lost.
func Shutdown() {
	if s := SetDefault(nil); s != nil {
		s.Close()
	}
}

// createPrivate creates path with mode 0600 if it does not exist, and
// tightens it to 0600 if it does.
func createPrivate(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("alerts: create %s: %w", path, err)
	}
	_ = f.Close()
	return os.Chmod(path, 0o600)
}

func ensureSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix     INTEGER NOT NULL,
    host        TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT '',
    country     TEXT NOT NULL DEFAULT '',
    country_iso TEXT NOT NULL DEFAULT '',
    asn         TEXT NOT NULL DEFAULT '',
    asn_num     INTEGER NOT NULL DEFAULT 0,
    ptr         TEXT NOT NULL DEFAULT '',
    vhost       TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT '',
    mode        TEXT NOT NULL DEFAULT '',
    ttl_sec     INTEGER NOT NULL DEFAULT 0,
    count       INTEGER NOT NULL DEFAULT 0,
    section     TEXT NOT NULL DEFAULT '',
    delivery    TEXT NOT NULL DEFAULT '',
    event_id    TEXT NOT NULL DEFAULT '',
    samples     TEXT NOT NULL DEFAULT '',
    extra       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_cat_ts   ON alerts(category, ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_kind_ts  ON alerts(kind, ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_ip_ts    ON alerts(ip, ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_cc_ts    ON alerts(country_iso, ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_asn_ts   ON alerts(asn_num, ts_unix);
CREATE INDEX IF NOT EXISTS idx_alerts_vhost_ts ON alerts(vhost, ts_unix);
`
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("alerts: init schema: %w", err)
	}
	return nil
}

// Add queues r for the writer. Never blocks: a full queue drops the row and
// counts it (Stats().Dropped).
func (s *Store) Add(r Record) {
	if s == nil {
		return
	}
	select {
	case s.queue <- normalize(r):
	default:
		s.dropped.Add(1)
	}
}

func (s *Store) writer() {
	defer s.done.Done()
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	batch := make([]Record, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insert(batch); err != nil {
			logging.Logf("[alerts] insert of %d rows failed: %v", len(batch), err)
			s.dropped.Add(int64(len(batch)))
		} else {
			s.written.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}
	for {
		select {
		case r := <-s.queue:
			batch = append(batch, r)
			if len(batch) >= batchSize {
				flush()
			}
		case <-t.C:
			flush()
		case done := <-s.flushCh:
			for drained := false; !drained; {
				select {
				case r := <-s.queue:
					batch = append(batch, r)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					drained = true
				}
			}
			flush()
			close(done)
		case <-s.stop:
			for {
				select {
				case r := <-s.queue:
					batch = append(batch, r)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func (s *Store) insert(rows []Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
INSERT INTO alerts (ts_unix, host, category, kind, severity, ip, country, country_iso, asn, asn_num,
    ptr, vhost, reason, mode, ttl_sec, count, section, delivery, event_id, samples, extra)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		samples, extra := "", ""
		if len(r.Samples) > 0 {
			if b, err := json.Marshal(r.Samples); err == nil {
				samples = string(b)
			}
		}
		if len(r.Extra) > 0 {
			if b, err := json.Marshal(r.Extra); err == nil {
				extra = string(b)
			}
		}
		if _, err := stmt.Exec(r.TsUnix, r.Host, r.Category, r.Kind, r.Severity, r.IP, r.Country, r.CountryISO,
			r.ASN, r.ASNNum, r.PTR, r.Vhost, r.Reason, r.Mode, r.TTLSec, r.Count, r.Section, r.Delivery,
			r.EventID, samples, extra); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) pruner() {
	defer s.done.Done()
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			if _, err := s.Prune(time.Now()); err != nil {
				logging.Logf("[alerts] prune failed: %v", err)
			}
		}
	}
}

// Prune deletes rows older than the max age and, past the row cap, the oldest
// rows. Returns how many rows it deleted.
func (s *Store) Prune(now time.Time) (int64, error) {
	var total int64
	res, err := s.db.Exec(`DELETE FROM alerts WHERE ts_unix < ?`, now.Add(-s.maxAge).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	total += n
	if s.maxRows > 0 {
		res, err = s.db.Exec(`DELETE FROM alerts WHERE id <= (SELECT id FROM alerts ORDER BY id DESC LIMIT 1 OFFSET ?)`, s.maxRows)
		if err != nil {
			return total, err
		}
		n, _ = res.RowsAffected()
		total += n
	}
	return total, nil
}

// Stats is the store's size and health, for the API and the UI header.
type Stats struct {
	Path       string `json:"path"`
	Rows       int64  `json:"rows"`
	SizeBytes  int64  `json:"size_bytes"`
	OldestUnix int64  `json:"oldest_unix,omitempty"`
	NewestUnix int64  `json:"newest_unix,omitempty"`
	MaxAgeSec  int64  `json:"max_age_sec"`
	MaxRows    int    `json:"max_rows"`
	Written    int64  `json:"written_since_start"`
	Dropped    int64  `json:"dropped_since_start"`
	Queued     int    `json:"queued"`
}

// Stats reports the store's size and counters.
func (s *Store) Stats() (Stats, error) {
	st := Stats{
		Path:      s.path,
		MaxAgeSec: int64(s.maxAge / time.Second),
		MaxRows:   s.maxRows,
		Written:   s.written.Load(),
		Dropped:   s.dropped.Load(),
		Queued:    len(s.queue),
	}
	var oldest, newest sql.NullInt64
	if err := s.ro.QueryRow(`SELECT COUNT(*), MIN(ts_unix), MAX(ts_unix) FROM alerts`).Scan(&st.Rows, &oldest, &newest); err != nil {
		return st, err
	}
	st.OldestUnix, st.NewestUnix = oldest.Int64, newest.Int64
	for _, p := range []string{s.path, s.path + "-wal"} {
		if fi, err := os.Stat(p); err == nil {
			st.SizeBytes += fi.Size()
		}
	}
	return st, nil
}

// Flush writes every row queued so far before returning.
func (s *Store) Flush() {
	if s == nil {
		return
	}
	done := make(chan struct{})
	select {
	case s.flushCh <- done:
		<-done
	case <-s.stop:
	}
}
