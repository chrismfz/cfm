// Package mailtraffic persists the Mail Monitor's per-mailbox traffic counters
// and tails the mail logs that feed them. It is the stateful stage on top of the
// pure internal/mailmeter parser leaf: a boot-time collector goroutine tails the
// exim mainlog and the syslog maillog every minute, folds new lines into
// per-hour counters via mailmeter, and writes them to a SQLite database it owns
// (/var/lib/cfm/mailtraffic.db). A read endpoint then serves top-N / per-domain
// views over the requested window.
//
// Hourly buckets (not day-only) are stored deliberately: they let a later
// "baseline anomaly" view compare a recent window against a trailing average
// without re-reading logs. The store is read-only to consumers — it never
// blocks, unblocks, or changes mail configuration.
package mailtraffic

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/mailmeter"

	_ "modernc.org/sqlite"
)

const (
	// bucketSeconds is the counter granularity (one row per address per hour).
	bucketSeconds = 3600
	// defaultRetention bounds how far back counters are kept; older buckets are
	// pruned so the DB stays small as addresses churn.
	defaultRetention = 30 * 24 * time.Hour
	// pruneEvery is how often the retention delete runs.
	pruneEvery = 6 * time.Hour
)

// Store is the SQLite-backed counter + tail-position persistence. Writes come
// from the single collector goroutine (plus the prune ticker); reads come from
// the HTTP endpoint. WAL + busy_timeout make concurrent read/write safe; a mutex
// serialises this process's own writers against the prune delete.
type Store struct {
	db        *sql.DB
	retention time.Duration
	wmu       sync.Mutex // serialises AddReport / SaveTailPos / prune
	stop      chan struct{}
	done      chan struct{}
}

// Open creates/opens the mail-traffic database at path and starts its prune
// ticker. The caller owns the returned Store and must Close it.
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, pragma := range []string{
		`PRAGMA journal_mode=WAL;`,
		`PRAGMA synchronous=NORMAL;`,
		`PRAGMA busy_timeout=5000;`,
		`PRAGMA journal_size_limit=16777216;`,
	} {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &Store{
		db:        db,
		retention: defaultRetention,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go s.pruneLoop()
	return s, nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS mail_counters (
	bucket      INTEGER NOT NULL,   -- unix epoch truncated to the hour
	address     TEXT    NOT NULL,   -- sender/recipient mailbox, local unix user, or "*" host-wide
	domain      TEXT    NOT NULL,   -- domain part of address, "*" for host-wide / local user
	outbound    INTEGER NOT NULL DEFAULT 0,
	local_sub   INTEGER NOT NULL DEFAULT 0,
	inbound     INTEGER NOT NULL DEFAULT 0,
	over_quota  INTEGER NOT NULL DEFAULT 0,
	throttled   INTEGER NOT NULL DEFAULT 0,
	auth_failed INTEGER NOT NULL DEFAULT 0,
	rejected    INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (bucket, address)
);
CREATE INDEX IF NOT EXISTS mail_counters_bucket ON mail_counters(bucket);
CREATE INDEX IF NOT EXISTS mail_counters_domain ON mail_counters(domain, bucket);

CREATE TABLE IF NOT EXISTS mail_tailpos (
	path   TEXT PRIMARY KEY,
	inode  INTEGER NOT NULL,
	offset INTEGER NOT NULL
);`

// bucketOf truncates t to the start of its hour (unix seconds).
func bucketOf(t time.Time) int64 {
	u := t.Unix()
	return u - u%bucketSeconds
}

type rowCounts struct {
	domain     string
	outbound   int64
	localSub   int64
	inbound    int64
	overQuota  int64
	throttled  int64
	authFailed int64
	rejected   int64
}

// reportRows unions a poll's per-kind mailmeter maps into one row per address,
// deriving each address's domain for scope filtering.
func reportRows(r mailmeter.Report) map[string]*rowCounts {
	rows := map[string]*rowCounts{}
	at := func(addr string) *rowCounts {
		c := rows[addr]
		if c == nil {
			c = &rowCounts{domain: domainOf(addr)}
			rows[addr] = c
		}
		return c
	}
	for a, n := range r.OutboundBySender {
		at(a).outbound += int64(n)
	}
	for a, n := range r.LocalSubmitByUser {
		at(a).localSub += int64(n)
	}
	for a, n := range r.InboundByMailbox {
		at(a).inbound += int64(n)
	}
	for a, n := range r.OverQuotaByMailbox {
		at(a).overQuota += int64(n)
	}
	for a, n := range r.ThrottledBySender {
		at(a).throttled += int64(n)
	}
	for a, n := range r.AuthFailByMailbox {
		at(a).authFailed += int64(n)
	}
	if r.RejectedTotal > 0 {
		at(mailmeter.HostWide).rejected += int64(r.RejectedTotal)
	}
	return rows
}

// upsertCounters applies one poll's per-address deltas to the given bucket
// within an open transaction. Caller owns the tx (commit/rollback).
func upsertCounters(tx *sql.Tx, bucket int64, rows map[string]*rowCounts) error {
	stmt, err := tx.Prepare(`INSERT INTO mail_counters
		(bucket,address,domain,outbound,local_sub,inbound,over_quota,throttled,auth_failed,rejected)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(bucket,address) DO UPDATE SET
			outbound=outbound+excluded.outbound,
			local_sub=local_sub+excluded.local_sub,
			inbound=inbound+excluded.inbound,
			over_quota=over_quota+excluded.over_quota,
			throttled=throttled+excluded.throttled,
			auth_failed=auth_failed+excluded.auth_failed,
			rejected=rejected+excluded.rejected`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for addr, c := range rows {
		if _, err := stmt.Exec(bucket, addr, c.domain,
			c.outbound, c.localSub, c.inbound, c.overQuota, c.throttled, c.authFailed, c.rejected); err != nil {
			return err
		}
	}
	return nil
}

// Flush atomically applies one poll's counters AND advances the tail position
// for path in a SINGLE transaction. Atomicity matters: if the counter upsert and
// the offset save were separate writes, a failure of the second after the first
// committed would leave the offset behind and the next poll would re-read and
// double-count the same lines. All-or-nothing means a failed poll simply
// re-reads cleanly next time. now is the poll time; the poll's lines are
// attributed to now's hour (a meter, not exact per-line accounting).
func (s *Store) Flush(now time.Time, r mailmeter.Report, path string, inode, offset int64) error {
	rows := reportRows(r)
	bucket := bucketOf(now)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		if err := upsertCounters(tx, bucket, rows); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(
		`INSERT INTO mail_tailpos(path,inode,offset) VALUES(?,?,?)
		 ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset`,
		path, inode, offset); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// AddReport increments the hour-bucket counters from one poll's deltas, without
// touching tail positions. Used by tests and any caller that isn't tailing a
// file; the collector uses Flush so counters and offset advance atomically.
// A no-op for an empty report.
func (s *Store) AddReport(now time.Time, r mailmeter.Report) error {
	rows := reportRows(r)
	if len(rows) == 0 {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := upsertCounters(tx, bucketOf(now), rows); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// LoadTailPos returns the saved (inode, offset) for a log path, or ok=false when
// the path has never been tailed.
func (s *Store) LoadTailPos(path string) (inode, offset int64, ok bool) {
	if err := s.db.QueryRow(`SELECT inode, offset FROM mail_tailpos WHERE path=?`, path).
		Scan(&inode, &offset); err != nil {
		return 0, 0, false
	}
	return inode, offset, true
}

// SaveTailPos records the tail position for a log path.
func (s *Store) SaveTailPos(path string, inode, offset int64) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.Exec(
		`INSERT INTO mail_tailpos(path,inode,offset) VALUES(?,?,?)
		 ON CONFLICT(path) DO UPDATE SET inode=excluded.inode, offset=excluded.offset`,
		path, inode, offset)
	return err
}

func (s *Store) pruneLoop() {
	defer close(s.done)
	t := time.NewTicker(pruneEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if s.retention > 0 {
				cutoff := bucketOf(time.Now().Add(-s.retention))
				s.wmu.Lock()
				_, _ = s.db.Exec(`DELETE FROM mail_counters WHERE bucket < ?`, cutoff)
				s.wmu.Unlock()
			}
		case <-s.stop:
			return
		}
	}
}

// Close stops the prune ticker and closes the database.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.stop)
	<-s.done
	return s.db.Close()
}

// inClause builds a "domain IN (?,?,…)" fragment and its args from a set, for
// scoped queries. Returns ("", nil) for an empty set (caller must special-case).
func inClause(domains map[string]struct{}) (string, []any) {
	if len(domains) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString(" AND domain IN (")
	args := make([]any, 0, len(domains))
	first := true
	for d := range domains {
		if !first {
			b.WriteByte(',')
		}
		b.WriteByte('?')
		args = append(args, d)
		first = false
	}
	b.WriteByte(')')
	return b.String(), args
}
