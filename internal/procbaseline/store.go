// Package procbaseline persists bounded process-family count snapshots for
// future rolling-baseline evaluation. It deliberately owns storage only: the
// daemon sampler and anomaly policy are separate layers.
package procbaseline

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// Samples are keyed to one-minute buckets. The future sampler can therefore
	// distinguish a transient spike from several consecutive elevated samples
	// without storing per-process detail.
	bucketSeconds int64 = 60

	// Keep slightly more than the intended seven-day baseline window so a recent
	// comparison window can be excluded without losing the oldest baseline edge.
	defaultRetention = 8 * 24 * time.Hour
)

// Sample is one complete, reliable process-table observation. Families contains
// exact Linux COMM values and their process counts. The family counts must sum to
// TotalProcesses; rejecting partial/inconsistent input keeps later baselines from
// silently learning bad data.
type Sample struct {
	TotalProcesses int
	Families       map[string]int
}

// Point is one minute-bucket observation for a requested COMM family. Count is
// zero when the family was absent from an otherwise valid sample. Keeping those
// zeroes explicit in the read model lets later policy choose between wall-clock
// and active-sample baselines without changing the persistence schema.
type Point struct {
	At             time.Time
	TotalProcesses int
	Count          int
}

// Store is a small SQLite-backed rolling sample store. Writers are serialized;
// reads may run concurrently. Retention is enforced transactionally on Record,
// so the DB stays bounded without a background goroutine.
type Store struct {
	db        *sql.DB
	retention time.Duration
	wmu       sync.Mutex
}

// Open creates/opens a process-baseline database at path.
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
		`PRAGMA foreign_keys=ON;`,
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
	return &Store{db: db, retention: defaultRetention}, nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS process_samples (
	bucket          INTEGER PRIMARY KEY, -- unix epoch truncated to the minute
	total_processes INTEGER NOT NULL CHECK(total_processes > 0)
);
CREATE TABLE IF NOT EXISTS process_family_counts (
	bucket INTEGER NOT NULL,
	comm   TEXT    NOT NULL,
	count  INTEGER NOT NULL CHECK(count > 0),
	PRIMARY KEY (bucket, comm),
	FOREIGN KEY (bucket) REFERENCES process_samples(bucket) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS process_family_counts_comm_bucket
	ON process_family_counts(comm, bucket);`

func bucketOf(t time.Time) int64 {
	u := t.Unix()
	return u - u%bucketSeconds
}

// validateSample refuses incomplete or malformed snapshots. Exact COMM strings
// are otherwise preserved as-is; no service-specific normalization belongs in
// the storage layer.
func validateSample(s Sample) error {
	if s.TotalProcesses <= 0 {
		return errors.New("procbaseline: total_processes must be positive")
	}
	if len(s.Families) == 0 {
		return errors.New("procbaseline: family counts are empty")
	}
	total := 0
	for comm, n := range s.Families {
		if comm == "" {
			return errors.New("procbaseline: empty COMM family")
		}
		if n <= 0 {
			return fmt.Errorf("procbaseline: family %q has non-positive count %d", comm, n)
		}
		total += n
	}
	if total != s.TotalProcesses {
		return fmt.Errorf("procbaseline: family counts sum to %d, total_processes is %d", total, s.TotalProcesses)
	}
	return nil
}

// Record atomically replaces the sample for now's minute bucket. Replacement,
// rather than additive upsert, matters if a caller retries within the same
// minute: stale families from the earlier observation must disappear. Retention
// pruning is part of the same transaction.
func (s *Store) Record(now time.Time, sample Sample) error {
	if s == nil || s.db == nil {
		return errors.New("procbaseline: store is unavailable")
	}
	if err := validateSample(sample); err != nil {
		return err
	}

	bucket := bucketOf(now)
	s.wmu.Lock()
	defer s.wmu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	rollback := func(err error) error {
		_ = tx.Rollback()
		return err
	}

	if _, err := tx.Exec(`INSERT INTO process_samples(bucket,total_processes) VALUES(?,?)
		ON CONFLICT(bucket) DO UPDATE SET total_processes=excluded.total_processes`,
		bucket, sample.TotalProcesses); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`DELETE FROM process_family_counts WHERE bucket=?`, bucket); err != nil {
		return rollback(err)
	}

	stmt, err := tx.Prepare(`INSERT INTO process_family_counts(bucket,comm,count) VALUES(?,?,?)`)
	if err != nil {
		return rollback(err)
	}
	keys := make([]string, 0, len(sample.Families))
	for comm := range sample.Families {
		keys = append(keys, comm)
	}
	sort.Strings(keys)
	for _, comm := range keys {
		if _, err := stmt.Exec(bucket, comm, sample.Families[comm]); err != nil {
			_ = stmt.Close()
			return rollback(err)
		}
	}
	if err := stmt.Close(); err != nil {
		return rollback(err)
	}

	if s.retention > 0 {
		cutoff := bucketOf(now.Add(-s.retention))
		// Delete both tables explicitly instead of relying on SQLite's
		// connection-local foreign_keys pragma for retention correctness.
		if _, err := tx.Exec(`DELETE FROM process_family_counts WHERE bucket < ?`, cutoff); err != nil {
			return rollback(err)
		}
		if _, err := tx.Exec(`DELETE FROM process_samples WHERE bucket < ?`, cutoff); err != nil {
			return rollback(err)
		}
	}
	return tx.Commit()
}

// FamilySeries returns every valid host sample in [start, end), ordered oldest
// first, with an explicit zero when comm was absent. The LEFT JOIN against the
// sample table is intentional: absence is data, not missing telemetry. Window
// boundaries are compared to the stored bucket timestamps directly rather than
// rounded, so callers retain normal half-open interval semantics.
func (s *Store) FamilySeries(comm string, start, end time.Time) ([]Point, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("procbaseline: store is unavailable")
	}
	if comm == "" {
		return nil, errors.New("procbaseline: empty COMM family")
	}
	if !end.After(start) {
		return []Point{}, nil
	}
	lo, hi := start.Unix(), end.Unix()

	rows, err := s.db.Query(`SELECT s.bucket, s.total_processes, COALESCE(f.count,0)
		FROM process_samples s
		LEFT JOIN process_family_counts f ON f.bucket=s.bucket AND f.comm=?
		WHERE s.bucket>=? AND s.bucket<?
		ORDER BY s.bucket ASC`, comm, lo, hi)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Point{}
	for rows.Next() {
		var bucket int64
		var p Point
		if err := rows.Scan(&bucket, &p.TotalProcesses, &p.Count); err != nil {
			return nil, err
		}
		p.At = time.Unix(bucket, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

// Close closes the underlying SQLite database. database/sql Close safely waits
// for already-started queries; keeping the pointer immutable avoids a data race
// with concurrent readers during shutdown.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return s.db.Close()
}
