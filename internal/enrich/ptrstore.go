package enrich

// ptrstore.go — a process-wide, SQLite-backed cache of resolved PTR (reverse-DNS)
// hostnames, shared by every Enricher in the process as an optional L2 behind
// each Enricher's in-memory ptrCache (L1).
//
// Why it exists:
//   - PTR is the only expensive enrich field (a blocking reverse-DNS, up to
//     dnsTimeout per cold IP) and an IP's rDNS is stable for months, so it is
//     worth caching aggressively and persisting.
//   - ~16 Enrichers are constructed across the daemon (engine + each detector +
//     nflog + outbound + status), each with its OWN in-memory L1. A shared L2
//     means a PTR resolved by ANY of them (a challenge-exclude check, WAF
//     top_ips, a host/IP drilldown, a detector alert) is visible to all the
//     others — so read views such as host_drilldown almost always have the PTR
//     rather than only after the resolving component has seen the IP.
//   - It is on disk (SQLite), so a daemon restart / redeploy does not re-resolve
//     every IP from scratch.
//
// Cost model: reads are an indexed primary-key SELECT (sub-millisecond) taken
// only on an L1 miss; writes are handed to a single background goroutine so a
// caller never blocks on disk. The store is OPT-IN via EnablePersistentPTR —
// tests and the short-lived CLI never enable it and keep the pure in-memory
// behaviour, so there is no new file I/O or cross-process SQLite contention
// outside the daemon.

import (
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cfm/internal/logging"

	_ "modernc.org/sqlite"
)

// ptrWriteQueue bounds how many pending PTR writes we buffer before dropping
// (a dropped write is simply re-queued the next time that IP is resolved).
const ptrWriteQueue = 2048

// ptrPruneEvery is how often the writer goroutine deletes rows older than the
// store TTL, keeping the DB from growing without bound as IPs churn.
const ptrPruneEvery = 6 * time.Hour

type ptrStore struct {
	db     *sql.DB
	ttl    time.Duration
	writes chan ptrRow
	stop   chan struct{}
	done   chan struct{}
}

type ptrRow struct {
	ip  string
	ptr string
}

var (
	sharedPTRMu sync.RWMutex
	sharedPTR   *ptrStore
)

// EnablePersistentPTR opens (once) the process-wide persistent PTR cache at path
// and wires it as the shared L2 for every Enricher. Best-effort: on any failure
// it returns the error and leaves the shared store unset, so enrichment simply
// falls back to each Enricher's in-memory ptrCache. Intended to be called once
// at daemon startup; the CLI and tests do not call it.
func EnablePersistentPTR(path string) error {
	sharedPTRMu.Lock()
	defer sharedPTRMu.Unlock()
	if sharedPTR != nil {
		return nil // already enabled
	}
	s, err := openPTRStore(path, ptrCacheTTL)
	if err != nil {
		return err
	}
	sharedPTR = s
	logging.Logf("[enrich] persistent PTR cache enabled: %s (ttl=%s)", path, ptrCacheTTL)
	return nil
}

// sharedPTRStore returns the process-wide store, or nil when persistence was
// never enabled (CLI / tests).
func sharedPTRStore() *ptrStore {
	sharedPTRMu.RLock()
	defer sharedPTRMu.RUnlock()
	return sharedPTR
}

func openPTRStore(path string, ttl time.Duration) (*ptrStore, error) {
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
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS ptr (
		ip          TEXT PRIMARY KEY,
		ptr         TEXT NOT NULL,
		resolved_at INTEGER NOT NULL
	);`); err != nil {
		_ = db.Close()
		return nil, err
	}
	s := &ptrStore{
		db:     db,
		ttl:    ttl,
		writes: make(chan ptrRow, ptrWriteQueue),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go s.writerLoop()
	return s, nil
}

// get returns a cached PTR for ip if present and not older than the store TTL.
// Safe to call on a nil store.
func (s *ptrStore) get(ip string) (string, bool) {
	if s == nil || ip == "" {
		return "", false
	}
	var ptr string
	var resolvedAt int64
	if err := s.db.QueryRow(`SELECT ptr, resolved_at FROM ptr WHERE ip = ?`, ip).Scan(&ptr, &resolvedAt); err != nil {
		return "", false
	}
	if ptr == "" {
		return "", false
	}
	if s.ttl > 0 && time.Since(time.Unix(resolvedAt, 0)) > s.ttl {
		return "", false
	}
	return ptr, true
}

// put queues a PTR for persistence. Non-blocking: if the writer is backed up the
// write is dropped (re-queued on the next resolve) rather than stalling the
// caller. Empty PTRs are never stored, so a transient miss is not pinned.
func (s *ptrStore) put(ip, ptr string) {
	if s == nil || ip == "" || ptr == "" {
		return
	}
	select {
	case s.writes <- ptrRow{ip: ip, ptr: ptr}:
	default:
	}
}

func (s *ptrStore) writerLoop() {
	defer close(s.done)
	prune := time.NewTicker(ptrPruneEvery)
	defer prune.Stop()
	for {
		select {
		case row := <-s.writes:
			s.upsert(row)
		case <-prune.C:
			if s.ttl > 0 {
				cutoff := time.Now().Add(-s.ttl).Unix()
				_, _ = s.db.Exec(`DELETE FROM ptr WHERE resolved_at < ?`, cutoff)
			}
		case <-s.stop:
			// Best-effort drain of queued writes before shutting down.
			for {
				select {
				case row := <-s.writes:
					s.upsert(row)
				default:
					return
				}
			}
		}
	}
}

func (s *ptrStore) upsert(row ptrRow) {
	_, _ = s.db.Exec(
		`INSERT INTO ptr(ip, ptr, resolved_at) VALUES(?, ?, ?)
		 ON CONFLICT(ip) DO UPDATE SET ptr=excluded.ptr, resolved_at=excluded.resolved_at`,
		row.ip, row.ptr, time.Now().Unix(),
	)
}

// close stops the writer goroutine (draining queued writes) and closes the DB.
func (s *ptrStore) close() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done
	_ = s.db.Close()
}
