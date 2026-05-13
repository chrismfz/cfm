package sslcollector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// regressionGuardMaxStale is the maximum age of the existing on-disk
// snapshot before the >33%-shrink guard automatically releases. Without
// this release valve, a legitimate bulk cert deletion (operator removes
// half their domains) would be permanently refused and the stale
// snapshot would resurface on every reboot. One hour is short enough
// that the next discovery tick (15min) plus its follow-ups will give us
// a clean post-deletion snapshot well within the window.
var regressionGuardMaxStale = 1 * time.Hour

func forceSnapshot() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CFM_SSLCOLLECTOR_FORCE_SNAPSHOT")))
	return v == "1" || v == "true" || v == "on" || v == "yes"
}

// snapshotPathForTests is the on-disk JSON used by the OpenResty/Angie
// workers' load_from_snapshot() to seed their in-memory cert store at
// init_worker time. The daemon is the sole writer; workers are readers
// only. This eliminates the race where a worker calling /dumpall mid-
// Refresh would overwrite a previously-good snapshot with a partial
// payload.
//
// Exposed as a var rather than a const so tests can point it at a
// tempdir; production code must not mutate it.
var snapshotPathForTests = "/var/lib/cfm/sslcollector/dump.json"

func snapshotPath() string { return snapshotPathForTests }

// snapshotMu serializes concurrent snapshot writes. Refresh() can be
// invoked from the watcher goroutine, the discovery ticker, the stat
// ticker, and the /refresh socket handler. The OS atomic-rename below
// keeps readers safe, but we still need to keep the regression-guard
// read+compare under a lock so two concurrent writers do not both see
// "no existing snapshot" and race to create one.
var snapshotMu sync.Mutex

// snapshotHeader is the minimal shape we need to validate the existing
// on-disk snapshot for the regression guard. Decoding into this avoids
// pulling cert/key PEMs into memory just to count them.
type snapshotHeader struct {
	Version string `json:"version"`
	Exact   []any  `json:"exact"`
	Wild    []any  `json:"wild"`
}

// WriteSnapshot serializes the collector's current cert index and writes
// it to /var/lib/cfm/sslcollector/dump.json. Best-effort: errors are
// logged but never returned to callers, because a missing snapshot only
// degrades the next boot's recovery — it never breaks the running
// daemon.
//
// Two guard rails:
//
//   - Refuse to overwrite with an empty payload. If Refresh runs before
//     any cert source is populated (e.g. cPanel install in progress),
//     we keep whatever snapshot was already on disk rather than letting
//     the workers boot with zero certs.
//   - Refuse to overwrite if the existing snapshot has materially more
//     entries than the new one. Catches the partial-overwrite hazard
//     the operator hit on reboot: if a transient scan returned fewer
//     pairs than we know about from the previous good state, keep the
//     good one.
func (c *Collector) WriteSnapshot() {
	snapshotMu.Lock()
	defer snapshotMu.Unlock()

	body, exactN, wildN, err := c.BuildDumpAllPayload()
	if err != nil {
		logging.Logf("[sslcollector] snapshot: build payload failed: %v", err)
		return
	}
	if exactN+wildN == 0 {
		logging.Logf("[sslcollector] snapshot: skip write (zero entries; keeping existing on-disk snapshot if any)")
		return
	}

	path := snapshotPath()
	if prevExact, prevWild, ok := readSnapshotCounts(path); ok {
		prev := prevExact + prevWild
		next := exactN + wildN
		// Allow shrinking by at most one third of the previous size in a
		// single tick. A small drop is normal during cert renewal (one
		// pair replaced by another); a large drop is suspicious and
		// likely a mid-scan partial.
		//
		// Release valves so an operator who legitimately removed many
		// certs isn't stuck on a stale snapshot forever:
		//   1. CFM_SSLCOLLECTOR_FORCE_SNAPSHOT=1 — emergency manual override.
		//   2. Time-based: if the existing snapshot is older than
		//      regressionGuardMaxStale (default 1h), accept the shrink.
		//      Real cert deletions will pass the guard on the next
		//      Refresh tick after this window.
		// Using next*3 < prev*2 (strict 33%) avoids integer-division
		// asymmetry at small counts.
		shrunkTooFar := next*3 < prev*2
		if shrunkTooFar {
			if forceSnapshot() {
				logging.Logf("[sslcollector] snapshot: regression guard bypassed by CFM_SSLCOLLECTOR_FORCE_SNAPSHOT (existing=%d new=%d)", prev, next)
			} else if st, sterr := os.Stat(path); sterr == nil && time.Since(st.ModTime()) > regressionGuardMaxStale {
				logging.Logf("[sslcollector] snapshot: regression guard released by staleness (existing=%d new=%d, snapshot age=%s > %s)",
					prev, next, time.Since(st.ModTime()).Truncate(time.Second), regressionGuardMaxStale)
			} else {
				logging.Logf("[sslcollector] snapshot: skip write (regression guard: existing has %d entries, new has %d; >33%% drop). Set CFM_SSLCOLLECTOR_FORCE_SNAPSHOT=1 to override.",
					prev, next)
				return
			}
		}
	}

	if err := writeSnapshotAtomic(path, body); err != nil {
		logging.Logf("[sslcollector] snapshot: write failed: %v", err)
		return
	}
	logging.Logf("[sslcollector] snapshot: wrote %d exact + %d wild entries to %s",
		exactN, wildN, path)
}

// readSnapshotCounts returns (exactN, wildN, ok). ok=false when the file
// is missing, unreadable, or not valid JSON — in which case the regression
// guard treats the new write as unconditionally safe (better to have a
// fresh snapshot than to keep a corrupted one).
func readSnapshotCounts(path string) (int, int, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false
	}
	var h snapshotHeader
	if err := json.Unmarshal(b, &h); err != nil {
		return 0, 0, false
	}
	return len(h.Exact), len(h.Wild), true
}

// writeSnapshotAtomic writes body to path via a sibling .tmp file +
// rename. The chown to the cfm group happens best-effort so OpenResty
// workers (cfm group) can read the file; the daemon-side directory
// chown in cmd/cfm/main.go handles the bootstrap when the group exists.
func writeSnapshotAtomic(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}
	if _, werr := f.Write(body); werr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write %s: %w", tmp, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync %s: %w", tmp, serr)
	}
	if cerr := f.Close(); cerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, cerr)
	}
	if gid := CfmGroupID(); gid > 0 {
		_ = os.Chown(tmp, 0, gid)
	}
	if rerr := os.Rename(tmp, path); rerr != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, rerr)
	}
	return nil
}
