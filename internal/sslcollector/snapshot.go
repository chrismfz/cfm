package sslcollector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"cfm/internal/logging"
)

// snapshotPath is the on-disk JSON used by the OpenResty/Angie workers'
// load_from_snapshot() to seed their in-memory cert store at init_worker
// time. Until this change the file was written by the workers themselves
// after a successful /dumpall round-trip; the worker could be tricked
// into overwriting a good snapshot with a partial one if it called
// /dumpall while the daemon's Refresh was still mid-scan. Making the
// daemon the sole writer removes that race because Refresh swaps in the
// fully-populated cert index atomically before this function ever runs.
const snapshotPath = "/var/lib/cfm/sslcollector/dump.json"

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

	if prevExact, prevWild, ok := readSnapshotCounts(snapshotPath); ok {
		prev := prevExact + prevWild
		next := exactN + wildN
		// Allow shrinking by at most one third of the previous size in a
		// single tick. A small drop is normal during cert renewal (one
		// pair replaced by another); a large drop is suspicious and
		// likely a mid-scan partial. The threshold is intentionally
		// loose so we don't get stuck refusing real shrinkage forever.
		if next < (prev-prev/3) {
			logging.Logf("[sslcollector] snapshot: skip write (regression guard: existing has %d entries, new has %d; > 33%% drop)",
				prev, next)
			return
		}
	}

	if err := writeSnapshotAtomic(snapshotPath, body); err != nil {
		logging.Logf("[sslcollector] snapshot: write failed: %v", err)
		return
	}
	logging.Logf("[sslcollector] snapshot: wrote %d exact + %d wild entries to %s",
		exactN, wildN, snapshotPath)
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
