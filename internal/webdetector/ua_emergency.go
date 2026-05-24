// internal/webdetector/ua_emergency.go
//
// Box-wide UA emergency rule store. Operators apply throttle/block/allow
// to a normalized User-Agent (see ua_norm.go) for a bounded TTL. Rules are
// keyed by UA only — they apply across all vhosts on the box.
//
// Persistence: the in-process map is mirrored to a JSON file so the Lua
// side can pick it up (via init_worker_by_lua / periodic reload). The file
// is also re-read on Go process restart so an operator restart doesn't
// silently lose active rules mid-TTL.
//
// Audit: every create/expire/undo event is appended to a dedicated log so
// post-mortems can answer "what got applied at 02:14, by whom, against
// which UA, and for how long?". Per-request actions are NOT logged here —
// the lifecycle audit log stays tiny by design.
package webdetector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"cfm/internal/logging"
)

// UA emergency action vocabulary.
//
// We intentionally do NOT expose an "allow" action. A UA-keyed allow would
// be a WAF bypass keyed on a spoofable header — any attacker could send
// "User-Agent: Googlebot/..." and inherit the bypass. If you need to
// exempt a verified crawler box-wide, use per-vhost rules driven by
// IP/ASN/rDNS verification instead.
const (
	UAActionThrottle = "throttle"
	UAActionBlock    = "block"
)

// TTL bounds — server-side guards applied in the API layer.
const (
	UAEmergencyDefaultTTL = 30 * time.Minute
	UAEmergencyMaxTTL     = 60 * time.Minute
	UAEmergencyMinTTL     = 1 * time.Minute
)

// UAEmergencyRule is one active emergency rule.
//
// The duplicate *_unix fields exist so the Lua enforcement reader can
// avoid RFC3339 parsing. Go callers use the time.Time fields; the unix
// mirrors are populated automatically by Set() and on reload from disk.
type UAEmergencyRule struct {
	UA             string    `json:"ua"`              // normalized UA key
	Action         string    `json:"action"`          // throttle | block
	CreatedAt      time.Time `json:"created_at"`      // wall clock
	ExpiresAt      time.Time `json:"expires_at"`      // wall clock
	CreatedAtUnix  int64     `json:"created_at_unix"` // for Lua consumers
	ExpiresAtUnix  int64     `json:"expires_at_unix"` // for Lua consumers
	CreatedBy      string    `json:"created_by"`      // token name / "admin" / "scoped:foo"
	Reason         string    `json:"reason,omitempty"`
	Hits           int64     `json:"hits"` // incremented by enforcement layer via IncHits
}

// UAEmergencyStore holds the active rules and writes them to disk so the
// Lua enforcement side can pick them up. It is safe for concurrent use.
type UAEmergencyStore struct {
	path       string
	auditPath  string
	mu         sync.RWMutex
	rules      map[string]*UAEmergencyRule // key: normalized UA
	saveSerial uint64                      // bumped on every disk write

	// saveMu serialises the snapshot+write+rename cycle so two concurrent
	// callers (e.g. Set and PruneExpired) can't collide on the temp file
	// path and can't reorder the on-disk state vs the in-memory state.
	saveMu sync.Mutex
}

// NewUAEmergencyStore loads any existing rules from `path` and returns a
// ready-to-use store. Missing file is not an error; corrupt file is logged
// and treated as empty.
func NewUAEmergencyStore(path, auditPath string) *UAEmergencyStore {
	s := &UAEmergencyStore{
		path:      path,
		auditPath: auditPath,
		rules:     make(map[string]*UAEmergencyRule),
	}
	// Sweep any orphan temp files left by a previous daemon crash between
	// CreateTemp and Rename. They have unique random suffixes so each crash
	// would otherwise leak one file indefinitely.
	s.sweepStaleTmp()
	s.load()
	// Drop anything already expired at startup so a long-stopped daemon
	// doesn't reincarnate stale rules.
	s.PruneExpired(time.Now())
	return s
}

// sweepStaleTmp removes orphan temp files matching the save() pattern in
// the store's directory. Called once at startup.
//
// We only delete files whose mtime is older than `staleCutoff` ago — that
// way a sibling daemon's in-flight save (created milliseconds ago, not yet
// renamed) survives this sweep. A graceful-restart sequence where the old
// process is mid-save while the new process boots is rare but realistic;
// without the cutoff we'd race with it and silently lose the mutation.
func (s *UAEmergencyStore) sweepStaleTmp() {
	if s.path == "" {
		return
	}
	const staleCutoff = 30 * time.Second
	dir := filepath.Dir(s.path)
	matches, err := filepath.Glob(filepath.Join(dir, ".ua_emergency-*.json.tmp"))
	if err != nil {
		return
	}
	now := time.Now()
	removed := 0
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil {
			continue
		}
		if now.Sub(st.ModTime()) < staleCutoff {
			continue
		}
		if err := os.Remove(m); err == nil {
			removed++
		}
	}
	if removed > 0 {
		logging.Logf("[ua_emergency] swept %d orphan tmp file(s) in %s", removed, dir)
	}
}

// snapshotCopy returns a value copy of r with Hits read via atomic.LoadInt64.
// Use this anywhere we'd otherwise do `*r` while another goroutine might be
// running IncHits — the plain struct copy reads Hits as a non-atomic int64,
// which the race detector flags and which can tear on 32-bit architectures.
func (r *UAEmergencyRule) snapshotCopy() UAEmergencyRule {
	return UAEmergencyRule{
		UA:            r.UA,
		Action:        r.Action,
		CreatedAt:     r.CreatedAt,
		ExpiresAt:     r.ExpiresAt,
		CreatedAtUnix: r.CreatedAtUnix,
		ExpiresAtUnix: r.ExpiresAtUnix,
		CreatedBy:     r.CreatedBy,
		Reason:        r.Reason,
		Hits:          atomic.LoadInt64(&r.Hits),
	}
}

// load reads the JSON snapshot from disk into memory. Errors are logged but
// non-fatal.
func (s *UAEmergencyStore) load() {
	if s.path == "" {
		return
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Logf("[ua_emergency] load %s failed: %v", s.path, err)
		}
		return
	}
	if len(data) == 0 {
		return
	}
	var rules []UAEmergencyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		logging.Logf("[ua_emergency] parse %s failed: %v (treating as empty)", s.path, err)
		return
	}
	dropped := 0
	s.mu.Lock()
	for i := range rules {
		r := rules[i]
		if r.UA == "" {
			continue
		}
		// Drop rules whose action is not in the supported vocabulary from
		// the in-memory map so they can't surface as ghost rules in the
		// API/UI. We do NOT rewrite the file: if a future cfm version
		// adds a new action and an operator rolls back to this one,
		// preserving the unknown-action rules on disk means rolling
		// forward restores them. The legacy "allow" cleanup just lives
		// on disk until the next legitimate Set/Delete naturally
		// overwrites the snapshot.
		if r.Action != UAActionThrottle && r.Action != UAActionBlock {
			logging.Logf("[ua_emergency] skipping rule with unsupported action on load: ua=%q action=%q (kept on disk)", r.UA, r.Action)
			dropped++
			continue
		}
		// Backfill unix mirrors if the snapshot predates that field.
		if r.CreatedAtUnix == 0 && !r.CreatedAt.IsZero() {
			r.CreatedAtUnix = r.CreatedAt.Unix()
		}
		if r.ExpiresAtUnix == 0 && !r.ExpiresAt.IsZero() {
			r.ExpiresAtUnix = r.ExpiresAt.Unix()
		}
		s.rules[r.UA] = &r
	}
	s.mu.Unlock()
	// Intentionally NOT calling s.save() here even if `dropped > 0`. Saving
	// would erase those rules from disk too, which is a forward-compat
	// hazard: a future version that introduces a new action would lose
	// every such rule if anyone ever downgraded across the boundary. The
	// next legitimate Set/Delete naturally rewrites the snapshot.
}

// save writes the current rule set to disk atomically (write-temp + rename).
//
// The saveMu serialises the entire snapshot+write+rename cycle. Without
// it, two concurrent saves would collide on the temp filename and the
// rename(2) order would not match the in-memory mutation order — a stale
// snapshot could win. Set/Delete/PruneExpired call saveLocked() directly
// because they already hold saveMu for the duration of mutation+audit.
func (s *UAEmergencyStore) save() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.saveLocked()
}

// saveLocked is the body of save() with the saveMu precondition. Callers
// that need to bracket mutation, save, and audit under a single saveMu
// hold (so the audit log line cannot reorder against another save) call
// this directly after taking saveMu themselves.
func (s *UAEmergencyStore) saveLocked() {
	if s.path == "" {
		return
	}

	s.mu.RLock()
	rules := make([]UAEmergencyRule, 0, len(s.rules))
	for _, r := range s.rules {
		rules = append(rules, r.snapshotCopy())
	}
	s.mu.RUnlock()

	sort.Slice(rules, func(i, j int) bool { return rules[i].UA < rules[j].UA })

	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		logging.Logf("[ua_emergency] marshal failed: %v", err)
		return
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logging.Logf("[ua_emergency] mkdir %s failed: %v", dir, err)
		return
	}

	// os.CreateTemp picks a unique name; cleanup on any failure so we
	// don't leave orphan tmp files behind.
	tmp, err := os.CreateTemp(dir, ".ua_emergency-*.json.tmp")
	if err != nil {
		logging.Logf("[ua_emergency] create temp in %s failed: %v", dir, err)
		return
	}
	tmpPath := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		logging.Logf("[ua_emergency] write %s failed: %v", tmpPath, err)
		return
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		logging.Logf("[ua_emergency] close %s failed: %v", tmpPath, err)
		return
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		cleanup()
		logging.Logf("[ua_emergency] chmod %s failed: %v", tmpPath, err)
		return
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		cleanup()
		logging.Logf("[ua_emergency] rename %s failed: %v", s.path, err)
		return
	}
	atomic.AddUint64(&s.saveSerial, 1)
}

// auditLine renders one lifecycle event into the stable single-line
// format. Callers either pass it to audit() (single-event) or batch
// many lines through auditBatch() (mass expiry).
func (s *UAEmergencyStore) auditLine(event string, r *UAEmergencyRule, extra string) string {
	if r == nil {
		return ""
	}
	return fmt.Sprintf(
		"ts=%s event=%s ua=%q action=%s ttl=%s expires=%s by=%q reason=%q hits=%d%s\n",
		time.Now().UTC().Format(time.RFC3339),
		event,
		r.UA,
		r.Action,
		r.ExpiresAt.Sub(r.CreatedAt).Round(time.Second),
		r.ExpiresAt.UTC().Format(time.RFC3339),
		r.CreatedBy,
		r.Reason,
		atomic.LoadInt64(&r.Hits),
		extra,
	)
}

// audit appends a single-line event to the lifecycle audit log.
func (s *UAEmergencyStore) audit(event string, r *UAEmergencyRule, extra string) {
	line := s.auditLine(event, r, extra)
	if line == "" {
		return
	}
	s.auditBatch([]string{line})
}

// auditBatch writes N pre-rendered lines to the audit log with a single
// open/write/close. Used by PruneExpired to avoid holding saveMu across
// N separate file syscalls when a mass expiry hits.
func (s *UAEmergencyStore) auditBatch(lines []string) {
	if s.auditPath == "" || len(lines) == 0 {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.auditPath), 0o755); err != nil {
		return
	}
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	for _, line := range lines {
		if line != "" {
			_, _ = f.WriteString(line)
		}
	}
}

// Set installs or replaces an emergency rule. The caller is responsible
// for normalizing the UA and enforcing TTL bounds / warn-list confirmation.
// Returns the stored rule (a copy).
func (s *UAEmergencyStore) Set(ua, action, createdBy, reason string, ttl time.Duration) (UAEmergencyRule, error) {
	if ua == "" || ua == "-" {
		return UAEmergencyRule{}, fmt.Errorf("ua is required")
	}
	switch action {
	case UAActionThrottle, UAActionBlock:
	default:
		return UAEmergencyRule{}, fmt.Errorf("invalid action %q (must be throttle or block)", action)
	}
	// Clamp TTL into [MinTTL, MaxTTL]. We intentionally clamp the floor
	// (instead of replacing with DefaultTTL) so a 30-second test rule
	// becomes a 1-minute rule, not a 30-minute rule — preserving the
	// operator's intent of "short". A zero/negative TTL still falls back
	// to DefaultTTL since the caller clearly didn't specify one.
	if ttl <= 0 {
		ttl = UAEmergencyDefaultTTL
	}
	if ttl < UAEmergencyMinTTL {
		ttl = UAEmergencyMinTTL
	}
	if ttl > UAEmergencyMaxTTL {
		ttl = UAEmergencyMaxTTL
	}

	now := time.Now()
	exp := now.Add(ttl)
	r := &UAEmergencyRule{
		UA:            ua,
		Action:        action,
		CreatedAt:     now,
		ExpiresAt:     exp,
		CreatedAtUnix: now.Unix(),
		ExpiresAtUnix: exp.Unix(),
		CreatedBy:     createdBy,
		Reason:        reason,
	}

	// saveMu brackets the whole mutation + save + audit so a concurrent
	// Delete or PruneExpired cannot interleave and produce an audit-vs-disk
	// inconsistency (e.g. "undo X" logged for a rule that's currently
	// active on disk because a parallel Set already replaced it).
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	s.rules[ua] = r
	s.mu.Unlock()

	s.saveLocked()
	s.audit("create", r, "")
	return r.snapshotCopy(), nil
}

// Delete removes an emergency rule by normalized UA. Returns the removed
// rule (if any) and a bool indicating whether it existed.
func (s *UAEmergencyStore) Delete(ua, by string) (UAEmergencyRule, bool) {
	// saveMu brackets mutation + save + audit (see Set for the rationale).
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.Lock()
	r, ok := s.rules[ua]
	if ok {
		delete(s.rules, ua)
	}
	s.mu.Unlock()
	if !ok {
		return UAEmergencyRule{}, false
	}
	snap := r.snapshotCopy()
	s.saveLocked()
	s.audit("undo", &snap, fmt.Sprintf(" undo_by=%q", by))
	return snap, true
}

// Get returns the rule for the given normalized UA (copy + true) or
// (zero, false) if no rule is active. The copy is a snapshot that reads
// Hits via atomic.LoadInt64.
func (s *UAEmergencyStore) Get(ua string) (UAEmergencyRule, bool) {
	s.mu.RLock()
	r, ok := s.rules[ua]
	s.mu.RUnlock()
	if !ok {
		return UAEmergencyRule{}, false
	}
	return r.snapshotCopy(), true
}

// List returns a snapshot of all active rules, sorted by expiry ascending
// (soonest-to-expire first). Expired rules are excluded. Each rule's Hits
// field is read via atomic.LoadInt64 to avoid a data race with IncHits.
func (s *UAEmergencyStore) List() []UAEmergencyRule {
	now := time.Now()
	s.mu.RLock()
	out := make([]UAEmergencyRule, 0, len(s.rules))
	for _, r := range s.rules {
		if r.ExpiresAt.Before(now) {
			continue
		}
		out = append(out, r.snapshotCopy())
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

// IncHits bumps the hit counter for a rule. Intended for the enforcement
// layer to call once per (throttled/blocked) request. No-op if the rule no
// longer exists.
//
// We hold the RLock across the atomic.AddInt64 so PruneExpired (which
// takes the write lock) cannot remove the rule between our pointer read
// and the increment — without this hold the increment lands on an
// orphaned struct that audit/save have already snapshotted, and the hit
// is silently dropped.
func (s *UAEmergencyStore) IncHits(ua string, delta int64) {
	if delta <= 0 {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rules[ua]
	if !ok {
		return
	}
	atomic.AddInt64(&r.Hits, delta)
}

// PruneExpired removes rules whose ExpiresAt is before `now`. Returns the
// number of rules removed. Caller is responsible for scheduling.
func (s *UAEmergencyStore) PruneExpired(now time.Time) int {
	// Hold saveMu only for the mutation + snapshot write. Render audit
	// lines under the lock (so they observe the same state save() did)
	// but defer the actual file open/write/close until after we release
	// saveMu — for a mass expiry that batch can be N file operations
	// long, and holding saveMu across them would stall every concurrent
	// Set/Delete on the API. Prune is the only writer of "expire" lines
	// so there's no risk of two prune ticks reordering against each other.
	s.saveMu.Lock()

	s.mu.Lock()
	expired := make([]*UAEmergencyRule, 0)
	for ua, r := range s.rules {
		if r.ExpiresAt.Before(now) {
			expired = append(expired, r)
			delete(s.rules, ua)
		}
	}
	s.mu.Unlock()
	if len(expired) == 0 {
		s.saveMu.Unlock()
		return 0
	}

	// Render lines while holding saveMu so any concurrent IncHits (RLock
	// only) sees a consistent view of Hits, then save the snapshot, then
	// release saveMu before doing the audit I/O.
	lines := make([]string, 0, len(expired))
	for _, r := range expired {
		lines = append(lines, s.auditLine("expire", r, ""))
	}
	s.saveLocked()
	s.saveMu.Unlock()

	s.auditBatch(lines)
	return len(expired)
}

// RunPruneLoop drives PruneExpired on a fixed interval until `stop` is
// closed. If `done` is non-nil it is closed when the loop exits so the
// caller can join on goroutine quiescence — used by Engine.StopUAEmergencyPruner
// to guarantee no overlap with a subsequent Start.
func (s *UAEmergencyStore) RunPruneLoop(stop <-chan struct{}, every time.Duration, done chan<- struct{}) {
	if every <= 0 {
		every = 10 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	if done != nil {
		defer close(done)
	}
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.PruneExpired(now)
		}
	}
}

// SaveSerial returns the monotonic counter of disk writes. Useful for
// tests / sanity checks.
func (s *UAEmergencyStore) SaveSerial() uint64 {
	return atomic.LoadUint64(&s.saveSerial)
}
