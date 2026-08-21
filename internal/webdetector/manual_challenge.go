// internal/webdetector/manual_challenge.go
//
// Runtime manual challenge API — lets operators challenge/unchallengetion
// a vhost at runtime without restarting or editing cfm.conf.
//
// Works for BOTH modes:
//   - NginxBridge (OpenResty): pushes immediately via ChallengeVhost/ClearVhost
//   - DNAT mode:               sets manualChalVhosts[host] which challenge_rules.go
//                              picks up on the next tick (≤ engine.Every)
//
// The manual state is stored in Engine.manualChalVhosts (protected by
// manualMu).  It is separate from e.cfg.ChallengeVHost (config-time list)
// so it can be added/removed at runtime without touching config.

package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// manualChalEntry holds the expiry for a runtime-added manual challenge.
type manualChalEntry struct {
	ExpiresAt time.Time
	Reason    string
	// TTL is the window the operator granted at set() time. It is kept next to
	// the expiry so the status list can report the granted total, not merely
	// what was left when the daemon last restarted (restoreManualChallenges
	// re-records with the REMAINING window). Zero for an entry loaded from a
	// snapshot written before TTLs were persisted.
	TTL time.Duration
}

// manualChalPersistEntry is the on-disk shape of one manual challenge. Kept
// separate from manualChalEntry so the map key (host) is captured explicitly
// in the JSON array and the format is stable/self-describing.
type manualChalPersistEntry struct {
	Host      string    `json:"host"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason,omitempty"`
	// TTLSec is the originally granted TTL in seconds. Optional: a snapshot
	// written by an older build has no such key and loads as 0, which callers
	// treat as "unknown, fall back to the remaining window".
	TTLSec int `json:"ttl_sec,omitempty"`
}

// manualChalState is embedded in Engine.
//
// It is persisted to disk (path, JSON) so an operator-set manual challenge with
// a long TTL survives a daemon restart (upgrade via `make sync`, crash, OOM).
// Without persistence the in-memory map was wiped on every restart and a 34h
// manual challenge silently dropped to nothing. Auto challenges are NOT
// persisted — they are score-driven and the scorer re-derives them from live
// traffic within a tick, so only the manual, operator-intended state is durable.
type manualChalState struct {
	mu     sync.Mutex
	vhosts map[string]manualChalEntry // host → entry
	path   string                     // on-disk JSON snapshot ("" disables persistence)
}

// initManualChal must be called from NewEngine (already done via field init).
// path is the JSON snapshot file; "" keeps the store purely in-memory (tests).
func (s *manualChalState) init(path string) {
	s.vhosts = make(map[string]manualChalEntry)
	s.path = strings.TrimSpace(path)
	s.load()
}

// set adds or refreshes a manual challenge for host.
func (s *manualChalState) set(host string, ttl time.Duration, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vhosts[host] = manualChalEntry{
		ExpiresAt: time.Now().Add(ttl),
		Reason:    reason,
		TTL:       ttl,
	}
	s.saveLocked()
}

// clear removes a manual challenge (returns whether it was present).
func (s *manualChalState) clear(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.vhosts[host]
	delete(s.vhosts, host)
	s.saveLocked()
	return ok
}

// load reads the persisted manual challenges, dropping any already-expired
// entry. Best-effort: a missing/empty/corrupt file leaves the store empty
// rather than failing daemon startup. Called from init before any concurrency.
func (s *manualChalState) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []manualChalPersistEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		logging.Logf("[challenge][vhost] manual persist load failed (%s): %v", s.path, err)
		return
	}
	now := time.Now()
	restored := 0
	for _, e := range arr {
		// Round-trips a key a prior set() wrote; the API/CLI already lowercased
		// the host, and lowercasing again here is a safe no-op that also fixes a
		// hand-edited file.
		h := strings.ToLower(strings.TrimSpace(e.Host))
		if h == "" || e.ExpiresAt.IsZero() || now.After(e.ExpiresAt) {
			continue
		}
		reason := e.Reason
		if reason == "" {
			reason = "manual"
		}
		s.vhosts[h] = manualChalEntry{
			ExpiresAt: e.ExpiresAt,
			Reason:    reason,
			TTL:       time.Duration(e.TTLSec) * time.Second,
		}
		restored++
	}
	if restored > 0 {
		logging.Logf("[challenge][vhost] restored %d manual challenge(s) from %s", restored, s.path)
	}
}

// saveLocked atomically writes the current (non-expired) entries to disk. The
// caller must hold s.mu. Persistence failure is logged, never fatal — the
// in-memory operation always stands. Mirrors excludeStore.saveLocked (tmp +
// rename + chmod 0600). Already-expired entries are skipped so the file stays
// tidy; load() also time-filters, so a stale entry surviving a crash is inert.
func (s *manualChalState) saveLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	arr := make([]manualChalPersistEntry, 0, len(s.vhosts))
	for h, e := range s.vhosts {
		if now.After(e.ExpiresAt) {
			continue
		}
		arr = append(arr, manualChalPersistEntry{
			Host:      h,
			ExpiresAt: e.ExpiresAt,
			Reason:    e.Reason,
			TTLSec:    int(e.TTL.Round(time.Second) / time.Second),
		})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Host < arr[j].Host })
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		logging.Logf("[challenge][vhost] manual persist marshal failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		logging.Logf("[challenge][vhost] manual persist mkdir failed (%s): %v", s.path, err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		logging.Logf("[challenge][vhost] manual persist write failed (%s): %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		logging.Logf("[challenge][vhost] manual persist rename failed (%s): %v", s.path, err)
		return
	}
	_ = os.Chmod(s.path, 0o600)
}

// active returns true if host has a non-expired manual challenge.
func (s *manualChalState) active(host string) (bool, time.Time, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.vhosts[host]
	if !ok {
		return false, time.Time{}, ""
	}
	if time.Now().After(e.ExpiresAt) {
		delete(s.vhosts, host)
		return false, time.Time{}, ""
	}
	return true, e.ExpiresAt, e.Reason
}

// snapshot returns a copy of all active (non-expired) entries.
func (s *manualChalState) snapshot() map[string]manualChalEntry {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]manualChalEntry, len(s.vhosts))
	for h, e := range s.vhosts {
		if now.After(e.ExpiresAt) {
			delete(s.vhosts, h)
			continue
		}
		out[h] = e
	}
	return out
}

// ── Public Engine methods ─────────────────────────────────────────────────────

const defaultManualChallengeTTL = 30 * time.Minute

// ManualChallengeVhost adds a runtime manual challenge for host with the given TTL.
//   - NginxBridge mode: pushed to OpenResty immediately.
//   - DNAT mode:        picked up by challenge_rules.go on next tick.
//
// Idempotent — calling again refreshes the TTL.
func (e *Engine) ManualChallengeVhost(host string, ttl time.Duration, reason string) {
	if ttl <= 0 {
		ttl = defaultManualChallengeTTL
	}
	if reason == "" {
		reason = "manual"
	}

	e.manualChal.set(host, ttl, reason)

	logging.LogfCHALLENGES(
		"[challenge][vhost] action=manual_on host=%s ttl=%s reason=%s",
		host, ttl, reason,
	)

	// NginxBridge: push immediately so OpenResty reacts without waiting for a tick.
	if e.nginxBridge != nil {
		e.nginxBridge.ChallengeVhostWithReason(host, ttl, reason)
	}

	// Record in ChalAPI store.
	if e.chalAPI != nil {
		e.chalAPI.RecordVhostManual(host, true, ttl, reason)
	}
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_vhost_manual_on", Host: host, Mode: "manual", Reason: reason, TTLSec: int(ttl / time.Second)})
}

// ClearManualChallengeVhost removes the runtime manual challenge for host.
//   - NginxBridge mode: clears immediately via bridge.
//   - DNAT mode:        next tick will no longer emit for manual-only hosts.
func (e *Engine) ClearManualChallengeVhost(host string) {
	wasActive := e.manualChal.clear(host)

	logging.LogfCHALLENGES(
		"[challenge][vhost] action=manual_off host=%s was_active=%v",
		host, wasActive,
	)

	if e.nginxBridge != nil {
		e.nginxBridge.ClearVhost(host, "manual_off")
	}

	if e.chalAPI != nil {
		e.chalAPI.RecordVhostManual(host, false, 0, "manual_off")
	}
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_vhost_manual_off", Host: host, Mode: "manual", Reason: "manual_off"})
}

// IsManualChallengeActive returns whether host has an active (non-expired)
// manual challenge, its expiry, and the reason.
func (e *Engine) IsManualChallengeActive(host string) (bool, time.Time, string) {
	return e.manualChal.active(host)
}

// manualChallengeCovering returns whether an active manual challenge applies
// to host, its expiry, and its reason. Unlike manualChal.active (exact-key
// lookup), it also honours the apex→www expansion the bridge performs: a
// manual challenge on "example.com" installs bridge entries for BOTH
// "example.com" and "www.example.com" (vhostVariantsForBridge), so for
// challenge-lifecycle decisions "www.example.com" must count as manually
// challenged when the operator challenged the apex. The reverse does not
// hold — a manual challenge on "www.example.com" does not expand to the apex.
func (e *Engine) manualChallengeCovering(host string) (bool, time.Time, string) {
	if ok, exp, reason := e.manualChal.active(host); ok {
		return ok, exp, reason
	}
	if apex, found := strings.CutPrefix(host, "www."); found && apex != "" {
		if ok, exp, reason := e.manualChal.active(apex); ok {
			return ok, exp, reason
		}
	}
	return false, time.Time{}, ""
}

// manualChallengeCoversClear reports whether calling ClearVhost(host) would
// tear down a bridge entry that belongs to an active manual challenge, and
// the latest such expiry (for logging).
//
// This is the guard for a *clear*, which is broader than the per-host
// lifecycle check above. ClearVhost expands host through
// vhostVariantsForBridge and deletes EVERY resulting entry, so an apex clear
// ("victim.com") also removes the "www.victim.com" entry — and that entry may
// belong to a manual challenge placed on EITHER "victim.com" or
// "www.victim.com". Guarding with manualChallengeCovering(host) alone missed
// the www-only manual case: the apex has no manual challenge, covering
// returns false, and the clear silently deletes the www manual entry. So test
// every variant the clear will delete via manualChallengeCovering (which in
// turn maps each www variant back to its apex manual challenge).
func (e *Engine) manualChallengeCoversClear(host string) (bool, time.Time) {
	covered := false
	var latest time.Time
	for _, v := range vhostVariantsForBridge(host) {
		if ok, exp, _ := e.manualChallengeCovering(v); ok {
			covered = true
			if exp.After(latest) {
				latest = exp
			}
		}
	}
	return covered, latest
}

// ManualChallengeSnapshot returns all currently active manual challenges.
func (e *Engine) ManualChallengeSnapshot() map[string]manualChalEntry {
	return e.manualChal.snapshot()
}

// restoreManualChallenges re-asserts manual challenges that survived a daemon
// restart. init() loads the in-memory manualChalState from disk, but the edge
// bridge and the challenge API store both start empty every boot — so each
// surviving (non-expired) manual challenge must be re-pushed to the bridge with
// its REMAINING window (not the original TTL) and re-recorded in chalAPI, the
// same shape the tick loop's keepManualOverSuppression uses. Called from
// NewEngine after the bridge is wired.
//
// It does NOT append a history event: the original manual_on already lives in
// the SQLite history (which persists across the restart), so re-adding one would
// double-count. A manual_restore log marker records the re-assertion instead.
func (e *Engine) restoreManualChallenges() {
	for host, ent := range e.manualChal.snapshot() { // snapshot already drops expired
		rem := time.Until(ent.ExpiresAt)
		if rem <= 0 {
			continue
		}
		logging.LogfCHALLENGES(
			"[challenge][vhost] action=manual_restore host=%s ttl=%s reason=%s",
			host, rem.Round(time.Second), ent.Reason,
		)
		if e.nginxBridge != nil {
			e.nginxBridge.ChallengeVhostWithReason(host, rem, ent.Reason)
		}
		if e.chalAPI != nil {
			// rem drives the expiry; ent.TTL keeps the reported total the one
			// the operator granted rather than what survived the restart.
			e.chalAPI.RecordVhostManualRestored(host, rem, ent.TTL, ent.Reason)
		}
	}
}
