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
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// manualChalEntry holds the expiry for a runtime-added manual challenge.
type manualChalEntry struct {
	ExpiresAt time.Time
	Reason    string
}

// manualChalState is embedded in Engine.
type manualChalState struct {
	mu     sync.Mutex
	vhosts map[string]manualChalEntry // host → entry
}

// initManualChal must be called from NewEngine (already done via field init).
func (s *manualChalState) init() {
	s.vhosts = make(map[string]manualChalEntry)
}

// set adds or refreshes a manual challenge for host.
func (s *manualChalState) set(host string, ttl time.Duration, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vhosts[host] = manualChalEntry{
		ExpiresAt: time.Now().Add(ttl),
		Reason:    reason,
	}
}

// clear removes a manual challenge (returns whether it was present).
func (s *manualChalState) clear(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.vhosts[host]
	delete(s.vhosts, host)
	return ok
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
