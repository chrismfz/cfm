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
		e.nginxBridge.ClearVhost(host)
	}

	if e.chalAPI != nil {
		e.chalAPI.RecordVhostManual(host, false, 0, "manual_off")
	}
}

// IsManualChallengeActive returns whether host has an active (non-expired)
// manual challenge, its expiry, and the reason.
func (e *Engine) IsManualChallengeActive(host string) (bool, time.Time, string) {
	return e.manualChal.active(host)
}

// ManualChallengeSnapshot returns all currently active manual challenges.
func (e *Engine) ManualChallengeSnapshot() map[string]manualChalEntry {
	return e.manualChal.snapshot()
}
