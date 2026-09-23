package webdetector

import (
	"sync"
	"time"

	"cfm/internal/logging"
)

// pairTTLStore is the ONE bounded, TTL'd, per-(ip,host) store behind both the
// ChallengeV2 rung marks (gate teeth, challengeV2Marks) and the traffic-rule
// challenge notes (telemetry, challengeRuleNotes) — one implementation, so a
// fix to the sweep, the cap or the once-per-episode warning reaches both.
// Keys come from challengeV2MarkKey.
//
// Bounded and fail-open: at maxKeys a NEW key is dropped after an expiry
// sweep (never an error); existing keys keep refreshing. Reads take only the
// RLock and never delete — an expired key answers "absent" and is left for
// the write-pressure sweep, which is what bounds the store.
//
// Per-store knobs (zero keeps the strictest, original behaviour):
//   - minRefresh: a put of the SAME value on a key with more than
//     ttl-minRefresh left is skipped under the RLock, so a per-request writer
//     does not take the write lock on every request.
//   - sweepEvery: under cap pressure, at most one O(n) sweep per interval; in
//     between, a new key is dropped without sweeping. Bounds the hot-path
//     cost when the store is full of LIVE entries (a sweep then frees
//     nothing).
type pairTTLStore[V comparable] struct {
	mu        sync.RWMutex
	m         map[string]time.Time // key → expiry
	vals      map[string]V         // key → value; nil for a presence-only store
	fullWarn  bool
	lastSweep time.Time

	ttl        time.Duration
	maxKeys    int
	minRefresh time.Duration
	sweepEvery time.Duration
	fullMsg    string // logged once per saturation episode (%d = maxKeys)
}

// put records v for key until now+ttl.
func (s *pairTTLStore[V]) put(key string, v V, now time.Time) {
	if key == "" {
		return
	}
	if s.minRefresh > 0 {
		s.mu.RLock()
		exp, ok := s.m[key]
		same := ok && (s.vals == nil || s.vals[key] == v)
		s.mu.RUnlock()
		if same && exp.Sub(now) > s.ttl-s.minRefresh {
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[key]; !exists && len(s.m) >= s.maxKeys {
		if s.sweepEvery == 0 || now.Sub(s.lastSweep) >= s.sweepEvery {
			s.lastSweep = now
			for k, exp := range s.m { // expiry sweep, only on pressure
				if now.After(exp) {
					delete(s.m, k)
					if s.vals != nil {
						delete(s.vals, k)
					}
				}
			}
		}
		if len(s.m) >= s.maxKeys {
			if !s.fullWarn {
				s.fullWarn = true
				logging.Logf(s.fullMsg, s.maxKeys)
			}
			return // fail-open: the newcomer is simply not recorded
		}
	}
	s.m[key] = now.Add(s.ttl)
	if s.vals != nil {
		s.vals[key] = v
	}
	// Re-arm the once-per-episode warning only when the store is genuinely
	// BELOW the cap again. Keying it on "any successful insert/refresh" was
	// wrong once reads stopped deleting expired keys: at saturation a per-
	// request writer refreshes an existing pair on every request, which would
	// clear the flag, and the next NEW pair would log the warning again —
	// alternating per client and flooding the log with a line documented to
	// appear once per episode. A refresh while still at capacity is not the
	// end of the episode.
	if len(s.m) < s.maxKeys {
		s.fullWarn = false
	}
}

// get returns key's value and whether a live (unexpired) entry exists.
func (s *pairTTLStore[V]) get(key string, now time.Time) (V, bool) {
	var zero V
	if key == "" {
		return zero, false
	}
	s.mu.RLock()
	exp, ok := s.m[key]
	v := zero
	if ok && s.vals != nil {
		v = s.vals[key]
	}
	s.mu.RUnlock()
	if !ok || !now.Before(exp) {
		return zero, false
	}
	return v, true
}
