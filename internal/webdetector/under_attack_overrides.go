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

// under_attack_overrides.go — the operator's `attack on`, made durable and
// self-protecting (docs/targeted-challenge-design.md §4, docs/under-attack-mode.md).
//
// `cfm webtop attack on <vhost>` (the cfm-admin Under-Attack toggle, the
// vhost/attack API) used to set an in-memory override only:
//   - it challenged nobody by itself (the state is reachable only from
//     CHALLENGED), so the confirm step needed a second command;
//   - any config reload (a detectors.conf save, a tailed log's rotation)
//     builds a new Engine and dropped it silently;
//   - an admin override never expired.
//
// Now an operator's `attack on`:
//   - arms a manual vhost challenge when no manual challenge covers the vhost
//     (reason "under_attack", the node's default tier for a tierless arm);
//   - holds for a TTL (UNDER_ATTACK_OVERRIDE_TTL, default 6h; a cPanel user
//     is capped at 24h), and the challenge it armed expires with it;
//   - is persisted here and restored on the next Engine (the manual challenge
//     persists in its own store, webdetector_manual_challenges.json).
//
// `attack off` clears the override and removes only the challenge the
// `attack on` itself armed, and only while that arm is still the one it made
// (an operator who re-armed the vhost by hand keeps theirs).
//
// The detector's AUTOMATIC entry still arms nothing: it never challenges a
// vhost the existing paths left alone.

// attackArmReason is the manual-challenge reason of an arm made by `attack on`.
const attackArmReason = "under_attack"

// defaultAttackOverrideTTL is UNDER_ATTACK_OVERRIDE_TTL's default, also used
// when a Config skipped fillDefaults.
const defaultAttackOverrideTTL = 6 * time.Hour

// attackOverrideTTL is the window of an `attack on` that names none.
func (e *Engine) attackOverrideTTL() time.Duration {
	if e.cfg.UnderAttackOverrideTTL > 0 {
		return e.cfg.UnderAttackOverrideTTL
	}
	return defaultAttackOverrideTTL
}

type attackOverrideEntry struct {
	Host      string    `json:"host"`
	ExpiresAt time.Time `json:"expires_at"`
	// ArmedChallenge: this `attack on` armed the vhost's manual challenge, so
	// `attack off` may remove it.
	ArmedChallenge bool   `json:"armed_challenge,omitempty"`
	Actor          string `json:"actor,omitempty"`
}

type attackOverrideStore struct {
	mu   sync.Mutex
	path string // "" = in memory only
	m    map[string]attackOverrideEntry
}

func newAttackOverrideStore(path string) *attackOverrideStore {
	s := &attackOverrideStore{path: strings.TrimSpace(path), m: map[string]attackOverrideEntry{}}
	s.load()
	return s
}

func (s *attackOverrideStore) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil {
		if !os.IsNotExist(err) {
			logging.Logf("[challenge][vhost] attack override load failed (%s): %v", s.path, err)
		}
		return
	}
	var arr []attackOverrideEntry
	if err := json.Unmarshal(b, &arr); err != nil {
		logging.Logf("[challenge][vhost] attack override load failed (%s): %v", s.path, err)
		return
	}
	now := time.Now()
	for _, e := range arr {
		if h := normalizeHost(e.Host); h != "" && e.ExpiresAt.After(now) {
			e.Host = h
			s.m[h] = e
		}
	}
}

func (s *attackOverrideStore) saveLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	arr := make([]attackOverrideEntry, 0, len(s.m))
	for h, e := range s.m {
		if !e.ExpiresAt.After(now) {
			delete(s.m, h)
			continue
		}
		arr = append(arr, e)
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Host < arr[j].Host })
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		logging.Logf("[challenge][vhost] attack override persist mkdir failed (%s): %v", s.path, err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		logging.Logf("[challenge][vhost] attack override persist failed (%s): %v", s.path, err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		logging.Logf("[challenge][vhost] attack override persist rename failed (%s): %v", s.path, err)
		_ = os.Remove(tmp)
	}
}

func (s *attackOverrideStore) set(e attackOverrideEntry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[e.Host] = e
	s.saveLocked()
}

// get returns host's unexpired entry.
func (s *attackOverrideStore) get(host string) (attackOverrideEntry, bool) {
	if s == nil {
		return attackOverrideEntry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[host]
	if !ok || !e.ExpiresAt.After(time.Now()) {
		return attackOverrideEntry{}, false
	}
	return e, true
}

// remove drops host and returns what it held (unexpired or not).
func (s *attackOverrideStore) remove(host string) (attackOverrideEntry, bool) {
	if s == nil {
		return attackOverrideEntry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[host]
	if ok {
		delete(s.m, host)
		s.saveLocked()
	}
	return e, ok
}

func (s *attackOverrideStore) snapshot() []attackOverrideEntry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	out := make([]attackOverrideEntry, 0, len(s.m))
	for _, e := range s.m {
		if e.ExpiresAt.After(now) {
			out = append(out, e)
		}
	}
	return out
}

// ForceVhostAttackAs is the operator's `attack on|off` (the vhost/attack API,
// the CLI, the cfm-admin toggle). on: hold host UNDER_ATTACK for ttl (<= 0 =
// UNDER_ATTACK_OVERRIDE_TTL), arming a manual challenge for the same window
// when none covers host (or refreshing the one an earlier `attack on` armed),
// and persist it. off: clear the override (auto re-entry suppressed for the
// holddown, as before) and remove the challenge the `attack on` armed, if it
// is still that arm. Returns whether a challenge is armed by the override and
// when the override ends (zero for off).
func (e *Engine) ForceVhostAttackAs(host string, on bool, ttl time.Duration, actor string) (armed bool, expires time.Time) {
	if e == nil || e.attack == nil || host == "" {
		return false, time.Time{}
	}
	now := time.Now()
	if !on {
		e.SetVhostAttackOverride(host, false, now, 0)
		if prev, ok := e.attackOverrides.remove(host); ok && prev.ArmedChallenge {
			if active, _, reason := e.manualChal.active(host); active && reason == attackArmReason {
				e.ClearManualChallengeVhostAs(host, actor)
			}
		}
		return false, time.Time{}
	}
	if ttl <= 0 {
		ttl = e.attackOverrideTTL()
	}
	expires = now.Add(ttl)
	// Arm (or refresh our own earlier arm) unless an operator's manual
	// challenge already covers the host: theirs stays as it is.
	prev, hadPrev := e.attackOverrides.get(host)
	own, _, ownReason := e.manualChal.active(host)
	covered, _, _ := e.manualChallengeCovering(host)
	switch {
	case own && ownReason == attackArmReason && (!hadPrev || prev.ArmedChallenge):
		armed = true
	case !covered:
		armed = true
	}
	if armed {
		rung, _, _ := e.tierlessArmRung(host)
		e.ManualChallengeVhostAs(host, ttl, attackArmReason, rung, actor)
	}
	e.SetVhostAttackOverride(host, true, now, ttl)
	e.attackOverrides.set(attackOverrideEntry{Host: host, ExpiresAt: expires, ArmedChallenge: armed, Actor: actor})
	return armed, expires
}

// restoreAttackOverrides re-applies the persisted `attack on` overrides with
// their remaining window, once the new Engine's tracker and bridge exist. The
// challenges they armed are restored by restoreManualChallenges.
func (e *Engine) restoreAttackOverrides() {
	now := time.Now()
	for _, ent := range e.attackOverrides.snapshot() {
		rem := ent.ExpiresAt.Sub(now)
		if rem <= 0 {
			continue
		}
		e.SetVhostAttackOverride(ent.Host, true, now, rem)
		logging.LogfCHALLENGES("[challenge][vhost] action=attack_restore host=%s ttl=%s armed_challenge=%v",
			ent.Host, rem.Round(time.Second), ent.ArmedChallenge)
	}
}
