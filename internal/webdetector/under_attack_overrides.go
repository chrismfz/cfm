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
	ArmedChallenge bool `json:"armed_challenge,omitempty"`
	// ArmExpiresAt is the expiry of the arm it made: the arm is still
	// "its own" only while the vhost's manual challenge carries the
	// under_attack reason AND this expiry (a reason anyone can type does not
	// make an operator's arm the override's).
	ArmExpiresAt time.Time `json:"arm_expires_at,omitempty"`
	Actor        string    `json:"actor,omitempty"`
	// Announced: the vhost's UNDER_ATTACK ON has been alerted and written to
	// history (Since is when). Only then does a restore seed the state as
	// already ON; an `attack on` followed by a reload before the first tick
	// still gets its ON alert from the new Engine.
	Announced bool      `json:"announced,omitempty"`
	Since     time.Time `json:"since,omitempty"`
}

// ownsArm reports whether host's live manual challenge is still the arm this
// entry's `attack on` made.
func (e *Engine) ownsArm(host string, ent attackOverrideEntry) bool {
	if !ent.ArmedChallenge || ent.ArmExpiresAt.IsZero() {
		return false
	}
	active, exp, reason := e.manualChal.active(host)
	if !active || reason != attackArmReason {
		return false
	}
	d := exp.Sub(ent.ArmExpiresAt)
	return d > -2*time.Second && d < 2*time.Second
}

type attackOverrideStore struct {
	mu   sync.Mutex
	path string // "" = in memory only
	m    map[string]attackOverrideEntry
}

// attackOverrideStores shares ONE store per state file across Engine
// rebuilds, like tierPinStores: a reload builds the new Engine (loading the
// file) before the API moves over to it, so an `attack on|off` written through
// the old Engine in between must land in the store the new one reads, or the
// new Engine's next save would overwrite it. Residual: the new Engine's
// tracker and manual challenges (per Engine, loaded at build) do not see such
// a write until the next reload; the manual challenges carry the same window.
// The store is read from disk once per process: a hand edit takes a restart.
var attackOverrideStores = struct {
	sync.Mutex
	m map[string]*attackOverrideStore
}{m: map[string]*attackOverrideStore{}}

// newAttackOverrideStore returns the process-wide store for path (loading it
// on first use); "" is a private in-memory store.
func newAttackOverrideStore(path string) *attackOverrideStore {
	path = strings.TrimSpace(path)
	if path == "" {
		return &attackOverrideStore{m: map[string]attackOverrideEntry{}}
	}
	attackOverrideStores.Lock()
	defer attackOverrideStores.Unlock()
	if s, ok := attackOverrideStores.m[path]; ok {
		return s
	}
	s := &attackOverrideStore{path: path, m: map[string]attackOverrideEntry{}}
	s.load()
	attackOverrideStores.m[path] = s
	return s
}

// resetAttackOverrideStoresForTest forgets the process-wide stores, so the
// next Engine reads its file from disk as after a restart.
func resetAttackOverrideStoresForTest() {
	attackOverrideStores.Lock()
	attackOverrideStores.m = map[string]*attackOverrideStore{}
	attackOverrideStores.Unlock()
}

// loadAttackOverrideFileForTest reads path afresh (bypassing the shared
// store), for tests that check what reached the disk.
func loadAttackOverrideFileForTest(path string) *attackOverrideStore {
	s := &attackOverrideStore{path: path, m: map[string]attackOverrideEntry{}}
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
	if len(b) == 0 {
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

// saveLocked writes the unexpired entries (best effort: a failure is logged
// and the in-memory state stays authoritative). The caller holds s.mu.
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
		logging.Logf("[challenge][vhost] attack override persist marshal failed: %v", err)
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
		return
	}
	_ = os.Chmod(s.path, 0o600)
}

func (s *attackOverrideStore) set(e attackOverrideEntry) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// The same (unexpired) override refreshed keeps its announcement: a tick
	// that sent the ON alert between a refresh's read and this write must not
	// be undone. An expired record starts a new override.
	if old, ok := s.m[e.Host]; ok && old.Announced && !e.Announced && old.ExpiresAt.After(time.Now()) {
		e.Announced, e.Since = true, old.Since
	}
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

// markAnnounced records that host's ON transition was alerted (no-op without
// an entry: an automatic entry has no record).
func (s *attackOverrideStore) markAnnounced(host string, since time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[host]
	if !ok || e.Announced {
		return
	}
	e.Announced, e.Since = true, since
	s.m[host] = e
	s.saveLocked()
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
	// One `attack on|off` at a time: check, arm, override and persist are
	// separate steps, and an interleaved off must not leave a persisted ON.
	e.attackOpMu.Lock()
	defer e.attackOpMu.Unlock()
	now := time.Now()
	if !on {
		e.SetVhostAttackOverride(host, false, now, 0)
		e.dropAttackOverride(host, actor)
		return false, time.Time{}
	}
	if ttl <= 0 {
		ttl = e.attackOverrideTTL()
	}
	expires = now.Add(ttl)
	// Arm (or refresh our own earlier arm) unless an operator's manual
	// challenge already covers the host: theirs stays as it is, and the
	// override never outlives it (UNDER_ATTACK and its confirm step act only
	// where a challenge is served), so it is cut to that challenge's expiry.
	prev, hadPrev := e.attackOverrides.get(host)
	covered, coverExp, _ := e.manualChallengeCovering(host)
	own := hadPrev && e.ownsArm(host, prev)
	armed = own || !covered
	var armExp time.Time
	if armed {
		rung := e.attackArmRung(host)
		if own {
			// A refresh keeps the arm's tier: a pin set since, or a re-tier
			// of the arm (vhost/rung), is not undone by a second `attack on`.
			rung = e.manualChal.rung(host)
		}
		e.ManualChallengeVhostAs(host, ttl, attackArmReason, rung, actor)
		_, armExp, _ = e.manualChal.active(host)
	} else if coverExp.Before(expires) {
		expires, ttl = coverExp, coverExp.Sub(now)
	}
	// Persist before the tracker: a cfm.allow tick that deescalates in
	// between finds the override on its next tick and drops both.
	ent := attackOverrideEntry{Host: host, ExpiresAt: expires, ArmedChallenge: armed, ArmExpiresAt: armExp, Actor: actor}
	if hadPrev {
		ent.Announced, ent.Since = prev.Announced, prev.Since
	}
	if on, since := e.vhostAttackOnSince(host); on && !ent.Announced {
		// Already UNDER_ATTACK (automatic entry, alerted): no ON transition
		// will come for this override, so it is announced as of then.
		ent.Announced, ent.Since = true, since
	}
	e.attackOverrides.set(ent)
	e.SetVhostAttackOverride(host, true, now, ttl)
	// An automatic entry that landed between the check above and the
	// override sends no forced ON either: announced as of then.
	if on, since := e.vhostAttackOnSince(host); on {
		e.attackOverrides.markAnnounced(host, since)
	}
	return armed, expires
}

// attackArmRung is the tier of the challenge an `attack on` arms: the tier pin
// on the vhost (or its apex) when one is set, whoever set it (an operator's,
// or a tenant's own on its vhost), since a manual v2 arm outranks every pin
// and "the way down is a v1 pin" must hold through the incident toggle too;
// else the tier-less default (tierlessArmRung: CHALLENGE_V2_MANUAL, v1 on a
// wildcard host). Read when arming only: a refresh keeps the arm's tier.
func (e *Engine) attackArmRung(host string) string {
	pin, _ := e.tierPins.covering(host, time.Now())
	switch pin.Rung {
	case "v1":
		return ""
	case "v2":
		return "v2"
	}
	rung, _, _ := e.tierlessArmRung(host)
	return rung
}

// dropAttackOverride forgets host's persisted override and removes the
// challenge its `attack on` armed, while that arm is still the one it made
// (ownsArm: reason under_attack and the recorded expiry). With no record
// nothing is removed: an operator can type that reason too.
func (e *Engine) dropAttackOverride(host, actor string) {
	prev, ok := e.attackOverrides.remove(host)
	if ok && e.ownsArm(host, prev) {
		e.ClearManualChallengeVhostAs(host, actor)
	}
}

// restoreAttackOverrides re-applies the persisted `attack on` overrides with
// their remaining window, once the new Engine's tracker and bridge exist. The
// challenges they armed are restored by restoreManualChallenges. Like that
// restore, it writes no history and sends no alert: an override whose ON was
// already alerted is seeded as ON since then, so the first tick sees no
// transition (the original ON alert and row stand); one that was not (a
// reload before the old Engine's first tick) gets its ON from the new one.
func (e *Engine) restoreAttackOverrides() {
	now := time.Now()
	for _, ent := range e.attackOverrides.snapshot() {
		rem := ent.ExpiresAt.Sub(now)
		if rem <= 0 {
			continue
		}
		e.restoreForcedOn(ent.Host, now, rem, ent.Announced, ent.Since)
		logging.LogfCHALLENGES("[challenge][vhost] action=attack_restore host=%s ttl=%s armed_challenge=%v announced=%v",
			ent.Host, rem.Round(time.Second), ent.ArmedChallenge, ent.Announced)
	}
}
