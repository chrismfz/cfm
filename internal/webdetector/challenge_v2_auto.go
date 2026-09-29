package webdetector

// ChallengeV2 on AUTOMATIC vhost challenges (auto-v2) + the per-host tier pin.
//
// Why: the Rung-1 week review (2026-09-29, 28 524 solves under the auto
// suspicious_vhost challenge) measured the arm before it existed — 36% of the
// convicted-farm solves would fail, ~0.06% of likely humans (2 of 3 395, both
// on software-rendered machines). A v2 tier on an auto challenge costs a
// passing human nothing (the page is the same), and its false-reject
// population is bounded by the challenge's own TTL: the auto challenge lapses
// and the host is unchallenged again. So the automatic sources arm v2 by
// default, and an operator can pin any host back to v1 (or forward to v2).
//
// The ONE resolver is challengeV2VhostTier: the verify gate
// (challengeV2HostArmed, wired in NewEngine) and every read surface (the vhost
// list, the per-host status, the CLI) answer "what tier is this vhost at"
// through it, so the teeth and the UI can never disagree. Precedence:
//
//  1. a MANUAL arm covering the host — its own tier (the operator's explicit
//     choice beats any automation, including Under-Attack);
//  2. no automatic source covering the host — no vhost tier at all;
//  3. a tier PIN on the host (or its apex, for a www. host) — the pinned tier;
//  4. the node knob CHALLENGE_V2_AUTO_VHOST: v2 when the covering source is in
//     the armed set, else v1.
//
// The automatic sources are the live bridge vhost entry's reason (the SAME
// entry and matcher the solve's src= snapshot reads — vhostEntryLocked) and
// the Under-Attack state (VhostAttackState, which includes an operator's
// forced-on override) — which only ever re-names a live vhost challenge's
// source: a forced `attack on` on a host no vhost challenge covers arms
// nothing, so the tier always ends with the vhost challenge.
//
// The grain stays "vhost" (v2=vhost on the solve line): the good-bot waiver
// applies exactly as for a manual v2 arm, and the src= field already names
// which vhost source covered the solve.

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

// Auto-v2 sources: the bridge vhost-entry reasons an automatic challenge
// writes, plus Under-Attack. "manual" is deliberately absent — a manual arm
// has its own tier.
const (
	autoV2SuspiciousVhost = "suspicious_vhost"
	autoV2UniqPathsShort  = "uniqpaths_short"
	autoV2VhostConfig     = "vhost_config"
	autoV2UnderAttack     = "under_attack"
)

// DefaultChallengeV2AutoVhost is the shipped CHALLENGE_V2_AUTO_VHOST: the two
// score-driven challenges and Under-Attack. vhost_config (the operator's own
// always-on list) is opt-in — it can be long-lived, which is exactly where a
// deterministic false reject would stop being bounded.
const DefaultChallengeV2AutoVhost = autoV2SuspiciousVhost + "," + autoV2UniqPathsShort + "," + autoV2UnderAttack

// ParseChallengeV2AutoVhost parses the CHALLENGE_V2_AUTO_VHOST list. `off`
// (or none / 0 / -) anywhere in the list arms NOTHING — it is an explicit
// "no", so `off,under_attack` is off, never a quiet under_attack. Unknown
// tokens are returned separately so the caller can log them; they never arm
// anything. (The register passes the shipped default for an absent or EMPTY
// key, like every other knob — write `off` to disable.)
func ParseChallengeV2AutoVhost(s string) (armed []string, unknown []string) {
	seen := map[string]bool{}
	off := false
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch tok {
		case "":
			continue
		case "off", "none", "0", "-":
			off = true
		case autoV2SuspiciousVhost, autoV2UniqPathsShort, autoV2VhostConfig, autoV2UnderAttack:
			if !seen[tok] {
				seen[tok] = true
				armed = append(armed, tok)
			}
		default:
			unknown = append(unknown, tok)
		}
	}
	if off {
		return nil, unknown
	}
	return armed, unknown
}

// Tier sources, as reported by the read surfaces (rung_source).
const (
	tierSourceManual = "manual"
	tierSourcePin    = "pin"
	tierSourceAuto   = "auto"
)

// vhostV2Tier is the resolved vhost-level tier of one host.
type vhostV2Tier struct {
	Rung   string // "v2", or "" (v1 / no vhost tier)
	Source string // tierSourceManual | tierSourcePin | tierSourceAuto | "" (nothing covers the host)
	// Trigger is the automatic source covering the host (suspicious_vhost,
	// uniqpaths_short, vhost_config, under_attack, or "vhost" for an entry the
	// edge pushed without a reason). Empty for a manual tier or no source.
	Trigger string
	// Pin is the host's tier pin ("v1" / "v2") when one exists, reported even
	// when a manual arm outranks it, so a surface can show it is parked there.
	Pin string
}

// challengeV2VhostTier is the ONE vhost-tier resolver (see the file header).
//
// Cost: it runs on EVERY scored solve (challengeV2ArmGrain's vhost grain), so
// no exclusive lock is taken on the common path beyond the manual store's,
// which the manual tier always took: the bridge entry is one RLock (the same
// read the src= snapshot does), the pin store one RLock, and the Under-Attack
// tracker (an exclusive lock) is consulted ONLY when a vhost challenge covers
// the host and under_attack is in the armed set.
func (e *Engine) challengeV2VhostTier(host string) vhostV2Tier {
	var t vhostV2Tier
	if e == nil || host == "" {
		return t
	}
	pin, _ := e.tierPins.covering(host, time.Now())
	t.Pin = pin.Rung
	if target := e.manualRungTarget(host); target != "" {
		t.Rung = e.manualChal.rung(target)
		t.Source = tierSourceManual
		return t
	}
	trigger := e.autoV2Trigger(host)
	if trigger == "" {
		return t
	}
	t.Trigger = trigger
	if pin.Rung != "" {
		t.Source = tierSourcePin
		if pin.Rung == "v2" {
			t.Rung = "v2"
		}
		return t
	}
	t.Source = tierSourceAuto
	if e.autoV2Armed[trigger] {
		t.Rung = "v2"
	}
	return t
}

// autoV2Trigger names the automatic source covering host: "" unless a live
// automatic vhost challenge covers it (a bridge entry whose reason is not a
// manual arm's). Under-Attack only ever RE-NAMES that source — when
// under_attack is armed and the host is under attack, the trigger is
// under_attack (the stronger statement: the challenge is being defeated).
// It never arms on its own: an operator `attack on` with no vhost challenge
// (UA can be forced on a host nothing challenges) arms nothing, and the tier
// ends with the vhost challenge, never later — the TTL bound in the file
// header.
func (e *Engine) autoV2Trigger(host string) string {
	if e.nginxBridge == nil {
		return ""
	}
	reason, ok := e.nginxBridge.vhostChallengeReason(host)
	if !ok || reason == "manual" {
		return ""
	}
	if e.autoV2Armed[autoV2UnderAttack] && e.underAttackCovering(host) {
		return autoV2UnderAttack
	}
	if reason == "" {
		return srcVhost // edge-pushed entry: no source named, never armed
	}
	return reason
}

// underAttackCovering reports Under-Attack on host, or on its apex for a www.
// host (the apex/www resolution the manual tier uses too).
func (e *Engine) underAttackCovering(host string) bool {
	if on, _, _ := e.VhostAttackState(host); on {
		return true
	}
	if apex, found := strings.CutPrefix(host, "www."); found && apex != "" {
		on, _, _ := e.VhostAttackState(apex)
		return on
	}
	return false
}

// vhostChallengeReason returns the reason of the live vhost-wide CHALLENGE
// entry covering host, through the one vhost matcher (vhostEntryLocked).
func (b *NginxBridge) vhostChallengeReason(host string) (string, bool) {
	if b == nil || host == "" {
		return "", false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	h, ok := b.vhostEntryLocked(host, time.Now())
	if !ok || h.Action != "challenge" {
		return "", false
	}
	return strings.TrimSpace(h.Reason), true
}

// ── Tier pins ───────────────────────────────────────────────────────────────
//
// A pin fixes the tier an AUTOMATIC challenge has on one host ("v1" = never
// v2 here, whatever the knob says; "v2" = always v2 here, even for a source
// the knob leaves at v1). It changes nothing while no automatic source covers
// the host, never creates or extends a challenge, and a manual arm outranks
// it. Persisted (like manual challenges) so a daemon restart — which every
// config reload is — can never silently re-arm a host an operator pinned to
// v1. Optional expiry; zero = until cleared.

type tierPin struct {
	Rung      string // "v1" | "v2"
	ExpiresAt time.Time
	SetAt     time.Time
	Actor     string
}

type tierPinPersist struct {
	Host      string    `json:"host"`
	Rung      string    `json:"rung"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	SetAt     time.Time `json:"set_at"`
	Actor     string    `json:"actor,omitempty"`
}

// tierPinStore: an RWMutex so the per-solve read (covering) never takes an
// exclusive lock. Expired pins are dropped on every write (and on load), so
// the map holds at most the pins set since the last write plus the live ones.
type tierPinStore struct {
	mu   sync.RWMutex
	pins map[string]tierPin
	path string // "" = in-memory only
}

func (p tierPin) live(now time.Time) bool {
	return p.Rung != "" && (p.ExpiresAt.IsZero() || now.Before(p.ExpiresAt))
}

func (s *tierPinStore) init(path string) {
	s.pins = make(map[string]tierPin)
	s.path = strings.TrimSpace(path)
	s.load()
}

// getLocked returns host's own live pin (caller holds s.mu, R or W).
func (s *tierPinStore) getLocked(host string, now time.Time) (tierPin, bool) {
	p, ok := s.pins[host]
	if !ok || !p.live(now) {
		return tierPin{}, false
	}
	return p, true
}

// get returns host's own live pin (exact key).
func (s *tierPinStore) get(host string) (tierPin, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getLocked(host, time.Now())
}

// covering returns the pin covering host and the host it is set on: host's
// own, else its apex's for a www. host (the manual tier's resolution). One
// RLock. The ONE resolver for reading, clearing and the scoped guard.
func (s *tierPinStore) covering(host string, now time.Time) (tierPin, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.getLocked(host, now); ok {
		return p, host
	}
	if apex, found := strings.CutPrefix(host, "www."); found && apex != "" {
		if p, ok := s.getLocked(apex, now); ok {
			return p, apex
		}
	}
	return tierPin{}, ""
}

// apply pins host to rung ("v1" | "v2"; ttl <= 0 = no expiry) or clears its
// pin (rung ""), atomically: the previous live rung, whether anything changed
// (re-pinning the same rung with no expiry on either side is a no-op), and the
// write, all under one lock — so two concurrent requests can never both
// record the same transition.
func (s *tierPinStore) apply(host, rung string, ttl time.Duration, actor string) (prev string, changed bool) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil { // a zero store (an Engine built without NewEngine) stays usable
		s.pins = make(map[string]tierPin)
	}
	cur, has := s.getLocked(host, now)
	if has {
		prev = cur.Rung
	}
	switch {
	case rung == "" && !has:
		return prev, false
	case rung != "" && has && cur.Rung == rung && ttl <= 0 && cur.ExpiresAt.IsZero():
		return prev, false
	}
	for h, p := range s.pins { // drop expired pins on every write
		if !p.live(now) {
			delete(s.pins, h)
		}
	}
	if rung == "" {
		delete(s.pins, host)
	} else {
		p := tierPin{Rung: rung, SetAt: now, Actor: actor}
		if ttl > 0 {
			p.ExpiresAt = now.Add(ttl)
		}
		s.pins[host] = p
	}
	s.saveLocked()
	return prev, true
}

// set / clear are apply's two halves (kept for tests and readability).
func (s *tierPinStore) set(host, rung string, ttl time.Duration, actor string) string {
	prev, _ := s.apply(host, rung, ttl, actor)
	return prev
}

func (s *tierPinStore) clear(host string) string {
	prev, _ := s.apply(host, "", 0, "")
	return prev
}

// snapshot returns the live pins.
func (s *tierPinStore) snapshot() map[string]tierPin {
	now := time.Now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]tierPin, len(s.pins))
	for h, p := range s.pins {
		if p.live(now) {
			out[h] = p
		}
	}
	return out
}

// load reads the persisted pins, dropping expired or malformed entries.
// Best-effort, like manualChalState.load: a bad file leaves the store empty.
func (s *tierPinStore) load() {
	if s.path == "" {
		return
	}
	b, err := os.ReadFile(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var arr []tierPinPersist
	if err := json.Unmarshal(b, &arr); err != nil {
		logging.Logf("[challenge][vhost] tier pin load failed (%s): %v", s.path, err)
		return
	}
	now := time.Now()
	n := 0
	for _, e := range arr {
		h := normalizeHost(e.Host)
		p := tierPin{Rung: e.Rung, ExpiresAt: e.ExpiresAt, SetAt: e.SetAt, Actor: e.Actor}
		if h == "" || (p.Rung != "v1" && p.Rung != "v2") || !p.live(now) {
			continue
		}
		s.pins[h] = p
		n++
	}
	if n > 0 {
		logging.Logf("[challenge][vhost] restored %d challenge tier pin(s) from %s", n, s.path)
	}
}

// saveLocked atomically writes the live pins (caller holds s.mu for writing). Failure is
// logged, never fatal — mirrors manualChalState.saveLocked.
func (s *tierPinStore) saveLocked() {
	if s.path == "" {
		return
	}
	now := time.Now()
	arr := make([]tierPinPersist, 0, len(s.pins))
	for h, p := range s.pins {
		if !p.live(now) {
			continue
		}
		arr = append(arr, tierPinPersist{Host: h, Rung: p.Rung, ExpiresAt: p.ExpiresAt, SetAt: p.SetAt, Actor: p.Actor})
	}
	sort.Slice(arr, func(i, j int) bool { return arr[i].Host < arr[j].Host })
	b, err := json.MarshalIndent(arr, "", "  ")
	if err != nil {
		logging.Logf("[challenge][vhost] tier pin marshal failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		logging.Logf("[challenge][vhost] tier pin mkdir failed (%s): %v", s.path, err)
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		logging.Logf("[challenge][vhost] tier pin write failed (%s): %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, s.path); err != nil {
		logging.Logf("[challenge][vhost] tier pin rename failed (%s): %v", s.path, err)
		return
	}
	_ = os.Chmod(s.path, 0o600)
}

// ── Engine surface ──────────────────────────────────────────────────────────

// SetChallengeTierPinAs pins target's automatic-challenge tier (rung "v1" |
// "v2", ttl <= 0 = until cleared), or clears the pin (rung ""), recording the
// actor. Returns the previous pin rung and whether anything changed; a no-op
// (same rung, no expiry either side) writes no audit row, log line or state
// file. The check and the write are one atomic store operation. Nothing
// reaches the edge: the tier is read live at verify.
func (e *Engine) SetChallengeTierPinAs(target, rung string, ttl time.Duration, actor string) (prev string, changed bool) {
	prev, changed = e.tierPins.apply(target, rung, ttl, actor)
	if !changed {
		return prev, false
	}
	to, from := rungOrAuto(rung), rungOrAuto(prev)
	logging.LogfCHALLENGES(
		"[challenge][vhost] action=tier_pin host=%s from=%s to=%s ttl=%s actor=%s",
		target, from, to, pinTTLText(ttl), actorOrDash(actor),
	)
	payload := map[string]interface{}{"from": from, "rung": to}
	if ttl > 0 {
		payload["ttl_sec"] = int(ttl / time.Second)
	}
	if actor != "" {
		payload["actor"] = actor
	}
	e.appendHistory(HistoryEvent{TsUnix: time.Now().Unix(), Type: "challenge_vhost_tier_pin", Host: target, Mode: "manual", Payload: payload})
	return prev, true
}

func pinTTLText(ttl time.Duration) string {
	if ttl <= 0 {
		return "none"
	}
	return ttl.String()
}

// ChallengeTierPins returns the live tier pins (host → pin).
func (e *Engine) ChallengeTierPins() map[string]tierPin {
	return e.tierPins.snapshot()
}
