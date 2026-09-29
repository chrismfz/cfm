package webdetector

// ChallengeV2 on AUTOMATIC vhost challenges (auto-v2) + the per-host tier pin.
//
// Why: the Rung-1 week review (2026-09-29, 28 524 solves under the auto
// suspicious_vhost challenge) measured the arm before it existed — 36% of the
// convicted-farm solves would fail, ~0.06% of likely humans (2 of 3 395, both
// on software-rendered machines). A v2 tier on an auto challenge costs a
// passing human nothing (the page is the same), and its false-reject
// population is bounded by the automatic challenge's LIFETIME: it lasts while
// the scorer keeps the vhost suspicious (plus its holddown) or Under-Attack
// holds, and ends with it. That is not a fixed TTL — a vhost that stays
// suspicious for days stays at v2 for days — so the per-vhost v1 pin is the
// way out, and the CHALLENGE_VHOST list (permanent by nature) is opt-in. So
// the automatic sources arm v2 by default, and an operator can pin any host
// back to v1 (or forward to v2).
//
// The ONE resolver is challengeV2VhostTier: the verify gate
// (challengeV2HostArmed, wired in NewEngine) and every read surface (the vhost
// list, the per-host status, the CLI) answer "what tier is this vhost at"
// through it, so the teeth and the UI can never disagree. Precedence:
//
//  1. a MANUAL arm at v2 — v2;
//  2. no automatic source covering the host — the manual arm's v1, or no
//     vhost tier at all;
//  3. a tier PIN on the host (or its apex, for a www. host) — the pinned tier;
//  4. the node knob CHALLENGE_V2_AUTO_VHOST: v2 when the covering source is in
//     the armed set, else v1.
//
// A manual arm at v1 never DOWNGRADES what 3/4 give: a tier-less "Challenge"
// click or a tenant's panic-button arm must not switch off an auto-v2,
// Under-Attack or operator-pinned-v2 vhost. Down is a v1 pin.
//
// The automatic sources are the ones the tick NOTES on the live bridge vhost
// entry (NoteVhostAutoSource — the SAME entry and matcher the solve's src=
// snapshot reads, vhostEntryLocked): suspicious_vhost, uniqpaths_short,
// vhost_config and under_attack (the Under-Attack state as the tick evaluates
// it, operator override included). Each is re-noted on every cycle it is
// active with a short TTL (autoSourceNoteTTL, 2–10 min) and dropped the cycle it turns
// off, so the tier ends with the source or the vhost challenge, whichever
// goes first — no missed transition can leave a stale v2 — and a forced
// `attack on` on a host no vhost challenge covers arms nothing. The entry's
// single sticky Reason (which a manual arm or the config list relabels) is
// never read for arming.
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

// ParseChallengeV2AutoVhost parses the CHALLENGE_V2_AUTO_VHOST list.
// `off` (or none / 0 / -) anywhere in the list arms NOTHING and sets off —
// an explicit "no", so `off,under_attack` is off, never a quiet under_attack.
// `on` / `1` / `default` stand for DefaultChallengeV2AutoVhost. Unknown tokens
// are returned separately; they never arm anything. The caller decides what a
// list that armed nothing WITHOUT an explicit off means (the register falls
// back to the default: a blank, commented-out or typo'd value must not
// silently disarm the node).
func ParseChallengeV2AutoVhost(s string) (armed []string, unknown []string, off bool) {
	seen := map[string]bool{}
	add := func(tok string) {
		if !seen[tok] {
			seen[tok] = true
			armed = append(armed, tok)
		}
	}
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		tok = strings.ToLower(strings.Trim(strings.TrimSpace(tok), `"'`))
		switch tok {
		case "":
			continue
		case "off", "none", "0", "-", "no", "false":
			off = true
		case "on", "1", "default", "yes", "true":
			for _, d := range strings.Split(DefaultChallengeV2AutoVhost, ",") {
				add(d)
			}
		case autoV2SuspiciousVhost, autoV2UniqPathsShort, autoV2VhostConfig, autoV2UnderAttack:
			add(tok)
		default:
			unknown = append(unknown, tok)
		}
	}
	if off {
		return nil, unknown, true
	}
	return armed, unknown, false
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
	// PinActor is who set it ("admin" / "scoped" / "" internal) — a scoped
	// caller may change only a pin a scoped caller set — and ApexPinActor who
	// set the apex's pin for a www. host ("" when none): a scoped caller may
	// not pin a www. host over an operator's apex pin either.
	Pin          string
	PinActor     string
	ApexPinActor string
}

// pinLockedFor reports whether the host's pin is out of reach for a caller
// with this scope: a scoped caller may not change an operator's pin (the API
// refuses with 403 — the surfaces say so up front instead of offering a
// control that always fails).
func (t vhostV2Tier) pinLockedFor(scope map[string]struct{}) bool {
	if scope == nil {
		return false
	}
	me := actorFromScope(scope)
	return (t.Pin != "" && t.PinActor != me) || (t.ApexPinActor != "" && t.ApexPinActor != me)
}

// challengeV2VhostTier is the ONE vhost-tier resolver (see the file header).
//
// A manual arm at v2 is v2. A manual arm at v1 is v1 ONLY when no automatic
// source puts the host at v2: a default (tier-less) manual challenge, or a
// tenant's panic-button arm, must never DOWNGRADE an auto-v2, Under-Attack or
// operator-pinned-v2 vhost — the way down is a v1 pin or the manual arm's own
// v2→v1 switch on a host no automatic source covers.
//
// Cost: it runs on EVERY scored solve (challengeV2ArmGrain's vhost grain). The
// only exclusive lock is the manual store's mutex, taken as the manual tier
// always took it (manualRungTarget: the host, then the apex; then the rung).
// Beyond that: one pin-store RLock and one bridge RLock (the same vhost-entry
// read the src= snapshot does, plus the noted sources). Under-Attack costs
// nothing here — it is a note like every other source.
func (e *Engine) challengeV2VhostTier(host string) vhostV2Tier {
	var t vhostV2Tier
	if e == nil || host == "" {
		return t
	}
	now := time.Now()
	pin, _ := e.tierPins.covering(host, now)
	t.Pin, t.PinActor = pin.Rung, pin.Actor
	if apex, cut := strings.CutPrefix(host, "www."); cut && apex != "" {
		if ap, on := e.tierPins.covering(apex, now); on == apex {
			t.ApexPinActor = ap.Actor
			if t.ApexPinActor == "" {
				t.ApexPinActor = "-" // an internal pin still locks a scoped caller out
			}
		}
	}
	manual := false
	if target := e.manualRungTarget(host); target != "" {
		manual = true
		if e.manualChal.rung(target) == "v2" {
			t.Rung, t.Source = "v2", tierSourceManual
			return t
		}
	}
	trigger := e.autoV2Trigger(host)
	if trigger == "" {
		if manual {
			t.Source = tierSourceManual
		}
		return t
	}
	t.Trigger = trigger
	src, v2 := tierSourceAuto, e.autoV2Armed[trigger]
	if pin.Rung != "" {
		src, v2 = tierSourcePin, pin.Rung == "v2"
	}
	switch {
	case v2:
		t.Rung, t.Source = "v2", src
	case manual:
		t.Source = tierSourceManual
	default:
		t.Source = src
	}
	return t
}

// autoV2Trigger names the automatic source covering host, or "" when none
// does: the first ARMED source among those the tick has noted on the live
// vhost challenge covering host, else the first noted one (reported,
// unarmed). With no live vhost challenge, or no live note, there is no
// automatic source — the entry's own sticky Reason is never used to arm (it
// can outlive the source that wrote it). Every source, Under-Attack included,
// is re-noted by the tick on each cycle it is active and lapses within
// autoSourceNoteTTL once it is not, so the tier can never outlive either the
// vhost challenge or the source.
func (e *Engine) autoV2Trigger(host string) string {
	if e.nginxBridge == nil {
		return ""
	}
	sources, ok := e.nginxBridge.vhostAutoSources(host)
	if !ok {
		return ""
	}
	for _, src := range sources {
		if e.autoV2Armed[src] {
			return src
		}
	}
	if len(sources) > 0 {
		return sources[0]
	}
	return ""
}

// autoSourceNoteTTL is how long one tick's note of an active automatic source
// lives: 10 ticks, at least 2 minutes (so a tick slowed by a log backlog in
// the very flood this is for never drops the tier to v1 between re-notes) and
// at most 10 (so a source the tick stops seeing lapses soon).
func (e *Engine) autoSourceNoteTTL() time.Duration {
	ttl := 10 * e.cfg.Every
	if ttl < 2*time.Minute {
		ttl = 2 * time.Minute
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
	}
	return ttl
}

// autoSourceOrder is the order vhostAutoSources reports noted sources in —
// strongest first (Under-Attack: the challenge is being defeated) and fixed,
// so equal situations always resolve the same way.
var autoSourceOrder = [...]string{autoV2UnderAttack, autoV2SuspiciousVhost, autoV2UniqPathsShort, autoV2VhostConfig}

// vhostAutoSources returns the live automatic sources noted for host — by
// host itself, by its apex for a www. host (the bridge's apex→www expansion),
// or on the key of the vhost entry covering it — provided a live vhost-wide
// CHALLENGE entry covers host (the one vhost matcher, vhostEntryKeyLocked);
// ok=false when none does. One RLock.
func (b *NginxBridge) vhostAutoSources(host string) (sources []string, ok bool) {
	if b == nil || host == "" {
		return nil, false
	}
	now := time.Now()
	b.mu.RLock()
	defer b.mu.RUnlock()
	key, h, found := b.vhostEntryKeyLocked(host, now)
	if !found || h.Action != "challenge" {
		return nil, false
	}
	writers := []string{host}
	if apex, cut := strings.CutPrefix(host, "www."); cut && apex != "" {
		writers = append(writers, apex)
	}
	if key != host {
		writers = append(writers, key)
	}
	for _, src := range autoSourceOrder {
		for _, w := range writers {
			if exp, live := b.vhAuto[w][src]; live && exp.After(now) {
				sources = append(sources, src)
				break
			}
		}
	}
	return sources, true
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
// RLock. The read-side resolver (apply repeats it inside its write lock).
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

// apply pins host to rung ("v1" | "v2"; ttl <= 0 = no expiry) or clears the
// pin covering host (rung ""), atomically — the covering lookup, the guards,
// the no-op test and the write are ONE critical section, so two concurrent
// requests can never both record the same transition, nor can a guard pass on
// a pin that changes before the write. Clearing acts on the covering pin (the
// host's own, else its apex's for www.); allowTarget (nil = allow) vets that
// host; protect (nil = none) refuses when it returns true for the covering
// pin. Returns the host acted on, the previous rung there, whether anything
// changed, and a non-empty refusal.
func (s *tierPinStore) apply(host, rung string, ttl time.Duration, actor string,
	allowTarget func(string) bool, protect func(tierPin) bool) (target, prev string, changed bool, refusal string) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pins == nil { // a zero store (an Engine built without NewEngine) stays usable
		s.pins = make(map[string]tierPin)
	}
	own, hasOwn := s.getLocked(host, now)
	apexPin, apexHost, hasApex := tierPin{}, "", false
	if apex, found := strings.CutPrefix(host, "www."); found && apex != "" {
		apexPin, hasApex = s.getLocked(apex, now)
		apexHost = apex
	}
	target = host
	if rung == "" && !hasOwn && hasApex {
		target = apexHost // clearing acts on the pin that covers host
	}
	if allowTarget != nil && !allowTarget(target) {
		return target, "", false, "the pin covering " + host + " is on " + target + ", which is not in scope"
	}
	if protect != nil {
		// The pin being changed must be the caller's to change; and a new
		// pin on a www. host must not shadow a protected apex pin — nor may
		// an existing www. pin be refreshed over one set later.
		refused := ""
		switch {
		case target == host && hasOwn && protect(own):
			refused = host
		case target == apexHost && hasApex && protect(apexPin):
			refused = apexHost
		case rung != "" && hasApex && protect(apexPin):
			refused = apexHost
		}
		if refused != "" {
			return target, "", false, "the tier on " + refused + " was pinned by the operator — ask them to change it"
		}
	}
	cur, has := s.getLocked(target, now)
	if has {
		prev = cur.Rung
	}
	switch {
	case rung == "" && !has:
		return target, prev, false, ""
	case rung != "" && has && cur.Rung == rung && ttl <= 0 && cur.ExpiresAt.IsZero():
		return target, prev, false, ""
	}
	for h, p := range s.pins { // drop expired pins on every write
		if !p.live(now) {
			delete(s.pins, h)
		}
	}
	if rung == "" {
		delete(s.pins, target)
	} else {
		p := tierPin{Rung: rung, SetAt: now, Actor: actor}
		if ttl > 0 {
			p.ExpiresAt = now.Add(ttl)
		}
		s.pins[target] = p
	}
	s.saveLocked()
	return target, prev, true, ""
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

// setChallengeTierPin pins host's automatic-challenge tier (rung "v1" | "v2",
// ttl <= 0 = until cleared), or clears the pin covering it (rung ""),
// recording the actor, with the API handler's guards (tierPinStore.apply)
// evaluated in the same critical section as the write. Returns the host acted
// on, the previous pin rung, whether anything changed, and a refusal. A no-op
// writes no audit row, log line or state file. Nothing reaches the edge: the
// tier is read live at verify.
func (e *Engine) setChallengeTierPin(host, rung string, ttl time.Duration, actor string,
	allowTarget func(string) bool, protect func(tierPin) bool) (target, prev string, changed bool, refusal string) {
	target, prev, changed, refusal = e.tierPins.apply(host, rung, ttl, actor, allowTarget, protect)
	if !changed {
		return target, prev, false, refusal
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
	return target, prev, true, ""
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
