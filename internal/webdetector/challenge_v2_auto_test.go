package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	core "cfm/internal/detectors/core"
)

// SetChallengeTierPinAs is the unguarded pin write the tests use (the API
// handler calls setChallengeTierPin with its scope/operator guards).
func (e *Engine) SetChallengeTierPinAs(host, rung string, ttl time.Duration, actor string) (target, prev string, changed bool) {
	target, prev, changed, _ = e.setChallengeTierPin(host, rung, ttl, actor, nil, nil)
	return target, prev, changed
}

// Auto-v2: an AUTOMATIC vhost challenge runs at the v2 tier when its source is
// in CHALLENGE_V2_AUTO_VHOST, a per-host tier pin overrides that, a manual v2
// arm is v2 and a manual v1 arm never downgrades — all through the one
// resolver the verify gate reads.

func newAutoV2TestEngine(t *testing.T, armed ...string) *Engine {
	t.Helper()
	e := newTestEngineForChallengeHandlers()
	e.tierPins.init("")
	e.nginxBridge = NewNginxBridge("/tmp/cfm-test-autov2.sock", "tok", time.Minute, time.Minute)
	e.autoV2Armed = map[string]bool{}
	for _, a := range armed {
		e.autoV2Armed[a] = true
	}
	return e
}

// setVhostEntry installs a live vhost challenge entry. When reason names an
// automatic source it also notes that source on the entry, as the tick does
// every cycle the source is active (only noted sources can arm).
func setVhostEntry(e *Engine, host, reason string) {
	e.nginxBridge.mu.Lock()
	e.nginxBridge.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Hour), Reason: reason}
	e.nginxBridge.mu.Unlock()
	switch reason {
	case autoV2SuspiciousVhost, autoV2UniqPathsShort, autoV2VhostConfig:
		noteSource(e, host, reason)
	}
}

// noteSource writes a live source note directly (independent of whether the
// bridge has a socket, unlike NoteVhostAutoSource).
func noteSource(e *Engine, host, src string) {
	b := e.nginxBridge
	b.mu.Lock()
	if b.vhAuto[host] == nil {
		b.vhAuto[host] = map[string]time.Time{}
	}
	b.vhAuto[host][src] = time.Now().Add(time.Hour)
	b.mu.Unlock()
}

func dropSource(e *Engine, host, src string) {
	b := e.nginxBridge
	b.mu.Lock()
	delete(b.vhAuto[host], src)
	b.mu.Unlock()
}

func TestParseChallengeV2AutoVhost(t *testing.T) {
	armed, unknown, off := ParseChallengeV2AutoVhost(DefaultChallengeV2AutoVhost)
	if strings.Join(armed, ",") != "suspicious_vhost,uniqpaths_short,under_attack" || len(unknown) != 0 || off {
		t.Fatalf("default: armed=%v unknown=%v off=%v", armed, unknown, off)
	}
	for _, v := range []string{"off", "none", "0", "-", "  OFF ", "no", `"off"`} {
		if armed, unknown, off := ParseChallengeV2AutoVhost(v); len(armed) != 0 || len(unknown) != 0 || !off {
			t.Fatalf("%q must be an explicit off: %v %v %v", v, armed, unknown, off)
		}
	}
	// A blank value arms nothing but is NOT an explicit off (the register
	// then keeps the default).
	if armed, _, off := ParseChallengeV2AutoVhost(""); len(armed) != 0 || off {
		t.Fatalf("blank: %v off=%v", armed, off)
	}
	// `off` anywhere is an explicit "no" — never a quiet partial arm.
	if armed, _, off := ParseChallengeV2AutoVhost("off,under_attack"); len(armed) != 0 || !off {
		t.Fatalf("off must win over other sources: %v", armed)
	}
	// on / 1 / default = the shipped set.
	for _, v := range []string{"on", "1", "default"} {
		if armed, _, _ := ParseChallengeV2AutoVhost(v); strings.Join(armed, ",") != DefaultChallengeV2AutoVhost {
			t.Fatalf("%q must mean the default: %v", v, armed)
		}
	}
	armed, unknown, _ = ParseChallengeV2AutoVhost("Vhost_Config, suspicious_vhost suspicious_vhost,manual,bogus")
	if strings.Join(armed, ",") != "vhost_config,suspicious_vhost" {
		t.Fatalf("case/dedupe: armed=%v", armed)
	}
	// "manual" is not an automatic source (a manual arm has its own tier).
	if strings.Join(unknown, ",") != "manual,bogus" {
		t.Fatalf("unknown tokens must be reported, never armed: %v", unknown)
	}
}

func TestChallengeV2VhostTier_KnobArmsAutomaticSources(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost, autoV2UniqPathsShort)

	if tier := e.challengeV2VhostTier("idle.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("no challenge covers the host: %+v", tier)
	}
	setVhostEntry(e, "busy.gr", "suspicious_vhost")
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "v2" || tier.Source != tierSourceAuto || tier.Trigger != "suspicious_vhost" {
		t.Fatalf("armed source: %+v", tier)
	}
	setVhostEntry(e, "paths.gr", "uniqpaths_short")
	if tier := e.challengeV2VhostTier("paths.gr"); tier.Rung != "v2" {
		t.Fatalf("uniqpaths_short armed: %+v", tier)
	}
	// The operator's config list is not in the set here: v1, but reported.
	setVhostEntry(e, "listed.gr", "vhost_config")
	if tier := e.challengeV2VhostTier("listed.gr"); tier.Rung != "" || tier.Source != tierSourceAuto || tier.Trigger != "vhost_config" {
		t.Fatalf("unarmed source must stay v1: %+v", tier)
	}
	// An entry with no noted source — edge-pushed, or whose source the tick
	// stopped noting — is not automatic: its sticky Reason never arms.
	setVhostEntry(e, "edge.gr", "")
	if tier := e.challengeV2VhostTier("edge.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("reason-less entry: %+v", tier)
	}
	setVhostEntry(e, "stale.gr", "suspicious_vhost")
	dropSource(e, "stale.gr", autoV2SuspiciousVhost)
	if tier := e.challengeV2VhostTier("stale.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("sticky reason without a live note must not arm: %+v", tier)
	}
	// A bridge entry left by a manual arm is not an automatic source once
	// the manual arm itself is gone.
	setVhostEntry(e, "gone.gr", "manual")
	if tier := e.challengeV2VhostTier("gone.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("manual bridge entry without a manual arm: %+v", tier)
	}
	// A wildcard entry is matched through the one vhost matcher; the notes
	// are the concrete host's (the tick notes the hosts it evaluates, never a
	// pattern key).
	setVhostEntry(e, "*.wild.gr", "")
	if tier := e.challengeV2VhostTier("a.wild.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("wildcard entry with no note: %+v", tier)
	}
	noteSource(e, "a.wild.gr", autoV2SuspiciousVhost)
	if tier := e.challengeV2VhostTier("a.wild.gr"); tier.Rung != "v2" {
		t.Fatalf("wildcard entry, noted host: %+v", tier)
	}

	// Knob off: every automatic source is v1.
	off := newAutoV2TestEngine(t)
	setVhostEntry(off, "busy.gr", "suspicious_vhost")
	if tier := off.challengeV2VhostTier("busy.gr"); tier.Rung != "" || tier.Source != tierSourceAuto {
		t.Fatalf("knob off: %+v", tier)
	}
}

func TestChallengeV2VhostTier_PinAndManualPrecedence(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost)
	setVhostEntry(e, "shop.gr", "suspicious_vhost")
	setVhostEntry(e, "www.shop.gr", "suspicious_vhost")

	// Pin v1: the "drop it back to v1" control beats the knob.
	e.SetChallengeTierPinAs("shop.gr", "v1", 0, "admin")
	if tier := e.challengeV2VhostTier("shop.gr"); tier.Rung != "" || tier.Source != tierSourcePin || tier.Pin != "v1" || tier.Trigger != "suspicious_vhost" {
		t.Fatalf("v1 pin: %+v", tier)
	}
	// ...and covers the www variant (the apex resolution of the manual tier).
	if tier := e.challengeV2VhostTier("www.shop.gr"); tier.Rung != "" || tier.Source != tierSourcePin {
		t.Fatalf("apex pin must cover www: %+v", tier)
	}
	// A www pin of its own is the more specific one.
	e.SetChallengeTierPinAs("www.shop.gr", "v2", 0, "admin")
	if tier := e.challengeV2VhostTier("www.shop.gr"); tier.Rung != "v2" || tier.Pin != "v2" {
		t.Fatalf("own www pin: %+v", tier)
	}

	// Pin v2 arms a source the knob leaves at v1.
	setVhostEntry(e, "listed.gr", "vhost_config")
	e.SetChallengeTierPinAs("listed.gr", "v2", 0, "admin")
	if tier := e.challengeV2VhostTier("listed.gr"); tier.Rung != "v2" || tier.Source != tierSourcePin {
		t.Fatalf("v2 pin: %+v", tier)
	}

	// A pin does nothing while no automatic challenge covers the host — but
	// it is still reported, so a surface can say it is parked there.
	e.SetChallengeTierPinAs("quiet.gr", "v2", 0, "admin")
	if tier := e.challengeV2VhostTier("quiet.gr"); tier.Rung != "" || tier.Source != "" || tier.Pin != "v2" {
		t.Fatalf("pin without a challenge must not arm: %+v", tier)
	}

	// A tier-less (v1) manual arm never DOWNGRADES an automatic v2: here the
	// operator's v2 pin keeps applying — the scoped panic-button bypass the
	// second review found. (A manual arm relabels the bridge entry "manual";
	// the source the tick noted on it still names the automatic challenge.)
	e.nginxBridge.NoteVhostAutoSource("listed.gr", autoV2VhostConfig, time.Hour)
	e.ManualChallengeVhost("listed.gr", time.Hour, "manual", "")
	setVhostEntry(e, "listed.gr", "manual")
	if tier := e.challengeV2VhostTier("listed.gr"); tier.Rung != "v2" || tier.Source != tierSourcePin || tier.Trigger != "vhost_config" {
		t.Fatalf("manual v1 must not beat a v2 pin: %+v", tier)
	}
	// ...but with no automatic source behind it, the manual v1 arm is v1.
	e.nginxBridge.DropVhostAutoSource("listed.gr", autoV2VhostConfig)
	if tier := e.challengeV2VhostTier("listed.gr"); tier.Rung != "" || tier.Source != tierSourceManual || tier.Pin != "v2" {
		t.Fatalf("manual v1 alone: %+v", tier)
	}
	// A manual v2 arm beats a v1 pin.
	e.ManualChallengeVhost("shop.gr", time.Hour, "manual", "v2")
	if tier := e.challengeV2VhostTier("shop.gr"); tier.Rung != "v2" || tier.Source != tierSourceManual {
		t.Fatalf("manual v2 must beat a v1 pin: %+v", tier)
	}

	// Clearing the pin hands the tier back to the knob.
	e.SetChallengeTierPinAs("listed.gr", "", 0, "admin")
	e.ClearManualChallengeVhost("listed.gr")
	setVhostEntry(e, "listed.gr", "vhost_config") // the manual clear dropped the bridge entry
	e.nginxBridge.NoteVhostAutoSource("listed.gr", autoV2VhostConfig, time.Hour)
	if tier := e.challengeV2VhostTier("listed.gr"); tier.Rung != "" || tier.Source != tierSourceAuto || tier.Pin != "" {
		t.Fatalf("cleared pin: %+v", tier)
	}
}

func TestChallengeV2VhostTier_ManualV1NeverDowngrades(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost, autoV2UnderAttack)
	// A tier-less "Challenge" click on an auto-v2 host relabels the entry
	// "manual"; the tick keeps noting the scorer's source on it.
	e.nginxBridge.NoteVhostAutoSource("busy.gr", autoV2SuspiciousVhost, time.Hour)
	e.ManualChallengeVhost("busy.gr", time.Hour, "cfm-admin-ui", "")
	setVhostEntry(e, "busy.gr", "manual")
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "v2" || tier.Source != tierSourceAuto || tier.Trigger != "suspicious_vhost" {
		t.Fatalf("manual v1 over auto-v2: %+v", tier)
	}
	// ...and the www variant (the note is written for the bridge variants).
	setVhostEntry(e, "www.busy.gr", "manual")
	if tier := e.challengeV2VhostTier("www.busy.gr"); tier.Rung != "v2" {
		t.Fatalf("www of an auto-v2 apex under a manual arm: %+v", tier)
	}
	// Under attack: v2 even over a manual v1 arm with no scorer source.
	e.nginxBridge.DropVhostAutoSource("busy.gr", autoV2SuspiciousVhost)
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "" || tier.Source != tierSourceManual {
		t.Fatalf("manual v1 alone after the source dropped: %+v", tier)
	}
	noteSource(e, "busy.gr", autoV2UnderAttack)
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("manual v1 under attack: %+v", tier)
	}
	// The way down is a v1 pin — and the surfaces say it is the PIN holding
	// the host at v1 (not the manual arm), so it is never mistaken for
	// inactive and cleared.
	e.SetChallengeTierPinAs("busy.gr", "v1", 0, "admin")
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "" || tier.Source != tierSourcePin {
		t.Fatalf("v1 pin under a manual v1 arm: %+v", tier)
	}
}

// The tick's source notes, not the entry's single sticky Reason, name the
// automatic source: the first ARMED one wins, a dropped or expired note is
// gone, and a clear takes the notes with the entry.
func TestChallengeV2VhostTier_SourceNotes(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2UniqPathsShort)
	b := e.nginxBridge

	// A CHALLENGE_VHOST-listed host the scorer ALSO flags: labelled
	// vhost_config (unarmed); the armed uniqpaths note is found anyway,
	// ahead of the unarmed suspicious one.
	setVhostEntry(e, "both.gr", "vhost_config")
	b.NoteVhostAutoSource("both.gr", autoV2SuspiciousVhost, time.Hour)
	b.NoteVhostAutoSource("both.gr", autoV2UniqPathsShort, time.Hour)
	b.NoteVhostAutoSource("both.gr", autoV2VhostConfig, time.Hour)
	if tier := e.challengeV2VhostTier("both.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UniqPathsShort {
		t.Fatalf("first armed noted source: %+v", tier)
	}
	// Source off → dropped: back to the first noted (unarmed) source.
	b.DropVhostAutoSource("both.gr", autoV2UniqPathsShort)
	if tier := e.challengeV2VhostTier("both.gr"); tier.Rung != "" || tier.Trigger != autoV2SuspiciousVhost {
		t.Fatalf("after drop: %+v", tier)
	}
	// An expired note is ignored even before the sweep removes it.
	b.mu.Lock()
	b.vhAuto["both.gr"][autoV2UniqPathsShort] = time.Now().Add(-time.Second)
	b.mu.Unlock()
	if tier := e.challengeV2VhostTier("both.gr"); tier.Trigger == autoV2UniqPathsShort {
		t.Fatalf("expired note used: %+v", tier)
	}
	// ClearVhost takes the notes with the entry.
	b.ClearVhost("both.gr", "test")
	b.mu.RLock()
	_, left := b.vhAuto["both.gr"]
	b.mu.RUnlock()
	if left {
		t.Fatalf("ClearVhost left the source notes behind")
	}
	if tier := e.challengeV2VhostTier("both.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("after clear: %+v", tier)
	}
	// Notes are keyed on the writer: a www. host's own cycle dropping its
	// (absent) note never erases what the apex noted — the reader resolves
	// www→apex.
	setVhostEntry(e, "apex.gr", "")
	setVhostEntry(e, "www.apex.gr", "")
	b.NoteVhostAutoSource("apex.gr", autoV2UniqPathsShort, time.Hour)
	b.DropVhostAutoSource("www.apex.gr", autoV2UniqPathsShort)
	if tier := e.challengeV2VhostTier("www.apex.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UniqPathsShort {
		t.Fatalf("www cycle erased the apex note: %+v", tier)
	}
	// Suppressing the automatic challenge (exclude/ignore under a kept manual
	// arm) forgets every note the host wrote at once — and a suppressed www.
	// host stops inheriting its apex's.
	b.NoteVhostAutoSource("apex.gr", autoV2SuspiciousVhost, time.Hour)
	b.SuppressVhostAutoSources("www.apex.gr", time.Hour)
	if tier := e.challengeV2VhostTier("www.apex.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("suppressed www still inherits its apex: %+v", tier)
	}
	if tier := e.challengeV2VhostTier("apex.gr"); tier.Rung != "v2" {
		t.Fatalf("the apex's own sources must be untouched: %+v", tier)
	}
	b.SuppressVhostAutoSources("apex.gr", time.Hour)
	if tier := e.challengeV2VhostTier("apex.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("after suppress: %+v", tier)
	}

	// A note with no live entry arms nothing (the tier ends with the entry).
	b.NoteVhostAutoSource("ghost.gr", autoV2UniqPathsShort, time.Hour)
	if tier := e.challengeV2VhostTier("ghost.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("note without an entry: %+v", tier)
	}
}

func TestChallengeV2VhostTier_UnderAttackArms(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2UnderAttack)
	setVhostEntry(e, "hit.gr", "vhost_config") // not in the set on its own

	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" {
		t.Fatalf("before under-attack: %+v", tier)
	}
	// The tick notes under_attack each cycle it evaluates the state ON.
	noteSource(e, "hit.gr", autoV2UnderAttack)
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("under-attack must arm v2: %+v", tier)
	}
	// An operator's v1 pin still wins (the emergency "drop it back").
	e.SetChallengeTierPinAs("hit.gr", "v1", 0, "admin")
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" || tier.Source != tierSourcePin {
		t.Fatalf("v1 pin under attack: %+v", tier)
	}
	e.SetChallengeTierPinAs("hit.gr", "", 0, "admin")

	// A forced `attack on` with NO vhost challenge arms nothing: the tier
	// must end with the vhost challenge, never outlive it.
	noteSource(e, "forced.gr", autoV2UnderAttack)
	if tier := e.challengeV2VhostTier("forced.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("under-attack without a vhost challenge must not arm: %+v", tier)
	}

	// `attack off` drops the note at once, not on the next tick.
	e.attack = newUnderAttackTracker()
	e.cfg.UnderAttackHolddown = time.Minute
	e.SetVhostAttackOverride("hit.gr", false, time.Now(), 0)
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Trigger == autoV2UnderAttack {
		t.Fatalf("attack off left the under_attack note: %+v", tier)
	}
	noteSource(e, "hit.gr", autoV2UnderAttack)

	// under_attack not in the set: the state alone does not arm, the other
	// noted source is reported instead (strongest-first order: UA listed
	// first, but only an ARMED source wins).
	e.autoV2Armed = map[string]bool{}
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("under_attack unarmed: %+v", tier)
	}
	e.autoV2Armed = map[string]bool{autoV2VhostConfig: true}
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "v2" || tier.Trigger != autoV2VhostConfig {
		t.Fatalf("armed vhost_config beside unarmed under_attack: %+v", tier)
	}
	// The state leaves (the tick stops noting it): back to the other source.
	e.autoV2Armed = map[string]bool{autoV2UnderAttack: true}
	dropSource(e, "hit.gr", autoV2UnderAttack)
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" || tier.Trigger != "vhost_config" {
		t.Fatalf("attack off: %+v", tier)
	}
}

func TestTierPinStore_ApplyIsAtomicAndSweeps(t *testing.T) {
	var s tierPinStore
	s.init("")
	if _, prev, changed, _ := s.apply("a.gr", "v1", 0, "admin", nil, nil); prev != "" || !changed {
		t.Fatalf("first pin: %q %v", prev, changed)
	}
	if _, prev, changed, _ := s.apply("a.gr", "v1", 0, "admin", nil, nil); prev != "v1" || changed {
		t.Fatalf("same pin must be a no-op: %q %v", prev, changed)
	}
	if _, _, changed, _ := s.apply("none.gr", "", 0, "", nil, nil); changed {
		t.Fatalf("clearing an absent pin must be a no-op")
	}
	// Clearing a www. host acts on the apex pin covering it; the guards see
	// THAT pin, inside the same lock as the write.
	if target, _, changed, refusal := s.apply("www.a.gr", "", 0, "scoped", nil, func(p tierPin) bool { return p.Actor != "scoped" }); changed || refusal == "" || target != "a.gr" {
		t.Fatalf("protected apex pin: target=%q changed=%v refusal=%q", target, changed, refusal)
	}
	if _, _, changed, refusal := s.apply("www.a.gr", "", 0, "admin", func(h string) bool { return h != "a.gr" }, nil); changed || refusal == "" {
		t.Fatalf("out-of-scope clear target must be refused: %v %q", changed, refusal)
	}
	// An expired pin is dropped from the map on the next write.
	s.mu.Lock()
	s.pins["old.gr"] = tierPin{Rung: "v1", ExpiresAt: time.Now().Add(-time.Minute)}
	s.mu.Unlock()
	s.apply("b.gr", "v2", 0, "admin", nil, nil)
	s.mu.RLock()
	_, stale := s.pins["old.gr"]
	s.mu.RUnlock()
	if stale {
		t.Fatalf("expired pin survived a write")
	}
	// covering: own pin, else the apex's for www.
	if p, on := s.covering("www.a.gr", time.Now()); p.Rung != "v1" || on != "a.gr" {
		t.Fatalf("apex covering: %+v %q", p, on)
	}
}

func TestTierPinStore_PersistsAndExpires(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")
	var s tierPinStore
	s.init(path)
	s.apply("a.gr", "v1", 0, "admin", nil, nil)
	s.apply("b.gr", "v2", time.Hour, "scoped", nil, nil)
	s.apply("gone.gr", "v2", time.Hour, "admin", nil, nil)
	s.apply("gone.gr", "", 0, "admin", nil, nil)

	var r tierPinStore
	r.init(path)
	if p, ok := r.get("a.gr"); !ok || p.Rung != "v1" || !p.ExpiresAt.IsZero() || p.Actor != "admin" {
		t.Fatalf("a.gr after reload: %+v %v", p, ok)
	}
	if p, ok := r.get("b.gr"); !ok || p.Rung != "v2" || p.ExpiresAt.IsZero() {
		t.Fatalf("b.gr after reload: %+v %v", p, ok)
	}
	if _, ok := r.get("gone.gr"); ok {
		t.Fatalf("cleared pin came back after reload")
	}

	// An expired or malformed entry never loads.
	raw := `[{"host":"old.gr","rung":"v1","expires_at":"2020-01-01T00:00:00Z","set_at":"2020-01-01T00:00:00Z"},
	         {"host":"bad.gr","rung":"v3","set_at":"2020-01-01T00:00:00Z"},
	         {"host":"OK.gr","rung":"v2","set_at":"2020-01-01T00:00:00Z"}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	var x tierPinStore
	x.init(path)
	if snap := x.snapshot(); len(snap) != 1 || snap["ok.gr"].Rung != "v2" {
		t.Fatalf("load must keep only live, valid, normalized pins: %+v", snap)
	}
}

func tierReq(t *testing.T, e *Engine, r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := httptest.NewRecorder()
	e.handleChallengeVhostTier(rr, r)
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr, body
}

func TestHandleChallengeVhostTier(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost)
	setVhostEntry(e, "shop.gr", "suspicious_vhost")
	post := func(qs string) (*httptest.ResponseRecorder, map[string]any) {
		return tierReq(t, e, httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/tier?"+qs, nil))
	}

	rr, body := post("host=shop.gr&rung=v1")
	if rr.Code != http.StatusOK || body["pin"] != "v1" || body["from"] != "auto" || body["changed"] != true {
		t.Fatalf("pin v1: %d %v", rr.Code, body)
	}
	if tier := body["tier"].(map[string]any); tier["rung"] != "v1" || tier["source"] != "pin" || tier["trigger"] != "suspicious_vhost" {
		t.Fatalf("effective tier after pin: %v", tier)
	}
	if tierArmedFor(e, "shop.gr") {
		t.Fatalf("v1 pin must disarm the gate")
	}
	// Same pin again: no-op, no audit.
	if _, body := post("host=shop.gr&rung=v1"); body["changed"] != false {
		t.Fatalf("repeat pin must be a no-op: %v", body)
	}
	// Back to auto: the knob arms v2 again.
	if rr, body := post("host=shop.gr&rung=auto"); rr.Code != http.StatusOK || body["pin"] != "auto" || body["from"] != "v1" {
		t.Fatalf("clear pin: %d %v", rr.Code, body)
	}
	if !tierArmedFor(e, "shop.gr") {
		t.Fatalf("clearing the pin must re-arm via the knob")
	}
	// A ttl expires the pin.
	if _, body := post("host=shop.gr&rung=v1&ttl=2h"); body["expires_at"] == nil {
		t.Fatalf("ttl pin without expires_at: %v", body)
	}

	for _, qs := range []string{"rung=v1", "host=shop.gr", "host=shop.gr&rung=v3", "host=*.shop.gr&rung=v1", "host=shop.gr&rung=v1&ttl=soon"} {
		if rr, _ := post(qs); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", qs, rr.Code)
		}
	}

	// Scoped: own vhost only, TTL always capped (never a permanent pin).
	if rr, _ := tierReq(t, e, scopedAddReq("/api/v1/challenge/vhost/tier?host=other.gr&rung=v1")); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped out-of-scope: %d", rr.Code)
	}
	rr, body = tierReq(t, e, scopedAddReq("/api/v1/challenge/vhost/tier?host=tenant-a.example.com&rung=v1"))
	if rr.Code != http.StatusOK || body["ttl_capped"] != true || body["expires_at"] == nil {
		t.Fatalf("scoped pin must be TTL-capped: %d %v", rr.Code, body)
	}
	p, _ := e.tierPins.get("tenant-a.example.com")
	if d := time.Until(p.ExpiresAt); d <= 0 || d > scopedMaxChallengeTTL {
		t.Fatalf("scoped pin expiry %v outside the cap", d)
	}
	// Clearing a www host acts on the apex pin covering it — which a token
	// holding only the www host may not touch.
	e.SetChallengeTierPinAs("example.com", "v1", 0, "admin")
	req := scopedAddReq("/api/v1/challenge/vhost/tier?host=www.example.com&rung=auto")
	req = req.WithContext(context.WithValue(req.Context(), CtxScopeKey{}, map[string]struct{}{"www.example.com": {}}))
	if rr, _ := tierReq(t, e, req); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped clear of an out-of-scope apex pin: %d", rr.Code)
	}
	if _, ok := e.tierPins.get("example.com"); !ok {
		t.Fatalf("the apex pin was cleared through an out-of-scope www")
	}

	// An operator's pin is not the tenant's to replace, clear, or shadow
	// with a www. pin of its own.
	e.SetChallengeTierPinAs("tenant-a.example.com", "v2", 0, "admin")
	for _, qs := range []string{"rung=v1", "rung=auto"} {
		if rr, _ := tierReq(t, e, scopedAddReq("/api/v1/challenge/vhost/tier?host=tenant-a.example.com&"+qs)); rr.Code != http.StatusForbidden {
			t.Fatalf("scoped %s over an operator pin: %d", qs, rr.Code)
		}
	}
	if p, ok := e.tierPins.get("tenant-a.example.com"); !ok || p.Rung != "v2" || p.Actor != "admin" || !p.ExpiresAt.IsZero() {
		t.Fatalf("operator pin was altered by a scoped call: %+v %v", p, ok)
	}
	e.SetChallengeTierPinAs("example.com", "v1", 0, "admin")
	both := func(qs string) *http.Request {
		r := scopedAddReq("/api/v1/challenge/vhost/tier?" + qs)
		return r.WithContext(context.WithValue(r.Context(), CtxScopeKey{}, map[string]struct{}{"www.example.com": {}, "example.com": {}}))
	}
	if rr, _ := tierReq(t, e, both("host=www.example.com&rung=v2")); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped www pin shadowing an operator apex pin: %d", rr.Code)
	}
	// Nor may a www. pin the tenant set EARLIER be refreshed over an
	// operator's apex pin set since — but the tenant may still remove it.
	e.SetChallengeTierPinAs("example.com", "", 0, "admin")
	if rr, _ := tierReq(t, e, both("host=www.example.com&rung=v1")); rr.Code != http.StatusOK {
		t.Fatalf("tenant www pin with no operator apex pin: %d", rr.Code)
	}
	e.SetChallengeTierPinAs("example.com", "v2", 0, "admin")
	if rr, _ := tierReq(t, e, both("host=www.example.com&rung=v1")); rr.Code != http.StatusForbidden {
		t.Fatalf("tenant www pin refreshed over an operator apex pin: %d", rr.Code)
	}
	if tier := e.challengeV2VhostTierForScope("www.example.com"); !tier.pinLockedFor(map[string]struct{}{"www.example.com": {}}) {
		t.Fatalf("www under an operator apex pin must read as locked for the tenant: %+v", tier)
	}
	// A www-only tenant under a TENANT apex pin: may set its own www pin,
	// may not clear the apex's (out of its scope).
	e.SetChallengeTierPinAs("www.example.com", "", 0, "admin")
	e.SetChallengeTierPinAs("example.com", "v1", time.Hour, "scoped")
	wwwOnly := map[string]struct{}{"www.example.com": {}}
	tier := e.challengeV2VhostTierForScope("www.example.com")
	if tier.pinLockedFor(wwwOnly) || !tier.unpinLockedFor(wwwOnly) || !tier.PinOnApex {
		t.Fatalf("www-only tenant under a tenant apex pin: %+v", tier)
	}
	e.SetChallengeTierPinAs("example.com", "v2", 0, "admin")
	e.SetChallengeTierPinAs("www.example.com", "v1", time.Hour, "scoped") // the tenant's own, for the next step
	if rr, _ := tierReq(t, e, both("host=www.example.com&rung=auto")); rr.Code != http.StatusOK {
		t.Fatalf("tenant removing its own www pin: %d", rr.Code)
	}

	// GET lists pins, admin only.
	rr, body = tierReq(t, e, httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/tier", nil).WithContext(adminCtx()))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"host":"example.com"`) {
		t.Fatalf("admin list: %d %s", rr.Code, rr.Body.String())
	}
	g := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/tier", nil)
	g = g.WithContext(scopedAddReq("/").Context())
	if rr, _ := tierReq(t, e, g); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped list must be refused: %d", rr.Code)
	}
}

// tierArmedFor answers the gate question for e without touching the
// package-level hook other tests may have installed.
func tierArmedFor(e *Engine, host string) bool {
	return e.challengeV2VhostTier(host).Rung == "v2"
}

// The read surfaces carry the resolved tier, so "auto · v2" and a pin are
// visible where the operator switches them.
func TestChallengeVhostStatus_ReportsAutoTier(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost)
	e.chalAPI = NewChallengeAPIStore(100)
	setVhostEntry(e, "busy.gr", "suspicious_vhost")

	rr := httptest.NewRecorder()
	e.handleChallengeVhostStatus(rr, httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host=busy.gr", nil))
	var st map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if st["rung"] != "v2" || st["rung_source"] != "auto" || st["rung_trigger"] != "suspicious_vhost" || st["rung_pin"] != "" {
		t.Fatalf("status tier fields: %v", st)
	}

	e.SetChallengeTierPinAs("busy.gr", "v1", 0, "admin")
	rr = httptest.NewRecorder()
	e.handleChallengeVhostStatus(rr, httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host=busy.gr", nil))
	st = nil
	_ = json.Unmarshal(rr.Body.Bytes(), &st)
	if st["rung"] != "" || st["rung_source"] != "pin" || st["rung_pin"] != "v1" {
		t.Fatalf("status after v1 pin: %v", st)
	}

	// A scoped caller is told when the pin is the operator's (its write
	// would 403); an admin, or a tenant's own pin, is not locked.
	status := func(r *http.Request) map[string]any {
		rr := httptest.NewRecorder()
		e.handleChallengeVhostStatus(rr, r)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}
	setVhostEntry(e, "tenant-a.example.com", "suspicious_vhost")
	e.SetChallengeTierPinAs("tenant-a.example.com", "v2", 0, "admin")
	if m := status(scopedAddReq("/api/v1/challenge/vhost/status?host=tenant-a.example.com")); m["rung_pin_locked"] != true {
		t.Fatalf("scoped view of an operator pin must be locked: %v", m)
	}
	if m := status(httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host=tenant-a.example.com", nil)); m["rung_pin_locked"] != false {
		t.Fatalf("admin view must not be locked: %v", m)
	}
	e.SetChallengeTierPinAs("tenant-a.example.com", "v1", time.Hour, "scoped")
	if m := status(scopedAddReq("/api/v1/challenge/vhost/status?host=tenant-a.example.com")); m["rung_pin_locked"] != false {
		t.Fatalf("a tenant's own pin must not be locked for it: %v", m)
	}

	var row ChallengeVhostState
	row.decorateTier(e.challengeV2VhostTier("busy.gr"))
	b, _ := json.Marshal(row)
	if !strings.Contains(string(b), `"rung_source":"pin"`) || !strings.Contains(string(b), `"rung_pin":"v1"`) || strings.Contains(string(b), `"rung":`) {
		t.Fatalf("list row tier fields: %s", b)
	}
}

// PRODUCTION wiring: NewEngine hooks the package-level verify gate to the
// resolver, with the knob and pin store it was built with.
func TestNewEngineWiresAutoV2(t *testing.T) {
	t.Cleanup(func() { SetChallengeV2HostArmed(nil) })
	dir := t.TempDir()
	e := NewEngine(Config{
		Every:                     time.Second,
		Window:                    time.Minute,
		ChallengeManualStorePath:  filepath.Join(dir, "manual.json"),
		ChallengeTierPinStorePath: filepath.Join(dir, "pins.json"),
		ChallengeV2AutoVhost:      []string{autoV2SuspiciousVhost},
	})
	setVhostEntry(e, "auto.gr", "suspicious_vhost")
	if !challengeV2HostArmed("auto.gr") {
		t.Fatalf("NewEngine did not arm v2 for an armed automatic source")
	}
	if grain, via := challengeV2ArmGrainVia("", "203.0.113.9", "auto.gr"); grain != v2GrainVhost || via != "auto:suspicious_vhost" {
		t.Fatalf("NewEngine did not wire the tier+via hook: %q %q", grain, via)
	}
	e.SetChallengeTierPinAs("auto.gr", "v1", 0, "admin")
	if challengeV2HostArmed("auto.gr") {
		t.Fatalf("a v1 pin did not reach the verify gate")
	}
	// The pin survives an engine rebuild (every config reload is one).
	e2 := NewEngine(Config{
		Every:                     time.Second,
		Window:                    time.Minute,
		ChallengeManualStorePath:  filepath.Join(dir, "manual.json"),
		ChallengeTierPinStorePath: filepath.Join(dir, "pins.json"),
		ChallengeV2AutoVhost:      []string{autoV2SuspiciousVhost},
	})
	setVhostEntry(e2, "auto.gr", "suspicious_vhost")
	if challengeV2HostArmed("auto.gr") {
		t.Fatalf("the v1 pin was lost across an engine rebuild")
	}
}

// The REAL tick writes the source notes: an active scorer challenge is noted
// (auto-v2), survives a manual v1 arm relabelling the entry, and is dropped
// on the cycle the scorer turns it off.
func TestEmitIPChallenges_NotesAutoSourcesForAutoV2(t *testing.T) {
	e := newTickTestEngine(t)
	e.autoV2Armed = map[string]bool{autoV2SuspiciousVhost: true}
	e.cfg.ChallengeSuspiciousHolddown = 10 * time.Minute
	host := "tick.gr"
	e.vhostUnderAttack[host] = true
	e.vhostLastChange[host] = time.Now() // inside the holddown → stays ON

	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "v2" || tier.Trigger != autoV2SuspiciousVhost {
		t.Fatalf("tick did not note the scorer source: %+v", tier)
	}

	// A tier-less manual arm relabels the entry; the next tick keeps the note.
	e.ManualChallengeVhost(host, time.Hour, "manual", "")
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "v2" || tier.Trigger != autoV2SuspiciousVhost {
		t.Fatalf("manual v1 arm hid the scorer source: %+v", tier)
	}

	// Under-Attack forced on: the tick evaluates it and notes under_attack,
	// the strongest source (armed here alongside suspicious_vhost).
	e.cfg.UnderAttack = true
	e.cfg.UnderAttackHolddown = 30 * time.Minute
	e.attack = newUnderAttackTracker()
	e.autoV2Armed[autoV2UnderAttack] = true
	e.SetVhostAttackOverride(host, true, time.Now(), 0)
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("tick did not note under_attack: %+v", tier)
	}
	// Forced off: the next cycle drops it.
	e.SetVhostAttackOverride(host, false, time.Now(), 0)
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Trigger == autoV2UnderAttack {
		t.Fatalf("under_attack note survived attack off: %+v", tier)
	}

	// The scorer turns off (no holddown left, empty long window → score 0):
	// the note goes the same cycle; the manual v1 arm is what remains.
	e.longwin = NewLongWindow(10*time.Minute, time.Minute, nil)
	e.vhostLastChange[host] = time.Now().Add(-time.Hour)
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "" || tier.Source != tierSourceManual {
		t.Fatalf("scorer off must drop the note: %+v", tier)
	}
}

// The UNDER_ATTACK transition updates its source note before it logs tier=,
// so the line and the gate agree from that moment (not a tick later).
func TestEmitUnderAttack_NotesBeforeLogging(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2UnderAttack)
	setVhostEntry(e, "ua.gr", "")
	out := make(chan core.Alert, 4)
	e.emitUnderAttack(time.Now(), "ua.gr", true, SuspiciousRow{Host: "ua.gr"}, 20, "test", "auto", out)
	if tier := e.challengeV2VhostTier("ua.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("entering UNDER_ATTACK: %+v", tier)
	}
	e.emitUnderAttack(time.Now(), "ua.gr", false, SuspiciousRow{Host: "ua.gr"}, 0, "test", "auto", out)
	if tier := e.challengeV2VhostTier("ua.gr"); tier.Rung != "" {
		t.Fatalf("leaving UNDER_ATTACK: %+v", tier)
	}
}

// Excluding a host from automatic challenges while a manual v1 arm keeps it
// challenged drops its automatic notes the same cycle: the tier is the
// manual arm's own from then on, not v2 until the notes lapse.
func TestEmitIPChallenges_ExcludeDropsAutoNotes(t *testing.T) {
	e := newTickTestEngine(t)
	e.autoV2Armed = map[string]bool{autoV2SuspiciousVhost: true}
	host := "excl.gr"
	e.ManualChallengeVhost(host, time.Hour, "manual", "")
	noteSource(e, host, autoV2SuspiciousVhost)
	if tier := e.challengeV2VhostTier(host); tier.Rung != "v2" {
		t.Fatalf("precondition: manual v1 under an armed source is v2: %+v", tier)
	}
	if !e.challengeExcludes.Add("host", host, map[string]struct{}{host: {}}) {
		t.Fatal("add exclude failed")
	}
	e.vhostUnderAttack[host] = true // a live candidate
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "" || tier.Source != tierSourceManual {
		t.Fatalf("exclude must drop the automatic notes: %+v", tier)
	}
}

// v2_via= names what put a v2=vhost solve at v2 — on the solve line, the
// reject line and the history row — because src= cannot (sticky reason).
func TestV2ViaRendering(t *testing.T) {
	s := ChallengeSolve{HumanityScored: true, HumanityScore: 130, HumanityTells: "sw_renderer,outer_zero,no_input", V2Grain: v2GrainVhost, V2Via: "auto:suspicious_vhost"}
	if got := s.HumanitySuffix(); !strings.Contains(got, " v2=vhost v2_via=auto:suspicious_vhost") {
		t.Fatalf("solve line: %q", got)
	}
	if got := s.RejectLine(); !strings.Contains(got, " v2=vhost tls_fp=") || !strings.HasSuffix(got, " v2_via=auto:suspicious_vhost") {
		t.Fatalf("reject line (v2= keeps its neighbour; v2_via rides at the end): %q", got)
	}
	s.V2Grain, s.V2Via = v2GrainGeo, ""
	if got := s.HumanitySuffix(); strings.Contains(got, "v2_via") {
		t.Fatalf("v2_via on a non-vhost grain: %q", got)
	}

	e := newAutoV2TestEngine(t, autoV2SuspiciousVhost)
	setVhostEntry(e, "via.gr", "suspicious_vhost")
	if via := e.challengeV2VhostVia("via.gr"); via != "auto:suspicious_vhost" {
		t.Fatalf("auto via: %q", via)
	}
	e.SetChallengeTierPinAs("via.gr", "v2", 0, "admin")
	if via := e.challengeV2VhostVia("via.gr"); via != "pin" {
		t.Fatalf("pin via: %q", via)
	}
	e.SetChallengeTierPinAs("via.gr", "v1", 0, "admin")
	if via := e.challengeV2VhostVia("via.gr"); via != "" {
		t.Fatalf("a v1 tier has no via: %q", via)
	}
	e.ManualChallengeVhost("via.gr", time.Hour, "manual", "v2")
	if via := e.challengeV2VhostVia("via.gr"); via != "manual" {
		t.Fatalf("manual via: %q", via)
	}
}
