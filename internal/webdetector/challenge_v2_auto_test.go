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

func setVhostEntry(e *Engine, host, reason string) {
	e.nginxBridge.mu.Lock()
	e.nginxBridge.vhState[host] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Hour), Reason: reason}
	e.nginxBridge.mu.Unlock()
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
	// An entry the edge pushed without a reason names no source and never arms.
	setVhostEntry(e, "edge.gr", "")
	if tier := e.challengeV2VhostTier("edge.gr"); tier.Rung != "" || tier.Trigger != "vhost" {
		t.Fatalf("reason-less entry: %+v", tier)
	}
	// A bridge entry left by a manual arm is not an automatic source once
	// the manual arm itself is gone.
	setVhostEntry(e, "gone.gr", "manual")
	if tier := e.challengeV2VhostTier("gone.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("manual bridge entry without a manual arm: %+v", tier)
	}
	// A wildcard entry is matched through the one vhost matcher.
	setVhostEntry(e, "*.wild.gr", "suspicious_vhost")
	if tier := e.challengeV2VhostTier("a.wild.gr"); tier.Rung != "v2" {
		t.Fatalf("wildcard entry: %+v", tier)
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
	e.attack = newUnderAttackTracker()
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
	e.SetVhostAttackOverride("busy.gr", true, time.Now(), 0)
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("manual v1 under attack: %+v", tier)
	}
	// The way down is a v1 pin.
	e.SetChallengeTierPinAs("busy.gr", "v1", 0, "admin")
	if tier := e.challengeV2VhostTier("busy.gr"); tier.Rung != "" || tier.Source != tierSourceManual {
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
	// A note with no live entry arms nothing (the tier ends with the entry).
	b.NoteVhostAutoSource("ghost.gr", autoV2UniqPathsShort, time.Hour)
	if tier := e.challengeV2VhostTier("ghost.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("note without an entry: %+v", tier)
	}
}

func TestChallengeV2VhostTier_UnderAttackArms(t *testing.T) {
	e := newAutoV2TestEngine(t, autoV2UnderAttack)
	e.attack = newUnderAttackTracker()
	setVhostEntry(e, "hit.gr", "vhost_config") // not in the set on its own

	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" {
		t.Fatalf("before under-attack: %+v", tier)
	}
	e.SetVhostAttackOverride("hit.gr", true, time.Now(), 0)
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "v2" || tier.Trigger != autoV2UnderAttack {
		t.Fatalf("under-attack must arm v2: %+v", tier)
	}
	// Covers the www variant of an under-attack apex.
	setVhostEntry(e, "www.hit.gr", "vhost_config")
	if tier := e.challengeV2VhostTier("www.hit.gr"); tier.Rung != "v2" {
		t.Fatalf("under-attack apex must cover www: %+v", tier)
	}
	// An operator's v1 pin still wins (the emergency "drop it back").
	e.SetChallengeTierPinAs("hit.gr", "v1", 0, "admin")
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" || tier.Source != tierSourcePin {
		t.Fatalf("v1 pin under attack: %+v", tier)
	}
	e.SetChallengeTierPinAs("hit.gr", "", 0, "admin")

	// A forced `attack on` with NO vhost challenge arms nothing: the tier
	// must end with the vhost challenge, never outlive it.
	e.SetVhostAttackOverride("forced.gr", true, time.Now(), 0)
	if tier := e.challengeV2VhostTier("forced.gr"); tier != (vhostV2Tier{}) {
		t.Fatalf("under-attack without a vhost challenge must not arm: %+v", tier)
	}
	// Nor after the vhost challenge clears while the state lingers.
	e.nginxBridge.mu.Lock()
	delete(e.nginxBridge.vhState, "www.hit.gr")
	e.nginxBridge.mu.Unlock()
	if tier := e.challengeV2VhostTier("www.hit.gr"); tier.Rung != "" || tier.Source != "" {
		t.Fatalf("cleared vhost challenge under attack: %+v", tier)
	}

	// under_attack not in the set: the state alone does not arm, the bridge
	// source is reported instead.
	e.autoV2Armed = map[string]bool{}
	if tier := e.challengeV2VhostTier("hit.gr"); tier.Rung != "" || tier.Trigger != "vhost_config" {
		t.Fatalf("under_attack unarmed: %+v", tier)
	}
	// Forced off: back to the bridge source.
	e.autoV2Armed = map[string]bool{autoV2UnderAttack: true}
	e.SetVhostAttackOverride("hit.gr", false, time.Now(), 0)
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
	if challengeV2HostArmedVia(e, "shop.gr") {
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
	if !challengeV2HostArmedVia(e, "shop.gr") {
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
	shadow := scopedAddReq("/api/v1/challenge/vhost/tier?host=www.example.com&rung=v2")
	shadow = shadow.WithContext(context.WithValue(shadow.Context(), CtxScopeKey{}, map[string]struct{}{"www.example.com": {}, "example.com": {}}))
	if rr, _ := tierReq(t, e, shadow); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped www pin shadowing an operator apex pin: %d", rr.Code)
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

// challengeV2HostArmedVia answers the gate question for e without touching the
// package-level hook other tests may have installed.
func challengeV2HostArmedVia(e *Engine, host string) bool {
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

	// The scorer turns off (no holddown left, empty long window → score 0):
	// the note goes the same cycle; the manual v1 arm is what remains.
	e.longwin = NewLongWindow(10*time.Minute, time.Minute, nil)
	e.vhostLastChange[host] = time.Now().Add(-time.Hour)
	e.emitIPChallenges(time.Now(), make(chan core.Alert, 16))
	if tier := e.challengeV2VhostTier(host); tier.Rung != "" || tier.Source != tierSourceManual {
		t.Fatalf("scorer off must drop the note: %+v", tier)
	}
}
