package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// manualChallengeRung is the tier ("v2" or "") of the manual arm covering host
// (manualRungTarget's resolution) — a TEST helper for the manual store alone.
// Production never asks this question: "what tier is this vhost at" is
// challengeV2VhostTier's, which a manual v1 arm does not decide on its own.
func (e *Engine) manualChallengeRung(host string) string {
	if target := e.manualRungTarget(host); target != "" {
		return e.manualChal.rung(target)
	}
	return ""
}

// Per-vhost ChallengeV2 (arm-surfaces slice A): the manual vhost challenge
// carries a rung ("" plain / "v2"), persisted across restarts, settable via
// the add API/CLI, surfaced in the status API, and consulted by the verify
// gate through challengeV2HostArmed with the same apex→www expansion as the
// challenge itself.

func TestManualChalRung_PersistRoundTripAndOldSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manual.json")

	var s1 manualChalState
	s1.init(path)
	s1.set("v2shop.gr", time.Hour, "manual", "v2")
	s1.set("plain.gr", time.Hour, "manual", "")

	// A fresh store loads the rung back.
	var s2 manualChalState
	s2.init(path)
	if got := s2.rung("v2shop.gr"); got != "v2" {
		t.Fatalf("rung after reload = %q, want v2", got)
	}
	if got := s2.rung("plain.gr"); got != "" {
		t.Fatalf("plain rung after reload = %q, want empty", got)
	}

	// A snapshot from an older build (no rung key) loads as plain challenge.
	old := `[{"host":"old.gr","expires_at":"` + time.Now().Add(time.Hour).Format(time.RFC3339Nano) + `","reason":"manual","ttl_sec":3600}]`
	oldPath := filepath.Join(dir, "old.json")
	if err := os.WriteFile(oldPath, []byte(old), 0o600); err != nil {
		t.Fatalf("write old snapshot: %v", err)
	}
	var s3 manualChalState
	s3.init(oldPath)
	if ok, _, _ := s3.active("old.gr"); !ok {
		t.Fatalf("old snapshot entry not restored")
	}
	if got := s3.rung("old.gr"); got != "" {
		t.Fatalf("old snapshot rung = %q, want empty (fail-safe plain)", got)
	}
}

func TestHandleChallengeVhostAdd_Rung(t *testing.T) {
	e := newTestEngineForChallengeHandlers()

	add := func(qs string) (*httptest.ResponseRecorder, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?"+qs, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostAdd(rr, req)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return rr, m
	}

	// Default (CHALLENGE_V2_MANUAL on, since 2026-11-14): a NEW tier-less arm
	// is v2, and the response says the tier was the node default.
	if rr, m := add("host=a.gr&ttl=1h"); rr.Code != http.StatusOK || m["rung"] != "v2" || m["rung_default"] != true {
		t.Fatalf("default add: code=%d rung=%v rung_default=%v", rr.Code, m["rung"], m["rung_default"])
	}
	if got := e.manualChallengeRung("a.gr"); got != "v2" {
		t.Fatalf("default add stored rung %q, want v2", got)
	}
	// An explicit v1 is honoured on a new arm (`--rung v1`), with no
	// rung_default.
	if rr, m := add("host=a1.gr&ttl=1h&rung=v1"); rr.Code != http.StatusOK || m["rung"] != "v1" || m["rung_default"] != nil {
		t.Fatalf("explicit v1 add: code=%d rung=%v rung_default=%v", rr.Code, m["rung"], m["rung_default"])
	}
	if got := e.manualChallengeRung("a1.gr"); got != "" {
		t.Fatalf("explicit v1 add stored rung %q", got)
	}
	// A tier-less RE-arm of that v1 arm keeps it v1: the default applies to
	// new arms only, never re-tiers one (either way).
	if _, m := add("host=a1.gr&ttl=2h"); m["rung"] != "v1" || m["rung_default"] != nil {
		t.Fatalf("tier-less re-arm of a v1 arm: rung=%v rung_default=%v, want preserved v1", m["rung"], m["rung_default"])
	}

	// v2 (and the challenge_v2 spelling) arms the tier.
	if rr, m := add("host=b.gr&ttl=1h&rung=v2"); rr.Code != http.StatusOK || m["rung"] != "v2" {
		t.Fatalf("v2 add: code=%d rung=%v", rr.Code, m["rung"])
	}
	if got := e.manualChallengeRung("b.gr"); got != "v2" {
		t.Fatalf("v2 add stored rung %q", got)
	}
	if rr, _ := add("host=c.gr&ttl=1h&rung=challenge_v2"); rr.Code != http.StatusOK {
		t.Fatalf("challenge_v2 spelling rejected: %d", rr.Code)
	}
	if got := e.manualChallengeRung("c.gr"); got != "v2" {
		t.Fatalf("challenge_v2 spelling stored rung %q", got)
	}

	// A typo fails closed instead of silently arming the wrong tier.
	if rr, _ := add("host=d.gr&ttl=1h&rung=v3"); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad rung accepted: %d", rr.Code)
	}
	if got := e.manualChallengeRung("d.gr"); got != "" {
		t.Fatalf("bad rung stored anyway: %q", got)
	}

	// A wildcard host cannot be v2-armed (the rung lookup is exact+www, so a
	// wildcard v2 would serve challenges the gate never checks — fail closed).
	if rr, _ := add("host=*.wild.gr&ttl=1h&rung=v2"); rr.Code != http.StatusBadRequest {
		t.Fatalf("wildcard v2 arm accepted: %d", rr.Code)
	}
	// ...a tier-less wildcard arm still works: it does NOT take the v2
	// default (which would 400), it arms v1 and says why.
	if rr, m := add("host=*.wild.gr&ttl=1h"); rr.Code != http.StatusOK || m["rung"] != "v1" || m["rung_note"] == nil {
		t.Fatalf("tier-less wildcard challenge: code=%d rung=%v rung_note=%v", rr.Code, m["rung"], m["rung_note"])
	}

	// A rung-LESS re-add (TTL extension from a rung-unaware surface: live
	// view, bots drilldown, plain CLI) PRESERVES an existing v2 arm...
	if _, m := add("host=b.gr&ttl=2h"); m["rung"] != "v2" {
		t.Fatalf("rung-less re-add reported %v, want preserved v2", m["rung"])
	}
	if got := e.manualChallengeRung("b.gr"); got != "v2" {
		t.Fatalf("rung-less re-add silently disarmed v2: %q", got)
	}

	// ...while an EXPLICIT v1 downgrades (the operator said so).
	if _, _ = add("host=b.gr&ttl=1h&rung=v1"); e.manualChallengeRung("b.gr") != "" {
		t.Fatalf("re-add with v1 did not clear the v2 rung")
	}
}

// CHALLENGE_V2_MANUAL = 0 (and the rung itself off) puts a tier-less new arm
// back at v1; an explicit v2 still arms v2 with the knob off.
func TestHandleChallengeVhostAdd_ManualDefaultKnob(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	add := func(qs string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?"+qs, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostAdd(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("add %s: code=%d body=%s", qs, rr.Code, rr.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}

	ConfigureChallengeV2Manual(false)
	t.Cleanup(func() { ConfigureChallengeV2Manual(true) })
	if m := add("host=off.gr&ttl=1h"); m["rung"] != "v1" {
		t.Fatalf("knob off: tier-less add rung=%v, want v1", m["rung"])
	}
	if got := e.manualChallengeRung("off.gr"); got != "" {
		t.Fatalf("knob off: stored rung %q", got)
	}
	if m := add("host=explicit.gr&ttl=1h&rung=v2"); m["rung"] != "v2" {
		t.Fatalf("knob off: explicit v2 add rung=%v", m["rung"])
	}
	ConfigureChallengeV2Manual(true)

	// The rung off (CHALLENGE_V2_PASSIVE = 0): no v2 default, since a v2 arm
	// would claim a gate that does not run.
	challengeV2.mu.Lock()
	prev := challengeV2.enabled
	challengeV2.enabled = false
	challengeV2.mu.Unlock()
	t.Cleanup(func() { challengeV2.mu.Lock(); challengeV2.enabled = prev; challengeV2.mu.Unlock() })
	if m := add("host=passive-off.gr&ttl=1h"); m["rung"] != "v1" {
		t.Fatalf("rung off: tier-less add rung=%v, want v1", m["rung"])
	}
}

// A tier-less arm on a www. host keeps the tier of the apex arm covering it,
// rather than taking the v2 default and shadowing an operator's v1 apex arm
// (the gate reads the host's own arm first, manualRungTarget).
func TestHandleChallengeVhostAdd_TierlessWWWKeepsApexTier(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	add := func(qs string) map[string]any {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/challenge/vhost/add?"+qs, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostAdd(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("add %s: code=%d body=%s", qs, rr.Code, rr.Body.String())
		}
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		return m
	}
	add("host=shop.gr&ttl=1h&rung=v1")
	if m := add("host=www.shop.gr&ttl=1h"); m["rung"] != "v1" || m["rung_default"] != nil {
		t.Fatalf("tier-less www arm under a v1 apex arm: rung=%v rung_default=%v, want v1 kept", m["rung"], m["rung_default"])
	}
	if got := e.manualChallengeRung("www.shop.gr"); got != "" {
		t.Fatalf("www arm shadows the v1 apex at %q", got)
	}
	// With no covering arm, www gets the default like any host.
	if m := add("host=www.other.gr&ttl=1h"); m["rung"] != "v2" || m["rung_default"] != true {
		t.Fatalf("uncovered www arm: rung=%v rung_default=%v, want the v2 default", m["rung"], m["rung_default"])
	}
}

// vhost/status names what a tier-less arm would get there (the add handler's
// own answer, tierlessArmRung): v2 by default, v1 on a wildcard host, and the
// covering arm's tier on a host an active manual arm covers (own or apex).
func TestHandleChallengeVhostStatus_ManualDefaultRung(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.ManualChallengeVhost("armed.gr", time.Hour, "manual", "")
	for host, want := range map[string]string{"plain.gr": "v2", "*.wild.gr": "v1", "armed.gr": "v1", "www.armed.gr": "v1"} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost/status?host="+host, nil)
		rr := httptest.NewRecorder()
		e.handleChallengeVhostStatus(rr, req)
		var m map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &m)
		if m["manual_default_rung"] != want {
			t.Fatalf("status %s: manual_default_rung=%v, want %s (code=%d)", host, m["manual_default_rung"], want, rr.Code)
		}
	}
}

func TestChallengeV2HostArmed_ApexCoversWWWAndWiring(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	// The production resolver (a manual-only engine: no bridge, no notes).
	SetChallengeV2HostArmed(func(host string) bool { return e.challengeV2VhostTier(host).Rung == "v2" })
	t.Cleanup(func() { SetChallengeV2HostArmed(nil) })

	// Unarmed / plain-challenge hosts never gate.
	e.ManualChallengeVhost("plain.gr", time.Hour, "manual", "")
	if challengeV2HostArmed("plain.gr") || challengeV2HostArmed("nothing.gr") || challengeV2HostArmed("") {
		t.Fatalf("v2 gate armed without a v2 arm")
	}

	// v2 on the apex covers the www variant (the bridge challenges both).
	e.ManualChallengeVhost("shop.gr", 2*time.Hour, "attack", "v2")
	if !challengeV2HostArmed("shop.gr") || !challengeV2HostArmed("www.shop.gr") {
		t.Fatalf("v2 arm on apex must cover apex and www")
	}
	// ...but a www-only arm does not expand to the apex (same rule as covering).
	e.ManualChallengeVhost("www.onlywww.gr", time.Hour, "manual", "v2")
	if challengeV2HostArmed("onlywww.gr") {
		t.Fatalf("www-only v2 arm must not cover the apex")
	}

	// Disarm (remove) drops the gate.
	e.ClearManualChallengeVhost("shop.gr")
	if challengeV2HostArmed("shop.gr") {
		t.Fatalf("v2 gate survived the manual challenge removal")
	}
}

// The PRODUCTION wiring: NewEngine must hook the package-level verify gate to
// its own manual store (review finding: the wiring line was untested — the
// sibling test above wires its own closure, so deleting the NewEngine line
// would leave the suite green while the teeth silently vanish).
func TestNewEngineWiresChallengeV2HostArmed(t *testing.T) {
	SetChallengeV2HostTier(nil) // no previous engine's hook to answer through
	t.Cleanup(func() { SetChallengeV2HostArmed(nil) })
	// Isolated store path: FillDefaults would otherwise point manualChal at
	// the REAL /var/lib/cfm snapshot — on a root-run test host this would
	// persist "wired.gr" into production state (second-review finding).
	e := NewEngine(Config{
		Every:                    time.Second,
		Window:                   time.Minute,
		ChallengeManualStorePath: filepath.Join(t.TempDir(), "manual.json"),
	})
	e.ManualChallengeVhost("wired.gr", time.Hour, "manual", "v2")
	if !challengeV2HostArmed("wired.gr") {
		t.Fatalf("NewEngine did not wire the v2 vhost gate to its manual store")
	}
}

func TestChallengeVhostStatusAPI_ReportsRung(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	e.chalAPI = NewChallengeAPIStore(100)
	e.ManualChallengeVhost("v2shop.gr", time.Hour, "manual", "v2")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/challenge/vhost?host=v2shop.gr", nil).WithContext(adminCtx())
	rr := httptest.NewRecorder()
	e.handleChallengeVhost(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"rung":"v2"`) {
		t.Fatalf("single-vhost status missing rung: %s", rr.Body.String())
	}
}
