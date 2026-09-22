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

	// Default: plain challenge, reported as v1.
	if rr, m := add("host=a.gr&ttl=1h"); rr.Code != http.StatusOK || m["rung"] != "v1" {
		t.Fatalf("default add: code=%d rung=%v", rr.Code, m["rung"])
	}
	if got := e.manualChallengeRung("a.gr"); got != "" {
		t.Fatalf("default add stored rung %q", got)
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

	// Re-adding with a different rung changes the tier (idempotent refresh).
	if _, _ = add("host=b.gr&ttl=1h&rung=v1"); e.manualChallengeRung("b.gr") != "" {
		t.Fatalf("re-add with v1 did not clear the v2 rung")
	}
}

func TestChallengeV2HostArmed_ApexCoversWWWAndWiring(t *testing.T) {
	e := newTestEngineForChallengeHandlers()
	SetChallengeV2HostArmed(func(host string) bool { return e.manualChallengeRung(host) == "v2" })
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
