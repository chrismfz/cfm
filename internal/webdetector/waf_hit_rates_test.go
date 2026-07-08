package webdetector

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// newTestHistoryStore opens a fresh SQLite history DB in t.TempDir for tests
// that need WAFInspected / WAFHitsByRuleID. The store is closed automatically.
func newTestHistoryStore(t *testing.T) *HistoryStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "history.db")
	hs, err := NewHistoryStore(path, 1, time.Hour)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	t.Cleanup(func() { hs.Close() })
	return hs
}

// TestWAFInspected_UpsertAndWindow asserts that repeated UPSERT calls for the
// same (hour, host) overwrite (not sum) and that the window filter respects
// the hours boundary.
func TestWAFInspected_UpsertAndWindow(t *testing.T) {
	hs := newTestHistoryStore(t)

	now := time.Now().Unix()
	hr := (now / 3600) * 3600
	hrPrev := hr - 3600

	// First push for current hour.
	if err := hs.RecordWAFInspected(hr, "example.com", 100); err != nil {
		t.Fatalf("RecordWAFInspected #1: %v", err)
	}
	// Repeated push for same (hour, host) overwrites — Lua resends the
	// monotonic shdict counter every flush; Go MUST NOT sum.
	if err := hs.RecordWAFInspected(hr, "example.com", 250); err != nil {
		t.Fatalf("RecordWAFInspected #2: %v", err)
	}
	// Different host, same hour.
	if err := hs.RecordWAFInspected(hr, "other.com", 50); err != nil {
		t.Fatalf("RecordWAFInspected #3: %v", err)
	}
	// Previous hour, global bucket.
	if err := hs.RecordWAFInspected(hrPrev, "", 1000); err != nil {
		t.Fatalf("RecordWAFInspected #4: %v", err)
	}

	// Per-host: should be 250 (last write wins), not 100+250=350.
	if n, err := hs.WAFInspected("example.com", 24); err != nil || n != 250 {
		t.Errorf("WAFInspected example.com 24h: got (%d, %v), want (250, nil)", n, err)
	}
	if n, err := hs.WAFInspected("other.com", 24); err != nil || n != 50 {
		t.Errorf("WAFInspected other.com: got %d, want 50", n)
	}
	// Empty host = the row with host='' only (NOT a sum across hosts).
	if n, err := hs.WAFInspected("", 24); err != nil || n != 1000 {
		t.Errorf("WAFInspected '' (global only) over 24h: got %d, want 1000", n)
	}
}

// TestWAFInspected_IgnoresInvalid covers the cheap guards on the hot path.
func TestWAFInspected_IgnoresInvalid(t *testing.T) {
	hs := newTestHistoryStore(t)
	if err := hs.RecordWAFInspected(0, "example.com", 5); err != nil {
		t.Errorf("hour=0 should be silently ignored, got err=%v", err)
	}
	if err := hs.RecordWAFInspected(time.Now().Unix(), "example.com", -1); err != nil {
		t.Errorf("negative count should be silently ignored, got err=%v", err)
	}
	if n, _ := hs.WAFInspected("example.com", 24); n != 0 {
		t.Errorf("nothing should have been persisted, got count=%d", n)
	}
}

// TestWAFHitsByRuleID_JSONExtract asserts the json_extract aggregation works.
// Inserts a few synthetic waf_trigger rows and verifies the per-id count.
func TestWAFHitsByRuleID_JSONExtract(t *testing.T) {
	hs := newTestHistoryStore(t)

	now := time.Now().Unix()
	mk := func(host string, ruleID int) HistoryEvent {
		return HistoryEvent{
			TsUnix: now,
			Type:   "waf_trigger",
			Host:   host,
			IP:     "1.2.3.4",
			Reason: "WAF_RCE",
			Mode:   "block",
			Payload: map[string]interface{}{
				"waf_rule_id": ruleID,
			},
		}
	}
	hs.Append(mk("example.com", 320))
	hs.Append(mk("example.com", 320))
	hs.Append(mk("example.com", 101))
	hs.Append(mk("other.com", 320))

	got, err := hs.WAFHitsByRuleID("", 24)
	if err != nil {
		t.Fatalf("WAFHitsByRuleID: %v", err)
	}
	if got[320] != 3 {
		t.Errorf("global rule 320: got %d, want 3", got[320])
	}
	if got[101] != 1 {
		t.Errorf("global rule 101: got %d, want 1", got[101])
	}

	// Per-host filter.
	gotHost, err := hs.WAFHitsByRuleID("example.com", 24)
	if err != nil {
		t.Fatalf("WAFHitsByRuleID host: %v", err)
	}
	if gotHost[320] != 2 || gotHost[101] != 1 {
		t.Errorf("example.com per-rule: got %v, want {320:2, 101:1}", gotHost)
	}
}

// TestHandleWAFHitRates_Smoke wires Engine + handler with a real history
// store. Asserts the response shape, promotion-hint mapping, and that every
// registered rule is present (silent rules included).
func TestHandleWAFHitRates_Smoke(t *testing.T) {
	hs := newTestHistoryStore(t)
	e := &Engine{history: hs}

	now := time.Now().Unix()
	hr := (now / 3600) * 3600

	// 100,000 inspections → makes the rate boundaries land on tidy numbers.
	_ = hs.RecordWAFInspected(hr, "", 100_000)
	// 5 hits on rule_rce (320) → 0.005% rate → ok_to_promote
	for i := 0; i < 5; i++ {
		hs.Append(HistoryEvent{
			TsUnix: now, Type: "waf_trigger", Host: "", Reason: "WAF_RCE",
			Payload: map[string]interface{}{"waf_rule_id": 320},
		})
	}
	// 5,000 hits on rule_traversal (101) → 5% rate → noisy
	for i := 0; i < 5_000; i++ {
		hs.Append(HistoryEvent{
			TsUnix: now, Type: "waf_trigger", Host: "", Reason: "WAF_TRAVERSAL",
			Payload: map[string]interface{}{"waf_rule_id": 101},
		})
	}

	req := httptest.NewRequest("GET", "/api/v1/waf/hit-rates?hours=24", nil)
	ctx := context.WithValue(req.Context(), CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, CtxRoleKey{}, CtxRoleAdmin)
	req = req.WithContext(ctx)
	rr := httptest.NewRecorder()
	e.handleWAFHitRates(rr, req)

	if rr.Code != 200 {
		t.Fatalf("status=%d, body=%s", rr.Code, rr.Body.String())
	}

	var out HitRatesResult
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v; body=%s", err, rr.Body.String())
	}
	if out.InspectedTotal != 100_000 {
		t.Errorf("inspected_total: got %d, want 100000", out.InspectedTotal)
	}
	if len(out.Rules) < 30 {
		t.Errorf("rules count: got %d, want ~39", len(out.Rules))
	}

	byID := map[int]RuleHitRate{}
	for _, r := range out.Rules {
		byID[r.ID] = r
	}

	if r, ok := byID[320]; !ok {
		t.Errorf("rule 320 missing from response")
	} else {
		if r.Hits != 5 {
			t.Errorf("rule 320 hits: got %d, want 5", r.Hits)
		}
		if r.PromotionHint != "ok_to_promote" {
			t.Errorf("rule 320 hint: got %q, want ok_to_promote (rate=%.6f)", r.PromotionHint, r.RatePct)
		}
	}
	if r, ok := byID[101]; !ok {
		t.Errorf("rule 101 missing")
	} else {
		if r.PromotionHint != "noisy" {
			t.Errorf("rule 101 hint: got %q, want noisy (rate=%.6f)", r.PromotionHint, r.RatePct)
		}
	}
	if r, ok := byID[201]; !ok || r.PromotionHint != "silent" {
		t.Errorf("rule 201 (silent): got %+v, ok=%v", r, ok)
	}
}

// TestHitRatePromotionHint covers the boundary mapping directly.
func TestHitRatePromotionHint(t *testing.T) {
	cases := []struct {
		name       string
		ratePct    float64
		hits       int
		inspected  int
		want       string
	}{
		{"no inspections", 0, 0, 0, "n_a"},
		{"silent with inspections", 0, 0, 1000, "silent"},
		{"clean signal", 0.005, 5, 1_000_000, "ok_to_promote"},
		{"borderline review", 0.5, 5_000, 1_000_000, "review"},
		{"noisy", 5.0, 50_000, 1_000_000, "noisy"},
		{"exactly at promote gate", 0.01, 100, 1_000_000, "review"},
		{"exactly at noisy gate", 1.0, 10_000, 1_000_000, "noisy"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := hitRatePromotionHint(c.ratePct, c.hits, c.inspected)
			if got != c.want {
				t.Errorf("rate=%.4f hits=%d inspected=%d: got %q, want %q",
					c.ratePct, c.hits, c.inspected, got, c.want)
			}
		})
	}
}

// TestHandleWAFHitRates_ScopeEnforced verifies the audit-F02 scope guard: it is
// keyed on role (not scope != nil), so a scoped token may only read hit-rates
// for a host inside a non-empty allowlist; an empty host (fleet-wide), an
// out-of-scope host, and a scoped token with a nil/empty scope are all refused,
// while admin stays unrestricted. Also checks that a mixed-case host is
// normalized for the history read, not just the authz check.
func TestHandleWAFHitRates_ScopeEnforced(t *testing.T) {
	hs := newTestHistoryStore(t)
	e := &Engine{history: hs}

	// Seed inspected data for the in-scope host (stored canonical-lowercase) so
	// the case-normalization assertion below is meaningful.
	now := time.Now().Unix()
	hr := (now / 3600) * 3600
	_ = hs.RecordWAFInspected(hr, "mine.com", 100)

	// call issues a GET with an explicit role and optional vhost scope (nil scope
	// = CtxScopeKey never set, which is how a vhost-less scoped token presents).
	call := func(role, host string, scope map[string]struct{}) *httptest.ResponseRecorder {
		q := "/api/v1/waf/hit-rates?hours=24"
		if host != "" {
			q += "&host=" + host
		}
		req := httptest.NewRequest("GET", q, nil)
		ctx := context.WithValue(req.Context(), CtxAuthnKey{}, true)
		ctx = context.WithValue(ctx, CtxRoleKey{}, role)
		if scope != nil {
			ctx = context.WithValue(ctx, CtxScopeKey{}, scope)
		}
		req = req.WithContext(ctx)
		rr := httptest.NewRecorder()
		e.handleWAFHitRates(rr, req)
		return rr
	}
	inScope := map[string]struct{}{"mine.com": {}}

	if rr := call(CtxRoleScoped, "mine.com", inScope); rr.Code != 200 {
		t.Errorf("scoped in-scope host: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	// Mixed-case in-scope host → 200 AND returns the in-scope host's data, proving
	// the host is lowercased before the history read (not only for authz).
	if rr := call(CtxRoleScoped, "MINE.com", inScope); rr.Code != 200 {
		t.Errorf("scoped mixed-case host: got %d, want 200", rr.Code)
	} else {
		var out HitRatesResult
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.InspectedTotal != 100 {
			t.Errorf("mixed-case host inspected_total: got %d, want 100 (case not normalized for history read)", out.InspectedTotal)
		}
	}
	if rr := call(CtxRoleScoped, "other.com", inScope); rr.Code != 403 {
		t.Errorf("scoped out-of-scope host: got %d, want 403", rr.Code)
	}
	if rr := call(CtxRoleScoped, "", inScope); rr.Code != 403 {
		t.Errorf("scoped empty host (fleet-wide): got %d, want 403", rr.Code)
	}
	// A scoped token with a nil/empty vhost scope (e.g. db-only) must NOT be
	// treated as admin — every request is refused (audit F02 hardening).
	if rr := call(CtxRoleScoped, "mine.com", nil); rr.Code != 403 {
		t.Errorf("scoped nil-scope host: got %d, want 403 (nil scope wrongly treated as admin)", rr.Code)
	}
	if rr := call(CtxRoleScoped, "", nil); rr.Code != 403 {
		t.Errorf("scoped nil-scope empty host: got %d, want 403", rr.Code)
	}

	// Admin with no host (fleet-wide aggregate) stays unrestricted.
	if rr := call(CtxRoleAdmin, "", nil); rr.Code != 200 {
		t.Errorf("admin fleet-wide: got %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
}
