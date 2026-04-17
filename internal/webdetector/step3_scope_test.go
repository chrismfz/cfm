// internal/webdetector/step3_scope_test.go
//
// Tests for Step 3: challenge API and exclude endpoint scope guards.
// MySQL governor guards are tested manually on virgo (requires live DB).

package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newStep3Engine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	e := NewEngine(Config{
		TrafficRulesStorePath: filepath.Join(t.TempDir(), "rules.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

// ── Challenge summary (Guard 3) ───────────────────────────────

func TestChallenge_Summary_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, adminCtx(), "/api/v1/challenge/summary")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin summary: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/challenge/summary")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped summary: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge vhosts list (Guard 3) ──────────────────────────

func TestChallenge_Vhosts_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhosts")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin vhosts: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/challenge/vhosts")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped vhosts: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge vhost single (Guard 2) ─────────────────────────

func TestChallenge_Vhost_ScopeCheck(t *testing.T) {
	_, mux := newStep3Engine(t)

	// Admin: any host
	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost?host=any.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin vhost: should not be 403")
	}

	// Scoped: own host allowed (will be 404 since not challenged, but not 403)
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/vhost?host=mysite.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped vhost own: expected not-403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped: other host blocked
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/vhost?host=other.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped vhost other: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge IPs (Guard 3) ───────────────────────────────────

func TestChallenge_IPs_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, adminCtx(), "/api/v1/challenge/ips")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin ips: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/challenge/ips")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped ips: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge IP single (Guard 3) ────────────────────────────

func TestChallenge_IP_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, adminCtx(), "/api/v1/challenge/ip?ip=1.2.3.4")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin ip: should not be 403")
	}

	rr = get(mux, scopedCtx("example.com"), "/api/v1/challenge/ip?ip=1.2.3.4")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped ip: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge events (Guard 2 with mandatory host for scoped) ─

func TestChallenge_Events_ScopeCheck(t *testing.T) {
	_, mux := newStep3Engine(t)

	// Admin: no host param — all events (200 or empty)
	rr := get(mux, adminCtx(), "/api/v1/challenge/events")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin events no host: expected 200, got %d", rr.Code)
	}

	// Admin: with host param — fine
	rr = get(mux, adminCtx(), "/api/v1/challenge/events?host=any.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin events with host: expected 200, got %d", rr.Code)
	}

	// Scoped: no host → 403
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/events")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped events no host: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped: own host → allowed
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/events?host=mysite.com")
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped events own host: expected not-403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped: other host → 403
	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/events?host=other.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped events other host: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestChallenge_VhostStatus_ScopeCheck(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, adminCtx(), "/api/v1/challenge/vhost/status?host=mysite.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin status: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/vhost/status?host=mysite.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped own status: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/challenge/vhost/status?host=other.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped other status: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── Challenge excludes (scoped list + scoped-write guard) ──────

func TestChallengeExclude_ScopedAndAdmin(t *testing.T) {
	_, mux := newStep3Engine(t)
	inScopeHost := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-") + ".example.com")
	outOfScopeHost := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-") + ".other.com")
	scoped := scopedCtx(inScopeHost)

	// List
	rr := get(mux, adminCtx(), "/api/v1/challenge/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin exclude list: expected 200, got %d", rr.Code)
	}
	rr = get(mux, scoped, "/api/v1/challenge/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped exclude list: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Scoped add in-scope host works.
	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/challenge/exclude/add?type=host&value="+inScopeHost, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped exclude add in-scope: should not be 403, got body=%s", rr.Body.String())
	}

	// Scoped add out-of-scope host is denied with explicit message.
	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/challenge/exclude/add?type=host&value="+outOfScopeHost, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped exclude add out-of-scope: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exclude value outside token scope") {
		t.Fatalf("scoped exclude add out-of-scope: expected explicit error, got body=%s", rr.Body.String())
	}

	// Scoped remove in-scope host works.
	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/challenge/exclude/remove?type=host&value="+inScopeHost, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped exclude remove in-scope: should not be 403, got body=%s", rr.Body.String())
	}

	// Scoped path excludes are denied.
	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/challenge/exclude/add?type=path&value=/global", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped exclude add path: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exclude value outside token scope") {
		t.Fatalf("scoped exclude add path: expected explicit error, got body=%s", rr.Body.String())
	}

	// Admin remains unrestricted.
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/challenge/exclude/add?type=host&value="+outOfScopeHost, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin exclude add out-of-scope host: should not be 403, got body=%s", rr.Body.String())
	}
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/challenge/exclude/add?type=path&value=/global", nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin exclude add path: should not be 403, got body=%s", rr.Body.String())
	}
}

// ── WAF excludes (scoped list + scoped-write guard) ───────────

func TestWAFExclude_ScopedAndAdmin(t *testing.T) {
	_, mux := newStep3Engine(t)
	inScopeHost := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-") + ".example.com")
	outOfScopeHost := strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-") + ".other.com")
	pathValue := "/" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")+".path")
	scoped := scopedCtx(inScopeHost)

	rr := get(mux, scoped, "/api/v1/waf/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped waf exclude list: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/waf/exclude/add?type=host&value="+inScopeHost, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped waf exclude add in-scope host: should not be 403, got body=%s", rr.Body.String())
	}

	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/waf/exclude/add?type=path&value="+pathValue, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped waf exclude add path: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exclude value outside token scope") {
		t.Fatalf("scoped waf exclude add path: expected explicit error, got body=%s", rr.Body.String())
	}

	rr = doRequest(mux, scoped, http.MethodPost,
		"/api/v1/waf/exclude/add?type=host&value="+outOfScopeHost, nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped waf exclude add out-of-scope host: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "exclude value outside token scope") {
		t.Fatalf("scoped waf exclude add out-of-scope host: expected explicit error, got body=%s", rr.Body.String())
	}

	// Admin can add global WAF path exclude
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/waf/exclude/add?type=path&value="+pathValue, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("admin waf exclude add: should not be 403, got body=%s", rr.Body.String())
	}
}

func TestHistoryStats_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)
	rr := get(mux, adminCtx(), "/api/v1/webdet/history/stats")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin history stats: expected 200, got %d", rr.Code)
	}
	rr = get(mux, scopedCtx("example.com"), "/api/v1/webdet/history/stats")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped history stats: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestWAFEngineSummary_ScopeFiltered(t *testing.T) {
	e, mux := newStep3Engine(t)
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.jsonl"), 30, time.Hour)
	if err != nil {
		t.Fatalf("new history store: %v", err)
	}
	e.history = hs
	now := time.Now().Unix()
	e.history.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "mysite.com", IP: "1.1.1.1", Reason: "WAF_SQLI"})
	e.history.Append(HistoryEvent{TsUnix: now, Type: "waf_trigger", Host: "other.com", IP: "2.2.2.2", Reason: "WAF_SQLI"})

	rr := get(mux, adminCtx(), "/api/v1/waf/engine/summary")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin waf summary: expected 200, got %d", rr.Code)
	}

	rr = get(mux, scopedCtx("mysite.com"), "/api/v1/waf/engine/summary")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped waf summary: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out wafEngineSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("scoped waf summary unmarshal: %v", err)
	}
	if out.TotalEvents != 1 {
		t.Fatalf("scoped waf summary total_events: expected 1, got %d", out.TotalEvents)
	}
	if len(out.Rows) != 1 || out.Rows[0].Host != "mysite.com" {
		t.Fatalf("scoped waf summary rows: expected only mysite.com row, got %+v", out.Rows)
	}
}
