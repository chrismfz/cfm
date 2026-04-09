// internal/webdetector/step3_scope_test.go
//
// Tests for Step 3: challenge API and exclude endpoint scope guards.
// MySQL governor guards are tested manually on virgo (requires live DB).

package webdetector

import (
	"net/http"
	"path/filepath"
	"testing"
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

// ── Challenge excludes (Guard 3 — global operation) ───────────

func TestChallengeExclude_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	// List
	rr := get(mux, adminCtx(), "/api/v1/challenge/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("admin exclude list: expected 200, got %d", rr.Code)
	}
	rr = get(mux, scopedCtx("example.com"), "/api/v1/challenge/exclude/list")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped exclude list: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Add
	rr = doRequest(mux, scopedCtx("example.com"), http.MethodPost,
		"/api/v1/challenge/exclude/add?type=host&value=example.com", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped exclude add: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Admin add works
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/challenge/exclude/add?type=host&value=example.com", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin exclude add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Remove
	rr = doRequest(mux, scopedCtx("example.com"), http.MethodPost,
		"/api/v1/challenge/exclude/remove?type=host&value=example.com", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped exclude remove: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}
}

// ── WAF excludes (Guard 3 — global operation) ─────────────────

func TestWAFExclude_AdminOnly(t *testing.T) {
	_, mux := newStep3Engine(t)

	rr := get(mux, scopedCtx("example.com"), "/api/v1/waf/exclude/list")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped waf exclude list: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	rr = doRequest(mux, scopedCtx("example.com"), http.MethodPost,
		"/api/v1/waf/exclude/add?type=path&value=/admin", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped waf exclude add: expected 403, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Admin can add global WAF path exclude
	rr = doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/waf/exclude/add?type=path&value=/healthz", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin waf exclude add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
}
