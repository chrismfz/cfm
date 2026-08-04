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
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "rules.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "challenge_excludes.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "waf_excludes.json"),
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

	// Scoped list must only include in-scope host excludes.
	rr = get(mux, scoped, "/api/v1/challenge/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped exclude list after writes: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var scopedRows []excludeEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &scopedRows); err != nil {
		t.Fatalf("scoped exclude list decode: %v body=%s", err, rr.Body.String())
	}
	for _, row := range scopedRows {
		if row.Type != "host" {
			t.Fatalf("scoped exclude list must hide non-host excludes, got type=%q value=%q", row.Type, row.Value)
		}
		if !strings.EqualFold(row.Value, inScopeHost) {
			t.Fatalf("scoped exclude list leaked out-of-scope entry: got value=%q expected=%q", row.Value, inScopeHost)
		}
	}
}

// ── WAF exclude scope_hosts qualifier (admin narrows; scoped can't widen) ──

// An admin may attach an explicit scope_hosts qualifier to narrow a path
// exclude to specific vhosts — the minimal-surface remedy for a per-vhost
// false positive (e.g. suppress rule 402 on /wp-admin/admin-ajax.php for one
// migrating site only).
func TestWAFExclude_AdminScopeHostsNarrowsPathRule(t *testing.T) {
	e, mux := newStep3Engine(t)
	host := "scoped-site.example.com"
	other := "other-site.example.com"
	path := "/wp-admin/admin-ajax.php"

	rr := doRequest(mux, adminCtx(), http.MethodPost,
		"/api/v1/waf/exclude/add?type=path&value="+path+"&scope_hosts="+host+"&rule_ids=402", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin path+scope+rule exclude add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Suppressed on the scoped vhost — and only rule 402, WAF still runs.
	skipAll, ids := e.wafExcludes.MatchWAFRules(host, path)
	if skipAll {
		t.Fatalf("rule-scoped exclude must not skip the whole WAF")
	}
	if _, ok := ids[402]; !ok {
		t.Fatalf("expected rule 402 suppressed on %s, got %v", host, ids)
	}
	// NOT suppressed on any other vhost — the scope qualifier is doing its job.
	if skipAll, ids := e.wafExcludes.MatchWAFRules(other, path); skipAll || len(ids) != 0 {
		t.Fatalf("scope_hosts leaked to out-of-scope vhost %s: skipAll=%v ids=%v", other, skipAll, ids)
	}
}

// A scoped (cPanel) token must NOT be able to point an exclude at another
// tenant's vhost by smuggling a scope_hosts param — the effective scope is
// always pinned to the token's own context scope, param ignored.
func TestWAFExclude_ScopedTokenCannotWidenViaScopeHosts(t *testing.T) {
	e, mux := newStep3Engine(t)
	own := "own.example.com"
	victim := "victim.example.com"

	rr := doRequest(mux, scopedCtx(own), http.MethodPost,
		"/api/v1/waf/exclude/add?type=host&value="+own+"&scope_hosts="+victim, nil)
	if rr.Code == http.StatusForbidden {
		t.Fatalf("scoped in-scope add should not be 403, body=%s", rr.Body.String())
	}

	// No stored entry may carry the attacker-supplied victim host in its scope.
	for _, row := range e.WAFExcludeList() {
		if strings.Contains(strings.ToLower(strings.Join(row.ScopeHosts, ",")), victim) {
			t.Fatalf("scoped token widened scope via scope_hosts: entry scope=%v", row.ScopeHosts)
		}
	}
	// And the exclude never fires for the victim vhost.
	if skipAll, ids := e.wafExcludes.MatchWAFRules(victim, "/anything"); skipAll || len(ids) != 0 {
		t.Fatalf("scoped host exclude must not affect victim vhost: skipAll=%v ids=%v", skipAll, ids)
	}
}

// A scope-qualified entry must be removable by echoing the list-returned
// (normalized) scope_hosts — the add/remove key symmetry the whole feature
// rests on. Also exercises input normalization (mixed case, dup, trailing
// comma) and a multi-host scope.
func TestWAFExclude_ScopeQualifiedRemoveRoundTrip(t *testing.T) {
	e, mux := newStep3Engine(t)
	path := "/wp-admin/admin-ajax.php"
	a := "a.example.com"
	b := "b.example.com"

	add := "/api/v1/waf/exclude/add?type=path&value=" + path +
		"&rule_ids=402&scope_hosts=B.example.com,a.example.com,a.example.com,"
	if rr := doRequest(mux, adminCtx(), http.MethodPost, add, nil); rr.Code != http.StatusOK {
		t.Fatalf("add: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	for _, h := range []string{a, b} {
		_, ids := e.wafExcludes.MatchWAFRules(h, path)
		if _, ok := ids[402]; !ok {
			t.Fatalf("rule 402 should be suppressed on %s, got %v", h, ids)
		}
	}

	rows := e.WAFExcludeList()
	if len(rows) != 1 {
		t.Fatalf("expected 1 stored entry, got %d (%v)", len(rows), rows)
	}
	// Echo exactly what the UI/CLI would from the list response.
	rm := "/api/v1/waf/exclude/remove?type=path&value=" + path +
		"&rule_ids=402&scope_hosts=" + strings.Join(rows[0].ScopeHosts, ",")
	if rr := doRequest(mux, adminCtx(), http.MethodPost, rm, nil); rr.Code != http.StatusOK {
		t.Fatalf("remove: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if _, ids := e.wafExcludes.MatchWAFRules(a, path); len(ids) != 0 {
		t.Fatalf("entry should be removed, still matches on %s: %v", a, ids)
	}
	if got := len(e.WAFExcludeList()); got != 0 {
		t.Fatalf("expected 0 entries after remove, got %d", got)
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

	// Scoped list must only include in-scope host excludes.
	rr = get(mux, scoped, "/api/v1/waf/exclude/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped waf exclude list after writes: expected 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var scopedRows []excludeEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &scopedRows); err != nil {
		t.Fatalf("scoped waf exclude list decode: %v body=%s", err, rr.Body.String())
	}
	for _, row := range scopedRows {
		if row.Type != "host" {
			t.Fatalf("scoped waf exclude list must hide non-host excludes, got type=%q value=%q", row.Type, row.Value)
		}
		if !strings.EqualFold(row.Value, inScopeHost) {
			t.Fatalf("scoped waf exclude list leaked out-of-scope entry: got value=%q expected=%q", row.Value, inScopeHost)
		}
	}
}

func TestScopedExcludes_DoNotSuppressOtherTenantRuntime(t *testing.T) {
	e, _ := newStep3Engine(t)
	tenantA := "tenant-a.example.com"
	tenantB := "tenant-b.example.com"
	tenantAScope := map[string]struct{}{tenantA: {}}

	if ok := e.ChallengeExcludeAdd("host", tenantA, tenantAScope); !ok {
		t.Fatalf("challenge scoped exclude add failed")
	}
	if ok := e.WAFExcludeAdd("host", tenantA, tenantAScope); !ok {
		t.Fatalf("waf scoped host exclude add failed")
	}
	if ok := e.WAFExcludeAdd("path", "/wp-admin/*", tenantAScope); !ok {
		t.Fatalf("waf scoped path exclude add failed")
	}

	if !e.isExcluded("1.2.3.4", tenantA, "", "rule") {
		t.Fatalf("expected tenant A challenge exclude to match own host")
	}
	if e.isExcluded("1.2.3.4", tenantB, "", "rule") {
		t.Fatalf("tenant A challenge exclude must not match tenant B host")
	}

	if !e.isWAFExcluded(tenantA, "/wp-admin/index.php") {
		t.Fatalf("expected tenant A waf exclude to match own host/path")
	}
	if e.isWAFExcluded(tenantB, "/wp-admin/index.php") {
		t.Fatalf("tenant A waf exclude must not match tenant B host")
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
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.jsonl"), 30, time.Hour, 0)
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
