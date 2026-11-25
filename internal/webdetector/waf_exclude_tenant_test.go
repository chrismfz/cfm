package webdetector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// The kept families are one list on each side: the edge decides which hits
// survive a site owner's WAF switch, the daemon which rules it refuses to
// exclude for one.
func TestWAFTenantKeptFamilies_LuaParity(t *testing.T) {
	src, err := os.ReadFile(findCFMRoot(t) + "/configs/lua/cfm_waf.lua")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "_M.WAF_TENANT_KEPT_REASONS = {")
	if start < 0 {
		t.Fatal("WAF_TENANT_KEPT_REASONS not found in cfm_waf.lua")
	}
	block := s[start : start+strings.Index(s[start:], "\n}")]
	var lua []string
	for _, m := range regexp.MustCompile(`(?m)^\s*(WAF_[A-Z0-9_]+)\s*=\s*true`).FindAllStringSubmatch(block, -1) {
		lua = append(lua, m[1])
	}
	var goList []string
	for f := range wafTenantKeptFamilies {
		goList = append(goList, f)
	}
	sort.Strings(lua)
	sort.Strings(goList)
	if strings.Join(lua, ",") != strings.Join(goList, ",") || len(goList) == 0 {
		t.Fatalf("kept families differ\n lua: %v\n go:  %v", lua, goList)
	}
	// The cfm-admin pages keep a copy to know what not to offer a site owner.
	js, err := os.ReadFile(findCFMRoot(t) + "/internal/webui/static/assets/webdet/excludes-model.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`TENANT_KEPT_FAMILIES = Object\.freeze\(\[([^\]]*)\]\)`).FindSubmatch(js)
	if m == nil {
		t.Fatal("TENANT_KEPT_FAMILIES not found in excludes-model.js")
	}
	var jsList []string
	for _, q := range regexp.MustCompile(`"(WAF_[A-Z0-9_]+)"`).FindAllSubmatch(m[1], -1) {
		jsList = append(jsList, string(q[1]))
	}
	sort.Strings(jsList)
	if strings.Join(jsList, ",") != strings.Join(goList, ",") {
		t.Fatalf("excludes-model.js TENANT_KEPT_FAMILIES = %v, want %v", jsList, goList)
	}
	// Each names a family the registry has, with at least one rule.
	for _, f := range goList {
		n := 0
		for _, r := range WAFRules() {
			if r.ReasonFamily == f {
				n++
			}
		}
		if n == 0 {
			t.Errorf("kept family %s has no rule in the registry", f)
		}
	}
	if !WAFFamilyKeptForTenant("WAF_CVE:CVE_2026_1:X") || !WAFFamilyKeptForTenant("WAF_WEBSHELL") || WAFFamilyKeptForTenant("WAF_SQLI:UNION") || WAFFamilyKeptForTenant("") {
		t.Fatal("WAFFamilyKeptForTenant")
	}
}

func TestParseExcludeTTL(t *testing.T) {
	for in, want := range map[string]time.Duration{"": 0, "24h": 24 * time.Hour, "7d": 168 * time.Hour, " 1D ": 24 * time.Hour, "90m": 90 * time.Minute} {
		got, err := parseExcludeTTL(in)
		if err != nil || got != want {
			t.Errorf("parseExcludeTTL(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"0", "0d", "-1d", "-5h", "d", "1.5d", "tomorrow", "99999d"} {
		if _, err := parseExcludeTTL(in); err == nil {
			t.Errorf("parseExcludeTTL(%q): no error", in)
		}
	}
}

// webshellRuleID is a rule of a kept family that a rule_ids value can name
// (the CVE band is above the 100..999 a rule exclude takes).
func webshellRuleID(t *testing.T) string {
	t.Helper()
	for _, r := range WAFRules() {
		if r.ReasonFamily == "WAF_WEBSHELL" && r.ID >= 100 && r.ID <= 999 {
			return itoa(r.ID)
		}
	}
	t.Fatal("no WAF_WEBSHELL rule in 100..999")
	return ""
}

func newTenantWAFEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	return NewEngine(Config{
		Every: time.Second, Window: 2 * time.Minute,
		ChallengeExcludeStorePath: filepath.Join(dir, "c.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "w.json"),
	})
}

func TestScopedWAFExcludeAPI(t *testing.T) {
	e := newTenantWAFEngine(t)
	var events []TenantPolicyEvent
	SetTenantPolicySink(func(ev TenantPolicyEvent) { events = append(events, ev) })
	defer SetTenantPolicySink(nil)
	call := func(h http.HandlerFunc, r *http.Request) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h(rr, r)
		return rr
	}
	add, rm, list := e.handleWAFExcludeAdd, e.handleWAFExcludeRemove, e.handleWAFExcludeList
	const base = "/api/v1/waf/exclude/"
	sAdd := func(q string, hosts ...string) *httptest.ResponseRecorder {
		return call(add, scopedReq("POST", base+"add?"+q, hosts...))
	}
	want := func(rr *httptest.ResponseRecorder, code int, what string) {
		t.Helper()
		if rr.Code != code {
			t.Fatalf("%s: got %d %s, want %d", what, rr.Code, rr.Body.String(), code)
		}
	}

	// ── Refused ───────────────────────────────────────────────────────────
	for q, code := range map[string]int{
		// another tenant's site, a scope-less token's anything
		"type=host&value=victim.gr":                                        403,
		"type=host&value=victim.gr&rule_ids=402&ttl=24h":                   403,
		"type=path&value=/api/&rule_ids=402&ttl=24h&scope_hosts=victim.gr": 403,
		"type=nonsense&value=t1.gr":                                        403,
		// a rule exclude: one rule, with an expiry in range, never a kept family
		"type=host&value=t1.gr&rule_ids=402":                               400,
		"type=host&value=t1.gr&rule_ids=402&ttl=30m":                       400,
		"type=host&value=t1.gr&rule_ids=402&ttl=8d":                        400,
		"type=host&value=t1.gr&rule_ids=402&ttl=soon":                      400,
		"type=host&value=t1.gr&rule_ids=402,403&ttl=24h":                   400,
		"type=host&value=t1.gr&rule_ids=4xx&ttl=24h":                       400,
		"type=host&value=t1.gr&rule_ids=401-402&ttl=24h":                   400,
		"type=host&value=t1.gr&rule_ids=199&ttl=24h":                       400, // no such rule
		"type=host&value=t1.gr&rule_ids=" + webshellRuleID(t) + "&ttl=24h": 403,
		"type=path&value=/api/&rule_ids=" + webshellRuleID(t) + "&ttl=24h": 403,
		// a path exclude: one rule, a literal path below the root
		"type=path&value=/api/":                                                  403,
		"type=path&value=/api/&ttl=24h":                                          403,
		"type=path&value=/api/&rule_ids=402":                                     400,
		"type=path&value=/&rule_ids=402&ttl=24h":                                 400,
		"type=path&value=/*&rule_ids=402&ttl=24h":                                400,
		"type=path&value=/api/*&rule_ids=402&ttl=24h":                            400,
		"type=path&value=/api/[a-z]&rule_ids=402&ttl=24h":                        400,
		"type=path&value=/api/../x&rule_ids=402&ttl=24h":                         400,
		"type=path&value=/a%0Ab&rule_ids=402&ttl=24h":                            400,
		"type=path&value=/a%00b&rule_ids=402&ttl=24h":                            400,
		"type=path&value=/" + strings.Repeat("a", 300) + "&rule_ids=402&ttl=24h": 400,
		// the switch: a ttl out of range
		"type=host&value=t1.gr&ttl=30d": 400,
	} {
		want(sAdd(q, "t1.gr", "t2.gr"), code, q)
	}
	want(call(add, scopedReq("POST", base+"add?type=host&value=t1.gr")), 403, "scope-less token")
	want(sAdd("type=path&value=/api/&rule_ids=402&ttl=24h", "*.t1.gr"), 403, "glob-only token, path")
	if n := len(e.WAFExcludeList()); n != 0 {
		t.Fatalf("a refused add stored %d entries", n)
	}
	if len(events) != 0 {
		t.Fatalf("a refused add was published: %+v", events)
	}

	// ── The switch ────────────────────────────────────────────────────────
	want(sAdd("type=host&value=t1.gr", "t1.gr", "t2.gr"), 200, "switch")
	skipAll, _, crit := e.wafExcludes.MatchWAFDecision("t1.gr", "/x")
	if skipAll || !crit {
		t.Fatalf("switch: skipAll=%v criticalOnly=%v, want false/true", skipAll, crit)
	}
	if _, _, crit := e.wafExcludes.MatchWAFDecision("t2.gr", "/x"); crit {
		t.Fatal("the switch reached the token's other site")
	}
	if got, ok := e.wafExcludes.FirstWAFHostMatch("t1.gr"); !ok || !got.KeepCritical || got.By != excludeByScoped || got.ExpiresUnix != 0 {
		t.Fatalf("switch entry: %+v %v", got, ok)
	}
	// What the daemon records of an edge hit there: the kept families only.
	if !e.wafObservationExcluded("t1.gr", "/x", "WAF_SQLI:UNION") || e.wafObservationExcluded("t1.gr", "/x", "WAF_CVE:CVE_2026_1:A:B") ||
		e.wafObservationExcluded("t1.gr", "/c99.php", "WAF_WEBSHELL:PATH:c99.php") || e.wafObservationExcluded("t2.gr", "/x", "WAF_SQLI:UNION") {
		t.Fatal("wafObservationExcluded under the owner's switch")
	}
	// The operator's whole-WAF exclude still switches everything off.
	want(call(add, adminReq("POST", base+"add?type=host&value=t1.gr")), 200, "admin whole")
	if skipAll, _, crit := e.wafExcludes.MatchWAFDecision("t1.gr", "/x"); !skipAll || crit {
		t.Fatalf("admin + owner: skipAll=%v criticalOnly=%v", skipAll, crit)
	}
	if !e.wafObservationExcluded("t1.gr", "/x", "WAF_CVE:CVE_2026_1:A:B") {
		t.Fatal("operator whole-WAF exclude: a CVE hit was not excluded")
	}
	want(call(rm, adminReq("POST", base+"remove?type=host&value=t1.gr")), 200, "admin remove")
	// ...and removing the operator's entry left the owner's in place.
	if _, _, crit := e.wafExcludes.MatchWAFDecision("t1.gr", "/x"); !crit {
		t.Fatal("the admin remove took the owner's switch")
	}

	// ── One rule on a host, one rule on a path ────────────────────────────
	rr := sAdd("type=host&value=t2.gr&rule_ids=402&ttl=24h", "t1.gr", "t2.gr")
	want(rr, 200, "host rule")
	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	exp, _ := resp["expires_unix"].(float64)
	if d := time.Until(time.Unix(int64(exp), 0)); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("expires_unix %v is %v away", resp["expires_unix"], d)
	}
	want(sAdd("type=path&value=/wp-admin/admin-ajax.php&rule_ids=402&ttl=7d&scope_hosts=t1.gr", "t1.gr", "t2.gr"), 200, "path rule")
	if _, ids, _ := e.wafExcludes.MatchWAFDecision("t1.gr", "/wp-admin/admin-ajax.php"); len(ids) != 1 {
		t.Fatalf("path rule on t1: %v", ids)
	}
	if _, ids, _ := e.wafExcludes.MatchWAFDecision("t2.gr", "/wp-admin/admin-ajax.php"); len(ids) != 1 { // t2's host rule
		t.Fatalf("t2: %v", ids)
	}
	if _, ids, _ := e.wafExcludes.MatchWAFDecision("victim.gr", "/wp-admin/admin-ajax.php"); len(ids) != 0 {
		t.Fatalf("a tenant's path rule reached another site: %v", ids)
	}
	// The same add again changes nothing: no write, no history row, no notification.
	n := len(events)
	rr = sAdd("type=path&value=/wp-admin/admin-ajax.php&rule_ids=402&ttl=7d&scope_hosts=t1.gr", "t1.gr", "t2.gr")
	want(rr, 200, "repeat")
	if !strings.Contains(rr.Body.String(), `"unchanged":true`) || len(events) != n {
		t.Fatalf("a repeated add was recorded again: %s, %d new events", rr.Body.String(), len(events)-n)
	}
	// A shorter ttl never shortens it either.
	want(sAdd("type=path&value=/wp-admin/admin-ajax.php&rule_ids=402&ttl=24h&scope_hosts=t1.gr", "t1.gr", "t2.gr"), 200, "repeat, shorter")
	if got, _ := e.wafExcludes.Get("path", "/wp-admin/admin-ajax.php", scopeSet("t1.gr"), []int{402}); time.Until(time.Unix(got.ExpiresUnix, 0)) < 6*24*time.Hour || len(events) != n {
		t.Fatalf("a shorter repeat changed the entry: %+v", got)
	}
	// A real renewal (the expiry moves by an hour or more) is one.
	want(sAdd("type=host&value=t2.gr&rule_ids=402&ttl=7d", "t1.gr", "t2.gr"), 200, "renew")
	if len(events) != n+1 {
		t.Fatalf("a renewal was not published")
	}

	// ── Lists ─────────────────────────────────────────────────────────────
	// The operator narrows an exclude to the tenant's site: not the tenant's to see or remove.
	want(call(add, adminReq("POST", base+"add?type=path&value=/import/&rule_ids=701&scope_hosts=t1.gr")), 200, "admin narrowed")
	var got []excludeEntry
	rr = call(list, scopedReq("GET", base+"list", "t1.gr", "t2.gr"))
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	var keys []string
	for _, x := range got {
		keys = append(keys, x.Type+":"+x.Value+":"+strings.Join(x.ScopeHosts, "+"))
	}
	sort.Strings(keys)
	if strings.Join(keys, " ") != "host:t1.gr:t1.gr+t2.gr host:t2.gr:t1.gr+t2.gr path:/wp-admin/admin-ajax.php:t1.gr" {
		t.Fatalf("scoped list: %v", keys)
	}
	// Another tenant sees none of it.
	rr = call(list, scopedReq("GET", base+"list", "other.gr"))
	got = nil
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if len(got) != 0 {
		t.Fatalf("another tenant's list: %+v", got)
	}

	// ── Removes ───────────────────────────────────────────────────────────
	want(call(rm, scopedReq("POST", base+"remove?type=path&value=/import/&rule_ids=701", "t1.gr", "t2.gr")), 400, "tenant removes the operator's narrowed exclude")
	if _, ids, _ := e.wafExcludes.MatchWAFDecision("t1.gr", "/import/x"); len(ids) != 1 {
		t.Fatal("the operator's narrowed exclude went")
	}
	want(call(rm, scopedReq("POST", base+"remove?type=path&value=/wp-admin/admin-ajax.php&rule_ids=402", "other.gr")), 400, "another tenant removes it")
	want(call(rm, scopedReq("POST", base+"remove?type=path&value=/wp-admin/admin-ajax.php&rule_ids=402&scope_hosts=victim.gr", "t1.gr")), 403, "remove naming another site")
	want(call(rm, scopedReq("POST", base+"remove?type=path&value=/wp-admin/admin-ajax.php&rule_ids=403", "t1.gr", "t2.gr")), 400, "remove with another rule")
	want(call(rm, scopedReq("POST", base+"remove?type=path&value=/wp-admin/admin-ajax.php&rule_ids=402", "t1.gr", "t2.gr")), 200, "tenant removes its path rule")
	if _, ids, _ := e.wafExcludes.MatchWAFDecision("t1.gr", "/wp-admin/admin-ajax.php"); len(ids) != 0 {
		t.Fatalf("path rule still applies: %v", ids)
	}
	want(call(rm, scopedReq("POST", base+"remove?type=host&value=t1.gr", "t1.gr", "t2.gr")), 200, "switch back on")
	if _, _, crit := e.wafExcludes.MatchWAFDecision("t1.gr", "/x"); crit {
		t.Fatal("the switch is still off")
	}

	// ── What the operator hears ───────────────────────────────────────────
	var got2 []string
	for _, ev := range events {
		got2 = append(got2, ev.Action+" "+ev.Type+" "+ev.Value+" "+strings.Join(ev.Hosts, "+")+" "+itoaList(ev.RuleIDs))
		if ev.Kind != "waf_exclude" || ev.Summary() == "" {
			t.Fatalf("event: %+v", ev)
		}
	}
	wantEvents := []string{
		"add host t1.gr t1.gr -",
		"add host t2.gr t2.gr 402",
		"add path /wp-admin/admin-ajax.php t1.gr 402",
		"add host t2.gr t2.gr 402",
		"remove path /wp-admin/admin-ajax.php t1.gr 402",
		"remove host t1.gr t1.gr -",
	}
	if s := events[len(events)-1].Summary(); strings.Contains(s, "stay on") || !strings.Contains(s, "switched back on the WAF on t1.gr") {
		t.Fatalf("switch-back summary: %s", s)
	}
	if strings.Join(got2, " | ") != strings.Join(wantEvents, " | ") {
		t.Fatalf("events:\n got  %v\n want %v", got2, wantEvents)
	}
	if s := events[0].Summary(); !strings.Contains(s, "CVE and webshell rules stay on") || !strings.Contains(s, "t1.gr") {
		t.Fatalf("switch summary: %s", s)
	}
	if s := events[2].Summary(); !strings.Contains(s, "rule 402") || !strings.Contains(s, "path /wp-admin/admin-ajax.php of t1.gr") || !strings.Contains(s, "until ") {
		t.Fatalf("path rule summary: %s", s)
	}
}

func itoaList(ids []int) string {
	if len(ids) == 0 {
		return "-"
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = itoa(id)
	}
	return strings.Join(parts, ",")
}

// The operator's API is unchanged, and gains an optional expiry.
func TestAdminWAFExcludeTTL(t *testing.T) {
	e := newTenantWAFEngine(t)
	call := func(q string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		e.handleWAFExcludeAdd(rr, adminReq("POST", "/api/v1/waf/exclude/add?"+q))
		return rr
	}
	for q, code := range map[string]int{
		"type=host&value=a.gr":                                           200,
		"type=host&value=b.gr&rule_ids=4xx":                              200,
		"type=path&value=/x/*&rule_ids=402,403&scope_hosts=c.gr&ttl=30d": 200,
		"type=host&value=d.gr&ttl=nope":                                  400,
		"type=host&value=e.gr&ttl=3000d":                                 400,
		"type=host&value=a.gr&rule_ids=10021":                            400,
	} {
		if rr := call(q); rr.Code != code {
			t.Fatalf("%s: %d %s", q, rr.Code, rr.Body.String())
		}
	}
	for _, x := range e.WAFExcludeList() {
		if x.By != "" || x.KeepCritical {
			t.Fatalf("an operator entry is marked: %+v", x)
		}
		if (x.Value == "/x/*") != (x.ExpiresUnix > 0) {
			t.Fatalf("expiry: %+v", x)
		}
	}
	if skipAll, _, crit := e.wafExcludes.MatchWAFDecision("a.gr", "/"); !skipAll || crit {
		t.Fatal("operator whole-WAF exclude")
	}
}

func TestExcludeStoreExpiry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.json")
	s := newExcludeStore(path)
	now := time.Now().Unix()
	if !s.AddEntry("host", "a.gr", nil, []int{402}, excludeOpts{ExpiresUnix: now + 3600}) ||
		!s.AddEntry("host", "b.gr", nil, nil, excludeOpts{ExpiresUnix: now - 1}) ||
		!s.AddEntry("path", "/p/", scopeSet("c.gr"), []int{301}, excludeOpts{ExpiresUnix: now - 1, By: excludeByScoped}) ||
		!s.AddEntry("host", "d.gr", nil, nil, excludeOpts{}) {
		t.Fatal("add")
	}
	if _, ids := s.MatchWAFRules("a.gr", "/"); len(ids) != 1 {
		t.Fatal("an entry that expires later does not apply")
	}
	if s.MatchWAF("b.gr", "/") {
		t.Fatal("an expired whole-WAF entry applies")
	}
	if _, ids := s.MatchWAFRules("c.gr", "/p/x"); len(ids) != 0 {
		t.Fatal("an expired path entry applies")
	}
	if _, ok := s.FirstWAFHostMatch("b.gr"); ok {
		t.Fatal("FirstWAFHostMatch returned an expired entry")
	}
	if n := len(s.WAFEntriesForHost("c.gr")); n != 0 {
		t.Fatalf("WAFEntriesForHost lists %d expired entries", n)
	}
	if n := len(s.List()); n != 2 {
		t.Fatalf("List has %d entries, want the 2 live ones", n)
	}
	// An expired entry does not block a new one on its key.
	if !s.AddEntry("host", "b.gr", nil, nil, excludeOpts{}) || !s.MatchWAF("b.gr", "/") {
		t.Fatal("re-add over an expired entry")
	}
	// Renewal: only an expiring entry, by an add that expires, of the same writer.
	if s.AddEntry("host", "d.gr", nil, nil, excludeOpts{ExpiresUnix: now + 60}) {
		t.Fatal("an add turned a permanent entry into an expiring one")
	}
	if s.AddEntry("host", "a.gr", nil, []int{402}, excludeOpts{}) {
		t.Fatal("an add turned an expiring entry into a permanent one")
	}
	if s.AddEntry("host", "a.gr", nil, []int{402}, excludeOpts{ExpiresUnix: now + 7200, By: excludeByScoped}) {
		t.Fatal("a tenant's add renewed the operator's entry")
	}
	if !s.AddEntry("host", "a.gr", nil, []int{402}, excludeOpts{ExpiresUnix: now + 7200}) {
		t.Fatal("renew")
	}
	if !s.PurgeExpired() {
		t.Fatal("PurgeExpired removed nothing")
	}
	if s.PurgeExpired() {
		t.Fatal("PurgeExpired removed something twice")
	}
	// On disk: the expired path entry is gone, the fields survive a reload.
	r := newExcludeStore(path)
	var vals []string
	for _, x := range r.List() {
		vals = append(vals, x.Value)
		if x.Value == "a.gr" && x.ExpiresUnix != now+7200 {
			t.Fatalf("expiry not persisted: %+v", x)
		}
	}
	sort.Strings(vals)
	if strings.Join(vals, " ") != "a.gr b.gr d.gr" {
		t.Fatalf("after reload: %v", vals)
	}
	// A store with no expiring entry never reads the clock for a match.
	p := newExcludeStore(filepath.Join(t.TempDir(), "p.json"))
	p.Add("host", "x.gr", nil)
	if p.expiryClock() != 0 || p.nextExpiry.Load() != 0 {
		t.Fatal("expiryClock without expiring entries")
	}
}

// The bridge sends the edge the new fields, and nothing expired.
func TestNginxBridgeWAFExcludesTenantFields(t *testing.T) {
	e := newTenantWAFEngine(t)
	now := time.Now().Unix()
	e.wafExcludes.AddEntry("host", "t1.gr", scopeSet("t1.gr"), nil, excludeOpts{By: excludeByScoped, KeepCritical: true})
	e.wafExcludes.AddEntry("path", "/a/", scopeSet("t1.gr"), []int{402}, excludeOpts{By: excludeByScoped, ExpiresUnix: now + 600})
	e.wafExcludes.AddEntry("path", "/gone/", scopeSet("t1.gr"), []int{402}, excludeOpts{ExpiresUnix: now - 5})
	b, _ := json.Marshal(map[string]any{"entries": e.WAFExcludeList()})
	s := string(b)
	if !strings.Contains(s, `"keep_critical":true`) || !strings.Contains(s, `"expires_unix":`) || strings.Contains(s, "/gone/") {
		t.Fatalf("bridge list: %s", s)
	}
	if strings.Count(s, "keep_critical") != 1 || strings.Count(s, "expires_unix") != 1 {
		t.Fatalf("zero values must be omitted: %s", s)
	}
}

// One account's sites hold a bounded number of rule excludes; renewing one of
// them stays possible at the cap, and another account is not affected.
func TestScopedWAFRuleExcludeCap(t *testing.T) {
	e := newTenantWAFEngine(t)
	SetTenantPolicySink(nil)
	add := func(q string, hosts ...string) int {
		rr := httptest.NewRecorder()
		e.handleWAFExcludeAdd(rr, scopedReq("POST", "/api/v1/waf/exclude/add?"+q, hosts...))
		return rr.Code
	}
	for i := 0; i < scopedWAFRuleExcludeMax; i++ {
		if code := add("type=path&value=/p"+itoa(i)+"/&rule_ids=402&ttl=24h", "t1.gr", "t2.gr"); code != 200 {
			t.Fatalf("add %d: %d", i, code)
		}
	}
	if code := add("type=path&value=/one-more/&rule_ids=402&ttl=24h", "t1.gr", "t2.gr"); code != http.StatusTooManyRequests {
		t.Fatalf("over the cap: %d", code)
	}
	if code := add("type=host&value=t2.gr&rule_ids=301&ttl=24h", "t1.gr", "t2.gr"); code != http.StatusTooManyRequests {
		t.Fatalf("a host rule exclude over the cap: %d", code)
	}
	if code := add("type=path&value=/p3/&rule_ids=402&ttl=7d", "t1.gr", "t2.gr"); code != 200 {
		t.Fatalf("renewing at the cap: %d", code)
	}
	if got, _ := e.wafExcludes.Get("path", "/p3/", scopeSet("t1.gr", "t2.gr"), []int{402}); time.Until(time.Unix(got.ExpiresUnix, 0)) < 6*24*time.Hour {
		t.Fatalf("the renewal at the cap did not extend: %+v", got)
	}
	if code := add("type=host&value=t1.gr", "t1.gr", "t2.gr"); code != 200 {
		t.Fatalf("the switch at the cap: %d", code)
	}
	if code := add("type=path&value=/mine/&rule_ids=402&ttl=24h", "other.gr"); code != 200 {
		t.Fatalf("another account at t1's cap: %d", code)
	}
	// The operator is not capped.
	rr := httptest.NewRecorder()
	e.handleWAFExcludeAdd(rr, adminReq("POST", "/api/v1/waf/exclude/add?type=path&value=/op/&rule_ids=402&scope_hosts=t1.gr"))
	if rr.Code != 200 {
		t.Fatalf("operator at t1's cap: %d", rr.Code)
	}
}
