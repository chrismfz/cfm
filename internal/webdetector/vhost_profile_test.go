package webdetector

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func newVhostProfileEngine(t *testing.T) (*Engine, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "rules.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "challenge_excludes.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "waf_excludes.json"),
		ClamScanOverrideStorePath: filepath.Join(dir, "clam_overrides.json"),
		SiteCacheStorePath:        filepath.Join(dir, "site_cache.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)
	return e, mux
}

func profileFor(t *testing.T, mux *http.ServeMux, host string) VhostProfile {
	t.Helper()
	rr := get(mux, adminCtx(), "/api/v1/webdet/vhost-profile?host="+host)
	if rr.Code != http.StatusOK {
		t.Fatalf("vhost-profile %s: status %d body=%s", host, rr.Code, rr.Body.String())
	}
	var p VhostProfile
	if err := json.Unmarshal(rr.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return p
}

func addProfileRule(t *testing.T, e *Engine, enabled bool, vhost string, m TrafficRuleMatch) TrafficRule {
	t.Helper()
	r, err := e.TrafficRuleAdd(TrafficRule{
		Enabled:  enabled,
		Priority: 100,
		Scope:    TrafficRuleScope{Vhosts: []string{vhost}},
		Match:    m,
		Action:   TrafficRuleAction{Type: "block"},
	})
	if err != nil {
		t.Fatalf("rule add %s: %v", vhost, err)
	}
	return r
}

// Admin only, a host is required, and the host is normalized the way the
// other per-host endpoints normalize it.
func TestVhostProfile_AuthAndHost(t *testing.T) {
	_, mux := newVhostProfileEngine(t)

	if rr := get(mux, scopedCtx("example.com"), "/api/v1/webdet/vhost-profile?host=example.com"); rr.Code != http.StatusForbidden {
		t.Fatalf("scoped caller: status %d, want 403", rr.Code)
	}
	if rr := get(mux, adminCtx(), "/api/v1/webdet/vhost-profile"); rr.Code != http.StatusBadRequest {
		t.Fatalf("no host: status %d, want 400", rr.Code)
	}
	p := profileFor(t, mux, "WWW.Example.com:443")
	if p.Host != "www.example.com" || p.Schema != VhostProfileSchema || p.Site != "example.com" {
		t.Fatalf("host=%q schema=%q site=%q", p.Host, p.Schema, p.Site)
	}
	// Empty blocks are lists, never null: the page iterates them.
	if p.Rules == nil || p.WAFExcludes == nil || p.ChallengeExcludes == nil {
		t.Fatalf("nil list in %+v", p)
	}
}

// Each block reports what applies to the host, inherited entries included,
// and nothing that does not.
func TestVhostProfile_WhatApplies(t *testing.T) {
	e, mux := newVhostProfileEngine(t)

	// WAF: a rule-scoped exclude on the apex covers its subdomains; a path
	// exclude applies on every host; another site's exclude does not.
	if !e.WAFExcludeAddRules("host", "example.com", nil, []int{402}) {
		t.Fatal("waf rule exclude")
	}
	if !e.WAFExcludeAdd("path", "/wp-admin/admin-ajax.php", nil) {
		t.Fatal("waf path exclude")
	}
	if !e.WAFExcludeAdd("host", "other.com", nil) {
		t.Fatal("waf other exclude")
	}
	// An admin narrowed a path exclude to another vhost: neither the edge nor
	// MatchWAFRules applies it here, so it is not listed. One narrowed to this
	// host is.
	if !e.WAFExcludeAddRules("path", "/import/", map[string]struct{}{"migrating.example.org": {}}, []int{402}) {
		t.Fatal("waf scoped path exclude")
	}
	if !e.WAFExcludeAddRules("path", "/export/", map[string]struct{}{"www.example.com": {}}, []int{402}) {
		t.Fatal("waf path exclude scoped to www")
	}
	// Challenge: an apex exclude covers www.
	if !e.ChallengeExcludeAdd("host", "example.com", nil) {
		t.Fatal("challenge exclude")
	}
	// Site Cache: a wildcard covers sub-hosts, not the apex.
	if _, err := e.SiteCacheApply(SiteCachePatch{
		Host:   "*.example.com",
		Static: &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean"), TTL: strPtr("7d")},
	}, false); err != nil {
		t.Fatalf("site cache: %v", err)
	}
	apexRule := addProfileRule(t, e, true, "example.com", TrafficRuleMatch{PathAny: []string{"/xmlrpc.php"}})
	wildRule := addProfileRule(t, e, false, "*.example.com", TrafficRuleMatch{PathAny: []string{"/wp-login.php"}})
	addProfileRule(t, e, true, "other.com", TrafficRuleMatch{PathAny: []string{"/"}})

	www := profileFor(t, mux, "www.example.com")

	if len(www.WAFExcludes) != 3 {
		t.Fatalf("www waf excludes = %+v, want the 402 host exclude, the unscoped path exclude and /export/", www.WAFExcludes)
	}
	for _, x := range www.WAFExcludes {
		switch x.Value {
		case "other.com":
			t.Fatalf("other.com's exclude listed for www.example.com")
		case "/import/":
			t.Fatalf("a path exclude scoped to migrating.example.org listed for www.example.com")
		}
	}
	// The profile follows the enforcement path: /import/ applies on its own
	// scope host only.
	if _, ids := e.wafExcludes.MatchWAFRules("unrelated.example.net", "/import/x"); ids != nil {
		t.Fatalf("MatchWAFRules applied /import/ outside its scope: %v", ids)
	}
	if _, ids := e.wafExcludes.MatchWAFRules("migrating.example.org", "/import/x"); ids == nil {
		t.Fatal("MatchWAFRules did not apply /import/ on its scope host")
	}
	mig := profileFor(t, mux, "migrating.example.org")
	found := false
	for _, x := range mig.WAFExcludes {
		found = found || x.Value == "/import/"
	}
	if !found {
		t.Fatalf("migrating.example.org's profile lacks its scoped /import/ exclude: %+v", mig.WAFExcludes)
	}
	if !www.Controls.WAFEnabled {
		t.Fatalf("a rule-scoped exclude must leave the WAF on")
	}
	if len(www.ChallengeExcludes) != 1 || www.ChallengeExcludes[0].Value != "example.com" || www.Controls.ChallengeEnabled {
		t.Fatalf("www challenge: excludes=%+v enabled=%v", www.ChallengeExcludes, www.Controls.ChallengeEnabled)
	}
	if www.SiteCache.Key != "*.example.com" || !www.SiteCache.Inherited || www.SiteCache.Entry == nil || !www.SiteCache.Entry.Static.Enabled {
		t.Fatalf("www site cache = %+v", www.SiteCache)
	}
	if len(www.Rules) != 1 || www.Rules[0].ID != wildRule.ID || www.Rules[0].State != "disabled" || www.Rules[0].MatchedBy != "*.example.com" {
		t.Fatalf("www rules = %+v", www.Rules)
	}

	apex := profileFor(t, mux, "example.com")
	if apex.SiteCache.Key != "" || apex.SiteCache.Entry != nil {
		t.Fatalf("a *.example.com policy must not cover the apex: %+v", apex.SiteCache)
	}
	if len(apex.Rules) != 1 || apex.Rules[0].ID != apexRule.ID || apex.Rules[0].State != "enabled" {
		t.Fatalf("apex rules = %+v", apex.Rules)
	}
	if apex.Challenge["host"] != "example.com" {
		t.Fatalf("challenge block = %+v", apex.Challenge)
	}
}

// An expiring rule reads "expired" once its until passed (it never matches
// again), and an exact all-off site cache entry is the policy that decides
// the host (an opt-out), even under an armed wildcard.
func TestVhostProfile_ExpiredRuleAndOptOut(t *testing.T) {
	e, _ := newVhostProfileEngine(t)
	until := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	r := addProfileRule(t, e, true, "shop.example.com", TrafficRuleMatch{PathAny: []string{"/"}, Until: until})

	if _, err := e.SiteCacheApply(SiteCachePatch{
		Host:   "*.example.com",
		Static: &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean"), TTL: strPtr("7d")},
	}, false); err != nil {
		t.Fatalf("wildcard: %v", err)
	}
	if _, err := e.SiteCacheApply(SiteCachePatch{
		Host:   "shop.example.com",
		Static: &SiteCacheTierPatch{Enabled: boolPtr(false)},
		Micro:  &SiteCacheTierPatch{Enabled: boolPtr(false)},
	}, false); err != nil {
		t.Fatalf("opt-out: %v", err)
	}

	now := e.VhostProfile("shop.example.com", time.Now())
	if len(now.Rules) != 1 || now.Rules[0].ID != r.ID || now.Rules[0].State != "enabled" {
		t.Fatalf("before until: %+v", now.Rules)
	}
	later := e.VhostProfile("shop.example.com", time.Now().Add(2*time.Hour))
	if later.Rules[0].State != "expired" {
		t.Fatalf("after until: state %q, want expired", later.Rules[0].State)
	}
	sc := now.SiteCache
	if sc.Key != "shop.example.com" || sc.Inherited || sc.Entry == nil || siteCacheArmed(*sc.Entry) {
		t.Fatalf("opt-out site cache = %+v", sc)
	}
}

// The profile's blocks are the existing surfaces' answers, not a second
// computation: the controls row equals the /webdet/vhosts row, the site cache
// key equals StatsKeyFor's when the policy is armed, and every rule the
// profile lists as enabled is one Simulate's host test takes.
func TestVhostProfile_ParityWithExistingSurfaces(t *testing.T) {
	e, mux := newVhostProfileEngine(t)
	if !e.ChallengeExcludeAdd("host", "example.com", nil) {
		t.Fatal("challenge exclude")
	}
	if !e.WAFExcludeAdd("host", "shop.example.com", nil) {
		t.Fatal("waf exclude")
	}
	if _, err := e.SiteCacheApply(SiteCachePatch{
		Host:   "*.example.com",
		Static: &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean"), TTL: strPtr("7d")},
	}, false); err != nil {
		t.Fatalf("site cache: %v", err)
	}
	addProfileRule(t, e, true, "*.example.com", TrafficRuleMatch{PathAny: []string{"/x"}})

	rr := get(mux, adminCtx(), "/api/v1/webdet/vhosts")
	var list struct {
		Rows []webdetVhostControlRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode vhosts: %v", err)
	}
	rows := map[string]webdetVhostControlRow{}
	for _, r := range list.Rows {
		rows[r.Host] = r
	}
	for _, host := range []string{"example.com", "shop.example.com"} {
		p := profileFor(t, mux, host)
		row, ok := rows[host]
		if !ok {
			t.Fatalf("%s: no /webdet/vhosts row", host)
		}
		a, _ := json.Marshal(row)
		b, _ := json.Marshal(p.Controls)
		if string(a) != string(b) {
			t.Fatalf("%s controls differ:\n vhosts  %s\n profile %s", host, a, b)
		}
		key, armed := e.siteCache.StatsKeyFor(host)
		if armed && key != p.SiteCache.Key {
			t.Fatalf("%s: StatsKeyFor %q, profile key %q", host, key, p.SiteCache.Key)
		}
		for _, r := range p.Rules {
			if r.State == "enabled" && !ruleHostMatch(r.Scope.Vhosts, host) {
				t.Fatalf("%s: profile lists rule %s that Simulate's host test refuses", host, r.ID)
			}
		}
	}
}

// The challenge column follows MatchChallenge, scope_hosts included: a
// tenant's exclude on example.com (scope [example.com]) does not cover
// www.example.com, which the decision still challenges.
func TestVhostProfile_ChallengeColumnFollowsScope(t *testing.T) {
	e, mux := newVhostProfileEngine(t)
	if !e.ChallengeExcludeAdd("host", "example.com", map[string]struct{}{"example.com": {}}) {
		t.Fatal("scoped challenge exclude")
	}
	// A literal scope host also takes its www. alias (scopeTakes: cPanel lists
	// a domain without it, so the tenant's token cannot name it); the value
	// matches shop.example.com but the scope does not take it, and
	// www.other.com is neither.
	for host, wantExcluded := range map[string]bool{
		"example.com":      true,
		"www.example.com":  true,
		"shop.example.com": false,
		"www.other.com":    false,
	} {
		p := profileFor(t, mux, host)
		if got := !p.Controls.ChallengeEnabled; got != wantExcluded {
			t.Fatalf("%s: challenge excluded=%v, want %v", host, got, wantExcluded)
		}
		if got := e.challengeExcludes.MatchChallenge(host); got != wantExcluded {
			t.Fatalf("%s: MatchChallenge=%v disagrees with the column", host, got)
		}
		if got := len(p.ChallengeExcludes) > 0; got != wantExcluded {
			t.Fatalf("%s: challenge_excludes=%+v", host, p.ChallengeExcludes)
		}
		if got := len(e.challengeExcludes.ChallengeEntriesForHost(host)) > 0; got != wantExcluded {
			t.Fatalf("%s: ChallengeEntriesForHost disagrees with MatchChallenge", host)
		}
		if _, got := e.challengeExcludes.FirstChallengeHostMatch(host); got != wantExcluded {
			t.Fatalf("%s: FirstChallengeHostMatch disagrees with MatchChallenge", host)
		}
	}
}

// An IP literal or a public suffix has no site to group by: related hosts is
// the host alone (publicsuffix would group 1.2.3.4 under "3.4").
func TestVhostProfile_NoSiteForIPOrSuffix(t *testing.T) {
	e, _ := newVhostProfileEngine(t)
	for _, host := range []string{"203.0.113.4", "2001:db8::1", "co.uk"} {
		p := e.VhostProfile(host, time.Now())
		if p.Site != "" || len(p.RelatedHosts) != 1 || p.RelatedHosts[0] != host {
			t.Fatalf("%s: site=%q related=%v", host, p.Site, p.RelatedHosts)
		}
	}
	if p := e.VhostProfile("www.example.co.uk", time.Now()); p.Site != "example.co.uk" {
		t.Fatalf("www.example.co.uk: site=%q", p.Site)
	}
}
