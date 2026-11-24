package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func controlRows(t *testing.T, mux *http.ServeMux, ctx context.Context, path string) map[string]webdetVhostControlRow {
	t.Helper()
	rr := get(mux, ctx, path)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s: status %d body=%s", path, rr.Code, rr.Body.String())
	}
	var resp struct {
		Rows []webdetVhostControlRow `json:"rows"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	out := map[string]webdetVhostControlRow{}
	for _, r := range resp.Rows {
		out[r.Host] = r
	}
	return out
}

// The vhost picker's chips: the Site Cache tiers the edge applies to each
// host (a covering wildcard included) and its live rule count, where a scoped
// caller counts only the rules it may list.
func TestWebdetVhosts_SiteCacheAndRuleCount(t *testing.T) {
	e, mux := newVhostProfileEngine(t)
	if !e.ChallengeExcludeAdd("host", "shop.example.com", nil) { // gives the host a row
		t.Fatal("seed row")
	}
	if !e.ChallengeExcludeAdd("host", "plain.example.org", nil) {
		t.Fatal("seed row")
	}
	if _, err := e.SiteCacheApply(SiteCachePatch{
		Host:   "*.example.com",
		Static: &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("static_lean"), TTL: strPtr("7d")},
		Micro:  &SiteCacheTierPatch{Enabled: boolPtr(true), Recipe: strPtr("micro_safe"), TTL: strPtr("10s")},
	}, false); err != nil {
		t.Fatalf("site cache: %v", err)
	}
	addProfileRule(t, e, true, "shop.example.com", TrafficRuleMatch{PathAny: []string{"/a"}})
	addProfileRule(t, e, true, "*", TrafficRuleMatch{PathAny: []string{"/b"}}) // operator's node-wide rule
	addProfileRule(t, e, false, "shop.example.com", TrafficRuleMatch{PathAny: []string{"/c"}})
	expiring := addProfileRule(t, e, true, "shop.example.com", TrafficRuleMatch{PathAny: []string{"/d"}, Until: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})

	admin := controlRows(t, mux, adminCtx(), "/api/v1/webdet/vhosts")
	shop := admin["shop.example.com"]
	if !shop.SiteCacheStatic || !shop.SiteCacheMicro {
		t.Fatalf("shop: the *.example.com policy covers it: %+v", shop)
	}
	if shop.Rules != 3 {
		t.Fatalf("shop: admin rule count %d, want 3 (two enabled own rules and the node-wide one; not the disabled one)", shop.Rules)
	}
	// Once its until passes, the expiring rule no longer counts.
	if got := vhostLiveRuleCount(e.TrafficRuleList(), "shop.example.com", time.Now().Add(2*time.Hour)); got != 2 {
		t.Fatalf("after %s expired: count %d, want 2", expiring.ID, got)
	}
	plain := admin["plain.example.org"]
	if plain.SiteCacheStatic || plain.SiteCacheMicro || plain.Rules != 1 {
		t.Fatalf("plain: %+v", plain)
	}

	scoped := controlRows(t, mux, scopedCtx("shop.example.com"), "/api/v1/webdet/vhosts")
	if got := scoped["shop.example.com"].Rules; got != 2 {
		t.Fatalf("scoped rule count %d, want 2: the operator's node-wide rule is not one the tenant can list", got)
	}
	if _, leaked := scoped["plain.example.org"]; leaked {
		t.Fatal("scoped caller got another tenant's row")
	}
}
