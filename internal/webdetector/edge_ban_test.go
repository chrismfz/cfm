package webdetector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"cfm/internal/edgeban"
	"cfm/internal/firewall"
)

// installEdgeBans installs a ready Default store holding ips (permanent),
// persisted in a temp dir; restored at cleanup.
func installEdgeBans(t *testing.T, ips ...string) *edgeban.Store {
	t.Helper()
	s := edgeban.New(filepath.Join(t.TempDir(), "edgeban.json"))
	var blocks []firewall.SetElementTimed
	for _, ip := range ips {
		s.Add(net.ParseIP(ip), nil, "waf_security", false)
		blocks = append(blocks, firewall.SetElementTimed{Elem: ip})
	}
	s.Reconcile(edgeban.Snapshot{Blocks: blocks, ReadAt: time.Now().Add(time.Second)})
	edgeban.SetDefault(s)
	t.Cleanup(func() { edgeban.SetDefault(nil) })
	return s
}

// edgeDecide asks for a decision as an edge would for a request that came
// through a trusted proxy (px=1); edgeDecideDirect as for a direct client.
func edgeDecide(b *NginxBridge, ip, host, scope string) (map[string]any, http.Header) {
	return decideWith(b, url.Values{"ip": {ip}, "host": {host}, "uri": {"/"}, "method": {"GET"}, "px": {"1"}}, scope)
}

func edgeDecideDirect(b *NginxBridge, ip, host string) (map[string]any, http.Header) {
	return decideWith(b, url.Values{"ip": {ip}, "host": {host}, "uri": {"/"}, "method": {"GET"}}, "")
}

func decideWith(b *NginxBridge, q url.Values, scope string) (map[string]any, http.Header) {
	if scope != "" {
		q.Set("scope", scope)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/nginx/decision?"+q.Encode(), nil)
	req.Header.Set("X-CFM-Token", "tok")
	b.handleDecision(rr, req)
	var payload map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &payload)
	return payload, rr.Header()
}

// A web ban the nft drop cannot enforce on a client behind a trusted proxy
// (2026-10-09: a banned scanner kept coming through Cloudflare) is answered
// ip_action=block by the decision, ahead of every allow but IGNORE_IPS.
func TestDecisionAnswersEdgeBan(t *testing.T) {
	installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)

	got, hdr := edgeDecide(b, "34.153.214.160", "shop.example.com", "")
	if got["ip_action"] != "block" || hdr.Get("X-CFM-Edge-Ban") != "1" {
		t.Fatalf("banned client: %+v, want ip_action=block with X-CFM-Edge-Ban", got)
	}
	if got, _ := edgeDecide(b, "34.153.214.161", "shop.example.com", ""); got["ip_action"] != "allow" {
		t.Fatalf("another client: %+v, want allow", got)
	}
	// A direct client is nft's alone (its ban drops it before the edge; nft's
	// allow sets decide for it), and an older edge sends no px.
	if got, hdr := edgeDecideDirect(b, "34.153.214.160", "shop.example.com"); got["ip_action"] == "block" || hdr.Get("X-CFM-Edge-Ban") != "" {
		t.Fatalf("direct client answered the edge ban: %+v", got)
	}

	// The host bypass (cPanel/webmail hosts) and the solved-ok state never
	// lift a ban, as nft's drop would not.
	b.hostBypassFunc = func(string) bool { return true }
	b.mu.Lock()
	b.okState[okStateKey{IP: "34.153.214.160", Host: "cpanel.example.com", Scope: "web"}] = time.Now().Add(time.Hour)
	b.mu.Unlock()
	if got, _ := edgeDecide(b, "34.153.214.160", "cpanel.example.com", "web"); got["ip_action"] != "block" {
		t.Fatalf("host bypass / solved-ok lifted the ban: %+v", got)
	}

	// IGNORE_IPS stays exempt (operator decision, 2026-10-10).
	b.bypassFunc = func(ip string) bool { return ip == "34.153.214.160" }
	if got, _ := edgeDecide(b, "34.153.214.160", "shop.example.com", ""); got["ip_action"] != "allow" {
		t.Fatalf("an IGNORE_IPS address must stay exempt: %+v", got)
	}
	b.bypassFunc = nil

	// A panel-scope decision is not touched (the panel gets its own,
	// separately rolled-out check).
	if got, _ := edgeDecide(b, "34.153.214.160", "cpanel.example.com", "panel:2083"); got["ip_action"] == "block" {
		t.Fatalf("panel scope answered the edge ban: %+v", got)
	}

	// EDGE_BAN = 0 stops it at once.
	edgeban.SetEnabled(false)
	got, _ = edgeDecide(b, "34.153.214.160", "shop.example.com", "")
	edgeban.SetEnabled(true)
	if got["ip_action"] == "block" {
		t.Fatalf("EDGE_BAN off still blocked: %+v", got)
	}

	// An unblock (ForceUnblock is how `cfm unblock` reaches the daemon) lifts it.
	b.ForceUnblock("34.153.214.160")
	if got, _ := edgeDecide(b, "34.153.214.160", "shop.example.com", ""); got["ip_action"] == "block" {
		t.Fatalf("still banned after ForceUnblock: %+v", got)
	}
}

// The ban holds while the bridge sheds (a map lookup, not the full decision).
func TestDecisionEdgeBanWhileShedding(t *testing.T) {
	installEdgeBans(t, "34.153.214.160")
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	for i := 0; i < cap(b.decisionSem); i++ {
		b.decisionSem <- struct{}{}
	}
	got, _ := edgeDecide(b, "34.153.214.160", "shop.example.com", "")
	if got["ip_action"] != "block" {
		t.Fatalf("shedding: %+v, want the edge ban answered", got)
	}
	if got, hdr := edgeDecide(b, "198.51.100.9", "shop.example.com", ""); got["rule_action"] != "shed" || hdr.Get("X-CFM-Bridge-Shed") != "1" {
		t.Fatalf("an unbanned client while shedding: %+v", got)
	}
	// IGNORE_IPS stays exempt on the shed path too.
	b.bypassFunc = func(ip string) bool { return ip == "34.153.214.160" }
	if got, _ := edgeDecide(b, "34.153.214.160", "shop.example.com", ""); got["ip_action"] == "block" {
		t.Fatalf("shedding: an IGNORE_IPS address was edge-banned: %+v", got)
	}
}

// `cfm block` reaches the daemon's store through the admin endpoint.
func TestEdgeBanEndpoint(t *testing.T) {
	s := installEdgeBans(t)
	e := &Engine{}
	call := func(q string, ctx context.Context) int {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webdet/edge-ban?"+q, nil).WithContext(ctx)
		e.handleEdgeBan(rr, req)
		return rr.Code
	}
	if code := call("ip=203.0.113.52", scopedCtx("a.gr")); code != http.StatusForbidden {
		t.Fatalf("scoped token: %d, want 403", code)
	}
	if code := call("ip=203.0.113.50&ttl=6h", adminCtx()); code != http.StatusOK {
		t.Fatalf("admin call: %d", code)
	}
	if code := call("ip=0.0.0.0", adminCtx()); code != http.StatusBadRequest {
		t.Fatalf("unspecified ip: %d, want 400", code)
	}
	if code := call("ip=203.0.113.51&ttl=-1h", adminCtx()); code != http.StatusBadRequest {
		t.Fatalf("bad ttl: %d, want 400", code)
	}
	s.Reconcile(edgeban.Snapshot{Blocks: []firewall.SetElementTimed{{Elem: "203.0.113.50"}}, ReadAt: time.Now().Add(time.Second)})
	if ok, _ := s.Banned("203.0.113.50"); !ok {
		t.Fatal("the manual ban did not reach the store")
	}
	if ok, _ := s.Banned("203.0.113.52"); ok {
		t.Fatal("a scoped token's ban reached the store")
	}
	// `cfm allow` lifts it.
	if code := call("ip=203.0.113.50&unban=1", adminCtx()); code != http.StatusOK {
		t.Fatalf("unban: %d", code)
	}
	if ok, _ := s.Banned("203.0.113.50"); ok {
		t.Fatal("unban=1 left the ban")
	}
}

type extendOnlyFW struct{ firewall.Backend }

func (extendOnlyFW) AddBlockBatch(e []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return firewall.BlockBatchResult{Added: len(e)}, nil
}

// The challenge server's self-protection block is enforced at the edge too.
func TestChallengeSelfProtectFeedsEdgeBan(t *testing.T) {
	s := installEdgeBans(t)
	cs := NewChallengeServer(extendOnlyFW{})
	cs.rlFwEnabled = true
	cs.rlFirewallBlock(net.ParseIP("203.0.113.80"), rlKindPage)
	s.Reconcile(edgeban.Snapshot{Blocks: []firewall.SetElementTimed{{Elem: "203.0.113.80"}}, ReadAt: time.Now().Add(time.Second)})
	if ok, _ := s.Banned("203.0.113.80"); !ok {
		t.Fatal("self-protection block not in the edge ban store")
	}
}
