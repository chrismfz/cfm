package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// caMatch builds a challengeAccessMatch from a base traffic-rule match plus ASNs.
func caMatch(base TrafficRuleMatch, asns ...uint32) challengeAccessMatch {
	return challengeAccessMatch{TrafficRuleMatch: base, AsnIn: asns}
}

func mustAddCA(t *testing.T, s *challengeAccessStore, scope []string, m challengeAccessMatch) ChallengeAccessEntry {
	t.Helper()
	e, err := s.Add(ChallengeAccessEntry{Enabled: true, Scope: TrafficRuleScope{Vhosts: scope}, Match: m})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return e
}

func TestChallengeAccessCRUD(t *testing.T) {
	s := newChallengeAccessStore("")

	e := mustAddCA(t, s, []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"/feed/"}}))
	if e.ID == "" {
		t.Fatal("expected generated id")
	}
	if got, ok := s.Get(e.ID); !ok || got.ID != e.ID {
		t.Fatalf("Get failed: %+v ok=%v", got, ok)
	}
	if n := len(s.List()); n != 1 {
		t.Fatalf("List len=%d want 1", n)
	}

	// Update toggles enabled and swaps the path.
	e.Enabled = false
	e.Match = caMatch(TrafficRuleMatch{PathAny: []string{"/other/"}})
	up, err := s.Update(e.ID, e)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if up.Enabled {
		t.Fatal("expected disabled after update")
	}
	if s.enabledCount != 0 {
		t.Fatalf("enabledCount=%d want 0 after disabling only entry", s.enabledCount)
	}

	if !s.Remove(e.ID) {
		t.Fatal("Remove returned false")
	}
	if _, ok := s.Get(e.ID); ok {
		t.Fatal("entry still present after Remove")
	}
}

func TestChallengeAccessNormalizeErrors(t *testing.T) {
	s := newChallengeAccessStore("")

	if _, err := s.Add(ChallengeAccessEntry{Enabled: true}); err == nil {
		t.Fatal("expected error for missing scope.vhosts")
	}
	if _, err := s.Add(ChallengeAccessEntry{
		Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}},
		Match: caMatch(TrafficRuleMatch{CountryIn: []string{"GR"}, CountryNotIn: []string{"DE"}}),
	}); err == nil {
		t.Fatal("expected error for country_in + country_not_in")
	}
	if _, err := s.Add(ChallengeAccessEntry{
		Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{"a.gr"}},
		Match: caMatch(TrafficRuleMatch{}, 0),
	}); err == nil {
		t.Fatal("expected error for ASN 0")
	}
}

func TestChallengeAccessMatchExempt(t *testing.T) {
	noASN := func() uint32 { return 0 }

	type tc struct {
		name  string
		scope []string
		match challengeAccessMatch
		in    ChallengeAccessInput
		asn   func() uint32
		want  bool
	}
	base := func(host string) ChallengeAccessInput { return ChallengeAccessInput{Host: host} }
	cases := []tc{
		{"host match empty rule", []string{"shop.gr"}, caMatch(TrafficRuleMatch{}),
			base("shop.gr"), noASN, true},
		{"host miss", []string{"shop.gr"}, caMatch(TrafficRuleMatch{}),
			base("other.gr"), noASN, false},
		{"wildcard host", []string{"*.shop.gr"}, caMatch(TrafficRuleMatch{}),
			base("www.shop.gr"), noASN, true},
		{"path hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"/feed/"}}),
			ChallengeAccessInput{Host: "shop.gr", Path: "/feed/google.xml"}, noASN, true},
		{"path miss", []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"/feed/"}}),
			ChallengeAccessInput{Host: "shop.gr", Path: "/wp-admin/"}, noASN, false},
		{"country_in hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{CountryIn: []string{"GR"}}),
			ChallengeAccessInput{Host: "shop.gr", Country: "GR"}, noASN, true},
		{"country_in unknown fails open", []string{"shop.gr"}, caMatch(TrafficRuleMatch{CountryIn: []string{"GR"}}),
			ChallengeAccessInput{Host: "shop.gr", Country: ""}, noASN, false},
		{"country_not_in hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{CountryNotIn: []string{"GR"}}),
			ChallengeAccessInput{Host: "shop.gr", Country: "DE"}, noASN, true},
		{"country_not_in unknown fails open", []string{"shop.gr"}, caMatch(TrafficRuleMatch{CountryNotIn: []string{"GR"}}),
			ChallengeAccessInput{Host: "shop.gr", Country: ""}, noASN, false},
		{"ip_any hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{IPAny: []string{"203.0.113.0/24"}}),
			ChallengeAccessInput{Host: "shop.gr", IP: "203.0.113.9"}, noASN, true},
		{"ip_any miss", []string{"shop.gr"}, caMatch(TrafficRuleMatch{IPAny: []string{"203.0.113.0/24"}}),
			ChallengeAccessInput{Host: "shop.gr", IP: "198.51.100.1"}, noASN, false},
		{"ua glob hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{UAAny: []string{"*xrawler*"}}),
			ChallengeAccessInput{Host: "shop.gr", UA: "google-xrawler"}, noASN, true},
		{"method hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{Methods: []string{"GET"}}),
			ChallengeAccessInput{Host: "shop.gr", Method: "GET"}, noASN, true},
		{"method miss", []string{"shop.gr"}, caMatch(TrafficRuleMatch{Methods: []string{"GET"}}),
			ChallengeAccessInput{Host: "shop.gr", Method: "POST"}, noASN, false},
		{"verified_bot keeps google", []string{"shop.gr"}, caMatch(TrafficRuleMatch{VerifiedBot: true}),
			ChallengeAccessInput{Host: "shop.gr", VerifiedBot: "google"}, noASN, true},
		{"verified_bot requires verdict", []string{"shop.gr"}, caMatch(TrafficRuleMatch{VerifiedBot: true}),
			ChallengeAccessInput{Host: "shop.gr", VerifiedBot: ""}, noASN, false},
		{"asn hit", []string{"shop.gr"}, caMatch(TrafficRuleMatch{}, 15169),
			base("shop.gr"), func() uint32 { return 15169 }, true},
		{"asn unresolved fails open", []string{"shop.gr"}, caMatch(TrafficRuleMatch{}, 15169),
			base("shop.gr"), noASN, false},
		{"asn miss", []string{"shop.gr"}, caMatch(TrafficRuleMatch{}, 15169),
			base("shop.gr"), func() uint32 { return 64500 }, false},
		// The google-xrawler feed incident: ASN AND path, both must hold.
		{"asn+path both hold", []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"*/google.xml"}}, 15169),
			ChallengeAccessInput{Host: "shop.gr", Path: "/wp-content/plugins/woofeed/files/google.xml"},
			func() uint32 { return 15169 }, true},
		{"asn+path path fails", []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"*/google.xml"}}, 15169),
			ChallengeAccessInput{Host: "shop.gr", Path: "/index.php"},
			func() uint32 { return 15169 }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newChallengeAccessStore("")
			mustAddCA(t, s, c.scope, c.match)
			if got := s.MatchExempt(c.in, c.asn); got != c.want {
				t.Fatalf("MatchExempt=%v want %v", got, c.want)
			}
		})
	}
}

func TestChallengeAccessDisabledAndEmptyStore(t *testing.T) {
	s := newChallengeAccessStore("")
	// Empty store: fast-path false, asnFn never invoked.
	called := false
	if s.MatchExempt(ChallengeAccessInput{Host: "shop.gr"}, func() uint32 { called = true; return 15169 }) {
		t.Fatal("empty store should not exempt")
	}
	if called {
		t.Fatal("asnFn must not be called on empty store")
	}

	// Disabled entry is ignored.
	e, _ := s.Add(ChallengeAccessEntry{Enabled: false, Scope: TrafficRuleScope{Vhosts: []string{"shop.gr"}},
		Match: caMatch(TrafficRuleMatch{})})
	_ = e
	if s.MatchExempt(ChallengeAccessInput{Host: "shop.gr"}, func() uint32 { return 0 }) {
		t.Fatal("disabled entry should not exempt")
	}
}

// asnFn must not be invoked when no host-matched entry uses asn_in (lazy).
func TestChallengeAccessASNLazy(t *testing.T) {
	s := newChallengeAccessStore("")
	mustAddCA(t, s, []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"/feed/"}}))
	calls := 0
	got := s.MatchExempt(ChallengeAccessInput{Host: "shop.gr", Path: "/feed/x"},
		func() uint32 { calls++; return 15169 })
	if !got {
		t.Fatal("expected path exemption")
	}
	if calls != 0 {
		t.Fatalf("asnFn called %d times; expected 0 for a path-only entry", calls)
	}
}

// Disk round-trip: the embedded match (shared traffic-rule fields + asn_in)
// must survive marshal → reload unchanged.
func TestChallengeAccessPersistence(t *testing.T) {
	path := t.TempDir() + "/ca.json"
	s := newChallengeAccessStore(path)
	e := mustAddCA(t, s, []string{"shop.gr"},
		caMatch(TrafficRuleMatch{PathAny: []string{"*/google.xml"}, CountryIn: []string{"GR"}}, 15169))

	s2 := newChallengeAccessStore(path)
	got, ok := s2.Get(e.ID)
	if !ok {
		t.Fatal("entry did not persist")
	}
	if len(got.Match.AsnIn) != 1 || got.Match.AsnIn[0] != 15169 {
		t.Fatalf("asn_in did not round-trip: %+v", got.Match.AsnIn)
	}
	// normalizePatternList prepends "/" to path patterns (shared traffic-rule
	// behaviour); "*" still crosses "/" so it matches deep feed paths.
	if len(got.Match.PathAny) != 1 || got.Match.PathAny[0] != "/*/google.xml" {
		t.Fatalf("path_any did not round-trip: %+v", got.Match.PathAny)
	}
	if len(got.Match.CountryIn) != 1 || got.Match.CountryIn[0] != "GR" {
		t.Fatalf("country_in did not round-trip: %+v", got.Match.CountryIn)
	}
	// Reloaded entry must still evaluate (ipAnyCompiled/asn matcher rebuilt).
	if !s2.MatchExempt(ChallengeAccessInput{Host: "shop.gr", Country: "GR", Path: "/x/google.xml"},
		func() uint32 { return 15169 }) {
		t.Fatal("reloaded entry did not match")
	}
}

// Forward-compat: an entry a newer cfm wrote with an unknown match key must be
// kept verbatim, never enforced (dropping the key would WIDEN the allow-list),
// and never dropped from disk on a later save.
func TestChallengeAccessForwardCompat(t *testing.T) {
	path := t.TempDir() + "/ca.json"
	raw := `[
	  {"id":"ca_future","enabled":true,"scope":{"vhosts":["shop.gr"]},
	   "match":{"path_any":["/feed"],"header_in":["X-Api-Key: secret"]},"note":"future"},
	  {"id":"ca_known","enabled":true,"scope":{"vhosts":["ok.gr"]},
	   "match":{"path_any":["/x"]},"created_at":"2020-01-01T00:00:00Z"}
	]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newChallengeAccessStore(path)
	fut, ok := s.Get("ca_future")
	if !ok || !fut.Unsupported || fut.Enabled {
		t.Fatalf("future entry should load as unsupported+disabled: %+v ok=%v", fut, ok)
	}
	// Never enforced — even though its known path matches, it is disabled.
	if s.MatchExempt(ChallengeAccessInput{Host: "shop.gr", Path: "/feed"}, func() uint32 { return 0 }) {
		t.Fatal("unsupported entry must never exempt (would widen the allow-list)")
	}
	// Editing it is refused.
	if _, err := s.Update("ca_future", fut); err == nil {
		t.Fatal("Update on an unsupported entry must be refused")
	}

	// A normal Add triggers saveLocked; the frozen entry's unknown key must
	// survive verbatim on disk (not be stripped → widening the exemption).
	if _, err := s.Add(ChallengeAccessEntry{
		Enabled: true, Scope: TrafficRuleScope{Vhosts: []string{"new.gr"}},
		Match: caMatch(TrafficRuleMatch{PathAny: []string{"/y"}}),
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "header_in") || !strings.Contains(string(b), "X-Api-Key: secret") {
		t.Fatalf("unknown key dropped on save (allow-list widened):\n%s", b)
	}

	// Reload: the known entry still enforces; the future one stays frozen.
	s2 := newChallengeAccessStore(path)
	if !s2.MatchExempt(ChallengeAccessInput{Host: "ok.gr", Path: "/x"}, func() uint32 { return 0 }) {
		t.Fatal("known entry should still enforce after reload")
	}
	if f2, ok := s2.Get("ca_future"); !ok || !f2.Unsupported {
		t.Fatalf("future entry lost frozen/unsupported status after reload: %+v ok=%v", f2, ok)
	}
}

// The bridge downgrade: a vhost-wide challenge becomes allow for a matching
// exemption, but a per-IP block is never softened.
func TestNginxBridgeChallengeAccessDowngrade(t *testing.T) {
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	s := newChallengeAccessStore("")
	mustAddCA(t, s, []string{"shop.gr"}, caMatch(TrafficRuleMatch{PathAny: []string{"/feed/"}}))
	b.ChallengeAccessExempt = s.MatchExempt
	b.ChallengeAccessNeedsVerifiedBot = s.NeedsVerifiedBotFor

	decide := func(uri string) map[string]any {
		b.mu.Lock()
		b.vhState["shop.gr"] = bridgeVhostEntry{Action: "challenge", Expires: time.Now().Add(time.Minute)}
		b.mu.Unlock()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet,
			"/nginx/decision?ip=203.0.113.9&host=shop.gr&uri="+uri+"&method=GET", nil)
		req.Header.Set("X-CFM-Token", "tok")
		b.handleDecision(rr, req)
		var payload map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &payload)
		return payload
	}

	if got := decide("%2Ffeed%2Fgoogle.xml"); got["vhost_action"] != "allow" {
		t.Fatalf("matching path should downgrade challenge→allow, got %+v", got)
	}
	if got := decide("%2Findex.php"); got["vhost_action"] != "challenge" {
		t.Fatalf("non-matching path should stay challenged, got %+v", got)
	}

	// A per-IP block is never softened by an exemption.
	b.mu.Lock()
	b.ipState["203.0.113.9"] = bridgeIPEntry{Action: "block", Expires: time.Now().Add(time.Minute)}
	b.mu.Unlock()
	if got := decide("%2Ffeed%2Fgoogle.xml"); got["ip_action"] != "block" {
		t.Fatalf("exemption must not soften a block, got %+v", got)
	}
}

// Scope filter hides entries whose vhosts are outside the token allowlist.
func TestChallengeAccessScopeFilter(t *testing.T) {
	entries := []ChallengeAccessEntry{
		{ID: "a", Scope: TrafficRuleScope{Vhosts: []string{"tenant-a.example.com"}}},
		{ID: "b", Scope: TrafficRuleScope{Vhosts: []string{"tenant-b.example.com"}}},
	}
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxScopeKey{}, map[string]struct{}{"tenant-a.example.com": {}}))
	out := scopeFilterChallengeAccess(entries, req)
	if len(out) != 1 || out[0].ID != "a" {
		t.Fatalf("scope filter = %+v, want only tenant-a", out)
	}
}
