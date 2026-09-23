package webdetector

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The Go↔Lua parity fixture for the Site Cache edge feed. The daemon serves
// the policy feed (/nginx/cache/config) that cfm_cache.lua rebuilds its
// lookups from, and it resolves a request host to the key the edge counts the
// host's stats under (StatsKeyFor, the Go mirror of cfm_cache.lua
// policy_key_for). Neither side can see the other's code, so this test renders
// both into one committed Lua file — the feed exactly as handleCacheConfig
// serves it, and StatsKeyFor's answer for a set of request hosts — and
// scripts/tests/cfm_cache_edge_parity_test.lua feeds the same file to the real
// cfm_cache.lua and asserts the edge gives the same answers, and reads every
// field. A change on either side that makes them disagree fails one of the
// two; a change to the fixture itself fails here until it is regenerated:
//
//	go test ./internal/webdetector -run TestSiteCacheEdgeParityFixture -update-edge-parity
var updateEdgeParity = flag.Bool("update-edge-parity", false, "rewrite scripts/tests/fixtures/site_cache_edge_parity.lua")

const edgeParityFixture = "../../scripts/tests/fixtures/site_cache_edge_parity.lua"

// edgeParityStore is stored as the daemon stores it (a JSON file, loaded), so
// the generations are fixed and the load path — which normalizes hosts and
// freezes a row it cannot read — is part of what the edge is fed.
const edgeParityStore = `[
 {"host":"myip.gr","generation":1758585600001,
  "static":{"enabled":true,"recipe":"static_aggressive","ttl":"7d"},
  "micro":{"enabled":true,"recipe":"micro_safe","ttl":"5s"},
  "strict_cookies":true,"auth_cookies":["my_sess","__Host-app"]},
 {"host":"www.myip.gr","generation":1758585600002,
  "static":{"enabled":false,"recipe":"static_lean"},
  "micro":{"enabled":true,"recipe":"micro_aggressive","ttl":"30s"}},
 {"host":"*.example.com","generation":1758585600003,
  "static":{"enabled":true,"recipe":"static_lean","ttl":"1h"},"micro":{"enabled":false}},
 {"host":"*.shop.example.com","generation":1758585600004,
  "static":{"enabled":false},"micro":{"enabled":true,"recipe":"micro_safe","ttl":"2s"}},
 {"host":"tenant.example.com","generation":1758585600005,
  "static":{"enabled":false,"recipe":"static_lean"},"micro":{"enabled":false}},
 {"host":"*.off.example.com","generation":1758585600006,
  "static":{"enabled":false,"recipe":"static_lean"},"micro":{"enabled":false}},
 {"host":"frozen.example.com","generation":1758585600007,
  "static":{"enabled":true,"recipe":"static_lean"},"micro":{"enabled":false},"a_future_field":1},
 {"host":"lonely.org","generation":1758585600008,
  "static":{"enabled":false,"recipe":"static_lean"},"micro":{"enabled":false}},
 {"host":"*.quiet.net","generation":1758585600009,
  "static":{"enabled":false,"recipe":"static_lean"},"micro":{"enabled":false}},
 {"host":"xn--bcher-kva.example","generation":1758585600010,
  "static":{"enabled":true,"recipe":"static_lean","ttl":"1d"},"micro":{"enabled":false}},
 {"host":"Upper.Example.NET.","generation":1758585600011,
  "static":{"enabled":true,"recipe":"static_lean"},"micro":{"enabled":false}}
]`

// edgeParityHosts are request Host values as nginx hands them to the edge
// (plus the spellings the normalizers must agree on).
var edgeParityHosts = []string{
	"myip.gr", "MyIP.GR", "myip.gr.", "myip.gr:8443", "www.myip.gr", "sub.myip.gr",
	"a.example.com", "x.y.example.com", "example.com", "shop.example.com",
	"x.shop.example.com", "a.b.shop.example.com",
	"tenant.example.com", "TENANT.example.com.", "a.tenant.example.com",
	"off.example.com", "a.off.example.com",
	"frozen.example.com",
	"lonely.org", "a.quiet.net", "quiet.net",
	"xn--bcher-kva.example", "upper.example.net", "a.upper.example.net",
	"[::1]", "[::1]:443", "127.0.0.1", "",
}

func TestSiteCacheEdgeParityFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "site_cache.json")
	if err := os.WriteFile(path, []byte(edgeParityStore), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newSiteCacheStore(path)
	if len(store.frozen) != 1 {
		t.Fatalf("fixture store: %d frozen rows, want 1 (frozen.example.com)", len(store.frozen))
	}

	// The feed exactly as the bridge serves it.
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	b.ListCachePolicy = store.PolicyFeed
	req := httptest.NewRequest(http.MethodGet, "/nginx/cache/config", nil)
	req.Header.Set("X-CFM-Token", "tok")
	rr := httptest.NewRecorder()
	b.handleCacheConfig(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("handleCacheConfig: %d", rr.Code)
	}
	var feed any
	dec := json.NewDecoder(bytes.NewReader(rr.Body.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&feed); err != nil {
		t.Fatalf("feed is not JSON: %v", err)
	}

	// The feed carries each stored entry as stored (a check of its own, so a
	// field dropped from PolicyFeed fails here, not only as a fixture diff
	// that a regeneration would accept).
	var armed []string
	for _, r := range store.PolicyFeed() {
		if r.Static != nil || r.Micro != nil {
			armed = append(armed, r.Host)
		}
		e, ok := store.entries[r.Host]
		if !ok {
			continue // a frozen row's opt-out stand-in
		}
		tier := func(row *CacheTierRow, st SiteCacheTier) bool {
			if !st.Enabled {
				return row == nil
			}
			return row != nil && row.On && row.Recipe == st.Recipe && row.TTL == st.TTL
		}
		if r.Generation != e.Generation || r.StrictCookies != e.StrictCookies || !sameStrings(r.AuthCookies, e.AuthCookies) ||
			!tier(r.Static, e.Static) || !tier(r.Micro, e.Micro) {
			rj, _ := json.Marshal(r)
			t.Errorf("feed row %s does not carry stored entry %+v", rj, e)
		}
	}
	sort.Strings(armed)
	// Every key the edge counts under is one the daemon's stats ingest keeps
	// (ArmedKey): a stats row the ingest drops is a vhost with no stats.
	for _, k := range armed {
		if !store.ArmedKey(k) {
			t.Errorf("ArmedKey(%q) = false for an armed feed key — its pushed stats would be dropped", k)
		}
	}
	for _, h := range edgeParityHosts {
		if k, ok := store.StatsKeyFor(h); ok && !store.ArmedKey(k) {
			t.Errorf("StatsKeyFor(%q) = %q, which ArmedKey rejects", h, k)
		}
	}

	var sb strings.Builder
	sb.WriteString("-- AUTO-GENERATED by internal/webdetector/site_cache_edge_parity_test.go — do not edit.\n")
	sb.WriteString("-- Regenerate: go test ./internal/webdetector -run TestSiteCacheEdgeParityFixture -update-edge-parity\n")
	sb.WriteString("-- feed: the /nginx/cache/config body as the daemon serves it; armed_keys: the\n")
	sb.WriteString("-- feed rows with a tier on; cases: StatsKeyFor for each request host (false = none).\n")
	sb.WriteString("return {\n  feed = ")
	luaLiteral(&sb, feed, "  ")
	sb.WriteString(",\n  armed_keys = {")
	for i, k := range armed {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(" " + luaQuote(k))
	}
	sb.WriteString(" },\n  cases = {\n")
	for _, h := range edgeParityHosts {
		key, ok := store.StatsKeyFor(h)
		want := "false"
		if ok {
			want = luaQuote(key)
		}
		fmt.Fprintf(&sb, "    { host = %s, key = %s },\n", luaQuote(h), want)
	}
	sb.WriteString("  },\n}\n")
	got := sb.String()

	if *updateEdgeParity {
		if err := os.WriteFile(edgeParityFixture, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(edgeParityFixture)
	if err != nil {
		t.Fatalf("read %s: %v (generate it with -update-edge-parity)", edgeParityFixture, err)
	}
	if string(want) != got {
		t.Fatalf("%s is stale — the feed or StatsKeyFor changed. Regenerate it (go test ./internal/webdetector -run TestSiteCacheEdgeParityFixture -update-edge-parity) and REVIEW its diff: a changed key or a dropped field is a behaviour change (make test-lua then checks the edge agrees with the new answers, not that they are right).\n--- generated:\n%s", edgeParityFixture, got)
	}
}

// luaLiteral renders a decoded JSON value (UseNumber) as a Lua table literal,
// keys sorted; an array of objects puts one element per line.
func luaLiteral(sb *strings.Builder, v any, indent string) {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		sb.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(" [" + luaQuote(k) + "] = ")
			luaLiteral(sb, x[k], indent)
		}
		sb.WriteString(" }")
	case []any:
		multi := len(x) > 0
		for _, e := range x {
			if _, ok := e.(map[string]any); !ok {
				multi = false
			}
		}
		sb.WriteString("{")
		for i, e := range x {
			if multi {
				sb.WriteString("\n" + indent + "  ")
			} else if i > 0 {
				sb.WriteString(",")
			}
			if !multi {
				sb.WriteString(" ")
			}
			luaLiteral(sb, e, indent+"  ")
			if multi {
				sb.WriteString(",")
			}
		}
		if multi {
			sb.WriteString("\n" + indent + "}")
		} else {
			sb.WriteString(" }")
		}
	case string:
		sb.WriteString(luaQuote(x))
	case json.Number:
		sb.WriteString(x.String())
	case bool:
		sb.WriteString(strconv.FormatBool(x))
	case nil:
		sb.WriteString("nil")
	default:
		panic(fmt.Sprintf("luaLiteral: unexpected %T", v))
	}
}

// luaQuote quotes s as a Lua 5.1 string literal (decimal escapes outside
// printable ASCII, which LuaJIT and Lua 5.1 both read).
func luaQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// The feed's wire fields are exactly the ones cfm_cache.lua rebuild_cache
// reads (host, gen, static/micro {on, recipe, ttl}, strict_cookies,
// auth_cookies). A field added here reaches the edge as nothing — the Lua
// ignores it — so adding one means teaching cfm_cache.lua (and its KNOWN list
// in cfm_cache_edge_parity_test.lua) in the same change.
func TestCachePolicyRowWireFields(t *testing.T) {
	row := CachePolicyRow{
		Host: "a.com", Generation: 1,
		Static:        &CacheTierRow{On: true, Recipe: "static_lean", TTL: "1h"},
		Micro:         &CacheTierRow{On: true, Recipe: "micro_safe", TTL: "5s"},
		StrictCookies: true, AuthCookies: []string{"x"},
	}
	buf, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(buf, &m); err != nil {
		t.Fatal(err)
	}
	keys := func(m map[string]json.RawMessage) string {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return strings.Join(ks, ",")
	}
	if got, want := keys(m), "auth_cookies,gen,host,micro,static,strict_cookies"; got != want {
		t.Fatalf("CachePolicyRow wire fields = %s, want %s", got, want)
	}
	for _, tier := range []string{"static", "micro"} {
		var tm map[string]json.RawMessage
		if err := json.Unmarshal(m[tier], &tm); err != nil {
			t.Fatal(err)
		}
		if got, want := keys(tm), "on,recipe,ttl"; got != want {
			t.Fatalf("CacheTierRow (%s) wire fields = %s, want %s", tier, got, want)
		}
	}
}

// handleCacheConfig: bridge token required, GET only, and the body is sent
// with an exact Content-Length (cfm_cache.lua's minimal cosocket reader reads
// "*a" after the headers and cannot de-chunk); no policy store, or an empty
// one, is `{"entries":[]}` — never null, which the edge would decode as no
// table and log as a bad response.
func TestNginxBridge_HandleCacheConfig(t *testing.T) {
	get := func(b *NginxBridge, method, tok string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/nginx/cache/config", nil)
		if tok != "" {
			req.Header.Set("X-CFM-Token", tok)
		}
		rr := httptest.NewRecorder()
		b.handleCacheConfig(rr, req)
		return rr
	}
	b := NewNginxBridge("/tmp/cfm-test.sock", "tok", time.Minute, time.Minute)
	if rr := get(b, http.MethodGet, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("no token: %d, want 403", rr.Code)
	}
	if rr := get(b, http.MethodGet, "wrong"); rr.Code != http.StatusForbidden {
		t.Fatalf("wrong token: %d, want 403", rr.Code)
	}
	if rr := get(b, http.MethodPost, "tok"); rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d, want 405", rr.Code)
	}
	for name, feed := range map[string]func() []CachePolicyRow{
		"unwired": nil,
		"nil":     func() []CachePolicyRow { return nil },
		"empty":   func() []CachePolicyRow { return []CachePolicyRow{} },
	} {
		b.ListCachePolicy = feed
		rr := get(b, http.MethodGet, "tok")
		if rr.Code != http.StatusOK || rr.Body.String() != `{"entries":[]}` {
			t.Fatalf("%s feed: %d %q, want 200 {\"entries\":[]}", name, rr.Code, rr.Body.String())
		}
	}
	b.ListCachePolicy = func() []CachePolicyRow {
		return []CachePolicyRow{{Host: "a.com", Generation: 1758585600001, Static: &CacheTierRow{On: true, Recipe: "static_lean", TTL: "1h"}}}
	}
	rr := get(b, http.MethodGet, "tok")
	if rr.Code != http.StatusOK {
		t.Fatalf("feed: %d", rr.Code)
	}
	if cl := rr.Header().Get("Content-Length"); cl != strconv.Itoa(rr.Body.Len()) {
		t.Fatalf("Content-Length %q, body %d bytes — the edge reader needs the exact length", cl, rr.Body.Len())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	if want := `{"entries":[{"host":"a.com","gen":1758585600001,"static":{"on":true,"recipe":"static_lean","ttl":"1h"}}]}`; rr.Body.String() != want {
		t.Fatalf("body %s, want %s", rr.Body.String(), want)
	}
}
