package webdetector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
)

func sigIgnorePost(mux *http.ServeMux, ctx context.Context, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, nil).WithContext(ctx)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// Store semantics: global entries match every host, host entries only their
// own vhost; matching is case-insensitive glob; persistence round-trips.
func TestClamSigIgnoreStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sigignore.json")
	s := newClamSigIgnoreStore(path)

	if !s.Add("", "*_Hunting.UNOFFICIAL", nil) {
		t.Fatal("global add failed")
	}
	if !s.Add("Shop.Example.COM.", "Doc.Dropper.Agent-*", []string{"shop.example.com"}) {
		t.Fatal("host add failed (host should normalize)")
	}
	if s.Add("shop.example.com", "doc.dropper.agent-*", nil) {
		t.Fatal("duplicate (case-insensitive pattern) must be rejected")
	}
	if s.Add("", "", nil) || s.Add("", "[unclosed", nil) || s.Add("", "bad\x01ctl", nil) {
		t.Fatal("empty/malformed/control-char patterns must be rejected")
	}

	if ok, by := s.Match("any.example.com", "YARA.Foo_Hunting.UNOFFICIAL"); !ok || by != "store:global:*_Hunting.UNOFFICIAL" {
		t.Fatalf("global match = (%v, %q)", ok, by)
	}
	if ok, by := s.Match("shop.example.com", "Doc.Dropper.Agent-123"); !ok || by != "store:shop.example.com:Doc.Dropper.Agent-*" {
		t.Fatalf("host match = (%v, %q)", ok, by)
	}
	if ok, _ := s.Match("other.example.com", "Doc.Dropper.Agent-123"); ok {
		t.Fatal("host entry must not match a different vhost")
	}
	if ok, _ := s.Match("shop.example.com", "Win.Trojan.Hide-1"); ok {
		t.Fatal("unrelated signature must not match")
	}

	// Reload from disk: entries survive.
	s2 := newClamSigIgnoreStore(path)
	if got := len(s2.List()); got != 2 {
		t.Fatalf("reloaded entries = %d, want 2", got)
	}
	if !s2.Remove("shop.example.com", "Doc.Dropper.Agent-*") {
		t.Fatal("remove failed after reload")
	}
	if ok, _ := s2.Match("shop.example.com", "Doc.Dropper.Agent-9"); ok {
		t.Fatal("removed entry still matches")
	}
}

// API scope model: global entries are admin-only; a scoped token can only
// manage (and see) entries for hosts inside its own vhost scope.
func TestClamSigIgnoreAPIScoping(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(Config{
		TrafficRulesStorePath:     filepath.Join(dir, "r.json"),
		ChallengeExcludeStorePath: filepath.Join(dir, "c.json"),
		WAFExcludeStorePath:       filepath.Join(dir, "w.json"),
		ClamScanOverrideStorePath: filepath.Join(dir, "o.json"),
		ClamSigIgnoreStorePath:    filepath.Join(dir, "s.json"),
	})
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

	post := func(ctx context.Context, path string) int {
		return sigIgnorePost(mux, ctx, path).Code
	}
	q := func(host, pattern string) string {
		v := url.Values{}
		if host != "" {
			v.Set("host", host)
		}
		v.Set("pattern", pattern)
		return v.Encode()
	}

	// Scoped token: own host OK, other host 403, global 403.
	if code := post(scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/add?"+q("mine.example.com", "Doc.Foo-*")); code != http.StatusOK {
		t.Fatalf("scoped add own host = %d, want 200", code)
	}
	if code := post(scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/add?"+q("other.example.com", "Doc.Foo-*")); code != http.StatusForbidden {
		t.Fatalf("scoped add other host = %d, want 403", code)
	}
	if code := post(scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/add?"+q("", "Doc.Foo-*")); code != http.StatusForbidden {
		t.Fatalf("scoped add GLOBAL = %d, want 403 (admin-only)", code)
	}

	// Admin: global + any host OK; missing pattern 400.
	if code := post(adminCtx(), "/api/v1/clam/sigignore/add?"+q("", "*_Hunting.UNOFFICIAL")); code != http.StatusOK {
		t.Fatalf("admin global add = %d, want 200", code)
	}
	if code := post(adminCtx(), "/api/v1/clam/sigignore/add?"+q("other.example.com", "Xls.Macro-*")); code != http.StatusOK {
		t.Fatalf("admin host add = %d, want 200", code)
	}
	if code := post(adminCtx(), "/api/v1/clam/sigignore/add"); code != http.StatusBadRequest {
		t.Fatalf("admin add without pattern = %d, want 400", code)
	}

	// List: scoped sees only its own host's entries (no global, no other host).
	rr := get(mux, scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/list")
	if rr.Code != http.StatusOK {
		t.Fatalf("scoped list = %d", rr.Code)
	}
	var scopedOut struct {
		Entries []clamSigIgnoreEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &scopedOut); err != nil {
		t.Fatalf("decode scoped list: %v", err)
	}
	if len(scopedOut.Entries) != 1 || scopedOut.Entries[0].Host != "mine.example.com" {
		t.Fatalf("scoped list leaked entries: %+v", scopedOut.Entries)
	}

	// Admin list sees all three.
	rr = get(mux, adminCtx(), "/api/v1/clam/sigignore/list")
	var adminOut struct {
		Entries []clamSigIgnoreEntry `json:"entries"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &adminOut); err != nil {
		t.Fatalf("decode admin list: %v", err)
	}
	if len(adminOut.Entries) != 3 {
		t.Fatalf("admin list = %d entries, want 3", len(adminOut.Entries))
	}

	// Scoped remove: own OK, other's 403.
	if code := post(scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/remove?"+q("mine.example.com", "Doc.Foo-*")); code != http.StatusOK {
		t.Fatalf("scoped remove own = %d, want 200", code)
	}
	if code := post(scopedCtx("mine.example.com"), "/api/v1/clam/sigignore/remove?"+q("", "*_Hunting.UNOFFICIAL")); code != http.StatusForbidden {
		t.Fatalf("scoped remove global = %d, want 403", code)
	}

	// The engine lookup (what the scanner consults) reflects the store.
	if ok, _ := e.ClamSigIgnoreMatch("whatever.example.com", "YARA.X_Hunting.UNOFFICIAL"); !ok {
		t.Fatal("engine lookup must match the admin global entry")
	}
	if ok, _ := e.ClamSigIgnoreMatch("mine.example.com", "Doc.Foo-1"); ok {
		t.Fatal("removed scoped entry must not match")
	}
}
