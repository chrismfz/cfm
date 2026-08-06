package webdetector

import (
	"strings"
	"testing"
)

func TestAccessRing_EvictAndOrder(t *testing.T) {
	r := newAccessRing(3)
	for i, ip := range []string{"a", "b", "c", "d"} {
		r.add(AccessEntry{IP: ip, TS: float64(i)})
	}
	// cap 3 → oldest ("a") evicted; recent returns oldest→newest.
	got := r.recent(AccessFilter{Limit: 10})
	if len(got) != 3 {
		t.Fatalf("held = %d, want 3", len(got))
	}
	if got[0].IP != "b" || got[1].IP != "c" || got[2].IP != "d" {
		t.Fatalf("order/evict wrong: %v", []string{got[0].IP, got[1].IP, got[2].IP})
	}
}

func TestAccessRing_Filters(t *testing.T) {
	r := newAccessRing(10)
	r.add(AccessEntry{IP: "1.1.1.1", Host: "a.com", Method: "get", URI: "/wp-login.php", Status: 200, TS: 100})
	r.add(AccessEntry{IP: "1.1.1.1", Host: "a.com", Method: "post", URI: "/admin-ajax.php?action=x", Status: 403, TS: 200})
	r.add(AccessEntry{IP: "2.2.2.2", Host: "b.com", Method: "get", URI: "/", Status: 404, TS: 300})

	if got := r.recent(AccessFilter{IP: "1.1.1.1", Limit: 10}); len(got) != 2 {
		t.Fatalf("ip filter = %d, want 2", len(got))
	}
	if got := r.recent(AccessFilter{Host: "B.COM", Limit: 10}); len(got) != 1 || got[0].IP != "2.2.2.2" {
		t.Fatalf("host filter (case-insensitive) wrong: %+v", got)
	}
	if got := r.recent(AccessFilter{Status: 403, Limit: 10}); len(got) != 1 || got[0].Status != 403 {
		t.Fatalf("exact status filter wrong: %+v", got)
	}
	if got := r.recent(AccessFilter{StatusClass: 4, Limit: 10}); len(got) != 2 {
		t.Fatalf("status-class 4xx = %d, want 2", len(got))
	}
	if got := r.recent(AccessFilter{PathSub: "AJAX", Limit: 10}); len(got) != 1 {
		t.Fatalf("path substring (case-insensitive) = %d, want 1", len(got))
	}
	if got := r.recent(AccessFilter{Since: 250, Limit: 10}); len(got) != 1 || got[0].TS != 300 {
		t.Fatalf("since filter wrong: %+v", got)
	}
}

func TestAccessRing_LimitKeepsNewest(t *testing.T) {
	r := newAccessRing(100)
	for i := 0; i < 10; i++ {
		r.add(AccessEntry{IP: "x", TS: float64(i)})
	}
	got := r.recent(AccessFilter{Limit: 3})
	if len(got) != 3 {
		t.Fatalf("limit = %d, want 3", len(got))
	}
	// newest three (7,8,9), returned oldest→newest.
	if got[0].TS != 7 || got[2].TS != 9 {
		t.Fatalf("limit should keep newest: %v..%v", got[0].TS, got[2].TS)
	}
}

func TestRedactQuery(t *testing.T) {
	cases := map[string]string{
		"/x?token=abc&a=1":            "/x?token=[redacted]&a=1",
		"/y?api_key=secret&b=2":       "/y?api_key=[redacted]&b=2",
		"/z?password=hunter2":         "/z?password=[redacted]",
		"/keep?a=1&b=2":               "/keep?a=1&b=2",
		"/nopath":                     "/nopath",
		"/sessionid?sessionid=deadbe": "/sessionid?sessionid=[redacted]",
	}
	for in, want := range cases {
		if got := redactQuery(in); got != want {
			t.Errorf("redactQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQueryHasSecretHint(t *testing.T) {
	if queryHasSecretHint("a=1&b=2") {
		t.Fatal("no hint should be false (fast path)")
	}
	if !queryHasSecretHint("a=1&token=x") {
		t.Fatal("token should be detected")
	}
	if !queryHasSecretHint("api_key=x") {
		t.Fatal("api_key should be detected")
	}
}

func TestBoundStr_TruncatesAndDetaches(t *testing.T) {
	// short: returned intact.
	if got := boundStr("hello", 16); got != "hello" {
		t.Fatalf("short boundStr = %q, want hello", got)
	}
	// long: capped + ellipsis.
	long := strings.Repeat("a", 20)
	got := boundStr(long, 5)
	if got != "aaaaa…" {
		t.Fatalf("long boundStr = %q, want aaaaa…", got)
	}
	// detaches from a large parent (substring must not survive as an alias):
	// we can't inspect the backing array, but a clone must be byte-equal.
	parent := strings.Repeat("x", 1000) + "tail"
	sub := parent[1000:] // aliases parent
	if boundStr(sub, 16) != "tail" {
		t.Fatalf("boundStr content changed on clone")
	}
}

func TestNewAccessEntry_TruncatesAndRedacts(t *testing.T) {
	long := make([]byte, accessMaxURI+50)
	for i := range long {
		long[i] = 'a'
	}
	rec := LogRec{
		IP: "1.2.3.4", Host: "h.com", Method: "get",
		URI: "/p?token=sekret&" + string(long), Status: 200, RT: 0.25, UA: "ua",
	}
	e := newAccessEntry(rec)
	if len([]rune(e.URI)) > accessMaxURI+1 { // +1 for the ellipsis rune
		t.Fatalf("URI not truncated: len=%d", len([]rune(e.URI)))
	}
	if !strings.Contains(e.URI, "token=[redacted]") {
		t.Fatalf("URI not redacted: %q", e.URI)
	}
	if e.RTms != 250 {
		t.Fatalf("RTms = %d, want 250", e.RTms)
	}
}
