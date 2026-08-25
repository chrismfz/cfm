package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestParseRateLimitMode(t *testing.T) {
	cases := map[string]rateLimitMode{
		"":         rlEnforce, // default: protect out of the box
		"enforce":  rlEnforce,
		"on":       rlEnforce,
		"1":        rlEnforce,
		"shadow":   rlShadow,
		"observe":  rlShadow,
		"off":      rlOff,
		"disabled": rlOff,
		"0":        rlOff,
	}
	for in, want := range cases {
		if got := parseRateLimitMode(in); got != want {
			t.Fatalf("parseRateLimitMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestClassifyRoute(t *testing.T) {
	cases := []struct {
		method, path string
		want         routeClass
	}{
		{"GET", "/api/v1/system/status", rcCheapRead},
		{"GET", "/api/v1/firewall/list", rcNormalRead},
		{"POST", "/api/v1/firewall/block", rcPrivilegedWrite},
		{"DELETE", "/api/v1/auth/token/abc", rcPrivilegedWrite},
		{"POST", "/api/v1/challenge/vhost/add", rcWrite},
		{"GET", "/api/v1/search?q=1", rcHeavyRead},
		{"GET", "/api/v1/ip/forensics", rcHeavyRead},
		{"GET", "/api/v1/host/drilldown/status", rcHeavyRead}, // trailing /status must NOT downgrade a heavy route
		{"GET", "/debug/pprof/heap", rcCaptureStream},
		{"GET", "/api/v1/detectors", rcNormalRead},
	}
	for _, c := range cases {
		if got := classifyRoute(c.method, c.path); got != c.want {
			t.Fatalf("classifyRoute(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestRateLimiterIsolatesSubjects(t *testing.T) {
	// A capacity-1 bucket: exhausting subject A must not affect subject B — one
	// scoped token cannot drain another's bucket (Step 8 hard requirement).
	now := time.Unix(1_700_000_000, 0)
	l := newRateLimiter(1.0)
	l.now = func() time.Time { return now }
	// Force capacity 1 by using a tiny window-less bucket via the store directly:
	l.buckets["scoped|normal_read|A"] = &rlEntry{bucket: newBucket(1, time.Minute, now), lastSeen: now}
	l.buckets["scoped|normal_read|B"] = &rlEntry{bucket: newBucket(1, time.Minute, now), lastSeen: now}

	if ok, _ := l.allow("scoped", rcNormalRead, "A"); !ok {
		t.Fatal("A first request should be allowed")
	}
	if ok, _ := l.allow("scoped", rcNormalRead, "A"); ok {
		t.Fatal("A second request should be throttled (capacity 1)")
	}
	if ok, _ := l.allow("scoped", rcNormalRead, "B"); !ok {
		t.Fatal("B must be unaffected by A's throttling")
	}
}

func TestRateLimiterRetryAfterPositive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newRateLimiter(1.0)
	l.now = func() time.Time { return now }
	l.buckets["trusted|write|s"] = &rlEntry{bucket: newBucket(1, 10*time.Second, now), lastSeen: now}

	if ok, _ := l.allow("trusted", rcWrite, "s"); !ok {
		t.Fatal("first allowed")
	}
	ok, retry := l.allow("trusted", rcWrite, "s")
	if ok {
		t.Fatal("second throttled")
	}
	if retry <= 0 || retry > 10*time.Second {
		t.Fatalf("retry-after = %v, want (0,10s]", retry)
	}
}

func TestCeilingScale(t *testing.T) {
	base := ceilingFor("trusted", rcNormalRead, 1.0).capacity
	half := ceilingFor("trusted", rcNormalRead, 0.5).capacity
	if half >= base || half < 1 {
		t.Fatalf("scale 0.5: capacity %d not a smaller positive fraction of %d", half, base)
	}
	// Never below 1 even at a tiny scale.
	if got := ceilingFor("scoped", rcCaptureStream, 0.0001).capacity; got != 1 {
		t.Fatalf("tiny scale capacity = %d, want clamped to 1", got)
	}
}

// --- middleware behaviour via the public API (tiny scale forces capacity→1) ---

func authedReq(mech authnMechanism, subject, method, path string) *http.Request {
	r := httptest.NewRequest(method, "http://host"+path, nil)
	ctx := withAuthnMechanism(r.Context(), mech)
	ctx = withAuthnSubject(ctx, subject)
	return r.WithContext(ctx)
}

type rlSpy struct{ n int }

func (s *rlSpy) h() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { s.n++; w.WriteHeader(http.StatusOK) }
}

func TestRateLimitMiddleware_Enforces429WithRetryAfter(t *testing.T) {
	spy := &rlSpy{}
	h := RateLimitMiddleware(rlEnforce, 0.0001)(spy.h()) // capacity clamps to 1
	path := "/api/v1/challenge/vhost/add"

	rr1 := httptest.NewRecorder()
	h.ServeHTTP(rr1, authedReq(authnMechanismTokenScoped, "tok1", "POST", path))
	if rr1.Code != http.StatusOK {
		t.Fatalf("first = %d, want 200", rr1.Code)
	}
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, authedReq(authnMechanismTokenScoped, "tok1", "POST", path))
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second = %d, want 429", rr2.Code)
	}
	if ra := rr2.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 must carry Retry-After")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", ra)
	}
	if spy.n != 1 {
		t.Fatalf("handler ran %d times, want 1 (second request blocked)", spy.n)
	}
}

func TestRateLimitMiddleware_ShadowLogsNotBlocks(t *testing.T) {
	spy := &rlSpy{}
	h := RateLimitMiddleware(rlShadow, 0.0001)(spy.h())
	path := "/api/v1/challenge/vhost/add"
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authedReq(authnMechanismTokenScoped, "tok1", "POST", path))
		if rr.Code != http.StatusOK {
			t.Fatalf("shadow request %d = %d, want 200 (observe only)", i, rr.Code)
		}
	}
	if spy.n != 3 {
		t.Fatalf("shadow must serve every request; handler ran %d/3", spy.n)
	}
}

func TestRateLimitMiddleware_OffIsPassthrough(t *testing.T) {
	spy := &rlSpy{}
	h := RateLimitMiddleware(rlOff, 0.0001)(spy.h())
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, authedReq(authnMechanismTokenScoped, "tok1", "POST", "/api/v1/x"))
		if rr.Code != http.StatusOK {
			t.Fatalf("off request %d blocked (%d)", i, rr.Code)
		}
	}
	if spy.n != 5 {
		t.Fatalf("off must pass everything; ran %d/5", spy.n)
	}
}

func TestRateLimitMiddleware_SkipsAnonymous(t *testing.T) {
	// No authn context (an anonymous request TokenMiddleware would already have
	// 401'd) must pass through so limiter behaviour never leaks credential validity.
	spy := &rlSpy{}
	h := RateLimitMiddleware(rlEnforce, 0.0001)(spy.h())
	for i := 0; i < 5; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "http://host/api/v1/x", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("anonymous request %d must not be rate-limited (got %d)", i, rr.Code)
		}
	}
	if spy.n != 5 {
		t.Fatalf("anonymous must pass; ran %d/5", spy.n)
	}
}

func TestRateLimitMiddleware_TrustedTierHigherThanScoped(t *testing.T) {
	// Same route + scale, admin (trusted) tolerates more before tripping than a
	// scoped token — sanity check the tier split actually raises admin ceilings.
	// scale 0.01 → trusted normal_read cap = int(1800*0.01)=18, scoped=int(600*0.01)=6.
	trip := func(mech authnMechanism, subject string) int {
		spy := &rlSpy{}
		h := RateLimitMiddleware(rlEnforce, 0.01)(spy.h())
		allowed := 0
		for i := 0; i < 100; i++ {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, authedReq(mech, subject, "GET", "/api/v1/detectors"))
			if rr.Code == http.StatusOK {
				allowed++
			} else {
				break
			}
		}
		return allowed
	}
	adminAllowed := trip(authnMechanismTokenAdmin, "admin")
	scopedAllowed := trip(authnMechanismTokenScoped, "tokX")
	if adminAllowed <= scopedAllowed {
		t.Fatalf("trusted tier (%d) should allow more than scoped (%d)", adminAllowed, scopedAllowed)
	}
}
