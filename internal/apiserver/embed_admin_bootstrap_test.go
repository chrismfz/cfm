package apiserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

func useTestEmbedAdminCookieSigningKey(t *testing.T) {
	t.Helper()
	prev := embedAdminCookieSigningKeyProvider
	embedAdminCookieSigningKeyProvider = func() ([]byte, error) {
		return []byte("fedcba9876543210fedcba9876543210"), nil
	}
	t.Cleanup(func() {
		embedAdminCookieSigningKeyProvider = prev
	})
}

// admin-code is not a public path: only an ADMIN credential may mint a code.
func TestEmbedAdminCodeRequiresAdminRole(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_000, 0).UTC())
	store := NewTokenStore()
	scoped := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	mux := http.NewServeMux()
	RegisterEmbedAdminBootstrapEndpoint(mux)
	h := TokenMiddleware("admin-secret", store)(mux)

	// Admin bearer → 200 + code.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-code?next=/cfm-admin/", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin mint: expected 200 got %d (%s)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"code"`) {
		t.Fatalf("admin mint: expected code in body, got %q", rr.Body.String())
	}

	// Scoped bearer → 403 (authenticated, but not admin).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-code?next=/cfm-admin/", nil)
	req.Header.Set("Authorization", "Bearer "+scoped.Token)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("scoped mint: expected 403 got %d (%s)", rr.Code, rr.Body.String())
	}

	// No credential (non-browser) → 401 from the middleware (path is not public).
	req = httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-code?next=/cfm-admin/", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("anon mint: expected 401 got %d (%s)", rr.Code, rr.Body.String())
	}
}

func TestEmbedAdminBootstrapSetsAdminCookieAndRedirects(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_100, 0).UTC())

	code, err := defaultEmbedAdminExchangeStore.Mint("/cfm-admin/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedAdminBootstrapEndpoint(mux)
	// admin-bootstrap is public — no auth needed to redeem a code.
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-bootstrap?code="+code+"&next=/cfm-admin/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 got %d (%s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/cfm-admin/" {
		t.Fatalf("unexpected redirect %q", got)
	}
	var found *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == embedAdminCookieName {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("expected %q cookie", embedAdminCookieName)
	}
	if found.Path != "/cfm-admin/" || !found.HttpOnly || !found.Secure {
		t.Fatalf("unexpected cookie attrs: path=%q httpOnly=%v secure=%v", found.Path, found.HttpOnly, found.Secure)
	}
	if found.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected SameSite=Lax, got %v", found.SameSite)
	}
}

func TestEmbedAdminBootstrapCodeIsSingleUse(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_200, 0).UTC())

	code, err := defaultEmbedAdminExchangeStore.Mint("/cfm-admin/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedAdminBootstrapEndpoint(mux)
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	do := func() int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-bootstrap?code="+code+"&next=/cfm-admin/", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}
	if c := do(); c != http.StatusSeeOther {
		t.Fatalf("first redeem: expected 303 got %d", c)
	}
	if c := do(); c != http.StatusUnauthorized {
		t.Fatalf("second redeem: expected 401 got %d", c)
	}
}

func TestEmbedAdminBootstrapRejectsBadNext(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_300, 0).UTC())

	mux := http.NewServeMux()
	RegisterEmbedAdminBootstrapEndpoint(mux)
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	// Off-origin next → 400.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-bootstrap?code=deadbeef&next=https://evil.example/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("off-origin next: expected 400 got %d", rr.Code)
	}

	// Valid next but not matching the code's stored next → 401.
	code, err := defaultEmbedAdminExchangeStore.Mint("/cfm-admin/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-bootstrap?code="+code+"&next=/cfm-admin/webdetector/", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("mismatched next: expected 401 got %d", rr.Code)
	}
}

// A valid admin cookie authenticates a /cfm-admin request as the admin role.
func TestEmbedAdminCookieAuthenticatesAsAdmin(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_400, 0).UTC())

	const ua = "Mozilla/5.0 (test)"
	signReq := httptest.NewRequest(http.MethodGet, "http://node.example/cfm-admin/api/v1/embed/admin-bootstrap", nil)
	signReq.Header.Set("User-Agent", ua)
	value, err := encodeEmbedAdminCookie(signReq, embedBootstrapNow().Add(embedAdminBootstrapTTL))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/cfm-admin/api/v1/__probe__", func(w http.ResponseWriter, r *http.Request) {
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		_, _ = w.Write([]byte("role=" + role))
	})
	RegisterEmbedAdminBootstrapEndpoint(mux)
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	probe := func(host, cookieVal, userAgent string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "http://"+host+"/cfm-admin/api/v1/__probe__", nil)
		req.Header.Set("User-Agent", userAgent)
		req.AddCookie(&http.Cookie{Name: embedAdminCookieName, Value: cookieVal})
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr
	}

	// Correct host + UA → admin.
	rr := probe("node.example", value, ua)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "role=admin") {
		t.Fatalf("valid cookie: expected 200 role=admin, got %d %q", rr.Code, rr.Body.String())
	}

	// Wrong host → cookie rejected → 401.
	rr = probe("other.example", value, ua)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("host mismatch: expected 401 got %d", rr.Code)
	}

	// Wrong UA → cookie rejected → 401.
	rr = probe("node.example", value, "curl/8.0")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("ua mismatch: expected 401 got %d", rr.Code)
	}

	// Tampered signature → 401.
	tampered := value[:len(value)-1] + flipLast(value)
	rr = probe("node.example", tampered, ua)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("tampered cookie: expected 401 got %d", rr.Code)
	}
}

// F4: a bare "/cfm-admin" next is canonicalized to "/cfm-admin/" at both mint
// and redeem, so it still matches and the redirect target carries the cookie's
// Path prefix.
func TestEmbedAdminBareNextCanonicalizedToTrailingSlash(t *testing.T) {
	useTestEmbedAdminCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_100_500, 0).UTC())

	mux := http.NewServeMux()
	RegisterEmbedAdminBootstrapEndpoint(mux)
	h := TokenMiddleware("admin-secret", NewTokenStore())(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-code?next=/cfm-admin", nil)
	req.Header.Set("Authorization", "Bearer admin-secret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("mint: expected 200 got %d (%s)", rr.Code, rr.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil || body.Code == "" {
		t.Fatalf("mint: bad body %q (%v)", rr.Body.String(), err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/embed/admin-bootstrap?code="+body.Code+"&next=/cfm-admin", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("redeem: expected 303 got %d (%s)", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/cfm-admin/" {
		t.Fatalf("expected Location /cfm-admin/ got %q", got)
	}
}

// F1: logout expires both embed bootstrap cookies (admin SSO + scoped).
func TestClearEmbedBootstrapCookiesExpiresBoth(t *testing.T) {
	rr := httptest.NewRecorder()
	clearEmbedBootstrapCookies(rr)
	expired := map[string]bool{}
	for _, c := range rr.Result().Cookies() {
		if c.MaxAge < 0 {
			expired[c.Name] = true
		}
	}
	if !expired[embedAdminCookieName] || !expired[embedBootstrapCookieName] {
		t.Fatalf("expected both embed cookies expired, got %+v", expired)
	}
}

func flipLast(s string) string {
	if s == "" {
		return "x"
	}
	last := s[len(s)-1]
	if last == 'A' {
		return "B"
	}
	return "A"
}
