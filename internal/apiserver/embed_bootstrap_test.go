package apiserver

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

func useTestEmbedCookieSigningKey(t *testing.T) {
	t.Helper()
	prev := embedCookieSigningKeyProvider
	embedCookieSigningKeyProvider = func() ([]byte, error) {
		return []byte("0123456789abcdef0123456789abcdef"), nil
	}
	t.Cleanup(func() {
		embedCookieSigningKeyProvider = prev
	})
}

func useTestEmbedClock(t *testing.T, start time.Time) *time.Time {
	t.Helper()
	now := start
	prev := embedBootstrapNow
	embedBootstrapNow = func() time.Time { return now }
	embedBootstrapRateLimiter.reset()
	t.Cleanup(func() {
		embedBootstrapNow = prev
		embedBootstrapRateLimiter.reset()
	})
	return &now
}

func TestEmbedBootstrapRejectsInvalidNext(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_000, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=https://evil.example/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestEmbedBootstrapValidConsumeSetsCookieAndRedirects(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_100, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	if got := rr.Header().Get("Location"); got != "/cfm-admin/webdetector/controls/" {
		t.Fatalf("unexpected redirect location %q", got)
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected cookie to be set")
	}
	found := false
	for _, c := range cookies {
		if c.Name == embedBootstrapCookieName {
			found = true
			if c.Path != "/cfm-admin/" {
				t.Fatalf("unexpected cookie path: %q", c.Path)
			}
			if !c.HttpOnly {
				t.Fatalf("expected HttpOnly cookie")
			}
		}
	}
	if !found {
		t.Fatalf("expected %q cookie", embedBootstrapCookieName)
	}
}

func TestEmbedBootstrapForwardsExpectedParentOrigin(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_150, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	target := "/api/v1/embed/bootstrap?code=" + code +
		"&next=%2Fcfm-admin%2Fwebdetector%2Fcontrols%2F" +
		"&cfmExpectedOrigin=https%3A%2F%2Fparent.example%3A2083"
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d", http.StatusSeeOther, rr.Code)
	}
	got := rr.Header().Get("Location")
	if !strings.Contains(got, "cfmExpectedOrigin=https%3A%2F%2Fparent.example%3A2083") {
		t.Fatalf("expected Location to carry cfmExpectedOrigin, got %q", got)
	}
	if !strings.HasPrefix(got, "/cfm-admin/webdetector/controls/?") {
		t.Fatalf("expected redirect to stay on next path, got %q", got)
	}
}

func TestEmbedBootstrapDropsInvalidExpectedParentOrigin(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_160, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	cases := []string{
		"",
		"javascript:alert(1)",
		"parent.example",
		"ftp://parent.example",
		"https://",
	}

	for _, raw := range cases {
		embedBootstrapRateLimiter.reset()
		code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}

		mux := http.NewServeMux()
		RegisterEmbedBootstrapEndpoint(mux, store)
		h := TokenMiddleware("admin-secret", store)(mux)

		target := "/api/v1/embed/bootstrap?code=" + code +
			"&next=%2Fcfm-admin%2Fwebdetector%2Fcontrols%2F" +
			"&cfmExpectedOrigin=" + url.QueryEscape(raw)
		req := httptest.NewRequest(http.MethodGet, target, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if rr.Code != http.StatusSeeOther {
			t.Fatalf("case %q: expected %d got %d", raw, http.StatusSeeOther, rr.Code)
		}
		if got := rr.Header().Get("Location"); got != "/cfm-admin/webdetector/controls/" {
			t.Fatalf("case %q: expected unchanged redirect, got %q", raw, got)
		}
	}
}

func TestEmbedBootstrapRejectsReplayCode(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_200, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	firstReq := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	firstRR := httptest.NewRecorder()
	h.ServeHTTP(firstRR, firstReq)
	if firstRR.Code != http.StatusSeeOther {
		t.Fatalf("expected first consume %d got %d", http.StatusSeeOther, firstRR.Code)
	}

	replayReq := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	replayRR := httptest.NewRecorder()
	h.ServeHTTP(replayRR, replayReq)
	if replayRR.Code != http.StatusUnauthorized {
		t.Fatalf("expected replay %d got %d", http.StatusUnauthorized, replayRR.Code)
	}
}

func TestEmbedBootstrapRejectsExpiredCode(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_300, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", -1*time.Second)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestEmbedBootstrapRejectsWrongPathForCode(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedClock(t, time.Unix(1_700_000_400, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestEmbedCodeRateLimitBurstAndRecovery(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	now := useTestEmbedClock(t, time.Unix(1_700_001_000, 0).UTC())
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)

	makeReq := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/code?next=/cfm-admin/webdetector/controls/", nil)
		req.RemoteAddr = "127.0.0.1:12345"
		req.Header.Set("X-Forwarded-For", "203.0.113.5")
		req.Header.Set("Authorization", "Bearer "+st.Token)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		return rr
	}

	for i := 0; i < embedCodeRLBurst; i++ {
		rr := makeReq()
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d expected 200, got %d body=%s", i+1, rr.Code, rr.Body.String())
		}
	}

	reject := makeReq()
	if reject.Code != http.StatusTooManyRequests {
		t.Fatalf("expected burst rejection 429, got %d", reject.Code)
	}

	*now = now.Add(embedCodeRLWindow + time.Second)
	recovered := makeReq()
	if recovered.Code != http.StatusOK {
		t.Fatalf("expected recovery to 200, got %d body=%s", recovered.Code, recovered.Body.String())
	}
}

func TestTokenMiddlewareAllowsScopedBootstrapCookieForCfmAdminHTML(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	called := false
	h := TokenMiddleware("admin-secret", store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
		if scope == nil {
			t.Fatalf("expected scoped context from bootstrap cookie")
		}
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleScoped {
			t.Fatalf("expected scoped role marker, got %q", role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	req.Header.Set("Accept", "text/html")
	cookieValue, err := encodeEmbedCookie(req, st.ID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: cookieValue})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be reached")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestTokenMiddlewareAllowsEmbeddedScopedBootstrapCookieForCfmAdminPath(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	called := false
	h := TokenMiddleware("admin-secret", store)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		scope, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
		if scope == nil {
			t.Fatalf("expected scoped context from bootstrap cookie")
		}
		authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
		if !authn {
			t.Fatalf("expected authenticated context marker")
		}
		role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
		if role != webdet.CtxRoleScoped {
			t.Fatalf("expected scoped role marker, got %q", role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	req.Header.Set("X-CFM-Embedded", "cpanel")
	cookieValue, err := encodeEmbedCookie(req, st.ID, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: cookieValue})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !called {
		t.Fatalf("expected handler to be reached")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected %d got %d", http.StatusOK, rr.Code)
	}
}

func TestDecodeEmbedCookieRejectsTamperedSignature(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/", nil)
	cookieValue, err := encodeEmbedCookie(req, "tok_abcd", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	parts := strings.Split(cookieValue, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected cookie format: %q", cookieValue)
	}
	parts[1] = "tampered"
	ok, _, _, _ := decodeEmbedCookie(req, strings.Join(parts, "."))
	if ok {
		t.Fatalf("expected tampered cookie to be rejected")
	}
}

func TestDecodeEmbedCookieLegacyCutoff(t *testing.T) {
	prev := embedLegacyCookieCutoff
	embedLegacyCookieCutoff = time.Now().Add(-time.Minute)
	t.Cleanup(func() { embedLegacyCookieCutoff = prev })
	raw := base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(time.Now().Add(time.Minute).Unix(), 10) + ":legacytoken"))
	ok, _, _, _ := decodeEmbedCookie(nil, raw)
	if ok {
		t.Fatalf("expected legacy cookie after cutoff to be rejected")
	}
}

func TestEmbedBootstrapFailsWhenSigningKeyUnavailable(t *testing.T) {
	prev := embedCookieSigningKeyProvider
	embedCookieSigningKeyProvider = func() ([]byte, error) {
		return nil, errors.New("boom")
	}
	t.Cleanup(func() { embedCookieSigningKeyProvider = prev })

	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected %d got %d", http.StatusInternalServerError, rr.Code)
	}
}

// findEmbedSetCookie returns the Set-Cookie header for the embed bootstrap
// cookie, or "" if none was issued on this response.
func findEmbedSetCookie(h http.Header) string {
	for _, v := range h.Values("Set-Cookie") {
		if strings.HasPrefix(v, embedBootstrapCookieName+"=") {
			return v
		}
	}
	return ""
}

func TestEmbedCookieRollingRenewalNearExpiry(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	// Issue a cookie with only 30s of lifetime left (< 300s threshold).
	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	cookieValue, err := encodeEmbedCookie(req, st.ID, time.Now().Add(30*time.Second))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: cookieValue})

	rr := httptest.NewRecorder()
	ctx, ok := embedScopedContextFromCookie(rr, req, store)
	if !ok || ctx == nil {
		t.Fatalf("expected cookie to authenticate")
	}
	setCookie := findEmbedSetCookie(rr.Header())
	if setCookie == "" {
		t.Fatalf("expected rolling renewal Set-Cookie header, got none")
	}
	if !strings.Contains(setCookie, "Path=/cfm-admin/") {
		t.Fatalf("renewed cookie missing Path attribute: %q", setCookie)
	}
	if !strings.Contains(setCookie, "HttpOnly") {
		t.Fatalf("renewed cookie missing HttpOnly: %q", setCookie)
	}
	if !strings.Contains(setCookie, "Secure") {
		t.Fatalf("renewed cookie missing Secure: %q", setCookie)
	}
}

func TestEmbedCookieRollingRenewalSkippedWhenFresh(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	// Fresh cookie: full TTL remaining, well above renew threshold.
	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	cookieValue, err := encodeEmbedCookie(req, st.ID, time.Now().Add(embedBootstrapTTL))
	if err != nil {
		t.Fatalf("encode cookie: %v", err)
	}
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: cookieValue})

	rr := httptest.NewRecorder()
	_, ok := embedScopedContextFromCookie(rr, req, store)
	if !ok {
		t.Fatalf("expected fresh cookie to authenticate")
	}
	if got := findEmbedSetCookie(rr.Header()); got != "" {
		t.Fatalf("did not expect renewal Set-Cookie on fresh cookie, got %q", got)
	}
}

func TestEmbedCookieRollingRenewalSkippedForLegacyCookie(t *testing.T) {
	// Legacy unsigned cookies must not be re-issued; they should phase out at
	// embedLegacyCookieCutoff.
	useTestEmbedCookieSigningKey(t)
	prevCutoff := embedLegacyCookieCutoff
	embedLegacyCookieCutoff = time.Now().Add(time.Hour)
	t.Cleanup(func() { embedLegacyCookieCutoff = prevCutoff })

	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)

	raw := base64.RawURLEncoding.EncodeToString([]byte(
		strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10) + ":" + st.Token,
	))
	req := httptest.NewRequest(http.MethodGet, "https://host/cfm-admin/webdetector/controls/", nil)
	req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: raw})

	rr := httptest.NewRecorder()
	_, ok := embedScopedContextFromCookie(rr, req, store)
	if !ok {
		t.Fatalf("expected legacy cookie to authenticate before cutoff")
	}
	if got := findEmbedSetCookie(rr.Header()); got != "" {
		t.Fatalf("did not expect renewal Set-Cookie for legacy cookie, got %q", got)
	}
}

func TestEmbedBootstrapTTLMatchesCookieMaxAge(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.com"}, nil, nil, "viewer", "embed", time.Hour)
	code, err := defaultEmbedExchangeStore.Mint(st.Token, "/cfm-admin/webdetector/controls/", time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	mux := http.NewServeMux()
	RegisterEmbedBootstrapEndpoint(mux, store)
	h := TokenMiddleware("admin-secret", store)(mux)

	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/embed/bootstrap?code="+code+"&next=/cfm-admin/webdetector/controls/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected %d got %d body=%s", http.StatusSeeOther, rr.Code, rr.Body.String())
	}
	setCookie := findEmbedSetCookie(rr.Header())
	if setCookie == "" {
		t.Fatalf("expected Set-Cookie on bootstrap response")
	}
	wantMaxAge := "Max-Age=" + strconv.Itoa(int(embedBootstrapTTL.Seconds()))
	if !strings.Contains(setCookie, wantMaxAge) {
		t.Fatalf("expected Set-Cookie to contain %q, got %q", wantMaxAge, setCookie)
	}
}
