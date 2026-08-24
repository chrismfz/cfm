package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type opaqueResponseWriter struct{ http.ResponseWriter }

func captureAuthAuditLines(t *testing.T) *[]string {
	t.Helper()
	original := writeAuthAuditLine
	lines := []string{}
	writeAuthAuditLine = func(line string) { lines = append(lines, line) }
	t.Cleanup(func() { writeAuthAuditLine = original })
	return &lines
}

func TestTokenAuthAuditIsSingleLineAndNeverLogsToken(t *testing.T) {
	lines := captureAuthAuditLines(t)
	const secret = "wrong-bearer-secret"
	events := []APIAnomalyEvent{}
	unsubscribe := SubscribeAPIAnomalyEvents(func(ev APIAnomalyEvent) { events = append(events, ev) })
	t.Cleanup(unsubscribe)

	h := TokenMiddleware("admin-secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("invalid explicit token must not reach the handler")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", rr.Code)
	}
	if len(*lines) != 1 {
		t.Fatalf("auth audit lines=%d, want exactly one: %v", len(*lines), *lines)
	}
	line := (*lines)[0]
	if strings.Contains(line, secret) || strings.ContainsAny(line, "\r\n") {
		t.Fatalf("unsafe auth audit line: %q", line)
	}
	for _, want := range []string{"event=auth_attempt", "kind=token", "result=invalid", "auth_mech=unknown", "status=401"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q missing %q", line, want)
		}
	}
	if len(events) != 1 || events[0].Reason != "AUTH_TOKEN_INVALID" {
		t.Fatalf("structured events=%+v, want one AUTH_TOKEN_INVALID", events)
	}
}

func TestScopedTokenAuthAuditUsesSafeTokenID(t *testing.T) {
	lines := captureAuthAuditLines(t)
	store := NewTokenStore()
	st := store.Issue([]string{"example.test"}, nil, nil, "viewer", "panel-user", time.Hour)
	if st == nil {
		t.Fatal("token issue failed")
	}
	h := TokenMiddleware("admin-secret", store)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://host/api/v1/webdet/vhosts", nil)
	req.Header.Set("Authorization", "Bearer "+st.Token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if len(*lines) != 1 {
		t.Fatalf("auth audit lines=%d, want one", len(*lines))
	}
	line := (*lines)[0]
	if !strings.Contains(line, "auth_mech=token_scoped") || !strings.Contains(line, "token_id="+st.ID) {
		t.Fatalf("missing scoped token identity: %q", line)
	}
	if strings.Contains(line, st.Token) {
		t.Fatalf("raw scoped token leaked: %q", line)
	}
}

func TestMalformedExplicitAuthorizationDoesNotFallBackToSession(t *testing.T) {
	lines := captureAuthAuditLines(t)
	originalSessionAllowed := sessionAllowedRequest
	sessionAllowedRequest = func(*http.Request) bool { return true }
	t.Cleanup(func() { sessionAllowedRequest = originalSessionAllowed })

	h := TokenMiddleware("admin-secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("malformed explicit authorization must not fall back to session")
	}))
	req := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
	req.Header.Set("Authorization", "Basic attacker-controlled")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized || len(*lines) != 1 || !strings.Contains((*lines)[0], "result=malformed") {
		t.Fatalf("status=%d lines=%v, want one malformed 401 audit", rr.Code, *lines)
	}
	if strings.Contains((*lines)[0], "attacker-controlled") {
		t.Fatalf("authorization material leaked: %q", (*lines)[0])
	}
}

func TestExplicitTokenOnPublicPathIsStillAudited(t *testing.T) {
	lines := captureAuthAuditLines(t)
	h := TokenMiddleware("admin-secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("invalid explicit token on public path must not reach handler")
	}))
	r := httptest.NewRequest(http.MethodGet, "https://host/login", nil)
	r.Header.Set("Authorization", "Bearer wrong-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || len(*lines) != 1 || !strings.Contains((*lines)[0], "result=invalid") {
		t.Fatalf("status=%d lines=%v, want one invalid public-path token audit", w.Code, *lines)
	}
}

func TestLoginAndMFAAuditDoNotLogSubmittedSecrets(t *testing.T) {
	lines := captureAuthAuditLines(t)
	originalLimiter := globalLoginRateLimiter
	globalLoginRateLimiter = newLoginRateLimiter()
	t.Cleanup(func() { globalLoginRateLimiter = originalLimiter })
	stubAuthHandlers(t,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
			}
		},
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}
		},
	)
	withMFALoginVerifyEnabled(t, true)

	loginReq := httptest.NewRequest(http.MethodPost, "https://host/login", strings.NewReader(`{"username":"alice","password":"never-log-this-password"}`))
	loginRR := httptest.NewRecorder()
	handleLogin(loginRR, loginReq)
	mfaReq := httptest.NewRequest(http.MethodPost, "https://host/login/verify", strings.NewReader(`{"method":"totp","code":"654321"}`))
	mfaRR := httptest.NewRecorder()
	handleLoginVerify(mfaRR, mfaReq)

	if len(*lines) != 2 {
		t.Fatalf("auth audit lines=%d, want login + MFA: %v", len(*lines), *lines)
	}
	joined := strings.Join(*lines, "\n")
	if strings.Contains(joined, "never-log-this-password") || strings.Contains(joined, "654321") {
		t.Fatalf("submitted auth secret leaked: %q", joined)
	}
	if !strings.Contains((*lines)[0], "kind=login result=fail") || !strings.Contains((*lines)[1], "kind=mfa_totp result=success") {
		t.Fatalf("unexpected auth audit lines: %v", *lines)
	}
}

func TestAPIAnomalySubscriptionCanBeRemoved(t *testing.T) {
	called := 0
	unsubscribe := SubscribeAPIAnomalyEvents(func(APIAnomalyEvent) { called++ })
	publishAPIAnomalyEvent(APIAnomalyEvent{})
	unsubscribe()
	publishAPIAnomalyEvent(APIAnomalyEvent{})
	if called != 1 {
		t.Fatalf("subscriber called %d times, want once before unsubscribe", called)
	}
}

func TestInternalMCPDispatchSuppressesTokenAudit(t *testing.T) {
	lines := captureAuthAuditLines(t)
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/system/status", nil)
	r = r.WithContext(suppressAuthAudit(r.Context()))
	auditAuthAttempt(r, authAttemptAudit{Kind: "token", Result: "success", AuthMech: "token_admin", Status: http.StatusOK})
	if len(*lines) != 0 {
		t.Fatalf("internal dispatch produced auth audit: %v", *lines)
	}
}

func TestDirectAuthEventDedupSurvivesWriterWrapAndRequestClone(t *testing.T) {
	_ = captureAuthAuditLines(t)
	originalClassifier := globalAPIAbuseSignalClassifier
	globalAPIAbuseSignalClassifier = newAPIAbuseSignalClassifier()
	t.Cleanup(func() { globalAPIAbuseSignalClassifier = originalClassifier })
	var events []APIAnomalyEvent
	unsubscribe := SubscribeAPIAnomalyEvents(func(event APIAnomalyEvent) { events = append(events, event) })
	t.Cleanup(unsubscribe)

	auth := TokenMiddleware("admin-secret", NewTokenStore())(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("invalid token reached handler")
	}))
	cloneAndWrap := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth.ServeHTTP(opaqueResponseWriter{ResponseWriter: w}, r.Clone(r.Context()))
	})
	h := APISecurityAnomalyMiddleware(cloneAndWrap)
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest(http.MethodGet, "https://host/api/v1/system/status", nil)
		r.RemoteAddr = "198.51.100.55:42000"
		r.Header.Set("Authorization", "Bearer wrong-secret")
		r.Header.Set("User-Agent", "dedup-test")
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if len(events) != 5 {
		t.Fatalf("events=%+v, want exactly five direct auth events", events)
	}
	for _, event := range events {
		if event.Reason != "AUTH_TOKEN_INVALID" {
			t.Fatalf("generic classifier double-counted direct event: %+v", events)
		}
	}
}
