package apiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginRateLimiterBackoffAndLock(t *testing.T) {
	lim := newLoginRateLimiter()
	now := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return now }

	ip := "198.51.100.10"
	acct := "alice"

	if d := lim.Evaluate(ip, acct); !d.Allow || d.Delay != 0 {
		t.Fatalf("expected first request allowed without delay, got %+v", d)
	}
	lim.ObserveResult(ip, acct, false)
	lim.ObserveResult(ip, acct, false)

	if d := lim.Evaluate(ip, acct); !d.Allow || d.Delay <= 0 {
		t.Fatalf("expected backoff delay after repeated failures, got %+v", d)
	}

	for i := 0; i < loginLockThreshold; i++ {
		lim.ObserveResult(ip, acct, false)
	}

	if d := lim.Evaluate(ip, acct); d.Allow || d.Cause != "lock" {
		t.Fatalf("expected account lock, got %+v", d)
	}

	now = now.Add(loginLockWindow + time.Second)
	if d := lim.Evaluate(ip, acct); !d.Allow {
		t.Fatalf("expected lock to expire, got %+v", d)
	}
}

func TestLoginBackoffDoesNotPublishRateLimitEvent(t *testing.T) {
	var events []APIAnomalyEvent
	unsubscribe := SubscribeAPIAnomalyEvents(func(event APIAnomalyEvent) { events = append(events, event) })
	t.Cleanup(unsubscribe)
	r := httptest.NewRequest(http.MethodPost, "https://host/login", nil)
	r.RemoteAddr = "198.51.100.40:42000"

	emitLoginLimiterAudit(r, "backoff", "198.51.100.40", "alice", 100*time.Millisecond)
	if len(events) != 0 {
		t.Fatalf("backoff published detector event: %+v", events)
	}
	emitLoginLimiterAudit(r, "throttle", "198.51.100.40", "alice", 0)
	if len(events) != 1 || events[0].Reason != "AUTH_LOGIN_RATE_LIMIT" {
		t.Fatalf("throttle events=%+v, want one AUTH_LOGIN_RATE_LIMIT", events)
	}
}

func TestProtectLoginAttemptReturnsGenericError(t *testing.T) {
	orig := globalLoginRateLimiter
	globalLoginRateLimiter = newLoginRateLimiter()
	t.Cleanup(func() { globalLoginRateLimiter = orig })

	username := "victim"
	for i := 0; i < 12; i++ {
		globalLoginRateLimiter.ObserveResult("203.0.113.9", username, false)
	}

	req := httptest.NewRequest(http.MethodPost, "https://host/login", strings.NewReader(`{"username":"victim","password":"bad"}`))
	req.RemoteAddr = "203.0.113.9:12345"
	rr := httptest.NewRecorder()

	if ok := protectLoginAttempt(rr, req, username); ok {
		t.Fatalf("expected request to be blocked by lock")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	if got := rr.Body.String(); !strings.Contains(got, "Invalid credentials") {
		t.Fatalf("unexpected response body: %s", got)
	}
}

func TestHandleLoginPostLimiterExecutesBeforeAuthVerification(t *testing.T) {
	origLimiter := globalLoginRateLimiter
	globalLoginRateLimiter = newLoginRateLimiter()
	t.Cleanup(func() { globalLoginRateLimiter = origLimiter })

	blockedUser := "blocked"
	for i := 0; i < 12; i++ {
		globalLoginRateLimiter.ObserveResult("203.0.113.22", blockedUser, false)
	}

	called := false
	stubAuthHandlers(t,
		func() http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			}
		},
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "https://host/login", strings.NewReader(`{"username":"blocked","password":"x"}`))
	req.RemoteAddr = "203.0.113.22:7777"
	rr := httptest.NewRecorder()

	handleLogin(rr, req)

	if called {
		t.Fatalf("expected auth handler not to run when limiter blocks")
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rr.Code)
	}
}
