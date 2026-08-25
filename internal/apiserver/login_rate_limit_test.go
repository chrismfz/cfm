package apiserver

import (
	"fmt"
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

func TestNormalizeLoginUsernameBoundsOverlongValues(t *testing.T) {
	if got := normalizeLoginUsername("  Alice  "); got != "alice" {
		t.Fatalf("normal username=%q, want alice", got)
	}

	prefix := strings.Repeat("A", maxNormalizedLoginUsernameBytes+1)
	got := normalizeLoginUsername("  " + prefix + "X  ")
	if len(got) > maxNormalizedLoginUsernameBytes || !strings.HasPrefix(got, "overlong-sha256:") {
		t.Fatalf("overlong normalized username is not bounded: len=%d value=%q", len(got), got)
	}
	if got != normalizeLoginUsername("  "+strings.ToLower(prefix)+"x  ") {
		t.Fatal("case/space variants must share one overlong identity")
	}
	if got != normalizeLoginUsername(got) {
		t.Fatal("overlong normalization must be idempotent")
	}
	if got == normalizeLoginUsername(prefix+"Y") {
		t.Fatal("different overlong suffixes must not collide by truncation")
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

func TestLoginLimiterAuditBoundsAttackerControlledFields(t *testing.T) {
	original := writeAuthDecisionLine
	line := ""
	writeAuthDecisionLine = func(got string) { line = got }
	t.Cleanup(func() { writeAuthDecisionLine = original })

	longAccount := strings.Repeat("a", maxAuthAuditUserBytes+100)
	longPath := "/" + strings.Repeat("p", maxAuthAuditPathBytes+100)
	longUA := strings.Repeat("u", maxAuthAuditUABytes+100)
	r := httptest.NewRequest(http.MethodPost, "https://host"+longPath, nil)
	r.Header.Set("User-Agent", longUA)
	emitLoginLimiterAudit(r, "backoff", "198.51.100.40", longAccount, 0)

	if len(line) > maxAuthAuditUserBytes+maxAuthAuditPathBytes+maxAuthAuditUABytes+512 {
		t.Fatalf("auth decision line is not bounded: len=%d", len(line))
	}
	if strings.Contains(line, longAccount) || strings.Contains(line, longPath) || strings.Contains(line, longUA) {
		t.Fatalf("auth decision retained an unbounded field: len=%d", len(line))
	}
	if strings.Count(line, "...[truncated]") != 3 {
		t.Fatalf("auth decision did not mark every truncated field: %q", line)
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

// TestLoginLimiterIgnoresForgedXFFForPerIPBucket is the Audit Step 1 item-7
// forged-XFF regression: a direct (non-loopback) client must not be able to
// evade the per-IP login limiter by rotating a spoofed X-Forwarded-For header.
//
// protectLoginAttempt keys the limiter on realIPFromRequest(r), which trusts
// forwarded identity only across the loopback edge hop (see request_identity.go
// / TestRequestPeerEntryTopologies). For a direct peer, forwarded headers are
// ignored, so every attempt from one real peer address shares ONE per-IP bucket
// regardless of the forged header. If realIPFromRequest ever regressed to trust
// a direct client's XFF, each rotated value would mint a fresh per-IP bucket and
// this test's overflow request would be allowed instead of throttled.
func TestLoginLimiterIgnoresForgedXFFForPerIPBucket(t *testing.T) {
	orig := globalLoginRateLimiter
	lim := newLoginRateLimiter()
	now := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return now }
	globalLoginRateLimiter = lim
	t.Cleanup(func() { globalLoginRateLimiter = orig })

	const attacker = "198.51.100.77:5000"

	// Fresh account names + a rotating forged XFF on every call keep the
	// per-account, per-tuple and account-lock paths out of the picture (each is
	// hit at most once), isolating the per-IP dimension. Drain the per-IP short
	// bucket exactly to capacity; all of these must be allowed.
	for i := 0; i < loginRateLimitPerIPShortTokens; i++ {
		req := httptest.NewRequest(http.MethodPost, "https://host/login", nil)
		req.RemoteAddr = attacker
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i+1))
		rr := httptest.NewRecorder()
		if ok := protectLoginAttempt(rr, req, fmt.Sprintf("acct-%d", i)); !ok {
			t.Fatalf("attempt %d from real peer %s was throttled early (code=%d)", i, attacker, rr.Code)
		}
	}

	// One more from the SAME real peer, with yet another forged XFF and a fresh
	// account, must be throttled: all attempts landed in one per-IP bucket keyed
	// by the real RemoteAddr, not by the rotating forged header.
	req := httptest.NewRequest(http.MethodPost, "https://host/login", nil)
	req.RemoteAddr = attacker
	req.Header.Set("X-Forwarded-For", "10.0.0.250")
	rr := httptest.NewRecorder()
	if ok := protectLoginAttempt(rr, req, "acct-overflow"); ok {
		t.Fatalf("forged XFF rotation evaded the per-IP limiter: overflow attempt from %s was allowed", attacker)
	}
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for throttled attempt, got %d", rr.Code)
	}

	// Control: a genuinely different real peer still has its own per-IP bucket,
	// proving the throttle above was IP-scoped rather than a global limit. Reuse
	// a forged XFF value from the drained set to show the header is not the key.
	other := httptest.NewRequest(http.MethodPost, "https://host/login", nil)
	other.RemoteAddr = "203.0.113.50:5000"
	other.Header.Set("X-Forwarded-For", "10.0.0.1")
	rrOther := httptest.NewRecorder()
	if ok := protectLoginAttempt(rrOther, other, "acct-other"); !ok {
		t.Fatalf("a different real peer was wrongly throttled (code=%d)", rrOther.Code)
	}
}

// TestLoginLimiterPerIPKeyIsRealPeerNotForgedXFF complements the rotation test:
// it proves the per-IP bucket key is the real socket peer, not the forwarded
// header and not a constant. Two distinct real peers send the IDENTICAL forged
// X-Forwarded-For; exhausting one peer's bucket must not throttle the other. A
// regression where realIPFromRequest keyed on the (shared) XFF, or returned a
// constant for every request, would collapse both peers onto one bucket and
// fail the final assertion.
func TestLoginLimiterPerIPKeyIsRealPeerNotForgedXFF(t *testing.T) {
	orig := globalLoginRateLimiter
	lim := newLoginRateLimiter()
	now := time.Unix(1_700_000_000, 0).UTC()
	lim.now = func() time.Time { return now }
	globalLoginRateLimiter = lim
	t.Cleanup(func() { globalLoginRateLimiter = orig })

	const sharedForgedXFF = "203.0.113.99"
	const peerA = "198.51.100.10:1"
	const peerB = "198.51.100.20:1"

	attempt := func(remoteAddr, account string) bool {
		req := httptest.NewRequest(http.MethodPost, "https://host/login", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", sharedForgedXFF)
		return protectLoginAttempt(httptest.NewRecorder(), req, account)
	}

	// Exhaust peer A's per-IP short bucket (fresh account per call keeps the
	// per-account/tuple paths clear). All should be allowed.
	for i := 0; i < loginRateLimitPerIPShortTokens; i++ {
		if !attempt(peerA, fmt.Sprintf("a-%d", i)) {
			t.Fatalf("draining peer A throttled early at attempt %d", i)
		}
	}
	// Peer A is now throttled...
	if attempt(peerA, "a-final") {
		t.Fatal("peer A should be throttled after draining its per-IP bucket")
	}
	// ...but peer B — same forged XFF, different real socket — still has a full
	// bucket on its very first attempt. Proves the key tracks the real peer.
	if !attempt(peerB, "b-first") {
		t.Fatal("peer B (identical forged XFF, different real peer) was wrongly throttled — per-IP key is not the real socket peer")
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
