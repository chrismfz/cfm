package apiserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	loginRateLimitShortWindow  = 15 * time.Second
	loginRateLimitMediumWindow = 5 * time.Minute

	loginRateLimitPerIPShortTokens       = 8
	loginRateLimitPerIPMediumTokens      = 80
	loginRateLimitPerAccountShortTokens  = 5
	loginRateLimitPerAccountMediumTokens = 30
	loginRateLimitPerTupleShortTokens    = 4
	loginRateLimitPerTupleMediumTokens   = 20

	loginLockThreshold = 10
	loginLockWindow    = 10 * time.Minute
)

type loginRateLimitDecision struct {
	Allow bool
	Delay time.Duration
	Cause string
}

type loginRateLimiter struct {
	now func() time.Time

	mu         sync.Mutex
	ipState    map[string]*bucketPair
	acctState  map[string]*accountLimiterState
	tupleState map[string]*bucketPair
}

type accountLimiterState struct {
	buckets     *bucketPair
	failures    int
	lastFailure time.Time
	lockUntil   time.Time
}

type bucketPair struct {
	short    *tokenBucket
	medium   *tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	capacity float64
	rate     float64
	tokens   float64
	last     time.Time
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{
		now:        time.Now,
		ipState:    map[string]*bucketPair{},
		acctState:  map[string]*accountLimiterState{},
		tupleState: map[string]*bucketPair{},
	}
}

func newBucket(capacity int, window time.Duration, now time.Time) *tokenBucket {
	if capacity <= 0 {
		capacity = 1
	}
	if window <= 0 {
		window = time.Second
	}
	return &tokenBucket{capacity: float64(capacity), rate: float64(capacity) / window.Seconds(), tokens: float64(capacity), last: now}
}

func (b *tokenBucket) allow(now time.Time) bool {
	if now.After(b.last) {
		b.tokens += now.Sub(b.last).Seconds() * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func (l *loginRateLimiter) Evaluate(ip, account string) loginRateLimitDecision {
	now := l.now().UTC()
	account = normalizeLoginUsername(account)
	ip = normalizeChallengeIP(ip)
	tuple := loginIPAccountTuple(ip, account)

	l.mu.Lock()
	defer l.mu.Unlock()

	l.prune(now)

	if account != "" {
		acct := l.getOrCreateAccount(account, now)
		if now.Before(acct.lockUntil) {
			return loginRateLimitDecision{Allow: false, Cause: "lock"}
		}
	}

	if !l.getOrCreateIP(ip, now).allow(now) {
		return loginRateLimitDecision{Allow: false, Cause: "throttle"}
	}
	if account != "" {
		if !l.getOrCreateAccount(account, now).buckets.allow(now) {
			return loginRateLimitDecision{Allow: false, Cause: "throttle"}
		}
	}
	if tuple != "" {
		if !l.getOrCreateTuple(tuple, now).allow(now) {
			return loginRateLimitDecision{Allow: false, Cause: "throttle"}
		}
	}

	delay := time.Duration(0)
	if account != "" {
		acct := l.getOrCreateAccount(account, now)
		delay = adaptiveBackoff(acct.failures, now.Sub(acct.lastFailure))
	}
	return loginRateLimitDecision{Allow: true, Delay: delay, Cause: "allow"}
}

func (l *loginRateLimiter) ObserveResult(ip, account string, success bool) {
	now := l.now().UTC()
	account = normalizeLoginUsername(account)

	l.mu.Lock()
	defer l.mu.Unlock()

	if account == "" {
		return
	}
	acct := l.getOrCreateAccount(account, now)
	if success {
		acct.failures = 0
		acct.lastFailure = time.Time{}
		acct.lockUntil = time.Time{}
		return
	}
	acct.failures++
	acct.lastFailure = now
	if acct.failures >= loginLockThreshold {
		acct.lockUntil = now.Add(loginLockWindow)
	}
}

func (l *loginRateLimiter) getOrCreateIP(ip string, now time.Time) *bucketPair {
	if ip == "" {
		ip = "unknown"
	}
	if st, ok := l.ipState[ip]; ok {
		st.lastSeen = now
		return st
	}
	st := &bucketPair{
		short:    newBucket(loginRateLimitPerIPShortTokens, loginRateLimitShortWindow, now),
		medium:   newBucket(loginRateLimitPerIPMediumTokens, loginRateLimitMediumWindow, now),
		lastSeen: now,
	}
	l.ipState[ip] = st
	return st
}

func (l *loginRateLimiter) getOrCreateAccount(account string, now time.Time) *accountLimiterState {
	if st, ok := l.acctState[account]; ok {
		st.buckets.lastSeen = now
		return st
	}
	st := &accountLimiterState{buckets: &bucketPair{
		short:    newBucket(loginRateLimitPerAccountShortTokens, loginRateLimitShortWindow, now),
		medium:   newBucket(loginRateLimitPerAccountMediumTokens, loginRateLimitMediumWindow, now),
		lastSeen: now,
	}}
	l.acctState[account] = st
	return st
}

func (l *loginRateLimiter) getOrCreateTuple(tuple string, now time.Time) *bucketPair {
	if st, ok := l.tupleState[tuple]; ok {
		st.lastSeen = now
		return st
	}
	st := &bucketPair{
		short:    newBucket(loginRateLimitPerTupleShortTokens, loginRateLimitShortWindow, now),
		medium:   newBucket(loginRateLimitPerTupleMediumTokens, loginRateLimitMediumWindow, now),
		lastSeen: now,
	}
	l.tupleState[tuple] = st
	return st
}

func (p *bucketPair) allow(now time.Time) bool {
	if !p.short.allow(now) {
		return false
	}
	if !p.medium.allow(now) {
		return false
	}
	p.lastSeen = now
	return true
}

func (l *loginRateLimiter) prune(now time.Time) {
	cutoff := now.Add(-(loginRateLimitMediumWindow + loginLockWindow))
	for k, st := range l.ipState {
		if st.lastSeen.Before(cutoff) {
			delete(l.ipState, k)
		}
	}
	for k, st := range l.tupleState {
		if st.lastSeen.Before(cutoff) {
			delete(l.tupleState, k)
		}
	}
	for k, st := range l.acctState {
		if st.buckets.lastSeen.Before(cutoff) && now.After(st.lockUntil) && st.failures == 0 {
			delete(l.acctState, k)
		}
	}
}

func normalizeLoginUsername(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func loginIPAccountTuple(ip, account string) string {
	if ip == "" || account == "" {
		return ""
	}
	return ip + "|" + account
}

func adaptiveBackoff(failures int, sinceLast time.Duration) time.Duration {
	if failures <= 1 {
		return 0
	}
	if sinceLast > 5*time.Minute {
		return 0
	}
	levels := []time.Duration{100 * time.Millisecond, 250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second}
	idx := failures - 2
	if idx >= len(levels) {
		idx = len(levels) - 1
	}
	if idx < 0 {
		idx = 0
	}
	return levels[idx]
}

var globalLoginRateLimiter = newLoginRateLimiter()

func protectLoginAttempt(w http.ResponseWriter, r *http.Request, username string) bool {
	ip := normalizeChallengeIP(realIPFromRequest(r))
	account := normalizeLoginUsername(username)
	decision := globalLoginRateLimiter.Evaluate(ip, account)
	switch {
	case !decision.Allow && decision.Cause == "lock":
		emitLoginLimiterAudit(r, "lock", ip, account, 0)
		writeGenericLoginFailure(w)
		return false
	case !decision.Allow:
		emitLoginLimiterAudit(r, "throttle", ip, account, 0)
		writeGenericLoginFailure(w)
		return false
	case decision.Delay > 0:
		emitLoginLimiterAudit(r, "backoff", ip, account, decision.Delay)
		if !sleepWithContext(r.Context(), decision.Delay) {
			return false
		}
	}
	return true
}

func recordLoginLimiterResult(r *http.Request, username string, status int) {
	if r == nil {
		return
	}
	ip := normalizeChallengeIP(realIPFromRequest(r))
	account := normalizeLoginUsername(username)
	success := status >= 200 && status < 300
	globalLoginRateLimiter.ObserveResult(ip, account, success)
}

func writeGenericLoginFailure(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"Invalid credentials."}`))
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func emitLoginLimiterAudit(r *http.Request, action, ip, account string, delay time.Duration) {
	method := ""
	path := ""
	ua := ""
	if r != nil {
		method = r.Method
		path = r.URL.Path
		ua = strings.TrimSpace(r.UserAgent())
	}
	if account == "" {
		account = "unknown"
	}
	detail := ""
	if delay > 0 {
		detail = fmt.Sprintf(" delay=%s", delay)
	}
	logging.LogfAPI("[apiserver] event=login_rate_limit action=%s src_ip=%s account=%s method=%s path=%q ua=%q%s", action, ip, account, method, path, ua, detail)
	publishAPIAnomalyEvent(APIAnomalyEvent{
		When:      time.Now(),
		Source:    "apiserver",
		Reason:    "login_rate_limit_" + action,
		Signal:    "login_rate_limit_" + action,
		Scope:     "login",
		Count:     1,
		SrcIP:     ip,
		Method:    method,
		Path:      path,
		Status:    http.StatusTooManyRequests,
		UserAgent: ua,
	})
}

// ── helpers shared with the login rate limiter (moved from the retired
//    pre-auth login-challenge subsystem, edge-unification Phase 1b) ──────────

func normalizeChallengeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, ",") {
		raw = strings.TrimSpace(strings.Split(raw, ",")[0])
	}
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	return ""
}

func loginAttemptUsername(r *http.Request) string {
	if r == nil || r.Body == nil {
		return ""
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return ""
	}
	r.Body.Close()
	r.Body = io.NopCloser(strings.NewReader(string(buf)))
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]))
	switch ct {
	case "application/json", "text/json", "":
		var payload struct {
			Username string `json:"username"`
		}
		if err := json.Unmarshal(buf, &payload); err == nil {
			return payload.Username
		}
	case "application/x-www-form-urlencoded":
		vals, err := url.ParseQuery(string(buf))
		if err == nil {
			return vals.Get("username")
		}
	}
	return ""
}
