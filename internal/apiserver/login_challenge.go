package apiserver

import (
	"encoding/json"
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
	defaultPreAuthChallengeTTL  = 5 * time.Minute
	defaultPreAuthFailureWindow = 15 * time.Minute
	preAuthChallengeQueryBypass = "__cfm_ch"
	preAuthChallengeReason      = "preauth_login"
)

type preAuthChallengeEnforcer func(ip net.IP, ttl time.Duration, reason string) error

type loginChallengePolicy struct {
	enabled          bool
	failedLoginLimit int
	window           time.Duration
	ttl              time.Duration
	enforce          preAuthChallengeEnforcer
}

var (
	loginChallengeMu sync.RWMutex
	loginChallenge   = loginChallengePolicy{
		enabled:          false,
		failedLoginLimit: 0, // 0 = challenge all interactive login GETs.
		window:           defaultPreAuthFailureWindow,
		ttl:              defaultPreAuthChallengeTTL,
	}

	failedLoginMu     sync.Mutex
	failedLoginByIP   = map[string][]time.Time{}
	failedLoginByUser = map[string][]time.Time{}
)

// SetPreAuthLoginChallengeEnabled toggles pre-auth login challenge gating.
func SetPreAuthLoginChallengeEnabled(enabled bool) {
	loginChallengeMu.Lock()
	loginChallenge.enabled = enabled
	loginChallengeMu.Unlock()
}

// SetPreAuthLoginChallengeFailedLoginPolicy optionally rate-gates challenging
// to IPs/users with repeated login failures in a time window.
// limit<=0 disables failure-count gating and challenges every interactive login GET.
func SetPreAuthLoginChallengeFailedLoginPolicy(limit int, window time.Duration) {
	if window <= 0 {
		window = defaultPreAuthFailureWindow
	}
	loginChallengeMu.Lock()
	loginChallenge.failedLoginLimit = limit
	loginChallenge.window = window
	loginChallengeMu.Unlock()
}

// SetPreAuthLoginChallengeEnforcer wires the backend challenge enforcer.
func SetPreAuthLoginChallengeEnforcer(enforcer preAuthChallengeEnforcer, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultPreAuthChallengeTTL
	}
	loginChallengeMu.Lock()
	loginChallenge.enforce = enforcer
	loginChallenge.ttl = ttl
	loginChallengeMu.Unlock()
}

func maybeHandlePreAuthLoginChallenge(w http.ResponseWriter, r *http.Request) bool {
	if !shouldEvaluatePreAuthChallenge(r) {
		return false
	}
	if sessionAllowedRequest(r) {
		return false
	}

	policy := getLoginChallengePolicy()
	if policy.failedLoginLimit > 0 {
		ip := normalizeChallengeIP(realIPFromRequest(r))
		if ip == "" || !hasFailedLoginsWithinWindow(ip, policy.failedLoginLimit, policy.window) {
			return false
		}
	}

	if policy.enforce == nil {
		return false
	}
	ip := net.ParseIP(normalizeChallengeIP(realIPFromRequest(r)))
	if ip == nil {
		return false
	}
	if err := policy.enforce(ip, policy.ttl, preAuthChallengeReason); err != nil {
		logging.LogfAPI("[apiserver] preauth challenge enforce failed ip=%s err=%v", ip.String(), err)
		return false
	}

	q := r.URL.Query()
	q.Set(preAuthChallengeQueryBypass, "1")
	nextURL := r.URL.Path
	if enc := q.Encode(); enc != "" {
		nextURL += "?" + enc
	}
	http.Redirect(w, r, nextURL, http.StatusSeeOther)
	return true
}

func shouldEvaluatePreAuthChallenge(r *http.Request) bool {
	policy := getLoginChallengePolicy()
	if !policy.enabled || policy.enforce == nil || r == nil || r.URL == nil {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}
	if r.URL.Query().Get(preAuthChallengeQueryBypass) == "1" {
		return false
	}
	if isExemptPreAuthChallengePath(r.URL.Path) {
		return false
	}
	if !isInteractiveLoginPath(r.URL.Path) {
		return false
	}
	if !strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html") {
		return false
	}
	if hasBearerAuthorization(r) {
		return false
	}
	if strings.TrimSpace(r.Header.Get("X-CFM-Actor-Assertion")) != "" {
		return false
	}
	return true
}

func getLoginChallengePolicy() loginChallengePolicy {
	loginChallengeMu.RLock()
	defer loginChallengeMu.RUnlock()
	return loginChallenge
}

func isInteractiveLoginPath(path string) bool {
	return path == "/cfm-admin/login" || path == "/login"
}

func isExemptPreAuthChallengePath(path string) bool {
	if path == "/api/v1/embed/bootstrap" || path == "/api/v1/embed/code" || path == "/api/v1/cpanel/user-info" {
		return true
	}
	if strings.HasPrefix(path, "/cfm-admin/assets/") || strings.HasPrefix(path, "/unblock/") {
		return true
	}
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/api/v1/") {
		return true
	}
	return false
}

func hasBearerAuthorization(r *http.Request) bool {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return false
	}
	parts := strings.Fields(auth)
	return len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && strings.TrimSpace(parts[1]) != ""
}

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

func recordLoginAttemptResult(r *http.Request, status int) {
	if r == nil {
		return
	}
	ip := normalizeChallengeIP(realIPFromRequest(r))
	user := strings.ToLower(strings.TrimSpace(loginAttemptUsername(r)))
	if status >= 200 && status < 300 {
		clearFailedLoginState(ip, user)
		return
	}
	if status < 400 {
		return
	}
	addFailedLoginState(ip, user, time.Now().UTC())
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

func addFailedLoginState(ip, user string, now time.Time) {
	policy := getLoginChallengePolicy()
	cutoff := now.Add(-policy.window)
	failedLoginMu.Lock()
	defer failedLoginMu.Unlock()
	if ip != "" {
		failedLoginByIP[ip] = appendPrunedFailures(failedLoginByIP[ip], cutoff, now)
	}
	if user != "" {
		failedLoginByUser[user] = appendPrunedFailures(failedLoginByUser[user], cutoff, now)
	}
}

func clearFailedLoginState(ip, user string) {
	failedLoginMu.Lock()
	defer failedLoginMu.Unlock()
	if ip != "" {
		delete(failedLoginByIP, ip)
	}
	if user != "" {
		delete(failedLoginByUser, user)
	}
}

func hasFailedLoginsWithinWindow(ip string, limit int, window time.Duration) bool {
	if ip == "" || limit <= 0 {
		return false
	}
	if window <= 0 {
		window = defaultPreAuthFailureWindow
	}
	cutoff := time.Now().UTC().Add(-window)
	failedLoginMu.Lock()
	defer failedLoginMu.Unlock()
	series := failedLoginByIP[ip]
	series = pruneFailures(series, cutoff)
	if len(series) == 0 {
		delete(failedLoginByIP, ip)
		return false
	}
	failedLoginByIP[ip] = series
	return len(series) >= limit
}

func appendPrunedFailures(series []time.Time, cutoff, now time.Time) []time.Time {
	series = pruneFailures(series, cutoff)
	series = append(series, now)
	return series
}

func pruneFailures(series []time.Time, cutoff time.Time) []time.Time {
	if len(series) == 0 {
		return series
	}
	n := 0
	for _, ts := range series {
		if ts.After(cutoff) {
			series[n] = ts
			n++
		}
	}
	return series[:n]
}

func resetPreAuthChallengeStateForTests() {
	loginChallengeMu.Lock()
	loginChallenge = loginChallengePolicy{
		enabled:          false,
		failedLoginLimit: 0,
		window:           defaultPreAuthFailureWindow,
		ttl:              defaultPreAuthChallengeTTL,
	}
	loginChallengeMu.Unlock()

	failedLoginMu.Lock()
	failedLoginByIP = map[string][]time.Time{}
	failedLoginByUser = map[string][]time.Time{}
	failedLoginMu.Unlock()
}
