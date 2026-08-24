package mcpserver

// ratelimit.go — a small, self-contained sliding-window rate limiter keyed by a
// string (source IP), mirroring the apiserver embed-bootstrap limiter. Used to
// throttle repeated OAuth consent submissions per IP so the consent page can't
// be hammered to brute-force MCP_TOKEN or to spam mcp_oauth_consent_denied logs.
// The token's own entropy (>=24 chars) is the primary defence; this is
// defence-in-depth + log-abuse control.

import (
	"strings"
	"sync"
	"time"
)

// Consent rate-limit budget: a legitimate operator submits the consent form once
// (a couple of times if they mistype the token), so a burst of 10 per 5-minute
// window per IP never inconveniences real use while making automated hammering
// pointless.
const (
	consentRLWindow = 5 * time.Minute
	consentRLBurst  = 10
)

type ipRateState struct {
	windowStart time.Time
	lastSeen    time.Time
	count       int
}

type ipRateLimiter struct {
	mu sync.Mutex
	m  map[string]ipRateState
}

// allow records one attempt for key and reports whether it is within burst for
// the current window. Unattributed attempts share one fail-closed bucket rather
// than bypassing the throttle. Memory is bounded by an opportunistic prune.
func (l *ipRateLimiter) allow(key string, now time.Time, window time.Duration, burst int) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		key = "unattributed"
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = make(map[string]ipRateState)
	}
	st := l.m[key]
	st.lastSeen = now
	if st.windowStart.IsZero() || now.Sub(st.windowStart) >= window {
		st.windowStart = now
		st.count = 0
	}
	st.count++
	l.m[key] = st
	if len(l.m) > 4096 {
		for k, v := range l.m {
			if now.Sub(v.lastSeen) > 3*window {
				delete(l.m, k)
			}
		}
	}
	return st.count <= burst
}
