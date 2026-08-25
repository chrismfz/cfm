package apiserver

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// Control-plane rate limiting (audit Step 8). Bounds already-authenticated abuse
// per identity class × route class, keyed by a non-secret subject so one caller
// cannot drain another's bucket. Enforcing by default with honestly-high ceilings
// (secure-fleet posture: protects on upgrade with no cfm.conf change); every trip
// is logged/API-visible; a trip is a self-healing 429 + alert, NEVER an nft block
// of the caller's IP (the admin token is the fleet controller). See
// docs/security/control-plane-rate-limiting.md.

type rateLimitMode int

const (
	rlEnforce rateLimitMode = iota // default
	rlShadow                       // log/observe only, serve normally
	rlOff                          // disabled
)

func parseRateLimitMode(s string) rateLimitMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "shadow", "observe", "log":
		return rlShadow
	case "off", "0", "disabled", "disable", "none":
		return rlOff
	default: // "", "enforce", "on", "1", "block"
		return rlEnforce
	}
}

// routeClass groups endpoints by cost so heavy/privileged/streaming routes get
// tighter budgets than cheap reads.
type routeClass string

const (
	rcCheapRead       routeClass = "cheap_read"
	rcNormalRead      routeClass = "normal_read"
	rcHeavyRead       routeClass = "heavy_read"
	rcWrite           routeClass = "write"
	rcPrivilegedWrite routeClass = "privileged_write"
	rcCaptureStream   routeClass = "capture_stream"
)

func isWriteMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// classifyRoute maps (method, path) to a route class. Pure and allocation-light;
// order matters (most specific first). Unknown routes fall back to normal_read /
// write by method so a new endpoint is always bounded by *something*.
func classifyRoute(method, path string) routeClass {
	p := strings.ToLower(path)
	write := isWriteMethod(method)

	switch {
	// Streaming / capture / profiling — already admin-only after R02; tightest.
	case strings.HasPrefix(p, "/debug/pprof"), strings.Contains(p, "/capture"),
		strings.Contains(p, "/stream"), strings.Contains(p, "/tail"):
		return rcCaptureStream

	// Privileged writes: firewall enforcement, token/auth mutation, config changes.
	case write && (strings.Contains(p, "/firewall/") ||
		strings.Contains(p, "/block") || strings.Contains(p, "/unblock") ||
		strings.Contains(p, "/auth/token") || strings.Contains(p, "/tokens") ||
		strings.Contains(p, "/config") || strings.Contains(p, "/kernsec") ||
		strings.Contains(p, "/lsm")):
		return rcPrivilegedWrite

	case write:
		return rcWrite

	// Expensive reads — checked BEFORE cheap so a heavy endpoint reachable by prefix
	// can't be downgraded to the loose cheap bucket by an attacker-appended trailing
	// segment (e.g. /…/drilldown/status).
	case strings.Contains(p, "/search") || strings.Contains(p, "/history") ||
		strings.Contains(p, "/forensics") || strings.Contains(p, "/drilldown") ||
		strings.Contains(p, "/whats") || strings.Contains(p, "/logs"):
		return rcHeavyRead

	// Cheap, high-frequency reads (health/status polling). Anchored to specific
	// endpoints, not a generic "/status" suffix, so an arbitrary path can't claim the
	// loosest bucket.
	case strings.Contains(p, "healthz") || strings.HasSuffix(p, "/ping") ||
		strings.HasSuffix(p, "/system/status") ||
		strings.HasSuffix(p, "/livez") || strings.HasSuffix(p, "/readyz"):
		return rcCheapRead

	default:
		return rcNormalRead
	}
}

// identityTier collapses the four authn classes into two ceiling tiers: the
// interactive admin and the fleet controller (token_admin / session_cookie) are
// trusted and get much higher ceilings than the per-vhost scoped/embed viewers.
func identityTier(mech authnMechanism) string {
	switch mech {
	case authnMechanismTokenAdmin, authnMechanismSession:
		return "trusted"
	default: // token_scoped, embed_bootstrap_cookie, unknown
		return "scoped"
	}
}

type rlCeiling struct {
	capacity int           // bucket size = max burst
	window   time.Duration // capacity refills over this window (rate = capacity/window)
}

// ceilings are honestly high — sized to catch orders-of-magnitude runaway, never
// legitimate fan-out. Overridable by a single global scale (RATE_LIMIT_SCALE) so an
// operator who sees a legitimate trip in the log/API can widen without a code change.
var rlCeilings = map[string]map[routeClass]rlCeiling{
	"trusted": {
		rcCheapRead:       {capacity: 1200, window: 10 * time.Second}, // 120/s sustained
		rcNormalRead:      {capacity: 1800, window: 60 * time.Second}, // 30/s sustained, 1800 burst
		rcHeavyRead:       {capacity: 300, window: 60 * time.Second},
		rcWrite:           {capacity: 600, window: 60 * time.Second},
		rcPrivilegedWrite: {capacity: 240, window: 60 * time.Second},
		rcCaptureStream:   {capacity: 60, window: 60 * time.Second},
	},
	"scoped": {
		rcCheapRead:       {capacity: 600, window: 10 * time.Second},
		rcNormalRead:      {capacity: 600, window: 60 * time.Second}, // 10/s sustained
		rcHeavyRead:       {capacity: 120, window: 60 * time.Second},
		rcWrite:           {capacity: 120, window: 60 * time.Second},
		rcPrivilegedWrite: {capacity: 60, window: 60 * time.Second}, // scoped shouldn't reach these
		rcCaptureStream:   {capacity: 20, window: 60 * time.Second},
	},
}

func ceilingFor(tier string, rc routeClass, scale float64) rlCeiling {
	c := rlCeilings[tier][rc]
	if scale > 0 && scale != 1 {
		c.capacity = int(float64(c.capacity) * scale)
	}
	if c.capacity <= 0 {
		c.capacity = 1
	}
	return c
}

// retryAfter reports how long until this bucket has a token again (0 if it has one
// now). Called after allow() returns false; allow() has already refilled.
func (b *tokenBucket) retryAfter() time.Duration {
	if b.tokens >= 1 || b.rate <= 0 {
		return 0
	}
	return time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
}

type rlEntry struct {
	bucket   *tokenBucket
	lastSeen time.Time
}

// rateLimiter is one bounded store of per-(identity,route) token buckets.
type rateLimiter struct {
	now     func() time.Time
	scale   float64
	maxKeys int

	mu        sync.Mutex
	buckets   map[string]*rlEntry
	lastPrune time.Time
}

const (
	rlPruneEvery = 60 * time.Second
	rlIdleTTL    = 10 * time.Minute
	rlMaxKeys    = 50000
)

func newRateLimiter(scale float64) *rateLimiter {
	return &rateLimiter{
		now:     time.Now,
		scale:   scale,
		maxKeys: rlMaxKeys,
		buckets: map[string]*rlEntry{},
	}
}

// allow consumes a token for (tier,routeClass,subject). Returns whether the request
// is under the ceiling and, if not, how long until it would be.
func (l *rateLimiter) allow(tier string, rc routeClass, subject string) (bool, time.Duration) {
	now := l.now()
	key := tier + "|" + string(rc) + "|" + subject

	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)

	e := l.buckets[key]
	if e == nil {
		c := ceilingFor(tier, rc, l.scale)
		e = &rlEntry{bucket: newBucket(c.capacity, c.window, now)}
		l.buckets[key] = e
	}
	e.lastSeen = now
	if e.bucket.allow(now) {
		return true, 0
	}
	return false, e.bucket.retryAfter()
}

func (l *rateLimiter) pruneLocked(now time.Time) {
	if now.Sub(l.lastPrune) < rlPruneEvery {
		return
	}
	l.lastPrune = now
	for k, e := range l.buckets {
		if now.Sub(e.lastSeen) > rlIdleTTL {
			delete(l.buckets, k)
		}
	}
	// Hard cap backstop: if distinct subjects still overflow after the idle sweep,
	// shed entries in a single O(n) pass (subjects are bound to valid credentials, so
	// reaching the cap is already implausible; precise oldest-eviction isn't worth an
	// O(n²) scan under the lock). Prefer shedding the more-idle half.
	if over := len(l.buckets) - l.maxKeys; over > 0 {
		cutoff := now.Add(-rlIdleTTL / 2)
		for k, e := range l.buckets {
			if over <= 0 {
				break
			}
			if e.lastSeen.Before(cutoff) {
				delete(l.buckets, k)
				over--
			}
		}
		// If still over (all entries fresh), shed arbitrary remaining entries.
		for k := range l.buckets {
			if over <= 0 {
				break
			}
			delete(l.buckets, k)
			over--
		}
	}
}

const rlTripDedup = 10 * time.Second

// rlTripLog rate-limits the trip log itself so a flood can't flood the log. Its map
// is bounded: entries older than the dedup window carry no information and are swept
// on a periodic prune, so it tracks only recently-tripping identities.
type rlTripLog struct {
	now       func() time.Time
	mu        sync.Mutex
	seen      map[string]time.Time
	lastPrune time.Time
}

func newRLTripLog() *rlTripLog { return &rlTripLog{now: time.Now, seen: map[string]time.Time{}} }

func (t *rlTripLog) shouldLog(key string) bool {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.lastPrune) > time.Minute {
		t.lastPrune = now
		for k, ts := range t.seen {
			if now.Sub(ts) > rlTripDedup {
				delete(t.seen, k)
			}
		}
	}
	if last, ok := t.seen[key]; ok && now.Sub(last) < rlTripDedup {
		return false
	}
	t.seen[key] = now
	return true
}

// RateLimitMiddleware bounds authenticated control-plane traffic. It runs INSIDE
// TokenMiddleware (identity context populated) and skips MCP + public/health paths,
// which are authenticated/limited elsewhere or intentionally unbounded.
func RateLimitMiddleware(mode rateLimitMode, scale float64) func(http.Handler) http.Handler {
	if mode == rlOff {
		return func(next http.Handler) http.Handler { return next }
	}
	limiter := newRateLimiter(scale)
	tripLog := newRLTripLog()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only rate-limit authenticated control-plane calls. Anonymous requests
			// were already rejected by TokenMiddleware (401) before this runs, so a
			// limiter trip never leaks credential validity. MCP is limited in its own
			// auth layer; public/health paths are intentionally unbounded.
			mech := authnMechanismFromContext(r.Context())
			if mech == authnMechanismUnknown || isMCPPublicPath(r) || isPublicPath(r) {
				next.ServeHTTP(w, r)
				return
			}

			tier := identityTier(mech)
			rc := classifyRoute(r.Method, r.URL.Path)
			subject := authnSubjectFromContext(r.Context())

			allowed, retry := limiter.allow(tier, rc, subject)
			if allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Retry-After in whole seconds, clamped ≥1 (a self-healing throttle always
			// tells the caller to wait at least a second). Used for both the log and
			// the response header so they never disagree.
			secs := int(retry.Seconds() + 0.999)
			if secs < 1 {
				secs = 1
			}

			// A trip. Log/API-visible (rate-limited), always — enforce and shadow
			// alike. Privileged-write and trusted-tier trips are high-severity: they
			// should be rare and loud, never silent, and are NOT fed to nft.
			if tripLog.shouldLog(tier + "|" + string(rc) + "|" + subject) {
				sev := "info"
				if rc == rcPrivilegedWrite || tier == "trusted" {
					sev = "high"
				}
				logging.LogfAPI("[apiserver] event=ratelimit_trip mode=%s severity=%s identity_class=%s route_class=%s key_kind=%s method=%s path=%q src_ip=%s retry_after=%ds",
					rlModeName(mode), sev, string(mech), string(rc), subjectKind(mech), r.Method, r.URL.Path, realIPFromRequest(r), secs)
			}

			if mode == rlShadow {
				next.ServeHTTP(w, r) // observe only
				return
			}

			// Enforce: self-healing 429 + Retry-After. Never an nft block.
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprintf(w, `{"error":"rate limited (%s); retry after %ds"}`, rc, secs)
		})
	}
}

func rlModeName(m rateLimitMode) string {
	switch m {
	case rlShadow:
		return "shadow"
	case rlOff:
		return "off"
	default:
		return "enforce"
	}
}

// subjectKind names the identity dimension a bucket is keyed by, for the log —
// never the secret value itself.
func subjectKind(mech authnMechanism) string {
	switch mech {
	case authnMechanismTokenAdmin:
		return "admin"
	case authnMechanismTokenScoped:
		return "token_id"
	case authnMechanismEmbedCookie:
		return "embed_token_id"
	case authnMechanismSession:
		return "session_user"
	default:
		return "unknown"
	}
}
