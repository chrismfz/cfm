package webdetector

// Per-IP FCrDNS good-bot exemption for the decision hot path.
//
// A verified good bot (Googlebot, Bingbot, Meta, Applebot, Yandex, …) must
// NEVER be served a challenge: it cannot solve a JS/PoW challenge, so
// challenging it silently breaks legitimate crawl / SEO / social. Observed live
// 2026-08: a real Googlebot IP repeatedly issued CHALLENGE_ERR_RATIO, and
// Meta's meta-externalagent vhost-challenged on shop vhosts (techking/shopzy).
// This mirrors the SUBNET good-bot exemption (challenge_subnet_goodbot.go) at
// PER-IP scope, reusing the same FCrDNS mechanism: the shared matcher
// (goodBotSuffixName, also used by verifiedGoodBot) plus a forward-confirm
// (verifyGoodBotIP, which additionally distinguishes a transient DNS failure so
// a blip is not cached). Membership is never trust; the PTR is forward-confirmed
// before an IP is exempt, so a spoofed PTR earns nothing (fail-closed).
//
// The forward-confirm is DNS-bound and must never run on the decision hot path,
// so the check is CACHE-ONLY:
//   - cache hit  → verdict served O(1) under a read lock; the PTR is NOT even
//     resolved (ptrFn is lazy), so a busy verified crawler costs one RLock.
//   - cache miss → resolve the PTR; only a good-bot-suffix candidate spends a
//     bounded, deduped async forward-confirm that populates the cache for the
//     crawler's next request (eventual: a good bot may be challenged a couple of
//     times before its first verdict lands). A plain attacker IP (no such PTR —
//     the flood case) leaves no state and takes no write lock.
//
// The guard runs ONLY when a challenge would otherwise be served. Note that a
// vhost-wide challenge makes that "every request to the host", so under such an
// attack the cache-hit RLock / non-candidate fast paths are what keep it cheap.
//
// Degradation note (accepted): an attacker who controls reverse DNS for many
// IPs can set PTR=*.googlebot.com and, during a vhost-wide challenge, spend the
// bounded verify slots on failing forward-confirms. This is FAIL-CLOSED (it only
// degrades to the pre-feature behaviour: a real crawler keeps getting challenged
// on an already-under-attack vhost) and is bounded by the negative-verdict cache
// (each spoofer IP is verified at most once per negTTL, then cached-negative and
// never re-kicked), so sustaining it needs a large, constantly-rotating fake-PTR
// IP pool for a minimal payoff.

import (
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	// verified crawler IPs are stable → cache a positive verdict for a while.
	goodBotIPPosTTL = 30 * time.Minute
	// a negative (spoofed / not-a-bot) verdict is cached briefly so a candidate
	// that momentarily failed forward-confirm is re-checked soon, but a spoofer
	// is not re-verified on every request within the window.
	goodBotIPNegTTL = 5 * time.Minute
	// bound cache growth (a distributed attack with good-bot-suffix PTRs cannot
	// grow it without bound; at the cap a new insert prunes expired entries first).
	goodBotIPCacheCap = 8192
	// cap concurrent in-flight forward-confirms so a burst of first-seen crawler
	// IPs cannot spawn unbounded DNS goroutines.
	goodBotIPMaxInflight = 32
)

type goodBotIPVerdict struct {
	name  string // "" = verified NOT a good bot (or unverifiable)
	until time.Time
}

// bridgeGoodBotState is the per-IP FCrDNS verdict cache. Its own RWMutex; safe
// for concurrent use from the decision handlers. The cache-read fast path takes
// only a read lock so concurrent decisions do not serialise on a hit.
type bridgeGoodBotState struct {
	mu       sync.RWMutex
	cache    map[string]goodBotIPVerdict
	inflight map[string]struct{}
	logged   map[string]struct{} // bot names already logged (visibility, once per TYPE)
	sem      chan struct{}       // bounds concurrent forward-confirms
	// verify returns the good-bot name (or "") and whether the result is
	// cacheable. cacheable=false means inconclusive (a transient resolver
	// failure) and must NOT be pinned in the cache. Injectable for tests.
	verify func(ptr, ip string) (name string, cacheable bool)
	// logVerified is called once per bot TYPE the first time a positive verdict is
	// stored, for operator visibility. It is instance-specific because the SAME
	// cache is used by two subsystems that mean different things: the edge bridge
	// actually challenge-exempts the crawler, while the log-only dcfrac signal only
	// excludes it from a datacenter-fraction count — so each sets a message that
	// matches what it did (never claim a challenge decision the caller didn't make).
	logVerified func(name, ip string)
}

func newBridgeGoodBotState() *bridgeGoodBotState {
	return &bridgeGoodBotState{
		cache:    make(map[string]goodBotIPVerdict),
		inflight: make(map[string]struct{}),
		logged:   make(map[string]struct{}),
		sem:      make(chan struct{}, goodBotIPMaxInflight),
		verify:   verifyGoodBotIP,
		// Default = the edge bridge's meaning (this verdict grants a challenge
		// exemption). Other callers (dcfrac) override this after construction.
		logVerified: func(name, ip string) {
			logging.LogfCHALLENGES("[challenge][goodbot] verified crawler %q is challenge-exempt (per-IP FCrDNS; e.g. ip=%s)", name, ip)
		},
	}
}

// verifyGoodBotIP forward-confirms a good-bot-suffix PTR for the verdict cache.
// cacheable=false means the result is inconclusive (a transient resolver error)
// and must NOT be cached — mirroring the enrich layer's choice not to cache
// negative PTR results, so a DNS blip does not challenge a real crawler for the
// negative TTL. A clean non-match (resolved but wrong IP → spoofed) is a real,
// cacheable negative.
func verifyGoodBotIP(ptr, ip string) (name string, cacheable bool) {
	nm, host, ok := goodBotSuffixName(ptr)
	if !ok {
		return "", true // definitively not a good-bot PTR → cacheable negative
	}
	matched, err := forwardConfirmsE(host, ip)
	if err != nil {
		return "", false // transient resolver failure → do not cache; re-verify later
	}
	if matched {
		return nm, true // FCrDNS-verified → cacheable positive
	}
	return "", true // resolved but no match (spoofed) → cacheable negative
}

// looksLikeGoodBotPTR reports whether ptr ends in a known good-bot suffix. This
// is a CANDIDATE test only (cheap, no DNS) — never trust; forward-confirm decides.
// Shares goodBotSuffixName with verifiedGoodBot so the two can never drift.
func looksLikeGoodBotPTR(ptr string) bool {
	_, _, ok := goodBotSuffixName(ptr)
	return ok
}

// verified returns the cached good-bot name for ip when a fresh positive verdict
// exists, else "". ptrFn is called ONLY on a cache miss, so a verified crawler
// (the hit path) never triggers an enrich/PTR lookup. On a miss where the PTR is
// a good-bot-suffix candidate it kicks a bounded, deduped async forward-confirm
// and returns "" for now. now is injected so the TTL logic is unit-testable.
func (s *bridgeGoodBotState) verified(ip string, ptrFn func() string, now time.Time) string {
	if s == nil || ip == "" {
		return ""
	}
	// Fast path: cache hit under a read lock (the common case for a busy crawler
	// and — as a fresh negative — for a re-seen spoofer).
	s.mu.RLock()
	v, ok := s.cache[ip]
	s.mu.RUnlock()
	if ok && now.Before(v.until) {
		return v.name
	}

	// Miss/expired: resolve the PTR now (lazy) and only spend a verify on a
	// good-bot-suffix candidate. A plain attacker IP takes no write lock.
	ptr := ""
	if ptrFn != nil {
		ptr = ptrFn()
	}
	if !looksLikeGoodBotPTR(ptr) {
		return ""
	}

	s.mu.Lock()
	// Re-check under the write lock: another goroutine may have resolved it.
	if v, ok := s.cache[ip]; ok && now.Before(v.until) {
		name := v.name
		s.mu.Unlock()
		return name
	}
	if _, busy := s.inflight[ip]; busy {
		s.mu.Unlock()
		return ""
	}
	// Acquire a verify slot without blocking the hot path; if full, try next time.
	select {
	case s.sem <- struct{}{}:
	default:
		s.mu.Unlock()
		return ""
	}
	s.inflight[ip] = struct{}{}
	s.mu.Unlock()

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.inflight, ip)
			s.mu.Unlock()
			<-s.sem
		}()
		s.resolveInto(ip, ptr, time.Now())
	}()
	return ""
}

// resolveInto performs the (DNS-bound) forward-confirm and stores the verdict.
// Split from the goroutine wrapper so tests can drive it synchronously.
func (s *bridgeGoodBotState) resolveInto(ip, ptr string, now time.Time) {
	name, cacheable := "", true
	if s.verify != nil {
		name, cacheable = s.verify(ptr, ip)
	}
	if !cacheable {
		// Inconclusive (transient resolver failure): leave no verdict so the IP
		// is re-verified on a later request rather than pinned for negTTL.
		return
	}
	s.store(ip, name, now)
	if name != "" && s.logFirst(name) && s.logVerified != nil {
		// Once per bot TYPE (a crawler fleet has thousands of IPs), not per IP.
		s.logVerified(name, ip)
	}
}

// logFirst reports whether name has not been logged before (and records it), so
// the visibility line is emitted once per bot TYPE rather than per IP.
func (s *bridgeGoodBotState) logFirst(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.logged == nil {
		s.logged = make(map[string]struct{})
	}
	if _, ok := s.logged[name]; ok {
		return false
	}
	s.logged[name] = struct{}{}
	return true
}

// store records a verdict under the pos/neg TTL, pruning expired entries first
// if the cache is at its cap (and dropping the insert if still full, so growth
// is strictly bounded).
func (s *bridgeGoodBotState) store(ip, name string, now time.Time) {
	until := now.Add(goodBotIPNegTTL)
	if name != "" {
		until = now.Add(goodBotIPPosTTL)
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]goodBotIPVerdict)
	}
	if len(s.cache) >= goodBotIPCacheCap {
		s.pruneLocked(now)
		if len(s.cache) >= goodBotIPCacheCap {
			// Full of unexpired entries. A positive verdict is rare and valuable
			// (posTTL) — never let a flood of cheap negatives (negTTL, e.g. a
			// rotating fake-PTR attack) crowd it out: evict one negative to admit a
			// positive. A new negative is simply dropped (it re-mints cheaply on the
			// IP's next request), so growth stays strictly bounded either way.
			if name == "" || !s.evictOneNegativeLocked() {
				s.mu.Unlock()
				return
			}
		}
	}
	s.cache[ip] = goodBotIPVerdict{name: name, until: until}
	s.mu.Unlock()
}

// evictOneNegativeLocked removes one negative (name=="") verdict to make room
// for a positive; caller holds s.mu. Returns false if the cache is all positives
// (then the new positive is dropped — a benign miss, re-verified later).
func (s *bridgeGoodBotState) evictOneNegativeLocked() bool {
	for k, v := range s.cache {
		if v.name == "" {
			delete(s.cache, k)
			return true
		}
	}
	return false
}

func (s *bridgeGoodBotState) pruneLocked(now time.Time) {
	for k, v := range s.cache {
		if now.After(v.until) {
			delete(s.cache, k)
		}
	}
}

// goodBotDowngrade turns a would-be challenge into allow for a verified good bot,
// preserving any block — a block is a stronger, deliberate decision and is never
// softened here. botName=="" is a no-op.
func goodBotDowngrade(ipAction, vhAction, botName string) (string, string) {
	if botName == "" {
		return ipAction, vhAction
	}
	if ipAction == "challenge" {
		ipAction = "allow"
	}
	if vhAction == "challenge" {
		vhAction = "allow"
	}
	return ipAction, vhAction
}
