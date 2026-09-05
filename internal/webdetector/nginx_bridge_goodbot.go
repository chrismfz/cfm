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
// Two consumers share this cache (nginx_bridge.go handleDecision):
//   - the challenge exemption: runs only when a challenge would otherwise be
//     served (a vhost-wide challenge makes that "every request to the host");
//   - verified_bot traffic rules: run for every non-blocked request on a host
//     that has an ENABLED verified_bot rule (trafficRuleStore.NeedsVerifiedBotFor).
// Under either, the cache-hit RLock / non-candidate fast paths keep it cheap.
// An expired POSITIVE verdict is served stale (goodBotIPStaleGrace) while a
// re-verify runs, unless the fresh PTR no longer looks like a crawler (then the
// stale entry is dropped on the spot — a reassigned IP loses the verdict).
//
// Degradation note (accepted): an attacker who controls reverse DNS for many
// IPs can set PTR=*.googlebot.com and spend the bounded verify slots on failing
// forward-confirms. For the exemption this degrades to the pre-feature
// behaviour (a real crawler on a cache miss keeps getting challenged); for a
// verified_bot ALLOW placed before a block fence it degrades to that fence's
// action for the crawler's cache-miss request. Both are bounded by the
// negative-verdict cache (each spoofer IP is verified at most once per negTTL,
// then cached-negative and never re-kicked) and by the stale grace (a crawler
// already verified once keeps its verdict through slot starvation), so
// sustaining it needs a large, constantly-rotating fake-PTR IP pool. The cache
// is in-memory: after a daemon restart every crawler IP is first-seen again
// (recipe warnings say so; persisting positives is a tracked follow-up).
//
// The simulate API uses verifiedSync (inline forward-confirm, bounded wait) —
// never the decision hot path, which stays cache-only.

import (
	"context"
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
	// an EXPIRED positive verdict is still served for this long while an async
	// re-verify runs ("stale while revalidate"). Without it every real crawler
	// IP would fall off the exemption / a verified_bot allow for one request
	// per posTTL — tolerable when the fallback was a challenge page, not when a
	// traffic rule turns it into a 403. Bounded so a reassigned IP cannot keep
	// a crawler's verdict forever.
	goodBotIPStaleGrace = 24 * time.Hour
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
			// Worded as the fact it is (an FCrDNS verdict), not as a decision:
			// the same cache now also feeds verified_bot traffic rules and the
			// simulate API, where no challenge exemption is in force.
			logging.LogfCHALLENGES("[challenge][goodbot] FCrDNS-verified crawler %q (per-IP; e.g. ip=%s) — challenge-exempt when CHALLENGE_GOODBOT_EXEMPT is on, matches verified_bot traffic rules", name, ip)
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
// and returns the stale positive (if any) or "" for now. now is injected so the
// TTL logic is unit-testable. Never blocks: decision hot path.
func (s *bridgeGoodBotState) verified(ip string, ptrFn func() string, now time.Time) string {
	if s == nil || ip == "" {
		return ""
	}
	l := s.lookup(ip, ptrFn, now)
	if l.fresh {
		return l.name
	}
	if l.candidate {
		s.kickAsyncVerify(ip, l.ptr, now)
	}
	return l.stale
}

// goodBotLookup is the shared prelude of verified() and verifiedSync(): the
// cache read, the stale-positive decision and the candidate test, so the two
// can never disagree on WHAT to verify — only on HOW (async vs inline).
type goodBotLookup struct {
	name      string // fresh cached verdict ("" = fresh negative) when fresh
	fresh     bool   // cache hit within TTL — nothing else to do
	stale     string // expired positive still within the grace, else ""
	ptr       string // PTR resolved via ptrFn (only on a non-fresh path)
	candidate bool   // ptr has a good-bot suffix → worth a forward-confirm
}

func (s *bridgeGoodBotState) lookup(ip string, ptrFn func() string, now time.Time) goodBotLookup {
	// Fast path: cache hit under a read lock (the common case for a busy crawler
	// and — as a fresh negative — for a re-seen spoofer).
	s.mu.RLock()
	v, ok := s.cache[ip]
	s.mu.RUnlock()
	if ok && now.Before(v.until) {
		return goodBotLookup{name: v.name, fresh: true}
	}
	l := goodBotLookup{}
	// Stale positive (expired, within grace): keep serving it while a
	// re-verify refreshes the entry, so a crawler never loses its verdict for
	// a request per posTTL. A stale NEGATIVE is a plain miss.
	if ok && v.name != "" && now.Before(v.until.Add(goodBotIPStaleGrace)) {
		l.stale = v.name
	}
	// Miss/expired: resolve the PTR now (lazy) and only spend a verify on a
	// good-bot-suffix candidate. A plain attacker IP takes no write lock.
	if ptrFn != nil {
		l.ptr = ptrFn()
	}
	l.candidate = looksLikeGoodBotPTR(l.ptr)
	if l.stale != "" && l.ptr != "" && !l.candidate {
		// Definitive evidence the IP is no longer a crawler (its PTR resolved
		// to something else): drop the stale verdict instead of serving it for
		// the rest of the grace. An EMPTY ptr is an enrich-cache miss, not
		// evidence, so the stale positive stands until the PTR is known.
		s.mu.Lock()
		if cur, still := s.cache[ip]; still && cur.until == v.until {
			delete(s.cache, ip)
		}
		s.mu.Unlock()
		l.stale = ""
	}
	return l
}

// kickAsyncVerify starts one bounded, de-duplicated background forward-confirm
// for a good-bot-suffix candidate; it never blocks the caller. If another
// goroutine already resolved the IP, or all verify slots are busy, it does
// nothing (the next request retries).
func (s *bridgeGoodBotState) kickAsyncVerify(ip, ptr string, now time.Time) {
	s.mu.Lock()
	if v, ok := s.cache[ip]; ok && now.Before(v.until) {
		s.mu.Unlock()
		return
	}
	if _, busy := s.inflight[ip]; busy {
		s.mu.Unlock()
		return
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.mu.Unlock()
		return
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
}

// verifiedSyncMaxWait bounds how long the simulate API waits for a verify slot
// when all goodBotIPMaxInflight are busy (e.g. a fake-PTR flood on the hot
// path): past it the answer is "inconclusive" rather than a hung handler.
const verifiedSyncMaxWait = 3 * time.Second

// verifiedSync is the SIMULATE-API variant of verified(): same lookup prelude,
// same verifier, same verify-slot bound (it WAITS for a slot, bounded by ctx
// and verifiedSyncMaxWait, instead of giving up), but the forward-confirm runs
// inline (DNS-bound, seconds at worst) so an operator's "test this rule" gets a
// definitive answer now instead of "not yet". A stale positive is re-verified
// inline too, so the answer reflects the PTR as it is now. Never call it on
// the decision hot path — TrafficRuleSimulateForAPI is its only caller.
func (s *bridgeGoodBotState) verifiedSync(ctx context.Context, ip string, ptrFn func() string, now time.Time) string {
	if s == nil || ip == "" {
		return ""
	}
	l := s.lookup(ip, ptrFn, now)
	if l.fresh {
		return l.name
	}
	if !l.candidate {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	wait, cancel := context.WithTimeout(ctx, verifiedSyncMaxWait)
	defer cancel()
	// Bounded like the async path: at most goodBotIPMaxInflight forward-confirms
	// in flight daemon-wide, so a burst of simulate calls (the endpoint is
	// reachable by scoped tokens for their own vhosts) cannot fan out
	// unbounded resolver work — and a client that went away stops waiting.
	select {
	case s.sem <- struct{}{}:
	case <-wait.Done():
		return l.stale // inconclusive: report what we still knew, if anything
	}
	name, cacheable := s.resolveInto(ip, l.ptr, now)
	<-s.sem
	if !cacheable {
		return l.stale
	}
	return name
}

// resolveInto performs the (DNS-bound) forward-confirm and stores the verdict.
// Split from the goroutine wrapper so tests can drive it synchronously. It
// returns the verdict itself (not a re-read of the cache) so a caller is not
// fooled when store() has to drop an insert at the cache cap.
func (s *bridgeGoodBotState) resolveInto(ip, ptr string, now time.Time) (name string, cacheable bool) {
	name, cacheable = "", true
	if s.verify != nil {
		name, cacheable = s.verify(ptr, ip)
	}
	if !cacheable {
		// Inconclusive (transient resolver failure): leave no verdict so the IP
		// is re-verified on a later request rather than pinned for negTTL.
		return "", false
	}
	s.store(ip, name, now)
	if name != "" && s.logFirst(name) && s.logVerified != nil {
		// Once per bot TYPE (a crawler fleet has thousands of IPs), not per IP.
		s.logVerified(name, ip)
	}
	return name, true
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
