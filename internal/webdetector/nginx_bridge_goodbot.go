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
// The simulate APIs use verifiedSync (inline reverse lookup + forward-confirm
// under their own slot bound, bounded wait), and the ChallengeV2 verify gate
// uses it for an inline forward-confirm before a reject (verifiedBeforeReject)
// — never the decision hot path, which stays cache-only. Note the hot path's first sight of a crawler IP costs it
// more than one request: the enrich PTR itself is fetched async, so request 1
// has no PTR (nothing to verify), request 2 kicks the forward-confirm, and the
// verdict is there from request 3 or so.

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
	// inline verifies (verifiedSync: the simulate APIs and the ChallengeV2
	// verify gate) have their OWN, smaller bound so a burst of them (simulate is
	// reachable by scoped tokens) can never take the hot path's slots and starve
	// real crawler verification.
	goodBotSyncMaxInflight = 4
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
	sem      chan struct{}       // bounds concurrent async forward-confirms (hot path)
	syncSem  chan struct{}       // bounds concurrent inline verifies (simulate APIs, v2 verify gate)
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
		syncSem:  make(chan struct{}, goodBotSyncMaxInflight),
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
	if l, done := s.cached(ip, now); done {
		return l
	}
	// Miss/expired: resolve the PTR now (lazy). On the hot path an EMPTY ptr
	// is an enrich-cache miss, not evidence — hence definitive=false.
	ptr := ""
	if ptrFn != nil {
		ptr = ptrFn()
	}
	return s.lookupPTR(ip, ptr, false, now)
}

// cached is the cache-only half of lookup(): a fresh hit returns done=true.
// Otherwise the returned lookup carries the stale positive (if any) and the
// caller decides how to obtain the PTR.
func (s *bridgeGoodBotState) cached(ip string, now time.Time) (goodBotLookup, bool) {
	// Fast path: cache hit under a read lock (the common case for a busy crawler
	// and — as a fresh negative — for a re-seen spoofer).
	s.mu.RLock()
	v, ok := s.cache[ip]
	s.mu.RUnlock()
	if ok && now.Before(v.until) {
		return goodBotLookup{name: v.name, fresh: true}, true
	}
	l := goodBotLookup{}
	// Stale positive (expired, within grace): keep serving it while a
	// re-verify refreshes the entry, so a crawler never loses its verdict for
	// a request per posTTL. A stale NEGATIVE is a plain miss.
	if ok && v.name != "" && now.Before(v.until.Add(goodBotIPStaleGrace)) {
		l.stale = v.name
	}
	return l, false
}

// lookupPTR completes a lookup with an already-resolved PTR. definitive says
// whether an EMPTY ptr is real evidence ("this IP has no PTR", as a completed
// NXDOMAIN answer is) or just unknown-yet (an enrich-cache miss). Only a
// good-bot-suffix candidate is worth a forward-confirm. A stale positive is
// dropped on the spot when the (definitive) PTR no longer looks like a
// crawler — the IP was reassigned.
func (s *bridgeGoodBotState) lookupPTR(ip, ptr string, definitive bool, now time.Time) goodBotLookup {
	l, done := s.cached(ip, now)
	if done {
		return l
	}
	l.ptr = ptr
	l.candidate = looksLikeGoodBotPTR(ptr)
	if l.stale != "" && !l.candidate && (ptr != "" || definitive) {
		s.mu.Lock()
		if cur, still := s.cache[ip]; still && cur.name == l.stale && !now.Before(cur.until) {
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

// verifiedSyncMaxWait bounds how long an inline verify waits for a syncSem slot
// when all goodBotSyncMaxInflight are busy: past it the answer is
// "inconclusive" rather than a hung handler.
const verifiedSyncMaxWait = 3 * time.Second

// Inconclusive reasons verifiedSync can report (empty = the answer is final).
const (
	verifiedInconclusiveTimeout   = "timeout"   // no verify slot within ctx / verifiedSyncMaxWait
	verifiedInconclusiveTransient = "transient" // resolver failed; nothing cached
)

// verifiedSync is the INLINE variant of verified(): same cache, same verifier —
// but it runs the reverse lookup AND the forward-confirm inline (DNS-bound,
// seconds at worst) so an operator's "test this rule" gets a definitive answer
// now instead of "not yet". It is bounded by its OWN small
// semaphore (goodBotSyncMaxInflight) plus ctx / verifiedSyncMaxWait, so a burst
// of simulate calls (the endpoint is reachable by scoped tokens) can neither
// fan out resolver work nor take the hot path's verify slots. ptrFn reports
// whether the reverse lookup COMPLETED (ok=false → resolver failure), so a
// crawler behind a DNS blip is "inconclusive", never "not a crawler"; a
// completed empty answer (no PTR) IS definitive. A stale positive is
// re-verified inline too, so the answer reflects the PTR as it is now.
//
// Returns the verdict and an inconclusive reason: name=="" with reason=="" is a
// definitive negative; a non-empty reason means "could not tell" (a non-empty
// name WITH a reason is a stale verdict whose re-verify did not complete).
// Never call it on the decision hot path. Callers: the simulate APIs
// (TrafficRuleSimulateForAPI, the challenge-access simulate) and the ChallengeV2
// verify gate, for a solve it is about to reject (verifiedBeforeReject). They
// share syncSem, so neither can take the hot path's slots; a burst of one can
// only make the other's answer "inconclusive" / no waiver. The verify gate
// passes an already-known PTR, so for it only the forward-confirm runs.
func (s *bridgeGoodBotState) verifiedSync(ctx context.Context, ip string, ptrFn func() (ptr string, ok bool), now time.Time) (name, inconclusive string) {
	if s == nil || ip == "" {
		return "", ""
	}
	// Cache-only first pass (no PTR): a fresh verdict needs no slot at all.
	l, done := s.cached(ip, now)
	if done {
		return l.name, ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	wait, cancel := context.WithTimeout(ctx, verifiedSyncMaxWait)
	defer cancel()
	select {
	case s.syncSem <- struct{}{}:
	case <-wait.Done():
		return l.stale, verifiedInconclusiveTimeout
	}
	defer func() { <-s.syncSem }()
	ptr, ok := "", false
	if ptrFn != nil {
		ptr, ok = ptrFn()
	}
	if !ok {
		return l.stale, verifiedInconclusiveTransient // reverse lookup did not complete
	}
	l = s.lookupPTR(ip, ptr, true, now)
	if l.fresh { // raced with an async verify that just landed
		return l.name, ""
	}
	if !l.candidate {
		return "", "" // definitive: no good-bot suffix (or no PTR at all)
	}
	name, cacheable := s.resolveInto(ip, l.ptr, now)
	if !cacheable {
		return l.stale, verifiedInconclusiveTransient
	}
	return name, ""
}

// verifiedBeforeReject is the ChallengeV2 verify gate's good-bot check, run
// ONLY for a solve the gate is about to reject (a failing score under a
// waivable arm), never for a solve that passes. The hot path's cache-only
// verified() would rarely answer there: Google's user-driven fetchers
// (Google-Read-Aloud) come from rotating, mostly first-seen IPs — 73 challenge
// solves from 48 IPs fleet-wide over 2026-09-16..23 — and a lone page fetch
// leaves no verdict behind (the decision had no PTR yet to verify). So a cached
// verdict answers when there is one, and otherwise a candidate PTR is
// forward-confirmed INLINE through verifiedSync (same verifier, same syncSem
// bound, the verdict cached for the decision path as well).
//
// knownPTR is the solve's PTR from the enrich cache ("" = none, or not
// resolved yet — enrich can't tell which). The only DNS this can cost is that
// forward-confirm, and only when knownPTR ends in a crawler's domain: the
// lookup then goes to the crawler operator's own DNS (google.com, …), not a
// zone the client controls, and its answer — spoofed or not — is cached. So:
//   - a cached fresh verdict answers as is;
//   - knownPTR "" → cache only (a stale positive is honoured, as verified()
//     serves it); no reverse lookup, so an IP without a PTR costs nothing;
//   - knownPTR not a crawler's → "" with no DNS and no slot, dropping a stale
//     positive (the IP was reassigned);
//   - otherwise the inline forward-confirm; if it can't complete (no slot in
//     time, resolver failure) a stale positive is still honoured, else "".
func (s *bridgeGoodBotState) verifiedBeforeReject(ctx context.Context, ip, knownPTR string, now time.Time) string {
	if s == nil || ip == "" {
		return ""
	}
	if knownPTR == "" {
		return s.verified(ip, nil, now)
	}
	if l := s.lookupPTR(ip, knownPTR, true, now); l.fresh || !l.candidate {
		return l.name
	}
	name, _ := s.verifiedSync(ctx, ip, func() (string, bool) { return knownPTR, true }, now)
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
			// With the stale grace, positives now linger ~24.5 h; a busy
			// multi-tenant host can fill the cache with them. Then a NEW
			// positive evicts the oldest EXPIRED positive (already past its
			// TTL, only being served stale) rather than being dropped and
			// re-verified on every request.
			if name == "" || (!s.evictOneNegativeLocked() && !s.evictOldestStalePositiveLocked(now)) {
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

// evictOldestStalePositiveLocked removes the expired positive with the oldest
// until (i.e. the one deepest into its stale grace); caller holds s.mu. Returns
// false when every positive is still fresh.
func (s *bridgeGoodBotState) evictOldestStalePositiveLocked(now time.Time) bool {
	victim := ""
	var oldest time.Time
	for k, v := range s.cache {
		if v.name == "" || now.Before(v.until) {
			continue
		}
		if victim == "" || v.until.Before(oldest) {
			victim, oldest = k, v.until
		}
	}
	if victim == "" {
		return false
	}
	delete(s.cache, victim)
	return true
}

// pruneLocked drops expired entries. A POSITIVE is kept for its stale grace
// (goodBotIPStaleGrace) past until: a fake-PTR flood that fills the cache with
// cheap negatives must not be able to evict a real crawler's expired-but-
// still-serviceable verdict while the same flood starves its re-verify slot.
func (s *bridgeGoodBotState) pruneLocked(now time.Time) {
	for k, v := range s.cache {
		limit := v.until
		if v.name != "" {
			limit = v.until.Add(goodBotIPStaleGrace)
		}
		if now.After(limit) {
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
