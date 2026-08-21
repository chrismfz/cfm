package webdetector

// Good-bot exemption for the subnet challenge path.
//
// CHALLENGE_SUBNET's heuristic — many IPs from one /24 hitting one host — is
// also the exact shape of a legitimate crawler farm: Meta's fetchers live in
// dedicated /24s and 60+ of them on a busy shop vhost trip SUBNET_MIN_IPS
// (observed live 2026-08-21: 57.141.20.0/24, meta-externalagent, challenged).
// So before a subnet fires, a small sample of its members is checked against
// the FCrDNS good-bot registry (goodBotPTRSuffixes + forward-confirm — the
// same fail-closed verifier the abuse-shadow uses): a subnet whose sampled
// members verify as one good bot is exempt. A spoofed PTR fails
// forward-confirm and earns nothing; a subnet with no PTRs earns nothing.
//
// Scope note: the exemption suppresses only the CHALLENGE_SUBNET heuristic for
// the (subnet,host) pair — one signal among many. Per-IP challenge/score paths,
// the WAF, and autoblock still see every IP, so a hostile IP co-resident in a
// verified-crawler /24 (rare — good bots use dedicated ranges) is not blanket
// trusted, only spared this one /24-shaped signal.
//
// See docs/under-attack-mode.md §4/§5 (increment I0).

import (
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	// subnetGoodBotSample bounds the members PTR-checked per candidate subnet.
	subnetGoodBotSample = 4
	// subnetGoodBotMinVerified: how many sampled members must FCrDNS-verify as
	// the SAME good bot for the subnet to be exempt. 3-of-4 keeps one stale PTR
	// or a couple of good-bot IPs parked in a hostile /24 from flipping it.
	subnetGoodBotMinVerified = 3
	// maxSubnetGoodBotVerifyPerTick bounds the synchronous DNS work per emit
	// tick, counted per SAMPLED IP (one unit per member inspected) — the same
	// per-IP accounting as abuse_shadow's maxShadowEnrichPerTick, not per-subnet.
	// The emit tick runs on the detection goroutine, so this is a hard ceiling on
	// how long good-bot verification can hold it. PTRs are read via
	// LookupCachedOrAsync: a cold PTR returns "" immediately and resolves in the
	// background (it never blocks the tick), so the only synchronous DNS here is
	// the forward-confirm, which runs for good-bot-suffix PTRs only — worst case
	// ~budget forward-confirms/tick. A budget-exhausted subnet is re-tried next
	// tick (not cached), so nothing is permanently mis-verified.
	maxSubnetGoodBotVerifyPerTick = 20
	// subnetGoodBotCacheCap bounds verdict-cache growth between the ~LongHorizon
	// prunes: at the cap, a new insert first drops expired entries inline (the
	// short negTTL makes most negatives collectable). Mirrors the CAP guards on
	// the other emit maps so a high-diversity distributed attack can't grow it
	// without bound.
	subnetGoodBotCacheCap = 4096

	subnetGoodBotPosTTL = 30 * time.Minute // verified crawler /24s are stable
	// subnetGoodBotNegTTL is deliberately short so a subnet that momentarily
	// failed to verify is re-checked within a minute rather than parked as "not
	// a bot" for a long window. It recovers a transient forward-confirm failure
	// (never cached) on the next tick, and — because cold PTRs are resolved in
	// the background via LookupCachedOrAsync — a first-seen good-bot /24 whose
	// members were not yet warm becomes exempt on a re-check once its PTRs land.
	// (A full reverse-DNS outage that pins empty PTRs in the enricher's own 24h
	// Result cache is an enrich-layer property this TTL cannot shortcut; the
	// common case — established crawler /24s warm in the 30-day ptrCache — is
	// unaffected.) Re-verifying a stable attacker /24 every 60s is cheap: its IPs
	// carry no good-bot-suffix PTR, so verifiedGoodBot returns before any
	// forward-confirm.
	subnetGoodBotNegTTL = 60 * time.Second
)

type subnetGoodBotVerdict struct {
	name  string // "" = not a good-bot subnet
	until time.Time
}

// subnetGoodBotCore is the pure decision: sample up to subnetGoodBotSample
// members, resolve each PTR via ptrOf, verify suffix-matching PTRs via verify,
// exempt only when >= subnetGoodBotMinVerified members verify as the SAME bot.
// One budget unit is spent per member inspected; when budget runs out before a
// decision it returns complete=false, signalling the caller NOT to cache the
// (necessarily negative) result so the subnet is re-tried next tick.
func subnetGoodBotCore(ips map[string]struct{}, budget *int, ptrOf func(string) string, verify func(ptr, ip string) string) (name string, ok, complete bool) {
	if len(ips) == 0 || ptrOf == nil || verify == nil {
		return "", false, true // nothing to check is a complete (negative) decision
	}
	sampled := 0
	counts := make(map[string]int, 2)
	for ip := range ips {
		if sampled >= subnetGoodBotSample {
			break
		}
		if budget != nil {
			if *budget <= 0 {
				return "", false, false // out of DNS budget this tick; re-try next tick
			}
			*budget--
		}
		sampled++
		ptr := ptrOf(ip)
		if ptr == "" {
			continue
		}
		if n := verify(ptr, ip); n != "" {
			counts[n]++
			if counts[n] >= subnetGoodBotMinVerified {
				return n, true, true
			}
		}
	}
	return "", false, true
}

// subnetGoodBotState caches per-/24 verdicts so a candidate subnet pays the DNS
// cost once per TTL, not once per tick. Its own mutex; the tick loop is the
// only caller.
type subnetGoodBotState struct {
	mu    sync.Mutex
	cache map[string]subnetGoodBotVerdict
}

// verdict returns the cached verdict for sub if still fresh; otherwise it calls
// resolve() (the DNS-bound decision) and, when resolve reports the result is
// cacheable (a real, budget-complete decision), caches it under the pos/neg
// TTL. A non-cacheable (budget-truncated) result is returned but NOT cached, so
// the subnet is re-tried next tick. The third return, fresh, is true only when
// this call performed a cacheable resolve (not a cache hit) — the caller logs
// on fresh positives only, so an exemption is announced once per posTTL, not
// once per emit tick. Splitting the cache logic from the DNS lets it be
// unit-tested with a stub resolve.
func (s *subnetGoodBotState) verdict(sub string, now time.Time, resolve func() (name string, ok, cacheable bool)) (name string, ok, fresh bool) {
	s.mu.Lock()
	if v, hit := s.cache[sub]; hit && now.Before(v.until) {
		s.mu.Unlock()
		return v.name, v.name != "", false
	}
	s.mu.Unlock()

	name, ok, cacheable := resolve()
	if !cacheable {
		return name, ok, false // budget-truncated; re-check next tick, not cached
	}

	v := subnetGoodBotVerdict{name: name, until: now.Add(subnetGoodBotNegTTL)}
	if ok {
		v.until = now.Add(subnetGoodBotPosTTL)
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]subnetGoodBotVerdict)
	}
	if len(s.cache) >= subnetGoodBotCacheCap {
		s.pruneLocked(now)
	}
	s.cache[sub] = v
	s.mu.Unlock()
	return name, ok, true
}

// prune drops expired verdicts (called from pruneEmitMaps).
func (s *subnetGoodBotState) prune(now time.Time) {
	s.mu.Lock()
	s.pruneLocked(now)
	s.mu.Unlock()
}

// pruneLocked drops expired verdicts; caller holds s.mu.
func (s *subnetGoodBotState) pruneLocked(now time.Time) {
	for k, v := range s.cache {
		if now.After(v.until) {
			delete(s.cache, k)
		}
	}
}

// subnetVerifiedGoodBot reports whether subnet sub (member sample ips) belongs
// to an FCrDNS-verified good bot, spending at most subnetGoodBotSample DNS
// verifications from *budget on a cache miss. now is threaded from the emit tick
// so verdict TTLs and prune share one clock. PTRs are read via
// LookupCachedOrAsync so a cold member never blocks the detection tick.
func (e *Engine) subnetVerifiedGoodBot(sub string, ips map[string]struct{}, budget *int, now time.Time) (string, bool) {
	if e == nil || e.enr == nil || sub == "" {
		return "", false
	}
	name, ok, fresh := e.subnetGoodBot.verdict(sub, now, func() (string, bool, bool) {
		return subnetGoodBotCore(ips, budget,
			func(ip string) string { return e.enr.LookupCachedOrAsync(ip).PTR },
			verifiedGoodBot,
		)
	})
	if ok && fresh {
		// Only on a fresh positive resolve (<= once per posTTL per subnet), never
		// on the cache hits that follow every tick: an exempted crawler farm is
		// worth one visible line, not a per-tick stream.
		logging.LogfCHALLENGES("[challenge][subnet] good-bot exemption subnet=%s bot=%s (FCrDNS-verified)", sub, name)
	}
	return name, ok
}
