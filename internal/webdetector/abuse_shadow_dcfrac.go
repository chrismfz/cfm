package webdetector

import (
	"time"

	"cfm/internal/logging"
)

// abuse_shadow_dcfrac.go — Signal H: LOG-ONLY vhost-level datacenter-ASN fraction,
// VERIFIED-GATED (docs/traffic-classifier.md, Phase 1). It measures what fraction
// of a vhost's requests come from datacenter/cloud ASNs that are NOT verified good
// bots — a corroborating feature for cloud-hosted scraper / proxy floods.
//
// Two hard rules from the audit shape it:
//   - Origin is never innocence, and datacenter-ASN ALONE never drives an adverse
//     decision (CLAUDE.md §6). This is a shadow FEATURE, gated behind the master,
//     with zero enforcement — it only records the fraction for later score fusion.
//   - It MUST exclude verified crawlers, or a heavily-Googlebot/Meta-crawled shop
//     (techking/shopzy in the audit) reads as ~100% datacenter and the feature is
//     pure noise. Exclusion is FCrDNS (verifiedGoodBot), the same rigorous check the
//     challenge exemption uses — a spoofed googlebot PTR cannot earn the exclusion.
//
// Cost discipline (CLAUDE.md §6 — do not create a per-tick DNS storm): ASN
// classification is a cheap inline mmdb lookup (LookupCachedOrAsync, no DNS) done
// for every IP under a per-tick IP budget (vhosts past the budget are deferred and
// logged, never silently dropped; a single vhost that alone exceeds a full budget
// is processed anyway so the largest floods are never invisible). The good-bot
// exclusion goes through a shared FCrDNS VERDICT CACHE (dcFracGoodBot): a verified
// crawler is a lock-free cache hit with NO DNS, and only a cache MISS on a
// good-bot-suffix PTR kicks a bounded, deduped, async forward-confirm — so a
// stable crawler is confirmed once per posTTL, not every 5s tick, and the verdict
// outlives geo-cache eviction. This is the fix for the earlier per-tick-storm and
// per-eviction-FP designs.
//
// Residual, documented, log-only limitation: on a COLD good-bot verdict (a crawler
// IP not yet in the verdict cache — chiefly the first ticks after a daemon
// restart), the IP counts as datacenter until the async confirm lands (~2–3
// ticks), so a freshly-restarted, heavily-crawled shop can briefly over-read its
// datacenter fraction. Counting the unknown is deliberate: a real cloud flood is
// mostly generic/absent-PTR IPs that would be excluded if "unknown ⇒ not counted",
// blinding the signal to its primary target; and every steady-state good bot is
// remembered by the verdict cache, so the FP is a startup transient, not ongoing.
// This asymmetry (count-on-unknown, exclude-on-verified) is safe for a log-only
// feature but must be closed before Signal H feeds any enforcement (e.g. a warmup
// grace period, or a synchronous confirm for the candidate subset).

// dcFracShadowCfg is the resolved Signal-H threshold set (defaults applied).
type dcFracShadowCfg struct {
	MinFrac float64 // datacenter reqs / total reqs must be ≥ this
	MinReq  int     // …with ≥ this many total requests (guards tiny vhosts)
	MinIPs  int     // …spread over ≥ this many distinct datacenter IPs (not one chatty host)
}

func (e *Engine) dcFracShadowCfg() dcFracShadowCfg {
	c := dcFracShadowCfg{
		MinFrac: e.cfg.AbuseShadowDCFracMinFrac,
		MinReq:  e.cfg.AbuseShadowDCFracMinReq,
		MinIPs:  e.cfg.AbuseShadowDCFracMinIPs,
	}
	if c.MinFrac <= 0 {
		// Half the traffic from unverified datacenter IPs is well above a normal
		// eyeball vhost (mostly residential) and separates a cloud-hosted flood.
		c.MinFrac = 0.5
	}
	if c.MinReq <= 0 {
		c.MinReq = 50
	}
	if c.MinIPs <= 0 {
		c.MinIPs = 5
	}
	return c
}

// maxDCFracIPEnrichPerTick caps how many IPs the signal mmdb-classifies per tick
// across all vhosts. mmdb is cheap, but this keeps a fleet with millions of
// distinct IPs from doing unbounded work under one eval; vhosts past the budget
// are deferred (and logged) to a later tick, not silently dropped. There is no
// separate FCrDNS budget: the good-bot verdict cache (dcFracGoodBot) already
// bounds and dedups the forward-confirms internally, and a confirmed crawler is
// then a lock-free cache hit — so DNS is not per-tick work to budget here.
const maxDCFracIPEnrichPerTick = 8000

// dcFracGoodBot is the shared FCrDNS good-bot verdict cache for Signal H. A cache
// hit (the steady state for a stable crawler) is DNS-free; a miss on a good-bot-
// suffix PTR kicks a bounded, deduped, async forward-confirm and caches the
// verdict (positive for posTTL, negative for negTTL), so a crawler is confirmed
// once per posTTL rather than every 5s tick, and the verdict outlives geo-cache
// eviction. Separate from the edge bridge's instance (different subsystem), same
// battle-tested machinery — but its verified-crawler visibility line goes to the
// abuse_shadow log and says "excluded from the datacenter count", NOT the bridge's
// "challenge-exempt" (this signal grants no exemption).
var dcFracGoodBot = newDCFracGoodBot()

func newDCFracGoodBot() *bridgeGoodBotState {
	s := newBridgeGoodBotState()
	s.logVerified = func(name, ip string) {
		logging.LogfABUSESHADOW("[abuse-shadow] signal=dc_fraction verified_crawler=%q excluded_from_datacenter_count (per-IP FCrDNS; e.g. ip=%s)", name, ip)
	}
	return s
}

// dcIPCountsAsDatacenter is the pure per-IP verdict: an IP counts toward the
// vhost's "unverified datacenter" numerator iff it is on a datacenter/cloud ASN
// AND is not an FCrDNS-verified good bot. Both inputs are computed ONCE by the emit
// (the ASN class and the verdict-cache lookup) and handed in as booleans, so the
// hot loop never re-runs either and the datacenter/good-bot rule lives in exactly
// one place. Unit-testable without an Enricher.
func dcIPCountsAsDatacenter(isDatacenter, verifiedGoodBot bool) bool {
	return isDatacenter && !verifiedGoodBot
}

// emitAbuseShadowDatacenterFrac runs Signal H in log-only mode. Called from the
// per-tick emitIPChallenges after the cost pass. Snapshots per-vhost per-IP totals
// under the read lock, then classifies + flags after unlock (all enrichment and
// DNS happen lock-free).
func (e *Engine) emitAbuseShadowDatacenterFrac(now time.Time) {
	if !e.cfg.AbuseShadow || !e.cfg.AbuseShadowDCFrac || e.enr == nil {
		return
	}
	cfg := e.dcFracShadowCfg()

	// Snapshot per-vhost per-IP request totals (all requests — datacenter is a
	// property of the client, and we want the fraction of the whole load). Apply the
	// cheap pre-filters UNDER the lock so a vhost too small to ever flag is skipped
	// BEFORE its per-IP map is copied — otherwise the snapshot would allocate every
	// vhost's full IP set every tick regardless of the budget, which on a large fleet
	// dwarfs the mmdb work the budget bounds. bucket.total ≥ the per-IP sum (IP-less
	// requests still bump total), so gating on it can only over-admit, never wrongly
	// drop a qualifying vhost; the main loop re-checks on the precise per-IP total.
	snap := make(map[string]map[string]int)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		total := 0
		for i := range hs.buckets {
			total += hs.buckets[i].total
		}
		if total < cfg.MinReq {
			continue // can't reach MinReq — don't copy its IPs
		}
		m := make(map[string]int)
		for i := range hs.buckets {
			for ip, n := range hs.buckets[i].ips {
				m[ip] += n
			}
		}
		if len(m) >= cfg.MinIPs { // needs a spread of IPs to ever flag
			snap[host] = m
		}
	}
	e.mu.RUnlock()

	if len(snap) == 0 {
		return
	}

	ipBudget := maxDCFracIPEnrichPerTick
	deferred := 0

	// Iterate in Go's randomized map order ON PURPOSE: when the per-tick IP budget
	// can't cover the whole fleet, a random subset is deferred each tick, so over a
	// few ticks every vhost gets classified. A sorted/stable order would instead
	// defer the SAME tail every tick and starve it forever. The deferral is reported
	// as a count (below), not a host list, so reproducibility buys nothing here.
	marks := make(map[string]int)
	for host, perIP := range snap {
		totalReqs := 0
		for _, n := range perIP {
			totalReqs += n
		}
		// Cheap pre-filters BEFORE spending any enrichment budget.
		if totalReqs < cfg.MinReq || len(perIP) < cfg.MinIPs {
			continue
		}
		// Enriching this vhost needs len(perIP) mmdb lookups. If it doesn't fit the
		// tick's REMAINING budget, defer the WHOLE vhost (a partial fraction would be
		// wrong) to a later tick rather than silent-truncate it — UNLESS the vhost
		// alone exceeds a full budget, in which case it can never fit and deferring
		// would blind the signal forever to the very largest vhosts (a >budget
		// distinct-IP vhost IS the flood we must catch). Process such a vhost now,
		// letting the budget go negative so the remaining vhosts defer to next tick.
		if len(perIP) > ipBudget && len(perIP) <= maxDCFracIPEnrichPerTick {
			deferred++
			continue
		}
		ipBudget -= len(perIP)

		dcReqs, dcIPs := 0, 0
		for ip, n := range perIP {
			r := e.enr.LookupCachedOrAsync(ip) // inline mmdb (no blocking DNS)
			isDC := IsDatacenter(r.ASN, r.ASNName)
			if !isDC {
				continue // residential/unknown — skip the good-bot check entirely
			}
			// Verified-gating through the shared good-bot verdict cache: a cache HIT
			// (the steady state for a stable crawler) returns instantly with NO DNS; a
			// miss on a good-bot-suffix PTR kicks a bounded, deduped, ASYNC forward-
			// confirm and returns "" for now. So a crawler is FCrDNS'd once per posTTL,
			// not every tick (kills the per-tick DNS storm), and the verdict survives
			// geo-cache eviction. r.PTR is already fetched, so ptrFn is a cheap closure
			// only called on a cache miss.
			ptr := r.PTR
			bot := dcFracGoodBot.verified(ip, func() string { return ptr }, now) != ""
			if dcIPCountsAsDatacenter(isDC, bot) {
				dcReqs += n
				dcIPs++
			}
		}

		if dcIPs < cfg.MinIPs {
			continue // datacenter traffic isn't a spread — one host or none
		}
		frac := float64(dcReqs) / float64(totalReqs)
		if frac < cfg.MinFrac {
			continue
		}
		// Badge = datacenter percent, floored to 1 so a flagged vhost never badges 0
		// (0 means "not flagged"). Not dead at the 0.5 default, but reachable: an
		// operator can set MIN_FRAC below 0.005, where frac*100 rounds to 0.
		pct := int(frac*100 + 0.5)
		if pct < 1 {
			pct = 1
		}
		marks[host] = pct

		if !e.shouldLogVhostSuppress("abuseshadowdcfrac:"+host, now) {
			continue
		}
		logging.LogfABUSESHADOW(
			"[abuse-shadow] signal=dc_fraction host=%s dc_frac=%.3f dc_reqs=%d dc_ips=%d total_reqs=%d total_ips=%d verdict=would_shadow",
			host, frac, dcReqs, dcIPs, totalReqs, len(perIP),
		)
	}

	if deferred > 0 {
		// No silent caps (CLAUDE.md §5): say what the budget dropped this tick.
		logging.LogfABUSESHADOW("[abuse-shadow] signal=dc_fraction deferred_vhosts=%d reason=ip_enrich_budget", deferred)
	}

	if len(marks) > 0 {
		ttl := 3 * e.cfg.Window
		if ttl < 90*time.Second {
			ttl = 90 * time.Second
		}
		MarkDCFracShadowBulk(marks, ttl)
	}
}
