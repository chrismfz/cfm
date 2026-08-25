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
// for every IP under a per-tick IP budget; the expensive FCrDNS forward-confirm
// runs ONLY for the rare datacenter IP whose already-cached PTR looks like a good
// bot, and is itself capped per tick. When a BUDGET is exhausted the code errs
// toward NOT flagging (a deferred vhost is logged, not dropped; an unverifiable
// good-bot candidate is given the benefit of the doubt). The one edge that goes
// the OTHER way is a cold PTR: LookupCachedOrAsync returns the ASN but no PTR on a
// cache miss, so a datacenter IP whose PTR has not warmed yet is not recognisable
// as a good bot and IS counted — deliberately, because a real datacenter flood
// usually has a generic/absent PTR and excluding cold IPs would make the signal
// blind to a fresh flood. The cost is a transient over-count of a freshly-observed
// verified crawler (e.g. Meta on a cloud ASN) until its PTR caches a tick or two
// later, then it drops out. All of it is log-only; nothing here blocks/challenges.

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

// dcFracBudgets bounds the per-tick enrichment work.
const (
	// maxDCFracIPEnrichPerTick caps how many IPs the signal mmdb-classifies per
	// tick across all vhosts. mmdb is cheap, but this keeps a fleet with millions
	// of distinct IPs from doing unbounded work under one eval; vhosts past the
	// budget are deferred (and logged) to a later tick, not silently dropped.
	maxDCFracIPEnrichPerTick = 8000
	// maxDCFracFCrDNSPerTick caps the expensive FCrDNS forward-confirms. Only
	// datacenter IPs whose cached PTR looks like a good bot are ever candidates, so
	// this is rarely reached; past it, a candidate is given the benefit of the doubt
	// (excluded — the safe direction).
	maxDCFracFCrDNSPerTick = 30
)

// dcIPClass is the per-IP verdict: does this IP count toward the vhost's
// "unverified datacenter" numerator? Pure given a resolved Result and a verifier,
// so the gating logic is unit-testable without an Enricher.
//
//	verify == nil  → FCrDNS budget exhausted; a good-bot-looking PTR is given the
//	                 benefit of the doubt (excluded). Safe (false-negative).
//	verify != nil  → run FCrDNS: a real crawler is excluded, a spoofed googlebot
//	                 PTR fails forward-confirm and IS counted as datacenter.
func dcIPCountsAsDatacenter(asn uint, asnName, ptr, ip string, verify func(ptr, ip string) bool) bool {
	if !IsDatacenter(asn, asnName) {
		return false
	}
	if ptr != "" && looksLikeGoodBotPTR(ptr) {
		if verify == nil {
			return false // can't confirm this tick → don't count (benefit of the doubt)
		}
		if verify(ptr, ip) {
			return false // verified good bot → not suspicious
		}
		// spoofed good-bot PTR that fails forward-confirm → falls through, counted.
	}
	return true
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
	// property of the client, and we want the fraction of the whole load).
	snap := make(map[string]map[string]int)
	e.mu.RLock()
	for host, hs := range e.hosts {
		if hs == nil {
			continue
		}
		m := make(map[string]int)
		for i := range hs.buckets {
			for ip, n := range hs.buckets[i].ips {
				m[ip] += n
			}
		}
		if len(m) > 0 {
			snap[host] = m
		}
	}
	e.mu.RUnlock()

	if len(snap) == 0 {
		return
	}

	ipBudget := maxDCFracIPEnrichPerTick
	fcrdnsBudget := maxDCFracFCrDNSPerTick
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
			var verify func(ptr, ip string) bool
			// Only pay for the good-bot verifier for actual candidates, and only
			// while the FCrDNS budget lasts.
			if IsDatacenter(r.ASN, r.ASNName) && r.PTR != "" && looksLikeGoodBotPTR(r.PTR) && fcrdnsBudget > 0 {
				fcrdnsBudget--
				verify = forwardConfirmGoodBot
			}
			if dcIPCountsAsDatacenter(r.ASN, r.ASNName, r.PTR, ip, verify) {
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

// forwardConfirmGoodBot is the FCrDNS verifier passed into dcIPCountsAsDatacenter:
// the PTR host is re-resolved and must forward-confirm back to ip. Wraps the
// shared verifiedGoodBot so a spoofed PTR (claims a good bot, fails forward-confirm)
// returns false and the IP is counted as datacenter.
func forwardConfirmGoodBot(ptr, ip string) bool {
	return verifiedGoodBot(ptr, ip) != ""
}
