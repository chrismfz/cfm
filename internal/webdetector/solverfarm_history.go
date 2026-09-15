package webdetector

import (
	"fmt"
	"time"

	"cfm/internal/detectors/solverfarm"
	"cfm/internal/logging"
)

// solverFarmGoodBot is the FCrDNS good-bot verdict cache for the finding emit —
// its OWN instance (not the edge bridge's, not dcfrac's), per the documented
// principle that a shared good-bot cache must never claim a decision the caller
// didn't make (CLAUDE.md §6 / nginx_bridge_goodbot.go): here the verdict only
// TAGS an address in the durable finding as a verified crawler, it grants no
// challenge exemption and no datacenter-count exclusion, so its visibility line
// says exactly that. Same battle-tested machinery (cache-only lookups, bounded
// async forward-confirm) as the other two instances.
var solverFarmGoodBot = newSolverFarmGoodBot()

func newSolverFarmGoodBot() *bridgeGoodBotState {
	s := newBridgeGoodBotState()
	s.logVerified = func(name, ip string) {
		logging.LogfABUSESHADOW("[abuse-shadow] signal=solver_farm verified_crawler=%q tagged_in_finding_sample (per-IP FCrDNS; e.g. ip=%s)", name, ip)
	}
	return s
}

// RecordSolverFarmFinding persists one emitted challenge_solver_farm finding into
// the durable webdetector history store as event_type=solver_farm, so a
// distributed-farm conviction — which today reaches only cfm.detector.log + mail
// — becomes queryable via detection_history and can be PULLed into the fleet
// fingerprint-reputation store (cfm-web). Wired as the finding sink in
// internal/detectors/webdetector_register.go; mirrors RecordClamScanEvent /
// RecordHardwareECCEvent (the detector package publishes, this subscribes).
//
// The Payload keys are the ingest CONTRACT (docs/fleet-fingerprint-reputation.md
// §5 → cfm-web:docs/fingerprint-reputation.md): keep them stable. `fingerprint`
// is the GROUP-BY key that flagged the vhost (empty for a subnet-spread-only
// finding), never a matched signature; `solves_per_ip` is evidence, not a gate.
// `ips` is the bounded address sample; `good_bots` is the sparse {ip: name} subset
// of those addresses that are FCrDNS-verified crawlers (a per-IP block exemption).
func (e *Engine) RecordSolverFarmFinding(f solverfarm.Finding) {
	if e == nil || e.history == nil {
		return
	}
	ts := f.When
	if ts.IsZero() {
		ts = time.Now()
	}
	payload := map[string]interface{}{
		"fingerprint":        f.Fingerprint,
		"tracks":             f.Tracks,
		"solves":             f.Solves,
		"distinct_ips":       f.DistinctIPs,
		"distinct_subnets":   f.Subnets,
		"distinct_countries": f.Countries,
		"host_share":         f.HostShare,
		"solves_per_ip":      f.SolvesPerIP,
		"hosts":              f.Hosts,
	}
	// A bounded, fingerprint-accurate sample of the client addresses (the fleet
	// store enriches these — PTR/ASN/country/datacenter — so an operator can tell a
	// residential-proxy pool from a datacenter crawler and, on the non-edge nodes,
	// block them via the firewall). Omitted when empty so older/spread-only rows
	// stay compact.
	if len(f.IPs) > 0 {
		payload["ips"] = f.IPs
		// A sparse {ip: name} map of the sampled addresses that are FCrDNS-verified
		// good bots (Googlebot/Bingbot/…) — the per-IP block EXEMPTION the fleet store
		// keys off (a real crawler can share a farm's coarse TLS bucket, so it must
		// never be swept into a fingerprint-keyed block). NODE-authoritative and
		// forward-confirmed here; the fleet store trusts it because a UA/PTR string is
		// spoofable but this verdict is not. Omitted when none (the common case).
		if gb := e.goodBotsForFinding(f.IPs); len(gb) > 0 {
			payload["good_bots"] = gb
		}
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  ts.Unix(),
		Type:    "solver_farm",
		Host:    f.Host,
		Reason:  solverFarmReason(f),
		UniqIP:  f.DistinctIPs,
		Payload: payload,
	})
}

// goodBotsForFinding resolves the sparse {ip: name} good-bot map for a finding's
// sampled IPs. For each IP it reads a PTR from the enrich cache
// (LookupCachedOrAsync — never blocks; on a COLD IP it best-effort DISPATCHES an
// async enrich lookup, bounded by the enricher's own semaphore) and feeds it to
// solverFarmGoodBot's verdict cache: a cache hit returns the name instantly, and a
// good-bot-suffix PTR miss kicks a bounded async forward-confirm and returns ""
// for now. So the pass never blocks and fans out no burst of SYNCHRONOUS DNS,
// though a fully-cold sample can dispatch up to len(ips) background lookups (the
// same warming dcfrac does per tick).
//
// solverFarmGoodBot is this path's OWN verdict cache (the separate-instance
// principle), so a crawler the edge bridge already verified is unknown here until
// THIS path confirms it — which needs a warm enrich PTR AND a completed async
// forward-confirm kicked by an earlier finding. A genuinely first-seen crawler IP
// is therefore absent from its FIRST finding and tagged on a later one; the fleet
// store stamps good_bot sticky-positive, so one eventual confirmation is enough.
//
// Only the canonical PTR-suffix map is consulted here; the operator exclude file's
// fcrdns rules are a follow-up (they live in internal/detectors, which webdetector
// can't import, and carry no bot name).
func (e *Engine) goodBotsForFinding(ips []string) map[string]string {
	if e == nil || e.enr == nil {
		return nil
	}
	return goodBotsFor(ips, func(ip string) string { return e.enr.LookupCachedOrAsync(ip).PTR }, solverFarmGoodBot, time.Now())
}

// goodBotsFor is the pure core of goodBotsForFinding (PTR source + verdict cache
// injected), so the sparse-map assembly is unit-testable without an Enricher or
// live DNS. ptrOf is called at most once per IP, only on a verdict-cache miss.
func goodBotsFor(ips []string, ptrOf func(string) string, gb *bridgeGoodBotState, now time.Time) map[string]string {
	if gb == nil || ptrOf == nil {
		return nil
	}
	var out map[string]string
	for _, ip := range ips {
		name := gb.verified(ip, func() string { return ptrOf(ip) }, now)
		if name == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string, 4)
		}
		out[ip] = name
	}
	return out
}

// solverFarmReason renders a short, human-readable summary for the history row.
func solverFarmReason(f solverfarm.Finding) string {
	fp := f.Fingerprint
	if fp == "" {
		fp = "(none)"
	}
	return fmt.Sprintf("solver farm on %s — fp %s [%s]: %d solves, %d /24, %d countries",
		f.Host, fp, f.Tracks, f.Solves, f.Subnets, f.Countries)
}
