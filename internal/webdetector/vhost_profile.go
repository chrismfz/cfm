package webdetector

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// GET /api/v1/webdet/vhost-profile?host=<host>
//
// One host's posture: every per-vhost setting that applies to it, with what
// decided each one. It is the "what applies here" half of the cfm-admin Vhost
// page; the traffic and security halves are the existing per-host endpoints
// (traffic-mix?host=, history/vhost-overview?host=, history/waf-by-rule?host=).
//
// Nothing here is a copy of a matcher: each block is computed by the function
// the enforcement path (or the surface that already reports it) uses —
//
//   - controls:           vhostControlRow, the /webdet/vhosts row (challenge /
//     WAF / HTTP3 / ClamAV columns, under attack, challengeV2VhostTier,
//     lockdown);
//   - challenge:          vhostChallengeStatus, the /challenge/vhost/status body;
//   - waf_excludes:       excludeStore.WAFEntriesForHost: what the in-path WAF
//     (cfm.lua waf_skip_for) applies on the host, each entry flagged with
//     whether its scope_hosts take the host (the edge ignores them);
//   - challenge_excludes: excludeStore.ChallengeEntriesForHost (MatchChallenge /
//     MatchChallengePath);
//   - site_cache:         siteCacheStore.PolicyFor (the edge's policy_key_for,
//     also behind StatsKeyFor) plus the node switches;
//   - rules:              ruleHostMatchPattern (Simulate's host test), every
//     rule in evaluation order, with its state.
//
// Admin only: the profile names operator policy (tier sources, pins, every
// rule and exclude whatever its scope), which scoped callers never see.
func (e *Engine) handleVhostProfile(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	if e == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "engine unavailable"})
		return
	}
	host := normalizeControlHost(normalizeHost(r.URL.Query().Get("host")))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	writeJSON(w, http.StatusOK, e.VhostProfile(host, time.Now()))
}

// VhostProfileSchema versions the vhost-profile payload.
const VhostProfileSchema = "webdet.vhost_profile.v1"

// vhostProfileMaxRelated caps related_hosts (a reseller apex can carry many).
const vhostProfileMaxRelated = 200

type VhostProfile struct {
	Schema      string    `json:"schema"`
	Host        string    `json:"host"`
	GeneratedAt time.Time `json:"generated_at"`
	// Site is the registrable domain (example.co.uk for www.example.co.uk);
	// RelatedHosts are the known hosts of that site, this one included
	// (cPanel userdata, recent traffic, challenge rows), sorted.
	Site         string   `json:"site"`
	RelatedHosts []string `json:"related_hosts"`
	// RelatedTruncated: more than vhostProfileMaxRelated related hosts.
	RelatedTruncated bool `json:"related_truncated,omitempty"`

	Controls          webdetVhostControlRow  `json:"controls"`
	Challenge         map[string]interface{} `json:"challenge"`
	WAFExcludes       []WAFHostMatch         `json:"waf_excludes"`
	ChallengeExcludes []excludeEntry         `json:"challenge_excludes"`
	SiteCache         VhostProfileSiteCache  `json:"site_cache"`
	Rules             []VhostProfileRule     `json:"rules"`
}

type VhostProfileSiteCache struct {
	// Key is the policy that decides this host at the edge (the host itself
	// or a covering "*.suffix"); empty when none does, i.e. nothing is
	// cached for it. Inherited: Key is not the host (a wildcard decides it).
	Key       string          `json:"key,omitempty"`
	Inherited bool            `json:"inherited,omitempty"`
	Entry     *SiteCacheEntry `json:"entry,omitempty"`
	// Unloadable: Key is a stored policy this build cannot load; the edge
	// treats it as opted out (never cached).
	Unloadable bool `json:"unloadable,omitempty"`
	// Switches is the node's SITE_CACHE / MICRO_CACHE_ENFORCE pair as the
	// edge was last handed it (absent until the daemon wrote it); either
	// overrides Entry on this node.
	Switches *SiteCacheSwitches `json:"switches,omitempty"`
}

type VhostProfileRule struct {
	TrafficRule
	// MatchedBy is the scope pattern that takes this host.
	MatchedBy string `json:"matched_by"`
	// State: "enabled" (evaluated), "disabled" (a would-match), "expired"
	// (its until passed: never matches again), "unsupported" (written by a
	// newer cfm; never evaluated by this build).
	State string `json:"state"`
}

// VhostProfile builds the profile of a normalized host.
func (e *Engine) VhostProfile(host string, now time.Time) VhostProfile {
	p := VhostProfile{
		Schema:            VhostProfileSchema,
		Host:              host,
		GeneratedAt:       now.UTC(),
		Site:              vhostProfileSite(host),
		Controls:          e.vhostControlRow(e.vhostControlInputs(), host),
		Challenge:         e.vhostChallengeStatus(host, nil),
		WAFExcludes:       []WAFHostMatch{},
		ChallengeExcludes: []excludeEntry{},
		Rules:             []VhostProfileRule{},
	}
	p.RelatedHosts, p.RelatedTruncated = e.vhostProfileRelated(host, p.Site)

	if got := e.wafExcludes.WAFEntriesForHost(host); got != nil {
		p.WAFExcludes = got
	}
	if got := e.challengeExcludes.ChallengeEntriesForHost(host); got != nil {
		p.ChallengeExcludes = got
	}

	p.SiteCache.Switches = publishedSiteCacheSwitches.Load()
	if e.siteCache != nil {
		if key, entry, ok := e.siteCache.PolicyFor(host); ok {
			p.SiteCache.Key = key
			p.SiteCache.Inherited = key != host
			ent := entry
			p.SiteCache.Entry = &ent
			for _, h := range e.siteCache.FrozenHosts() {
				if h == key {
					p.SiteCache.Unloadable = true
					p.SiteCache.Entry = nil // a stand-in, not the stored policy
					break
				}
			}
		}
	}

	if e.trafficRules != nil {
		for _, rule := range e.trafficRules.List() {
			pat, ok := ruleHostMatchPattern(rule.Scope.Vhosts, host)
			if !ok {
				continue
			}
			p.Rules = append(p.Rules, VhostProfileRule{
				TrafficRule: rule,
				MatchedBy:   pat,
				State:       vhostProfileRuleState(rule, now),
			})
		}
	}
	return p
}

func vhostProfileRuleState(r TrafficRule, now time.Time) string {
	switch {
	case r.Unsupported:
		return "unsupported"
	case r.Match.Expired(now):
		return "expired"
	case !r.Enabled:
		return "disabled"
	}
	return "enabled"
}

// vhostProfileSite is host's registrable domain (one owner's www., shop. and
// bare names are one site); host itself when it has none (an IP, a bare TLD).
func vhostProfileSite(host string) string {
	if d, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		return d
	}
	return host
}

// vhostProfileRelated lists the known hosts of site, host included.
func (e *Engine) vhostProfileRelated(host, site string) ([]string, bool) {
	set := map[string]struct{}{host: {}}
	for h := range e.collectKnownVhosts() {
		h = normalizeControlHost(h)
		if h == site || strings.HasSuffix(h, "."+site) {
			set[h] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		// The site first, then by name.
		if (out[i] == site) != (out[j] == site) {
			return out[i] == site
		}
		return out[i] < out[j]
	})
	if len(out) > vhostProfileMaxRelated {
		// Keep host itself in a truncated list.
		trimmed := out[:vhostProfileMaxRelated]
		found := false
		for _, h := range trimmed {
			if h == host {
				found = true
				break
			}
		}
		if !found {
			trimmed[len(trimmed)-1] = host
		}
		return trimmed, true
	}
	return out, false
}
