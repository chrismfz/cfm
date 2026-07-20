package webdetector

import (
	"net/http"
	"strconv"
	"strings"
)

// RuleHitRate is one row of /api/v1/waf/hit-rates response — per-rule hit
// count + rate over the requested window, plus a promotion hint that maps
// the rate to the rollout playbook's <0.01% gate.
type RuleHitRate struct {
	ID            int     `json:"id"`
	Name          string  `json:"name"`
	Group         int     `json:"group"`
	GroupName     string  `json:"group_name"`
	ReasonFamily  string  `json:"reason_family"`
	DefaultMode   string  `json:"default_mode"`
	Hits          int     `json:"hits"`
	RatePct       float64 `json:"rate_pct"`       // hits / inspected * 100
	PromotionHint string  `json:"promotion_hint"` // ok_to_promote | silent | review | noisy | n_a
}

// HitRatesResult is the /api/v1/waf/hit-rates response envelope.
type HitRatesResult struct {
	Hours          int           `json:"hours"`
	Host           string        `json:"host"`
	InspectedTotal int           `json:"inspected_total"`
	Rules          []RuleHitRate `json:"rules"`
}

// hitRatePromotionHint maps a (rate_pct, hits, inspected) triple to a label
// the operator can act on. Thresholds match the rollout playbook in
// docs/waf.md ("<0.01% FP rate before promoting"); over time these may
// move into config.
//
//	ok_to_promote — fired but at <0.01% (clean signal, ready to promote)
//	silent        — never fired in window (verify rule isn't broken)
//	review        — fired between 0.01% and 1% (likely some FP, investigate)
//	noisy         — fired at >=1% (FP-heavy, demote or tighten)
//	n_a           — no inspection data yet
func hitRatePromotionHint(ratePct float64, hits, inspected int) string {
	if inspected == 0 {
		return "n_a"
	}
	if hits == 0 {
		return "silent"
	}
	if ratePct < 0.01 {
		return "ok_to_promote"
	}
	if ratePct < 1.0 {
		return "review"
	}
	return "noisy"
}

// handleWAFHitRates implements GET /api/v1/waf/hit-rates?hours=24[&host=X].
//
// Joins the WAFRules() registry (PR A) with WAFHitsByRuleID hits and the
// WAFInspected denominator. Returns one row per registered rule even when
// hits=0, so operators can see "this rule is silent" alongside "this rule
// is noisy".
//
// Scoped-allowed with a vhost-scope guard: admin/loopback callers may pass any
// host (or none for the fleet-wide aggregate); a scoped token must target a
// single host within its allowlist, and an empty or out-of-scope host is 403
// (see the scope block below — audit F02).
func (e *Engine) handleWAFHitRates(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 && n <= 24*30 {
			hours = n
		}
	}
	// Normalize once. Hosts are stored canonical-lowercase in history and the
	// scope allowlist keys are lowercased at token issue, so lowercasing here
	// keeps the scope check, the history reads, and the echoed Host in agreement
	// (a mixed-case ?host=Foo.COM must not authorize and then read empty).
	host := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host")))

	// Scope enforcement (audit F02), keyed on ROLE — not on `scope != nil`.
	// Admin/loopback may read any host, or the fleet-wide aggregate when host is
	// empty. Any non-admin (scoped) caller MUST target a single host inside a
	// NON-EMPTY vhost allowlist: an empty host (which would aggregate every
	// tenant), an empty/nil scope (e.g. a db-only scoped token whose Vhosts map
	// is nil), and any out-of-scope host are all refused. Keying on
	// IsAdminRequest (like scopedMySQLFilterHandler) means a vhost-less scoped
	// token can never be misclassified as admin through a nil scope map.
	if !IsAdminRequest(r) {
		scope := vhostScopeFromContext(r.Context())
		if host == "" || len(scope) == 0 || !vhostAllowed(host, scope) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": errForbidden})
			return
		}
	}

	inspected := 0
	if e != nil && e.history != nil {
		inspected = e.WAFInspected(host, hours)
	}
	perRule := map[int]int{}
	if e != nil && e.history != nil {
		if m, err := e.history.WAFHitsByRuleID(host, hours); err == nil {
			perRule = m
		}
	}

	rules := WAFRules()
	out := make([]RuleHitRate, 0, len(rules))
	for _, rule := range rules {
		hits := perRule[rule.ID]
		ratePct := 0.0
		if inspected > 0 {
			ratePct = float64(hits) / float64(inspected) * 100
		}
		out = append(out, RuleHitRate{
			ID:            rule.ID,
			Name:          rule.Name,
			Group:         rule.Group,
			GroupName:     rule.GroupName,
			ReasonFamily:  rule.ReasonFamily,
			DefaultMode:   rule.DefaultMode,
			Hits:          hits,
			RatePct:       ratePct,
			PromotionHint: hitRatePromotionHint(ratePct, hits, inspected),
		})
	}

	writeJSON(w, http.StatusOK, HitRatesResult{
		Hours:          hours,
		Host:           host,
		InspectedTotal: inspected,
		Rules:          out,
	})
}
