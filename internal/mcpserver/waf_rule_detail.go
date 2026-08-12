package mcpserver

// waf_rule_detail gives a per-rule view of ONE WAF rule/reason-family across
// BOTH enforcement surfaces at once: the in-path WEB edge (cfm.lua, from the
// webdetector WAF-event history) and the PANEL edge (cfm_panel.lua, from the
// edge error-log LOGONLY/enforce lines that waf_fp_hunt aggregates). Since the
// panel now runs the SAME cfm_waf ruleset as the web edge, a rule that is clean
// on the web but fires on the panel from real browsers is exactly the
// false-positive this unifies into one lookup — the burn-in companion to the
// aggregate waf_activity (web) and waf_fp_hunt (panel) tools.
//
// The cross-surface join key is the REASON FAMILY (WAF_SQLI, WAF_RCE, …): web
// WAF events carry only the reason string (family[:tag]), not the panel log's
// numeric rule_id. So a numeric-id query is resolved to its family (via
// waf/rules) for the web side, while the panel side can match either. It
// composes three read-only endpoints in-process (no caller-controlled path).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type wafRuleDetailInput struct {
	Rule  string `json:"rule" jsonschema:"the rule to inspect: a reason family or substring (WAF_SQLI, WAF_RCE:EVAL, sqli) OR a numeric rule id (320, 10001). A numeric id is resolved to its reason family for the web side (web WAF events key on reason, not id)."`
	Hours int    `json:"hours,omitempty" jsonschema:"web look-back window in hours; default 24, max 720"`
}

func registerWAFRuleDetail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "waf_rule_detail",
		Description: "Deep-dive ONE WAF rule / reason-family across BOTH surfaces at once — the in-path WEB edge and the PANEL (cPanel/WHM) edge — because the panel now runs the same cfm_waf ruleset. Give a reason family or substring (WAF_SQLI, WAF_RCE:EVAL, sqli) or a numeric rule id (320, 10001; resolved to its family for the web side). Returns: matched_rules (id, reason_family, group, built-in default_mode) from the registry; web {total/blocked events, unique ips/hosts, top exact-reasons, top ips (GeoIP), top hosts, top countries} over the last `hours`; panel {hits, scanner vs non-scanner split, nonscanner_would_block, matched rule_ids, sample non-scanner requests} from the panel LOGONLY/enforce burn-in lines. Use it to answer 'is rule X safe to enforce?' and to spot a rule clean on the web but firing on the panel from real browsers (an FP). Complements waf_activity (web aggregate) and waf_fp_hunt (panel aggregate). Read the `notes`.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wafRuleDetailInput) (*mcp.CallToolResult, any, error) {
		query := strings.TrimSpace(in.Rule)
		if query == "" {
			return nil, nil, fmt.Errorf("waf_rule_detail: `rule` is required (a reason family, substring, or numeric rule id)")
		}
		hours := in.Hours
		if hours <= 0 {
			hours = 24
		}
		if hours > 720 {
			hours = 720
		}

		// Rules registry first — it resolves a numeric-id query to the reason
		// family the web summary filters on.
		rulesBody := section(ctx, d, "/api/v1/waf/rules", nil)
		if e := sectionError(rulesBody); e != "" {
			return nil, nil, fmt.Errorf("waf/rules: %s", e)
		}
		webFilter := webFilterForQuery(rulesBody, query)

		webQ := url.Values{"rule": {webFilter}, "enrich": {"1"}, "hours": {strconv.Itoa(hours)}}
		webBody := section(ctx, d, "/api/v1/waf/engine/summary", webQ)
		if e := sectionError(webBody); e != "" {
			return nil, nil, fmt.Errorf("waf/engine/summary: %s", e)
		}
		// Panel side is optional context: a non-panel node (or no edge error log)
		// must not fail the whole lookup — tolerate its absence with a note.
		panelBody := section(ctx, d, "/api/v1/system/waf-fp-hunt", nil)

		out := buildWAFRuleDetail(webBody, panelBody, rulesBody, query, webFilter, hours)
		b, err := marshal(out)
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// --- parse shapes (subset of each endpoint we consume) ----------------------

type wafRuleRow struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	GroupName    string `json:"group_name"`
	ReasonFamily string `json:"reason_family"`
	DefaultMode  string `json:"default_mode"`
}

type wafRulesBody struct {
	Rules []wafRuleRow `json:"rules"`
}

type wafTopKV struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}
type wafTopIP struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	PTR     string `json:"ptr,omitempty"`
	Country string `json:"country,omitempty"`
	ASNName string `json:"asn_name,omitempty"`
}

type wafSummaryBody struct {
	Hours         int        `json:"hours"`
	TotalEvents   int        `json:"total_events"`
	BlockedEvents int        `json:"blocked_events"`
	UniqueHosts   int        `json:"unique_hosts"`
	UniqueIPs     int        `json:"unique_ips"`
	TopRules      []wafTopKV `json:"top_rules"`
	TopHosts      []wafTopKV `json:"top_hosts"`
	TopIPs        []wafTopIP `json:"top_ips"`
	TopCountries  []wafTopKV `json:"top_countries"`
}

type panelRuleAgg struct {
	RuleID             string   `json:"rule_id"`
	Reason             string   `json:"reason"`
	Count              int      `json:"count"`
	ScannerHits        int      `json:"scanner_hits"`
	NonScannerHits     int      `json:"nonscanner_hits"`
	NonScannerWouldBlk int      `json:"nonscanner_would_block"`
	SampleNonScanner   []string `json:"sample_nonscanner,omitempty"`
}

type panelFPBody struct {
	OK      bool `json:"ok"`
	Summary struct {
		WAF struct {
			ByRule []panelRuleAgg `json:"by_rule"`
		} `json:"panel_waf"`
	} `json:"summary"`
}

// webFilterForQuery resolves the web-summary `rule` filter for the query. Web
// WAF events carry the reason family (not the numeric id), so a numeric query is
// mapped to the reason family of the matching registry rule; anything else is
// used verbatim (a family/substring the summary already filters on).
func webFilterForQuery(rulesBody json.RawMessage, query string) string {
	if id, err := strconv.Atoi(query); err == nil {
		var rb wafRulesBody
		if json.Unmarshal(rulesBody, &rb) == nil {
			for _, r := range rb.Rules {
				if r.ID == id && strings.TrimSpace(r.ReasonFamily) != "" {
					return r.ReasonFamily
				}
			}
		}
	}
	return query
}

// buildWAFRuleDetail is the pure assembler (separated from the handler so it is
// unit-testable). query is the caller's raw input; webFilter is what the web
// summary was actually queried with (query, or a resolved reason family).
func buildWAFRuleDetail(webBody, panelBody, rulesBody json.RawMessage, query, webFilter string, hours int) map[string]any {
	var notes []string
	ql := strings.ToLower(query)

	// Matched registry rules: numeric id exact, else family/name substring.
	var rb wafRulesBody
	_ = json.Unmarshal(rulesBody, &rb)
	qid, qErr := strconv.Atoi(query)
	qIsNum := qErr == nil
	matched := make([]wafRuleRow, 0, 4)
	hasBlockTier := false
	for _, r := range rb.Rules {
		hit := false
		if qIsNum {
			hit = r.ID == qid
		}
		if !hit {
			hit = strings.Contains(strings.ToLower(r.ReasonFamily), ql) ||
				strings.Contains(strings.ToLower(r.Name), ql)
		}
		if hit {
			matched = append(matched, r)
			if strings.EqualFold(r.DefaultMode, "block") {
				hasBlockTier = true
			}
		}
	}

	// Web side.
	var web wafSummaryBody
	if len(webBody) > 0 {
		if err := json.Unmarshal(webBody, &web); err != nil {
			notes = append(notes, "waf/engine/summary: unexpected response shape ("+err.Error()+")")
		}
	}

	// Panel side (optional).
	var panelHits, panelScanner, panelNonScanner, panelWouldBlk int
	panelIDs := map[string]struct{}{}
	panelSamples := []string{}
	panelAvailable := false
	if e := sectionError(panelBody); e != "" {
		notes = append(notes, "panel burn-in unavailable (waf-fp-hunt: "+e+"): panel side omitted — non-panel node or no edge error log.")
	} else {
		var pf panelFPBody
		if err := json.Unmarshal(panelBody, &pf); err != nil {
			notes = append(notes, "waf-fp-hunt: unexpected response shape ("+err.Error()+")")
		} else {
			panelAvailable = true
			for _, ra := range pf.Summary.WAF.ByRule {
				// Match the same query against the panel rows: numeric id exact,
				// else reason substring.
				hit := false
				if qIsNum {
					hit = ra.RuleID == query
				}
				if !hit {
					hit = strings.Contains(strings.ToLower(ra.Reason), ql)
				}
				if !hit {
					continue
				}
				panelHits += ra.Count
				panelScanner += ra.ScannerHits
				panelNonScanner += ra.NonScannerHits
				panelWouldBlk += ra.NonScannerWouldBlk
				if ra.RuleID != "" {
					panelIDs[ra.RuleID] = struct{}{}
				}
				for _, s := range ra.SampleNonScanner {
					if len(panelSamples) < 5 {
						panelSamples = append(panelSamples, s)
					}
				}
			}
		}
	}

	// Notes: the operator-facing signal.
	if len(matched) == 0 {
		notes = append(notes, "no registry rule matched \""+query+"\" — check the family/id (see waf_rules); the web/panel counts below still reflect a reason substring match.")
	}
	if web.TotalEvents == 0 && (!panelAvailable || panelHits == 0) {
		notes = append(notes, "no hits for \""+query+"\" on either surface in the window.")
	}
	if panelNonScanner > 0 && panelWouldBlk > 0 {
		notes = append(notes, fmt.Sprintf("panel: %d non-scanner request(s) a BLOCK-tier rule would deny — review these before/while enforcing on the panel (FP risk).", panelWouldBlk))
	}
	if hasBlockTier {
		notes = append(notes, "at least one matched rule ships default_mode=block (enforcing tier). default_mode is the built-in default; the LIVE tier can differ per detectors.conf.")
	}

	ids := make([]string, 0, len(panelIDs))
	for id := range panelIDs {
		ids = append(ids, id)
	}

	panelOut := any(nil)
	if panelAvailable {
		panelOut = map[string]any{
			"hits":                  panelHits,
			"scanner_hits":          panelScanner,
			"nonscanner_hits":       panelNonScanner,
			"nonscanner_would_block": panelWouldBlk,
			"matched_rule_ids":      ids,
			"sample_nonscanner":     panelSamples,
		}
	}

	return map[string]any{
		"rule_query":     query,
		"web_filter":     webFilter,
		"hours":          hours,
		"matched_rules":  matched,
		"web": map[string]any{
			"total_events":   web.TotalEvents,
			"blocked_events": web.BlockedEvents,
			"unique_ips":     web.UniqueIPs,
			"unique_hosts":   web.UniqueHosts,
			"top_reasons":    web.TopRules,
			"top_hosts":      web.TopHosts,
			"top_ips":        web.TopIPs,
			"top_countries":  web.TopCountries,
		},
		"panel":            panelOut,
		"panel_available":  panelAvailable,
		"notes":            notes,
	}
}
