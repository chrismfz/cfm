package mcpserver

// tools.go registers the read-only MCP tool set. Every tool maps to a hard-coded,
// allow-listed /api/v1 GET endpoint (the same one the CLI/web UI use) and passes
// user args through as typed query params — the path is never caller-controlled,
// so the surface stays read-only and bounded. Keep this list and MCP.md in sync.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// overviewSectionBudget bounds how long any single security_overview section may
// take. The sections run concurrently (see registerSecurityOverview), so the
// tool's latency is ~the slowest section rather than the sum of all five; this
// caps a stuck/slow read so it degrades to an error object instead of blowing the
// MCP client's ~60s per-call timeout. A var so tests can shrink it.
var overviewSectionBudget = 25 * time.Second

var readOnly = &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: ptrTrue()}

func ptrTrue() *bool { b := true; return &b }

type emptyInput struct{}

// registerTools wires the full read-only tool set onto srv. Single choke point.
func registerTools(srv *mcp.Server, d Deps) {
	registerWhatsWrong(srv, d)
	registerSecurityOverview(srv, d)
	registerWAFActivity(srv, d)
	registerWAFRules(srv, d)
	registerWAFRuleDetail(srv, d)
	registerChallengeVhosts(srv, d)
	registerChallengeEvents(srv, d)
	registerSuspiciousHosts(srv, d)
	registerTopTalkers(srv, d)
	registerHotIPs(srv, d)
	registerHostDrilldown(srv, d)
	registerIPDrilldown(srv, d)
	registerDetectionHistory(srv, d)
	registerBotsTop(srv, d)
	registerFirewallBlocks(srv, d)
	registerFirewallCounters(srv, d)
	registerFirewallSelfTest(srv, d)
	registerIPLocate(srv, d)
	registerDetectorsStatus(srv, d)
	registerSystemHealth(srv, d)
	registerProcessList(srv, d)
	registerProcessHealth(srv, d)
	registerListeningPorts(srv, d)
	registerDmesgTail(srv, d)
	registerServiceStatus(srv, d)
	registerEdgeAccessTail(srv, d)
	registerIPForensics(srv, d)
	registerEdgeErrorTail(srv, d)
	registerWAFFPHunt(srv, d)
	registerAbuseShadow(srv, d)
	registerLSMDetections(srv, d)
	registerLSMStatus(srv, d)
	registerLVECPU(srv, d)
	registerMySQLPressure(srv, d)
	registerDBWebPressure(srv, d)
	registerCPUThrottle(srv, d)
	registerClamStatus(srv, d)
	registerNotifierStatus(srv, d)
	registerHTTP3Status(srv, d)
	registerMailRuntime(srv, d)
	registerMySQLLogTail(srv, d)
	registerMySQLSlowQueries(srv, d)
	registerCFMLogTail(srv, d)
	registerJournalTail(srv, d)
	registerMailQueueSummary(srv, d)
	registerMailLogTail(srv, d)
	registerMailTraffic(srv, d)
	registerMailDNSCheck(srv, d)
}

// ── query-param helpers ────────────────────────────────────────────────────────

func setInt(q url.Values, key string, v int) {
	if v > 0 {
		q.Set(key, strconv.Itoa(v))
	}
}

func setStr(q url.Values, key, v string) {
	if v != "" {
		q.Set(key, v)
	}
}

// ── overview ────────────────────────────────────────────────────────────────────

func registerSecurityOverview(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "security_overview",
		Description: "Headline security picture for this CFM node in one call: system health, recent WAF activity (last hour), active challenged vhosts, current firewall-block count, and top suspicious hosts. Deliberately compact — counts + top-N, not full lists; call firewall_blocks / waf_activity for the raw rows. Start here for \"what's going on right now?\", then drill in.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		secs := []struct {
			key, path string
			q         url.Values
		}{
			{"health", "/api/v1/health/snapshot", nil},
			{"waf_last_hour", "/api/v1/waf/engine/summary", url.Values{"hours": {"1"}, "top": {"10"}, "enrich": {"1"}}},
			{"challenge_vhosts", "/api/v1/challenge/vhosts", url.Values{"status": {"active"}, "mode": {"all"}, "limit": {"100"}}},
			{"firewall_blocks", "/api/v1/firewall/list", nil},
			{"suspicious_hosts", "/api/v1/webdet/suspicious", url.Values{"limit": {"20"}}},
		}
		// Run the sections concurrently and cap each with overviewSectionBudget, so
		// the composed call's latency is ~the slowest section (not the sum) and a
		// single slow endpoint degrades to a per-section error instead of blowing
		// the MCP client's ~60s timeout for the whole tool.
		out := make(map[string]any, len(secs))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, s := range secs {
			wg.Add(1)
			go func(key, path string, q url.Values) {
				defer wg.Done()
				res := compactOverviewSection(key, sectionBudgeted(ctx, d, path, q))
				mu.Lock()
				out[key] = res
				mu.Unlock()
			}(s.key, s.path, s.q)
		}
		wg.Wait()
		b, err := marshal(out)
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// overviewRowSample bounds how many rows any embedded list keeps in the
// composed security_overview (counts stay authoritative; the full list lives in
// the dedicated tool).
const overviewRowSample = 10

// compactOverviewSection trims a section body to headline size. The underlying
// endpoints embed full lists — firewall/list returns every active block (1000s),
// waf/engine/summary carries the raw per-hit rows — which turn the "headline"
// tool into hundreds of KB and blow the MCP response budget. We keep the
// summary (counts, top-N, histogram) and drop/sample the big arrays, pointing
// the caller to firewall_blocks / waf_activity for the raw rows. A non-object
// body (error stub, array) is passed through untouched.
func compactOverviewSection(key string, body json.RawMessage) any {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return body
	}
	switch key {
	case "firewall_blocks":
		if rows, ok := m["rows"].([]any); ok {
			m["rows_total"] = len(rows)
			if len(rows) > overviewRowSample {
				m["rows"] = rows[:overviewRowSample]
				m["rows_truncated"] = true
				m["note"] = "sample only; call firewall_blocks for the full list"
			}
		}
	case "waf_last_hour":
		// top_rules/top_ips/top_countries/histogram are the summary; the raw
		// per-hit rows are what bloat it — drop them.
		if _, ok := m["rows"]; ok {
			delete(m, "rows")
			m["note"] = "summary only; call waf_activity for the raw hit rows"
		}
	}
	return m
}

// sectionBudgeted runs one composed-tool section under overviewSectionBudget,
// returning its body or an {"error":...} object if it overruns — so one slow read
// can't hold the whole composed call past the client timeout. The dispatch runs
// on a child context (best-effort cancellation for ctx-aware handlers); the
// buffered channel lets a late-returning dispatch finish without leaking a blocked
// goroutine.
func sectionBudgeted(ctx context.Context, d Deps, path string, q url.Values) json.RawMessage {
	cctx, cancel := context.WithTimeout(ctx, overviewSectionBudget)
	defer cancel()
	ch := make(chan json.RawMessage, 1)
	go func() { ch <- section(cctx, d, path, q) }()
	select {
	case res := <-ch:
		return res
	case <-cctx.Done():
		e, _ := json.Marshal(map[string]string{"error": "section timed out"})
		return e
	}
}

// section runs one read endpoint for a composed tool, returning its body as raw
// JSON or a small {"error":...} object so one failing section never sinks the call.
func section(ctx context.Context, d Deps, path string, q url.Values) json.RawMessage {
	status, body, err := d.Dispatch(ctx, path, q)
	if err != nil {
		e, _ := json.Marshal(map[string]string{"error": err.Error()})
		return e
	}
	if status < 200 || status >= 300 {
		e, _ := json.Marshal(map[string]any{"error": "HTTP " + strconv.Itoa(status)})
		return e
	}
	if !json.Valid(body) {
		e, _ := json.Marshal(map[string]string{"error": "non-JSON response"})
		return e
	}
	return body
}

// ── WAF ───────────────────────────────────────────────────────────────────────

type wafActivityInput struct {
	Hours int `json:"hours,omitempty" jsonschema:"look-back window in hours; default 24"`
	Limit int `json:"limit,omitempty" jsonschema:"max recent hit rows to return; default server-side"`
	Top   int `json:"top,omitempty" jsonschema:"how many top rules/IPs to rank; default server-side"`
}

func registerWAFActivity(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "waf_activity",
		Description: "WAF engine summary: recent in-path WAF hits, the top firing rules, top source IPs (GeoIP-enriched), and a per-hour histogram over the window. Answers \"is the WAF firing, on what rules, from where?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wafActivityInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{"enrich": {"1"}}
		setInt(q, "hours", in.Hours)
		setInt(q, "limit", in.Limit)
		setInt(q, "top", in.Top)
		return dispatchJSON(ctx, d, "/api/v1/waf/engine/summary", q)
	})
}

func registerWAFRules(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "waf_rules",
		Description: "The WAF rules currently loaded in the edge (id, reason family, tier: logonly/challenge/block). Use to see what the WAF can detect and at what enforcement tier.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/waf/rules", nil)
	})
}

// ── Challenge engine ────────────────────────────────────────────────────────────

type challengeVhostsInput struct {
	Status string `json:"status,omitempty" jsonschema:"filter by challenge status, e.g. active; omit for all"`
	Mode   string `json:"mode,omitempty" jsonschema:"filter by how the challenge was set: manual, auto, or all; default all"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max vhosts to return; default server-side"`
}

func registerChallengeVhosts(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "challenge_vhosts",
		Description: "Virtual hosts under an interactive challenge (proof-of-work / JS), showing whether each was set manually or automatically by the detector, plus its current state. Answers \"which sites are being challenged and why?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in challengeVhostsInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "status", in.Status)
		setStr(q, "mode", in.Mode)
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/challenge/vhosts", q)
	})
}

type challengeEventsInput struct {
	Limit int    `json:"limit,omitempty" jsonschema:"max events to return; default server-side"`
	Host  string `json:"host,omitempty" jsonschema:"restrict to one vhost; omit for all vhosts"`
}

func registerChallengeEvents(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "challenge_events",
		Description: "Recent challenge-engine events (arm / pass / fail) across vhosts, newest first. Answers \"are visitors solving the challenge, and when did challenges get armed?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in challengeEventsInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "limit", in.Limit)
		setStr(q, "host", in.Host)
		return dispatchJSON(ctx, d, "/api/v1/challenge/events", q)
	})
}

// ── Traffic & attacks (web detector) ────────────────────────────────────────────

type limitInput struct {
	Limit int `json:"limit,omitempty" jsonschema:"max rows to return; default server-side"`
}

func registerSuspiciousHosts(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "suspicious_hosts",
		Description: "Long-window suspicious vhosts ranked by behavioural score — the scanners / attackers / abusive clients the log-driven detector is flagging. Answers \"who is attacking, and how badly?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in limitInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/webdet/suspicious", q)
	})
}

type topTalkersInput struct {
	Limit  int    `json:"limit,omitempty" jsonschema:"max hosts to return; default server-side"`
	Window string `json:"window,omitempty" jsonschema:"short (recent, default) or long (long-window) traffic window"`
}

func registerTopTalkers(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "top_talkers",
		Description: "Vhosts by request volume / rate — the busiest sites, i.e. where load and any request-rate spikes are. Use window=short for the recent window (spikes/RPS) or window=long for sustained volume.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in topTalkersInput) (*mcp.CallToolResult, any, error) {
		path := "/api/v1/webdet/top-short"
		if strings.EqualFold(strings.TrimSpace(in.Window), "long") {
			path = "/api/v1/webdet/long-top"
		}
		q := url.Values{}
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, path, q)
	})
}

func registerHotIPs(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "hot_ips",
		Description: "The hottest source IPs by recent request rate across all vhosts — the individual clients driving traffic right now.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in limitInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/webdet/ip-short", q)
	})
}

type hostDrilldownInput struct {
	Host string `json:"host" jsonschema:"the vhost to drill into (from top_talkers / suspicious_hosts / challenge_vhosts)"`
	Top  int    `json:"top,omitempty" jsonschema:"how many top paths/IPs to include; default server-side"`
}

func registerHostDrilldown(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "host_drilldown",
		Description: "Per-vhost drilldown: the top request paths and top source IPs hitting one host, in both the short and long windows. The \"why is this host busy/suspicious?\" view.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in hostDrilldownInput) (*mcp.CallToolResult, any, error) {
		// The SDK's schema enforces `host` is PRESENT (no omitempty); this guard
		// additionally rejects present-but-empty ("host":"").
		if strings.TrimSpace(in.Host) == "" {
			return nil, nil, errRequired("host")
		}
		q := url.Values{"host": {in.Host}}
		setInt(q, "top", in.Top)
		return dispatchJSON(ctx, d, "/api/v1/webdet/drilldown", q)
	})
}

type ipDrilldownInput struct {
	IP string `json:"ip" jsonschema:"the source IP to drill into (from hot_ips / suspicious host drilldown / firewall_blocks)"`
}

type edgeAccessTailInput struct {
	IP     string `json:"ip,omitempty" jsonschema:"filter to one source IP (e.g. the IP from a WAF hit / firewall_blocks)"`
	Host   string `json:"host,omitempty" jsonschema:"filter to one vhost"`
	Method string `json:"method,omitempty" jsonschema:"filter by HTTP method (get/post/…)"`
	Status string `json:"status,omitempty" jsonschema:"filter by status: an exact code ('403') or a class digit ('4' = 4xx, '5' = 5xx)"`
	Path   string `json:"path,omitempty" jsonschema:"case-insensitive substring of the request URI (e.g. 'admin-ajax.php')"`
	Since  string `json:"since,omitempty" jsonschema:"only entries newer than now minus this duration (e.g. '10m', '2h')"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max rows (default 50, max 500)"`
}

type ipForensicsInput struct {
	IP             string `json:"ip" jsonschema:"the source IP to look up (e.g. from a WAF hit / firewall_blocks / suspicious_hosts)"`
	Lines          int    `json:"lines,omitempty" jsonschema:"how many trailing access-log lines to scan (tail window); default 300000, max 2000000"`
	Limit          int    `json:"limit,omitempty" jsonschema:"max matching lines to return (default 200, max 1000)"`
	Source         string `json:"source,omitempty" jsonschema:"which edge access log to scan (basename or full path from the available list); omit for the default main access log"`
	IncludeRotated bool   `json:"include_rotated,omitempty" jsonschema:"also scan the rotated siblings of the resolved log (access.log.1, .2.gz, -YYYYMMDD.gz) newest-first, to reach evidence from before the last logrotate; default false (live file only)"`
	MaxFiles       int    `json:"max_files,omitempty" jsonschema:"when include_rotated is set, cap how many rotated siblings to scan (default 10, max 60)"`
}

func registerIPForensics(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "ip_forensics",
		Description: "On-demand: the raw edge access-log lines for one source IP — what it actually requested, for correlating an OLDER WAF hit (reaches back further than edge_access_tail's live ring; complements ip_drilldown's aggregate vhosts/rate/score). Runs the equivalent of `tail -n N access.log | grep <ip>`: bounded to the last N lines (default 300k) with a timeout and a capped result, so it costs nothing until called and never scans a multi-GB log whole. Returns raw log lines (and `files_scanned`). Set include_rotated=true to ALSO scan the resolved log's rotated siblings (access.log.1, .2.gz, -YYYYMMDD.gz) newest-first — evidence from before the last logrotate — still bounded (max_files siblings, default 10; a shared line budget; one timeout; gz streamed). For the aggregate 'how much / which vhosts' use ip_drilldown; for right-now traffic use edge_access_tail.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ipForensicsInput) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(in.IP) == "" {
			return nil, nil, errRequired("ip")
		}
		q := url.Values{}
		setStr(q, "ip", in.IP)
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "source", in.Source)
		if in.IncludeRotated {
			q.Set("include_rotated", "1")
		}
		setInt(q, "max_files", in.MaxFiles)
		return dispatchJSON(ctx, d, "/api/v1/system/ip-forensics", q)
	})
}

type edgeErrorTailInput struct {
	Grep   string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter (e.g. 'logonly=would_enforce', 'cfm_decision', '[error]', a vhost); omit for the raw tail"`
	Lines  int    `json:"lines,omitempty" jsonschema:"how many trailing error-log lines to scan (tail window); default 5000, max 200000"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max matching lines to return, NEWEST first-kept (default 200, max 1000)"`
	Source string `json:"source,omitempty" jsonschema:"which edge error log to scan (basename or full path from the available list); omit for the default"`
}

func registerEdgeErrorTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "edge_error_tail",
		Description: "Tail the edge (OpenResty/Angie) ERROR log — where the in-path Lua writes ngx.log(): the panel LOGONLY decision verdicts ('[cfm_panel_decision] logonly=would_enforce …' — what the bridge WOULD challenge/block on panel human-entry), module-load failures, and Lua runtime errors. This is the companion to edge_access_tail (which is the ACCESS ring and cannot show error-log lines). Bounded on-demand tail (last N lines, default 5000) with an optional case-insensitive grep, returning the newest matches; costs nothing until called. For a specific IP's raw requests use ip_forensics; for right-now access traffic use edge_access_tail.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in edgeErrorTailInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "grep", in.Grep)
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "source", in.Source)
		return dispatchJSON(ctx, d, "/api/v1/system/edge-error-log", q)
	})
}

type wafFPHuntInput struct {
	Lines  int    `json:"lines,omitempty" jsonschema:"how many trailing edge error-log lines to scan (tail window); default 5000, max 200000"`
	Source string `json:"source,omitempty" jsonschema:"which edge error log to scan (basename or full path from the available list); omit for the default"`
}

func registerWAFFPHunt(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "waf_fp_hunt",
		Description: "Aggregate the panel LOGONLY burn-in signal from the edge ERROR log to answer 'is it safe to turn panel enforcement on?'. Scans the edge error log for the panel WAF would-be actions ('[cfm_panel_waf] logonly=would_block/would_challenge/…', Phase 2e) and the panel bridge-decision would-enforce verdicts ('[cfm_panel_decision] logonly=would_enforce …', Phase 2d) and returns aggregates that SEPARATE expected internet-scanner noise (Censys/Shodan/… by UA) from the customer-facing residue. The two numbers that gate enforcement: panel_waf.nonscanner_would_block (non-scanner clients a panel WAF BLOCK rule would have blocked) and panel_decision.ip_block_count (requests the bridge would ip-block on a panel port); both near-zero after excluding scanners ⇒ header/URI/args rules are safe to enforce. Also returns per-rule breakdowns, candidate false positives (worst first, with sample requests) and top user-agents. Bounded on-demand tail (last N lines, default 5000); costs nothing until called. NOTE the panel WAF reads no request body, so body-rule coverage is not represented here. Companion to edge_error_tail (raw lines) — this is the aggregated view.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in wafFPHuntInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "lines", in.Lines)
		setStr(q, "source", in.Source)
		return dispatchJSON(ctx, d, "/api/v1/system/waf-fp-hunt", q)
	})
}

type abuseShadowInput struct {
	Lines int `json:"lines,omitempty" jsonschema:"how many trailing abuse-shadow log lines to scan (tail window); default 5000, max 200000"`
}

func registerAbuseShadow(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "abuse_shadow",
		Description: "Aggregate the LOG-ONLY abuse-shadow burn-in log (/var/log/cfm/cfm.abuse_shadow.log) to answer 'what would the entity-abuse signals have challenged, and is it safe to enforce?'. Signal C flags a per-IP request-rate OUTLIER against the vhost's own median (the concentrated shape — a few IPs doing many× the site's normal per-IP rate, e.g. a scraper melting one shop's backend — that hides UNDER the vhost-aggregate score and is missed by the uniqIP path). This tool tails those log lines and returns: would_challenge vs exempt_goodbot counts, unique hosts/IPs, the top would-challenge (host,ip) outliers by peak ratio (with hits, max reqs, datacenter provider tag), the by-provider (datacenter-ASN), by-country (ISO-2 of the source IP), and by-good-bot (FCrDNS-verified, e.g. Googlebot/Bingbot) splits. NOTHING here is enforced — it's the measurement view to tune ABUSE_SHADOW_RATE_* and confirm FPs (verified bots correctly land in exempt_goodbot) before promoting Signal C to a real per-IP challenge. Empty summary when the feature is off / the log doesn't exist yet. Bounded on-demand tail (default 5000 lines); costs nothing until called. See docs/webdetector-refactor.md.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in abuseShadowInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "lines", in.Lines)
		return dispatchJSON(ctx, d, "/api/v1/system/abuse-shadow", q)
	})
}

type lveCPUInput struct {
	Top int `json:"top,omitempty" jsonschema:"how many tenants (by CPU pressure) to return, hottest first; default 25, max 500"`
}

func registerLVECPU(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "lve_cpu",
		Description: "Per-tenant CPU pressure on CloudLinux (LVE) — which hosting account is burning CPU right now. Reads the in-memory collector that samples /proc/lve/list every ~15s and returns each tenant hottest-first with: uid + username (the resolved login — on cPanel/DirectAdmin the Linux user IS the hosting account, so this is WHO to look at; empty if the uid has no passwd entry, and the default/aggregate LVE uid 4294967295 is labelled '(default LVE / outside)', not a real account), cores (CPU cores consumed, 0.93 = 93% of one core), pct_of_limit (% of the account's LVE CPU cap; 100 = at its limit → being throttled), plus its lCPU/nCPU limits and current EP/NPROC. The per-tenant companion to mysql_pressure — use it for 'the box load is high, which account is responsible?' and correlate with vhost hit-rates (a tenant near 100% of its CPU cap with few requests = heavy/looping code, not traffic). `available:false` on non-CloudLinux hosts; `ready:false` briefly at startup (needs two samples).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lveCPUInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "top", in.Top)
		return dispatchJSON(ctx, d, "/api/v1/system/lve-cpu", q)
	})
}

type mysqlPressureInput struct {
	Top int `json:"top,omitempty" jsonschema:"how many top users (by pressure) to return; default 25, max 200"`
}

func registerMySQLPressure(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mysql_pressure",
		Description: "MySQL/MariaDB pressure right now (the mysqltop view): overall connection saturation (used/max, %), and per-user connection load MERGED with per-user CPU/busy/query deltas, ranked by pressure. This is where you catch the offender — a user with few connections but high CPU/busy-time/queries, or the correlation 'this account drives heavy MySQL load with little HTTP traffic'. The perf block says which numbers are real: on many CloudLinux MariaDB builds CPU_TIME is 0 but busy_sec (wall-clock busy time) is populated and is the CPU proxy — ranking falls back to it. If perf_schema/userstat are off, cpu/busy read 0 and ranking uses query volume.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mysqlPressureInput) (*mcp.CallToolResult, any, error) {
		topN := in.Top
		if topN <= 0 {
			topN = 25
		}
		if topN > 200 {
			topN = 200
		}
		topBody := section(ctx, d, "/api/v1/mysql/top", nil)
		cpuBody := section(ctx, d, "/api/v1/mysql/cpu", nil)
		// Surface a section error (e.g. governor not running → HTTP 404) instead
		// of a misleading empty result.
		if e := sectionError(topBody); e != "" {
			return nil, nil, fmt.Errorf("mysql/top: %s", e)
		}
		b, err := marshal(mergeMySQLPressure(topBody, cpuBody, topN))
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// mysqlUserRow is one merged per-user pressure row.
type mysqlUserRow struct {
	User         string  `json:"user"`
	Conns        int     `json:"conns"`
	Active       int     `json:"active"`
	Sleeping     int     `json:"sleeping"`
	Locked       int     `json:"locked"`
	MaxSleepSec  int64   `json:"max_sleep_sec,omitempty"`
	CPUSec       float64 `json:"cpu_sec,omitempty"`
	BusySec      float64 `json:"busy_sec,omitempty"` // wall-clock busy time; the CPU proxy when CPU_TIME is 0 (common on CloudLinux MariaDB)
	QueryCount   int64   `json:"query_count,omitempty"`
	AvgQueryMsec float64 `json:"avg_query_msec,omitempty"`
	RowsRead     int64   `json:"rows_read,omitempty"`
}

// mergeMySQLPressure joins the /mysql/top per-user connection view with the
// /mysql/cpu per-user CPU/query deltas by user, ranks by pressure (active conns,
// then CPU, then queries, then total conns) and keeps the top N. Separated from
// dispatch so it is unit-tested. Note UserStat has no json tags, so the top
// endpoint emits capitalized keys (User/Active/…) — matched below.
func mergeMySQLPressure(topBody, cpuBody json.RawMessage, topN int) map[string]any {
	var top struct {
		Ts      string  `json:"ts"`
		Flavor  string  `json:"flavor"`
		Mode    string  `json:"mode"`
		ConnPct float64 `json:"conn_pct"`
		Total   int     `json:"total"`
		Max     int     `json:"max"`
		PerUser []struct {
			User        string `json:"User"`
			Total       int    `json:"Total"`
			Active      int    `json:"Active"`
			Sleeping    int    `json:"Sleeping"`
			Locked      int    `json:"Locked"`
			MaxSleepSec int64  `json:"MaxSleepSec"`
		} `json:"per_user"`
	}
	_ = json.Unmarshal(topBody, &top)

	var cpu struct {
		PerfSchemaOK  bool `json:"perf_schema_ok"`
		PerfCPUActive bool `json:"perf_cpu_active"`
		UserstatOK    bool `json:"userstat_ok"`
		UserstatOff   bool `json:"userstat_off"`
		Users         []struct {
			User         string  `json:"user"`
			CPUSec       float64 `json:"cpu_sec"`
			BusySec      float64 `json:"busy_sec"`
			QueryCount   int64   `json:"query_count"`
			AvgQueryMsec float64 `json:"avg_query_msec"`
			RowsRead     int64   `json:"rows_read"`
		} `json:"users"`
	}
	_ = json.Unmarshal(cpuBody, &cpu)

	cpuByUser := make(map[string]int, len(cpu.Users))
	for i, u := range cpu.Users {
		cpuByUser[u.User] = i
	}

	rows := make([]mysqlUserRow, 0, len(top.PerUser))
	for _, u := range top.PerUser {
		r := mysqlUserRow{
			User: u.User, Conns: u.Total, Active: u.Active,
			Sleeping: u.Sleeping, Locked: u.Locked, MaxSleepSec: u.MaxSleepSec,
		}
		if i, ok := cpuByUser[u.User]; ok {
			c := cpu.Users[i]
			r.CPUSec, r.BusySec, r.QueryCount, r.AvgQueryMsec, r.RowsRead = c.CPUSec, c.BusySec, c.QueryCount, c.AvgQueryMsec, c.RowsRead
		}
		rows = append(rows, r)
	}
	// A user with CPU/query activity but no live connection row still matters
	// (short-lived queries) — fold those in too.
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		seen[r.User] = true
	}
	for _, c := range cpu.Users {
		if !seen[c.User] {
			rows = append(rows, mysqlUserRow{User: c.User, CPUSec: c.CPUSec, BusySec: c.BusySec, QueryCount: c.QueryCount, AvgQueryMsec: c.AvgQueryMsec, RowsRead: c.RowsRead})
		}
	}

	// Rank by pressure: active conns, then CPU, then BUSY (the CPU proxy when
	// CPU_TIME is 0 — common on CloudLinux MariaDB), then query volume, then conns.
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Active != b.Active {
			return a.Active > b.Active
		}
		if a.CPUSec != b.CPUSec {
			return a.CPUSec > b.CPUSec
		}
		if a.BusySec != b.BusySec {
			return a.BusySec > b.BusySec
		}
		if a.QueryCount != b.QueryCount {
			return a.QueryCount > b.QueryCount
		}
		return a.Conns > b.Conns
	})
	truncated := false
	if len(rows) > topN {
		rows = rows[:topN]
		truncated = true
	}

	return map[string]any{
		"ts":     top.Ts,
		"flavor": top.Flavor,
		"mode":   top.Mode,
		"conn": map[string]any{
			"used": top.Total, "max": top.Max, "pct": top.ConnPct,
		},
		"perf": map[string]any{
			"perf_schema_ok": cpu.PerfSchemaOK, "perf_cpu_active": cpu.PerfCPUActive,
			"userstat_ok": cpu.UserstatOK, "userstat_off": cpu.UserstatOff,
		},
		"users_total":     len(top.PerUser),
		"users_truncated": truncated,
		"top_users":       rows,
	}
}

func registerCPUThrottle(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "cpu_throttle",
		Description: "Root-causes high CPU load: is the CPU being THROTTLED or is this genuine demand? Reads instantaneous cpufreq + thermal + loadavg from sysfs/proc and returns a `cause`: `genuine_demand` (cores at/near max freq under load — go find the workload, not a fault), `thermal_throttling` (slow under load + hot / kernel throttle counters set — check cooling), `frequency_capped` (slow under load but cool — powersave governor or a policy cap, switch to performance), `frequency_reduced` (slow under load, cause unclear — BIOS/host cap), `low_load` (not under pressure; reduced clock is normal idle downclock), or `no_cpufreq_data` (cpufreq/thermal not exposed — typical on VMs; check the hypervisor's CPU steal instead). The verdict is LOAD-GATED (a downclocked idle CPU is never called throttled). Each cause carries a plain-language summary + the freq ratio, governor, temperature, and throttle counters behind it.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/cpu-throttle", nil)
	})
}

type mysqlLogInput struct {
	Lines int    `json:"lines,omitempty" jsonschema:"how many trailing log lines to scan (tail window); default 200, max 5000"`
	Grep  string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter (e.g. 'error', 'deadlock', a table/db name); omit for all"`
	Limit int    `json:"limit,omitempty" jsonschema:"max matching lines to return; default 200, max 2000"`
}

func registerMySQLLogTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mysql_log_tail",
		Description: "Tail the MySQL/MariaDB ERROR log: crashes, aborted connections, deadlocks, InnoDB errors, 'too many connections', table corruption. The 'MySQL pressure is high / something's wrong — what's erroring?' companion to mysql_pressure. Bounded on-demand tail (last N lines) with optional grep; no DB connection needed.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mysqlLogInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{"which": {"error"}}
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/mysql-log", q)
	})
}

func registerMySQLSlowQueries(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mysql_slow_queries",
		Description: "Tail the MySQL/MariaDB SLOW-QUERY log (where enabled): the actual slow statements behind high MySQL CPU — query time, rows examined, the SQL. The 'why is this account's MySQL pressure high?' drill-down after mysql_pressure. Bounded on-demand tail with optional grep (e.g. a db/table/user). If the slow log isn't configured, result.found is false (likely disabled).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mysqlLogInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{"which": {"slow"}}
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/mysql-log", q)
	})
}

type cfmLogInput struct {
	Which string `json:"which,omitempty" jsonschema:"which CFM log: main|error|api|detector|challenges|smtp|mysql|waf|clam|socket|lsm|service (default main)"`
	Lines int    `json:"lines,omitempty" jsonschema:"trailing lines to scan (tail window); default 500, max 20000"`
	Grep  string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter; omit for all"`
	Limit int    `json:"limit,omitempty" jsonschema:"max matching lines to return; default 200, max 2000"`
}

func registerCFMLogTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "cfm_log_tail",
		Description: "Tail one of CFM's OWN logs (`/var/log/cfm/*`, with a few legacy `/var/log/cfm.*` fallbacks) — pick `which`: main (daemon), error, api, detector, challenges, smtp, mysql, waf, clam, socket, lsm, service. This is 'what did the CFM daemon / a subsystem log?' when a symptom isn't explained by the edge access/error logs (which edge_access_tail / edge_error_tail cover) — e.g. why a detector acted, a socket/API error, a challenge-engine note. Bounded on-demand tail (last N lines) + optional grep; a log that isn't present returns result.found=false (feature off or relocated), not an error. result.window_full=true means the tail window was saturated (older lines exist — raise `lines` if a grep found nothing).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in cfmLogInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "which", in.Which)
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/cfm-log", q)
	})
}

type journalInput struct {
	Unit  string `json:"unit" jsonschema:"systemd unit to tail; MUST be allow-listed: cfm, angie, openresty, nginx, httpd, apache2, mysql, mysqld, mariadb, exim, dovecot, postfix, sshd, clamd, named"`
	Lines int    `json:"lines,omitempty" jsonschema:"trailing journal lines (journalctl -n); default 500, max 20000"`
	Grep  string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter; omit for all"`
	Limit int    `json:"limit,omitempty" jsonschema:"max matching lines to return; default 200, max 2000"`
}

func registerJournalTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "journal_tail",
		Description: "Tail the systemd journal for an ALLOW-LISTED unit (cfm, angie/openresty/nginx/httpd/apache2, mysql/mysqld/mariadb, exim, dovecot, postfix, sshd, clamd, named). This is where a service's own startup/crash/restart output lives — 'did cfm/the edge/mysql restart or fail to start, and why?' — that the app-level logs don't carry. An arbitrary (non-allow-listed) unit is rejected; a non-systemd host returns result.available=false. Bounded (journalctl -n N) + optional grep.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in journalInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "unit", in.Unit)
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/journal", q)
	})
}

func registerMailQueueSummary(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mail_queue_summary",
		Description: "Mail-queue breakdown (exim or postfix, auto-detected): total/frozen/deferred counts, age distribution (<10m…>1d), top sender + recipient domains, top_senders (WHO filled the queue — per individual sender with the frozen/deferred split, '<>' = bounce backscatter), the oldest messages, AND the top deferral/freeze reasons (e.g. 'retry time not reached', 'Connection refused', a 550 mailbox-not-found bounce). The \"why is mail backing up / who's flooding it / why are messages stuck?\" view on top of the raw counts in system_health. Reads the report the queue detector publishes each poll — no per-request probe; `available:false` if no queue detector is enabled yet. (A single sender with many frozen messages is often a compromised account or a bounce storm.)",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/mail-queue", nil)
	})
}

type mailLogInput struct {
	Which string `json:"which,omitempty" jsonschema:"which mail log: exim (default), dovecot, or postfix"`
	Lines int    `json:"lines,omitempty" jsonschema:"how many trailing log lines to scan (tail window); default 500, max 20000"`
	Grep  string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter (e.g. an email, a user, 'A=dovecot_login', 'cwd=/home', a recipient domain); omit for all"`
	Limit int    `json:"limit,omitempty" jsonschema:"max matching lines to return; default 200, max 2000"`
}

func registerMailLogTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mail_log_tail",
		Description: "Tail a mail log — exim (exim_mainlog, default), dovecot, or postfix. The raw-log companion to mail_queue_summary: the exim mainlog is where outbound-abuse evidence lives — authenticated senders (grep 'A=dovecot_login:'), injecting scripts (grep 'cwd=/home'), and per-message sender/recipient/defer lines. Bounded on-demand tail (last N lines via `tail`, timeout, optional case-insensitive grep, capped output); no continuous overhead. Path is resolved from a fixed per-service candidate list, never caller-supplied. `result.found` is false when that service isn't logging at a known path (not installed / logs elsewhere).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mailLogInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "which", in.Which)
		setInt(q, "lines", in.Lines)
		setInt(q, "limit", in.Limit)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/mail-log", q)
	})
}

type mailTrafficInput struct {
	Hours int `json:"hours,omitempty" jsonschema:"lookback window in hours (default 24, max 720/30d)"`
	Limit int `json:"limit,omitempty" jsonschema:"max rows per list (default 20, max 200)"`
}

func registerMailTraffic(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mail_traffic",
		Description: "Mail traffic over a window (default 24h): top outbound senders, most-sent domains, top inbound mailboxes, local-script (PHP/cron) submitters keyed by unix user, plus rejected/throttled/over-quota/failed-login tallies. Carries an `anomalies` block — senders whose last-2h outbound is far above their OWN 7-day baseline (ratio), or brand-new senders suddenly blasting (kind=new-sender): the earliest compromised-account signal, before a sender reaches the top list. For admins it also carries a `deliverability` block — per remote provider (Gmail/Microsoft/…) delivered/deferred/bounced, and the top defer/bounce reasons (spf-not-passed, unsolicited-rate-limited, unsolicited-blocked, over-quota, …) — the outbound reputation/deliverability view (pair it with mail_dns_check for the DNS-side why). The \"who is sending a lot / which account is compromised / is our mail even landing\" view — aggregated companion to mail_log_tail (raw lines) and mail_queue_summary (what's stuck now). Reads per-hour counters the Mail Monitor collector persists from the exim mainlog + syslog maillog, so there is NO per-request MTA probe; `available:false` until the collector has run.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mailTrafficInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "hours", in.Hours)
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/mail/traffic", q)
	})
}

type mailDNSInput struct {
	Domain       string `json:"domain" jsonschema:"the mail domain to check, e.g. axidwear.com (required)"`
	DKIMSelector string `json:"dkim_selector,omitempty" jsonschema:"DKIM selector(s) to probe at <selector>._domainkey.<domain>; comma-separated; default 'default'"`
}

func registerMailDNSCheck(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mail_dns_check",
		Description: "Check a domain's mail-authentication DNS: SPF (present? does it list this server's sending IP? all-qualifier), DMARC (present? policy p=none/quarantine/reject), DKIM (key at the selector?), the sending IP's PTR/forward-confirmed rDNS, and MX — plus plain-language findings, worst first. The DNS half of a deliverability diagnosis: when mail_traffic / mail_log_tail show Gmail returning '421-4.7.27 SPF did not pass' or '550 unsolicited', this says WHY (missing/misaligned SPF, no DMARC, bad PTR). Live TXT lookups, read-only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in mailDNSInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "domain", in.Domain)
		setStr(q, "dkim_selector", in.DKIMSelector)
		return dispatchJSON(ctx, d, "/api/v1/mail/dns", q)
	})
}

// sectionError returns the error string if body is a section error stub
// ({"error":"..."}), else "".
func sectionError(body json.RawMessage) string {
	var m struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &m) == nil {
		return m.Error
	}
	return ""
}

func registerEdgeAccessTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "edge_access_tail",
		Description: "Recent edge access-log lines (method, URI, status, bytes, response time, UA, referer), newest last — the raw request context around a WAF hit, for false-positive triage. Filter by ip/host/method/status/path/since. Pair it with waf_activity or a WAF hit: use the same ip= or host= to see what the client was actually requesting. Request bodies are never included; secret-looking query params are redacted. Bounded in-memory ring (recent traffic only).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in edgeAccessTailInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "ip", in.IP)
		setStr(q, "host", in.Host)
		setStr(q, "method", in.Method)
		setStr(q, "status", in.Status)
		setStr(q, "path", in.Path)
		setStr(q, "since", in.Since)
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/webdet/access-recent", q)
	})
}

func registerIPDrilldown(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "ip_drilldown",
		Description: "Per-IP drilldown: which vhosts and paths one source IP is touching, its request pattern and score. The \"what is this IP doing?\" view.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ipDrilldownInput) (*mcp.CallToolResult, any, error) {
		// Schema enforces presence; this also rejects present-but-empty ("ip":"").
		if strings.TrimSpace(in.IP) == "" {
			return nil, nil, errRequired("ip")
		}
		return dispatchJSON(ctx, d, "/api/v1/webdet/ip-drilldown", url.Values{"ip": {in.IP}})
	})
}

type detectionHistoryInput struct {
	Limit int    `json:"limit,omitempty" jsonschema:"max event rows to return; default server-side"`
	Type  string `json:"type,omitempty" jsonschema:"filter by event type, e.g. waf, challenge_arm, clam_infected; omit for all"`
	Host  string `json:"host,omitempty" jsonschema:"restrict to one vhost; omit for all"`
	IP    string `json:"ip,omitempty" jsonschema:"restrict to ONE source IP — the events CFM recorded for it (WAF hits, challenge, autoblock), i.e. WHO/WHY this IP was acted on; omit for all. Detector/WAF/challenge bans appear here; manual/blocklist bans do not."`
}

func registerDetectionHistory(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detection_history",
		Description: "Durable, time-ordered log of detection events (WAF hits, challenge arm/pass/fail, ClamAV infections, autoblocks, …), GeoIP-enriched. The forensic timeline: \"what has CFM detected/done over time?\". Pass ip=<addr> to attribute one IP — the WAF/detector/challenge events behind why CFM acted on it (a firewall_blocks ban with no comment: check here for its origin; note manual/blocklist bans leave no detection event).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in detectionHistoryInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{"enrich": {"1"}}
		setInt(q, "limit", in.Limit)
		setStr(q, "type", in.Type)
		setStr(q, "host", in.Host)
		setStr(q, "ip", in.IP)
		return dispatchJSON(ctx, d, "/api/v1/webdet/history/events", q)
	})
}

func registerBotsTop(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "bots_top",
		Description: "Top user-agents by request volume — the bots, crawlers and scrapers hitting the node. Answers \"which bots/UAs are most active?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in limitInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "limit", in.Limit)
		return dispatchJSON(ctx, d, "/api/v1/webdet/ua-top", q)
	})
}

// ── Enforcement & platform ──────────────────────────────────────────────────────

type firewallBlocksInput struct {
	Country string `json:"country,omitempty" jsonschema:"drill down to blocks from ONE country — a value from the summary's by_country (case-insensitive, substring ok: 'greece', 'china', 'united states'); omit for the summary view"`
	ASN     int    `json:"asn,omitempty" jsonschema:"drill down to blocks in ONE ASN number (from the summary's by_asn); omit for the summary view"`
	Reason  string `json:"reason,omitempty" jsonschema:"drill down to blocks whose ban comment CONTAINS this text, case-insensitive (e.g. 'ssh','exim','waf'); only useful where autoblocks carry a comment (many bulk/blocklist bans have none). Omit for the summary view"`
	Limit   int    `json:"limit,omitempty" jsonschema:"in a drill-down, max ban rows to return; default 100, max 1000"`
}

func registerFirewallBlocks(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "firewall_blocks",
		Description: "Currently blocked IPs in the nftables firewall (WAF autoblocks, detector bans, blocklist/manual). The full ban list is often THOUSANDS of IPs, so with no args this returns a COMPACT SUMMARY: total + permanent/temporary counts, the top blocked countries (by_country), and the top blocked networks (by_asn — GeoIP ASN + name). To see the actual bans, DRILL DOWN with country=<name from by_country>, asn=<number from by_asn>, and/or reason=<comment substring>; the drill-down returns the matching rows plus a within-facet ASN breakdown, so you can judge likely false positives (a residential-ISP ASN is a more likely FP than a hosting/VPS network). e.g. country='greece' to review bans of your own country. Read-only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in firewallBlocksInput) (*mcp.CallToolResult, any, error) {
		body := section(ctx, d, "/api/v1/firewall/list", nil)
		if e := sectionError(body); e != "" {
			return nil, nil, fmt.Errorf("firewall/list: %s", e)
		}
		b, err := marshal(summarizeFirewallBlocks(body, in))
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

// fwBlockRow mirrors the firewallListRow the /api/v1/firewall/list handler emits.
type fwBlockRow struct {
	IP           string `json:"ip"`
	Country      string `json:"country,omitempty"`
	ASN          uint   `json:"asn,omitempty"`
	ASNName      string `json:"asn_name,omitempty"`
	Comment      string `json:"comment,omitempty"`
	Permanent    bool   `json:"permanent"`
	ExpiresInSec int64  `json:"expires_in_sec,omitempty"`
}

const (
	fwSummaryTopN = 15   // countries/ASNs listed in the summary
	fwDrillTopN   = 10   // ASN breakdown within a drill-down
	fwDrillLimit  = 100  // default drill-down row cap
	fwDrillMax    = 1000 // hard drill-down row cap
)

// summarizeFirewallBlocks turns the full ban list (often thousands of rows) into
// either a compact summary (top countries + top ASNs + perm/temp counts) or, when
// a country/asn/reason facet is given, the matching rows with an ASN breakdown.
// Separated from dispatch so it is unit-tested.
func summarizeFirewallBlocks(body json.RawMessage, in firewallBlocksInput) map[string]any {
	var resp struct {
		Rows      []fwBlockRow `json:"rows"`
		Total     int          `json:"total"`
		Permanent int          `json:"permanent"`
	}
	_ = json.Unmarshal(body, &resp)

	country := strings.ToLower(strings.TrimSpace(in.Country))
	reason := strings.ToLower(strings.TrimSpace(in.Reason))
	drill := country != "" || in.ASN > 0 || reason != ""

	if !drill {
		perm, temp := splitPermTemp(resp.Rows)
		total := resp.Total
		if total <= 0 {
			total = len(resp.Rows)
		}
		return map[string]any{
			"view":            "summary",
			"total":           total,
			"permanent":       perm,
			"temporary":       temp,
			"countries_total": distinctCountries(resp.Rows),
			"by_country":      topCountries(resp.Rows, fwSummaryTopN),
			"by_asn":          topASNs(resp.Rows, fwSummaryTopN),
			"note":            "summary — drill down with country=<name>, asn=<number>, or reason=<comment substring> to get the actual ban rows (with GeoIP + ASN for FP judgement)",
		}
	}

	matched := make([]fwBlockRow, 0)
	for _, r := range resp.Rows {
		if country != "" && !strings.Contains(strings.ToLower(r.Country), country) {
			continue
		}
		if in.ASN > 0 && r.ASN != uint(in.ASN) {
			continue
		}
		if reason != "" && !strings.Contains(strings.ToLower(r.Comment), reason) {
			continue
		}
		matched = append(matched, r)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = fwDrillLimit
	}
	if limit > fwDrillMax {
		limit = fwDrillMax
	}
	perm, temp := splitPermTemp(matched)
	rows := matched
	truncated := false
	if len(rows) > limit {
		rows = rows[:limit]
		truncated = true
	}
	filter := map[string]any{}
	if in.Country != "" {
		filter["country"] = in.Country
	}
	if in.ASN > 0 {
		filter["asn"] = in.ASN
	}
	if in.Reason != "" {
		filter["reason"] = in.Reason
	}
	return map[string]any{
		"view":      "drilldown",
		"filter":    filter,
		"matched":   len(matched),
		"returned":  len(rows),
		"truncated": truncated,
		"permanent": perm,
		"temporary": temp,
		"by_asn":    topASNs(matched, fwDrillTopN),
		"rows":      rows,
	}
}

func splitPermTemp(rows []fwBlockRow) (perm, temp int) {
	for _, r := range rows {
		if r.Permanent {
			perm++
		} else {
			temp++
		}
	}
	return perm, temp
}

func distinctCountries(rows []fwBlockRow) int {
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Country != "" {
			seen[r.Country] = true
		}
	}
	return len(seen)
}

type fwCountRow struct {
	Country string `json:"country"`
	Count   int    `json:"count"`
}

func topCountries(rows []fwBlockRow, topN int) []fwCountRow {
	m := map[string]int{}
	for _, r := range rows {
		c := r.Country
		if c == "" {
			c = "(unknown)"
		}
		m[c]++
	}
	out := make([]fwCountRow, 0, len(m))
	for c, n := range m {
		out = append(out, fwCountRow{Country: c, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Country < out[j].Country
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

type fwASNRow struct {
	ASN     uint   `json:"asn"`
	ASNName string `json:"asn_name,omitempty"`
	Count   int    `json:"count"`
}

func topASNs(rows []fwBlockRow, topN int) []fwASNRow {
	type agg struct {
		name  string
		count int
	}
	m := map[uint]*agg{}
	for _, r := range rows {
		a := m[r.ASN]
		if a == nil {
			a = &agg{name: r.ASNName}
			m[r.ASN] = a
		}
		if a.name == "" && r.ASNName != "" {
			a.name = r.ASNName
		}
		a.count++
	}
	out := make([]fwASNRow, 0, len(m))
	for asn, a := range m {
		out = append(out, fwASNRow{ASN: asn, ASNName: a.name, Count: a.count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ASN < out[j].ASN
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

type ipLocateInput struct {
	IP string `json:"ip" jsonschema:"the source IP (or CIDR) to locate across every block source"`
}

func registerIPLocate(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "ip_locate",
		Description: "Where — and WHY — an IP is blocked across ALL sources on this node: nft, cfm.deny, csf, fail2ban, imunify360. Each hit carries source, list/set/jail, action, the matched entry, and the REASON when the source records one — notably cfm.deny keeps the autoblock reason (e.g. \"autoblock: portscan (N distinct ports) … at <time>\"). This is the `cfm which/search <ip>` equivalent, and the tool that explains a firewall_blocks ban whose nft entry has no comment: the reason lives in cfm.deny, which this reads. (detection_history only covers WAF/challenge/webdet events — portscan/detector autoblocks written to cfm.deny won't show there, but will here.) Admin-only, read-only; accepts an IP or CIDR.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in ipLocateInput) (*mcp.CallToolResult, any, error) {
		// Schema enforces presence; this also rejects present-but-empty ("ip":"").
		if strings.TrimSpace(in.IP) == "" {
			return nil, nil, errRequired("ip")
		}
		return dispatchJSON(ctx, d, "/search", url.Values{"ip": {in.IP}})
	})
}

type nftCountersInput struct {
	Nonzero bool `json:"nonzero,omitempty" jsonschema:"only return counters that have matched at least one packet (hide idle rules)"`
}

func registerFirewallCounters(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "nft_counters",
		Description: "nftables named-counter view (read-only): how much traffic each L3/L4 firewall RULE is matching in `table inet cfm`, grouped by family — portflood, connlimit, synflood (SYN rate), ppsflood (packet rate), hardening (badflags/icmp/new-conn-rate drops), smtpblock. This is the RULE-match volume, distinct from firewall_blocks (which lists the blocked-IP sets). Answers \"which firewall rules are actually firing, and how hard?\" — e.g. a spiking portflood_80_tcp or synrate counter points at an active L3/L4 flood. Note: this does NOT reflect panel/web WAF or bridge enforcement (those are edge-layer 403 denials, not nftables rules — use waf_activity / waf_fp_hunt for those). Reads on the default exec-nft backend; on the nftlib backend it returns available:false. Pass nonzero=true to hide idle counters.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in nftCountersInput) (*mcp.CallToolResult, any, error) {
		var q url.Values
		if in.Nonzero {
			q = url.Values{"nonzero": {"1"}}
		}
		return dispatchJSON(ctx, d, "/api/v1/firewall/counters", q)
	})
}

func registerFirewallSelfTest(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "firewall_selftest",
		Description: "nftlib firewall self-diagnostics (read-only): the recent EnsureBase calls with their time split into lock_wait_ms (contention on the backend mutex), nl_work_ms (netlink add+flush — the shared connection's own health) and cli_work_ms (the `nft` CLI part), the worst call in the window, and the latest per-set feed writes (elems, dur, error). Use to root-cause an nftlib node whose EnsureBase duration climbs over a run (rising lock_wait ⇒ contention from a slow/failed feed write; rising nl_work ⇒ the netlink connection degrading) or a feed that never applies (a large set write erroring with 'message too long'). `available:false` on the exec-nft backend (it doesn't record this).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/firewall/selftest", nil)
	})
}

func registerDetectorsStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detectors_status",
		Description: "Runtime status of CFM's detector framework (ssh/exim/dovecot/ftp/mysql/modsec/health/…): which detectors are enabled and running, and a summary of recent activity.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/detectors/status", nil)
	})
}

type systemHealthInput struct {
	Since string `json:"since,omitempty" jsonschema:"for the anomalies section: RFC3339 timestamp or duration like 1h; omit for the default window"`
}

func registerSystemHealth(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "system_health",
		Description: "System health snapshot (load, memory, disk, service/edge liveness, ingest) plus any recently detected health anomalies. The \"is the node/edge healthy?\" view.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in systemHealthInput) (*mcp.CallToolResult, any, error) {
		aq := url.Values{}
		setStr(aq, "since", in.Since)
		out := map[string]any{
			"snapshot":  section(ctx, d, "/api/v1/health/snapshot", nil),
			"anomalies": section(ctx, d, "/api/v1/health/anomalies", aq),
		}
		b, err := marshal(out)
		if err != nil {
			return nil, nil, err
		}
		return textResult(b), nil, nil
	})
}

type processListInput struct {
	Top     int    `json:"top,omitempty" jsonschema:"how many busiest matching processes to return; default 15, max 200. With no filters this is the original top-like process_list behaviour"`
	Match   string `json:"match,omitempty" jsonschema:"case-insensitive substring match on the process command name (COMM); applied before the top limit so idle matching processes are not lost"`
	PID     int    `json:"pid,omitempty" jsonschema:"exact positive process ID to inspect; applied before the top limit"`
	Details bool   `json:"details,omitempty" jsonschema:"include direct child PIDs plus bounded, best-effort sanitized argv for returned processes; default false. Raw cmdline is never returned"`
}

func registerProcessList(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "process_list",
		Description: "The busiest processes on the node right now (top-like: pid, ppid, user, state, %cpu, %mem, rss, threads, command name), newest CPU sample. With no filters it preserves the original process_list behaviour. Use match=<comm substring> or pid=<pid> to inspect a process even when it is idle; filters are applied before the top limit. Set details=true to add direct child PIDs and bounded, best-effort sanitized argv. The default view still exposes command NAME only; raw /proc/<pid>/cmdline is never returned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in processListInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "top", in.Top)
		setStr(q, "match", in.Match)
		setInt(q, "pid", in.PID)
		if in.Details {
			q.Set("details", "1")
		}
		return dispatchJSON(ctx, d, "/api/v1/system/processes", q)
	})
}

func registerListeningPorts(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "listening_ports",
		Description: "Listening TCP/UDP sockets on the node and the process that owns each — the `ss -tlnp` view, grouped by (proto, port, process): each group has the owning command name + pid, a count of bind addresses, and a bounded address sample (just the wildcard when it binds 0.0.0.0/::). Use to confirm the edge/daemon/panel are actually listening, spot an unexpected open port, or see who owns :443. Owning command + bind addresses only; no connections or peers.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/listeners", nil)
	})
}

type dmesgTailInput struct {
	Lines int    `json:"lines,omitempty" jsonschema:"how many recent kernel-ring lines to return; default 80, max 1000"`
	Grep  string `json:"grep,omitempty" jsonschema:"case-insensitive substring filter (e.g. 'oom', 'segfault', 'I/O error', 'nft'); omit for all"`
}

func registerDmesgTail(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "dmesg_tail",
		Description: "Tail the kernel ring buffer (dmesg): OOM kills, I/O/disk errors, segfaults, nftables drops, hardware/driver messages. The \"why did it OOM/crash/reset?\" view that the health snapshot can't answer. Use grep to focus (e.g. 'oom', 'segfault', 'error').",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in dmesgTailInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "lines", in.Lines)
		setStr(q, "grep", in.Grep)
		return dispatchJSON(ctx, d, "/api/v1/system/dmesg", q)
	})
}

type serviceStatusInput struct {
	Units string `json:"units,omitempty" jsonschema:"comma-separated systemd units to check (e.g. 'cfm,mariadb,exim'); a bare name is treated as '.service'. Omit to get the curated CFM + hosting-stack set (cfm, edge, db, mail, dns, ftp, ssh, panel), with not-installed units elided."`
}

func registerServiceStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "service_status",
		Description: "systemd unit status (structured `systemctl status`): for each unit whether it's loaded, active, enabled-at-boot, its sub-state, main pid, memory, restart count and how long it's been up. Use to confirm cfm/the edge/mysql/mail are actually running and to spot a flapping service (high restart count). Omit units for the curated CFM + hosting-stack set; pass units= to check specific ones (an explicitly named unit that isn't installed is reported as not-found).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in serviceStatusInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setStr(q, "units", in.Units)
		return dispatchJSON(ctx, d, "/api/v1/system/services", q)
	})
}
