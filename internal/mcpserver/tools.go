package mcpserver

// tools.go registers the read-only MCP tool set. Every tool maps to a hard-coded,
// allow-listed /api/v1 GET endpoint (the same one the CLI/web UI use) and passes
// user args through as typed query params — the path is never caller-controlled,
// so the surface stays read-only and bounded. Keep this list and MCP.md in sync.

import (
	"context"
	"encoding/json"
	"net/url"
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
	registerSecurityOverview(srv, d)
	registerWAFActivity(srv, d)
	registerWAFRules(srv, d)
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
	registerDetectorsStatus(srv, d)
	registerSystemHealth(srv, d)
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
		Description: "Headline security picture for this CFM node in one call: system health, recent WAF activity (last hour), active challenged vhosts, current firewall blocks, and top suspicious hosts. Start here for \"what's going on right now?\", then drill in with the more specific tools.",
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
				res := sectionBudgeted(ctx, d, path, q)
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
}

func registerDetectionHistory(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detection_history",
		Description: "Durable, time-ordered log of detection events (WAF hits, challenge arm/pass/fail, ClamAV infections, autoblocks, …), GeoIP-enriched. The forensic timeline: \"what has CFM detected/done over time?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in detectionHistoryInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{"enrich": {"1"}}
		setInt(q, "limit", in.Limit)
		setStr(q, "type", in.Type)
		setStr(q, "host", in.Host)
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

func registerFirewallBlocks(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "firewall_blocks",
		Description: "Currently blocked IPs in the nftables firewall — including WAF autoblocks and detector-driven bans — each with its TTL (or permanent), comment/reason, and GeoIP. Answers \"who is banned right now, and why?\".",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/firewall/list", nil)
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
