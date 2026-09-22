package mcpserver

// status_reads.go — small read-only "is X healthy / configured?" MCP tools that
// each wrap one existing admin /api/v1 status endpoint (the "minor read wins"
// group). Pure passthroughs via dispatchJSON: no logic, no new endpoints.

import (
	"context"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerClamStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "clam_status",
		Description: "ClamAV on-upload scanner health (box-wide): whether scanning is enabled, the effective scan scope/mode (archives-gate vs full, async vs inline, inline dry-run), the circuit-breaker state (open? since when? consecutive failures, last OK/last error), the work queue geometry (len/cap), and lifetime counters (scanned OK, scan errors, breaker-skips, queue drops, scope-skips, signatures ignored, inline blocks / dry-run hits). Answers 'is upload scanning actually running, or has clamd gone away / tripped the breaker / filled the queue?'. Not per-vhost — host-level daemon status.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/clam/health", nil)
	})
}

func registerNotifierStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "notifier_status",
		Description: "Alert-notifier runtime status: which channels are configured/enabled (Slack/email/webhook/…) and the delivery runtime state — so you can answer 'are CFM's alerts actually going out, or is a channel disabled/misconfigured?'. The companion to the alerting you see on Slack/mail: if an incident happened but no alert arrived, check here. Read-only; secrets (tokens/webhook URLs) are not returned.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/notifier/status", nil)
	})
}

func registerHTTP3Status(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "http3_status",
		Description: "HTTP/3 (QUIC) opt-in status: the list of vhosts that have HTTP/3 enabled at the edge (the rest serve HTTP/1.1+2 only). Answers 'is HTTP/3 on for this site?' and 'which hosts opted in?'. Read-only view of the same opt-in list the `cfm` HTTP/3 CLI and the Vhost-controls UI manage.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/http3/list", nil)
	})
}

func registerSiteCacheStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "site_cache_status",
		Description: "Site Cache per-vhost opt-in status: the vhosts that have edge caching ARMED and, per vhost, the static/micro tier + recipe/TTL and the current purge generation. Answers 'is caching on for this site, and how?'. Caching is bypass-by-default — a vhost absent from this list is NOT cached. Read-only view of the same policy list the `cfm webtop site-cache` CLI manages.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/site-cache/list", nil)
	})
}

type siteCacheStatsInput struct {
	Host string `json:"host,omitempty" jsonschema:"limit to one vhost (exact host, e.g. www.myip.gr); omit for every reported vhost"`
}

func registerSiteCacheStats(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "site_cache_stats",
		Description: "Site Cache EFFECTIVENESS per vhost: HIT / MISS / EXPIRED / STALE / UPDATING / REVALIDATED / BYPASS counts and a derived STRICT hit ratio (hit / cacheable, BYPASS excluded), as the edge reports them — pushed ~every 60s, ONLY for currently-ARMED vhosts, as absolute counts since the edge last reloaded. Answers 'is this armed vhost actually served from cache?'. Read the full breakdown, not just the ratio: STALE/UPDATING/REVALIDATED are also served from cache but sit in the denominator, so the strict ratio understates a vhost that leans on stale-while-revalidate. A vhost with near-zero HIT *and* high MISS/EXPIRED means the origin isn't returning cacheable responses (or a caching misconfig — e.g. the buffering/no-store class). Pass `host` (a concrete sub-host resolves to its wildcard-armed vhost) to drill into one. Read-only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in siteCacheStatsInput) (*mcp.CallToolResult, any, error) {
		var q url.Values
		if h := strings.TrimSpace(in.Host); h != "" {
			q = url.Values{"host": {h}}
		}
		return dispatchJSON(ctx, d, "/api/v1/site-cache/stats", q)
	})
}

func registerMailRuntime(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "mail_runtime",
		Description: "SMTP/spamd runtime SATURATION — the 'mail is up but wedged' signal the queue summary can't see. Reports current inbound SMTP sessions vs Exim's smtp_accept_max, and active spamd scanner children vs --max-children, each as current/max → utilisation% → a saturation class (ok/warn/critical), plus the worst of the two. Answers 'why is submission (587) timing out even though Exim and spamd are running?' — e.g. spamd saturated (10/10 children) backing up SMTP sessions until Exim hits its connection cap. A cap that can't be read from config shows 'unknown' (never a false 'ok'). Host-level, read-only.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/mail/runtime", nil)
	})
}
