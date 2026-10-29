package mcpserver

// edge_health.go — read-only MCP tool over GET /api/v1/system/edge-health:
// a focused, correlated edge → origin correctness check (logs × live engine
// version) that names the class of bug behind the 2026-08 cross-SNI 421
// incident before it hides for a week. See docs/edge-health.md.

import (
	"context"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type edgeHealthInput struct {
	Window int `json:"window,omitempty" jsonschema:"how many trailing edge access-log lines to scan for the 421/SNI-mismatch fingerprint (default 50000, max 500000)"`
}

func registerEdgeHealth(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "edge_health",
		Description: "Focused edge origin-hop CORRECTNESS check: correlates the edge access/error logs with the live engine+version to catch the class of bug behind the 2026-08 cross-SNI Apache 421 incident, which the raw tails (edge_access_tail/edge_error_tail) and generic config_drift can't surface in one call. Returns severity-ranked findings (overall = ok|warn|critical|unknown) plus engine/version. Tier-1 checks: (A) engine + version + native-keepalive-default-on trap — nginx >=1.29.7 (OpenResty 1.31.x) turns native upstream keepalive ON by default and SNI-blind, so it can reuse a hostA 443 connection for hostB; Angie keeps it off; (B) 421/SNI-mismatch fingerprint from the access log — counts status=421 and the WARM-REUSE shape (uct~=0 via cfm_origin_https), the exact incident signature, with top hosts; RECENCY-AWARE (msec epoch): only warm 421s inside a freshness window read `critical`, so a storm that stopped after a fix/restart but is still in the file tail reads `warn` (see newest_warm_421_age_sec / recent_warm_421), not a stale `critical`; (C) [cfm_origin_ka] activation/degradation tiers from the error log (pooling active / 443 per-request / degraded / module load failed); (D) ORIGIN_KEEPALIVE knob state from the published bridge config; (E) origin premature-close / gateway-5xx rate from the access log (uht=- with a real upstream peer: the origin accepted then dropped, or never became usable), with the vhost spread; (F) cdn-cached-challenge — vhosts where visitors holding a valid clearance were bounced back to the challenge page through a trusted proxy from 3+ distinct clients in 24 h (only for a page target; direct bounces are listed in evidence.direct_hosts, relayed downloads in evidence.download_hosts, never as a warning), likely a CDN (Cloudflare) caching CFM's challenge despite no-store; the fix is the CDN's cache rule (in-memory; `ok` with measured=false when the challenge server is not serving, since it then serves no challenge to cache); (G) origin-real-ip — does the origin (Apache/LiteSpeed/nginx; cPanel, DirectAdmin, NGM, plain) trust the edge's 127.0.0.1 to name the client, or does it log 127.0.0.1 for every visitor and hand PHP REMOTE_ADDR=127.0.0.1 (config only; `ok` when no edge engine runs; the fix is `cfm realip fix`, or the manual step for LiteSpeed/NGM). Read-only: reads logs + config + runs the edge binary's `-v` (never `-t`/reload). `window` bounds the access-log scan. Drill into a finding with edge_access_tail / edge_error_tail. Design + Tier-2/3 roadmap: docs/edge-health.md.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in edgeHealthInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "window", in.Window)
		return dispatchJSON(ctx, d, "/api/v1/system/edge-health", q)
	})
}
