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
		Description: "Focused edge origin-hop CORRECTNESS check: correlates the edge access/error logs with the live engine+version to catch the class of bug behind the 2026-08 cross-SNI Apache 421 incident, which the raw tails (edge_access_tail/edge_error_tail) and generic config_drift can't surface in one call. Returns severity-ranked findings (overall = ok|warn|critical) plus engine/version. Tier-1 checks: (A) engine + version + native-keepalive-default-on trap — nginx >=1.29.7 (OpenResty 1.31.x) turns native upstream keepalive ON by default and SNI-blind, so it can reuse a hostA 443 connection for hostB; Angie keeps it off; (B) 421/SNI-mismatch fingerprint from the access log — counts status=421 and the WARM-REUSE shape (uct~=0 via cfm_origin_https), the exact incident signature, with top hosts; (C) [cfm_origin_ka] activation/degradation tiers from the error log (pooling active / 443 per-request / degraded / module load failed); (D) ORIGIN_KEEPALIVE knob state from the published bridge config. Read-only: reads logs + runs the edge binary's `-v` (never `-t`/reload). `window` bounds the access-log scan. Drill into a finding with edge_access_tail / edge_error_tail. Design + Tier-2/3 roadmap: docs/edge-health.md.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in edgeHealthInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "window", in.Window)
		return dispatchJSON(ctx, d, "/api/v1/system/edge-health", q)
	})
}
