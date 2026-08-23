package mcpserver

// config_drift.go — read-only MCP tool over GET /api/v1/system/config-drift:
// stock (/usr/share/cfm/configs/) vs live (/etc/cfm/) config comparison that
// surfaces features a release shipped but the operator's conffile never
// received (upgrades seed /etc/cfm once and never touch it again).

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerConfigDrift(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "config_drift",
		Description: "Stock-vs-live CONFIG DRIFT for this node: 'which features did a CFM release ship that my /etc/cfm configs never received?'. Live conffiles are seeded at install and upgrades never touch them, so new sections/keys accumulate in the packaged reference (/usr/share/cfm/configs/) while older hosts stay blind to them. For detectors.conf (parsed with the SAME reader the daemon uses, so commented-out stock sections don't count): missing_sections (e.g. a whole [waf_security] or [challenge_solver_farm] your live file predates), missing_keys (section exists but a newer knob like challenge_cookie_discard's MIN_SOLVES isn't there — each one is an INACTIVE feature), extra live-only sections/keys, and value_diffs (informational — per-host values legitimately differ). For cfm.conf: stock-documented keys absent from the live text entirely (commented-out counts as seen). Workflow: read summary counts → list missing keys/sections → decide per feature whether to enable (copy the stock block into /etc/cfm/detectors.conf, tune, then `cfm detector reload`) — nothing here changes any file.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/config-drift", nil)
	})
}
