package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerProcessHealth exposes the compact /proc summary plus its conservative
// single-snapshot evaluation. Historical baselines and broader process-count /
// fanout / RSS verdicts remain separate follow-up work.
func registerProcessHealth(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "process_health",
		Description: "Compact process-table health snapshot: readable process/thread totals, scan completeness (PIDs enumerated/readable/skipped), counts by process state, exact COMM-family aggregates with per-family state breakdowns, bounded top families for each observed state, rankings by process count/aggregate RSS, and direct-child fanout. Also includes a deliberately conservative single-snapshot evaluation for D-state pileups and zombie accumulation; materially partial/inconsistent scans return evaluation.status=degraded rather than being treated as healthy. It does NOT yet classify family counts, fanout, RSS, or total process count without a historical baseline. Cheap single /proc scan: no cmdline, username/NSS lookup, or CPU sampling. Use process_list to drill into a named family or PID.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/process-health", nil)
	})
}
