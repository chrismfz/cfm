package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerProcessHealth exposes the compact /proc summary built by procstat.Health.
// This slice is intentionally descriptive only: it reports process-table shape
// (states, COMM-family aggregates and child fanout) but makes no anomaly verdicts.
func registerProcessHealth(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "process_health",
		Description: "Compact process-table health snapshot: readable process/thread totals, scan completeness (PIDs enumerated/readable/skipped), counts by process state (including D/Z), exact COMM-family aggregates ranked by process count and aggregate RSS, and the largest direct-child fanouts. Cheap single /proc scan: no cmdline, no username/NSS lookup, no CPU sampling. A small skipped count is normal when processes exit during the scan; the completeness fields let callers recognize a materially partial snapshot. This tool is DESCRIPTIVE ONLY in this slice — it does not yet decide whether a value is abnormal; use process_list to drill into a named family or PID.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/process-health", nil)
	})
}
