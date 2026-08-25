package mcpserver

// detector_sources.go — read-only MCP tool over
// GET /api/v1/detectors/source-resolution: the per-section dry run of the
// shared source resolver (which journald unit / log file / docker container
// each detector would tail on THIS node, and why). The preview surface for
// rolling out MODE=auto fleet-wide; ask it per node (or fan out with
// node_call node=all from cfm-web) before shipping a unified detectors.conf.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerDetectorSources(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detectors_srcresolve",
		Description: "Dry-run SOURCE RESOLUTION for every detector section on this node: which log source (journald unit / log file / docker container) each section would use RIGHT NOW, and why — the same planners the daemon's registers use, probes run live (journalctl/systemctl/docker/stat), nothing starts or changes. Per row: section, enabled, engine (srcresolve = shared resolver; legacy-auto = detector's own older autodetect, e.g. ftpd/modsec/mysql/webdetector; n/a = not source-based), the source-relevant configured keys, resolved kind+target (journal unit, file path, container name; 'as-configured' = explicit keys or package-internal resolution used verbatim), the resolution reason, provisional=true (blind historical default in use — self-heals when the source appears), and would_disable=true (section self-disables: its MTA has no binary/unit/container/log here). Use BEFORE removing hand-set MODE/LOG_PATH/JOURNAL_UNIT/DOCKER_CONTAINER pins from a node's detectors.conf: confirm every row resolves to the intended source. A wrong row usually means a non-standard layout — pin the explicit key for that section. Companion: detectors_status (runtime state of what actually started), config_drift (stock-vs-live config diff).",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/detectors/source-resolution", nil)
	})
}
