package mcpserver

// backup_status.go — read-only MCP tool over GET /api/v1/health/backup: the
// node's latest backup check (docs/backup-check.md).

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerBackupStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "backup_status",
		Description: "This node's latest backup check (JetBackup 5 on cPanel/DirectAdmin, Virtualmin scheduled backups, Proxmox vzdump — whichever is installed; run by the health detector every 15 min). Per adapter: every job with its last result (ok / partial / failed / unknown), last SUCCESSFUL run, schedule and running flag, plus the open findings — backup_failed, backup_stale (no successful run within the job's own period), backup_stuck, backup_partial (info: some accounts not backed up, typically one over its own disk quota), backup_uncovered (Proxmox guests in no job), backup_dest (destination offline / nearly full), backup_no_job, and an adapter `error` when the backup CLI could not be read. `enabled`=false means BACKUP_ALERT is off; `status`=null means no check has finished yet; `age_seconds` says how old it is. Freshness is measured from the last successful (or partial) run, never JetBackup's last_completed, which advances on failed runs. Use it to answer \"are backups OK on this node, and since when not\"; fan out with node=\"all\" for the fleet.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/health/backup", nil)
	})
}
