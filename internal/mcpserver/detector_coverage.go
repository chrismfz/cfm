package mcpserver

// detector_coverage.go — read-only MCP tool over GET /api/v1/detectors/coverage:
// the daemon-vs-detector coverage matrix. For every registered detector type it
// answers whether the watched daemon exists on this host (svcstat over a curated
// type→units affinity table), whether a live detectors.conf section enables it,
// and a reality-aware verdict so "not configured" stops being noise when the
// daemon itself is absent.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerDetectorCoverage(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "detector_coverage",
		Description: "Daemon-vs-detector coverage matrix for this node — 'what runs here that nothing watches, and what watches something that isn't there?'. For every registered detector type (ssh_auth, exim_*/postfix_* queues+security+relays, dovecot_auth, ftpd, mysql(+governor), cpanel, modsec, proxmox_auth, webdetector, …) it probes whether the watched daemon's systemd unit EXISTS and is ACTIVE (curated affinity: sshd/exim/postfix/dovecot/vsftpd|pure-ftpd|proftpd/mysqld|mariadb/cpanel/modsec-inside-webserver/pvedaemon/edge), lists the live detectors.conf sections for it (configured / ENABLED / active / log-source-probe-ok) and returns a verdict: ok; GAP (daemon RUNNING but no section or all ENABLED=0 — the real 'I forgot' case); disabled; dormant (enabled but daemon absent/stopped — it will idle or fail its source probe); absent (daemon not present AND not configured — informational, NOT a problem); na (event-driven, no daemon). Verdicts are host-reality-aware, so absent types are not complaints. Start from summary.gaps + summary.dormant, then read the per-type rows; sections[] carries runtime detail (last_error, init diagnostics). Pair with detectors_status for run counters.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/detectors/coverage", nil)
	})
}
