package mcpserver

// lsm_detections.go — read-only MCP tool over GET /api/v1/system/lsm-detections
// (internal/lsmdetect): aggregates the cfm-lsm DETECT lines from CFM's own lsm
// log so the operator can triage kernel-level detections — which policy keeps
// firing, on which binaries, and how much is repeat noise vs something novel.

import (
	"context"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type lsmDetectionsInput struct {
	Lines int `json:"lines,omitempty" jsonschema:"how many trailing lsm-log lines to scan (tail window); default 5000, max 20000"`
}

func registerLSMDetections(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "lsm_detections",
		Description: "Aggregate cfm-lsm (BPF LSM) DETECT events from CFM's own lsm log: per-policy totals with the rate-cap suppression count, plus top repeat offenders ranked by (policy, comm, exe) with last-seen time, user, and a short exe sha256. Answers 'is cfm-lsm firing at anything real, or is this one noisy false positive?' — e.g. hundreds of CFML-CRED-002 hits from sssd/sssd_kcm/cagefsctl/panel perl are uid-transition noise to silence via allow_comm=/allow_exe= under [policy \"CFML-CRED-002\"] in /etc/cfm/lsm.conf + `cfm lsm restart`, while ONE event whose exe lives under /tmp,/dev/shm or shows (deleted) is the dropper pattern worth escalating (pair with detection_history ip=… and dmesg_tail). Aggregates the NEWEST ≤2000 detect lines of the tail window; window_full=true means older events exist beyond it (raise lines, or use cfm_log_tail which=lsm for raw lines). Empty summary when cfm-lsm has never fired.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in lsmDetectionsInput) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		setInt(q, "lines", in.Lines)
		return dispatchJSON(ctx, d, "/api/v1/system/lsm-detections", q)
	})
}
