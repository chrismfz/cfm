package mcpserver

// lsm_status.go — read-only MCP tool over GET /api/v1/system/lsm-status: the
// cfm-lsm kernel-side state (the `cfm lsm status --json` wire format) plus the
// effective per-policy allowlists, so triage starts from what is ALREADY
// allowed before proposing lsm.conf edits.

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerLSMStatus(srv *mcp.Server, d Deps) {
	mcp.AddTool(srv, &mcp.Tool{
		Annotations: readOnly,
		Name:        "lsm_status",
		Description: "cfm-lsm (BPF LSM) kernel-side state for this node: whether the host CAN load BPF LSM programs at all (preflight checks with remediation hints), whether it is enabled in /etc/cfm/lsm.conf and actually attached (pinned links under /sys/fs/bpf/cfm), BTF drift picks for this kernel, and each policy's configured mode vs live runtime state (attached / would-attach / skip / unavailable). Also returns effective_allows — the MERGED allow_exe/allow_comm/allow_path set per policy (compiled-in defaults + operator entries) — so before blaming a noisy CFML-CRED-002 false positive you can check whether that binary is already allow-listed, and propose additions as [policy] allow_exe=/allow_comm= lines followed by `cfm lsm restart`. Pair with lsm_detections (what is actually firing) — status says what COULD fire and how it would act; ok=false means preflight/config/pin mismatch worth surfacing.",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, any, error) {
		return dispatchJSON(ctx, d, "/api/v1/system/lsm-status", nil)
	})
}
