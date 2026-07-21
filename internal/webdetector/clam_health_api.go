package webdetector

import (
	"net/http"
	"time"
)

// clamHealthResponse is the admin-facing scanner status for the ClamAV page.
// Global daemon state (clamd reachability, circuit breaker, queue geometry,
// lifetime counters) — deliberately NOT scoped: this is box-level, not
// per-vhost. Times are unix seconds (0 when zero) to match the UI's fmtTs.
type clamHealthResponse struct {
	Available         bool   `json:"available"`           // a clam manager is wired and reporting
	Enabled           bool   `json:"enabled"`             // scanner running (started + clamd address set)
	GlobalScanDefault bool   `json:"global_scan_default"` // CLAM_SCAN_DEFAULT (config policy)
	ScanScope         string `json:"scan_scope"`          // CLAM_SCAN_SCOPE effective value (archives|all)
	ScanMode          string `json:"scan_mode"`           // CLAM_SCAN_MODE global default (async|inline)
	InlineDryRun      bool   `json:"inline_dry_run"`      // inline burn-in guard active
	BreakerOpen       bool   `json:"breaker_open"`        // circuit breaker tripped (clamd unreachable)
	DownSince         int64  `json:"down_since"`
	ConsecFails       int    `json:"consec_fails"`
	LastOK            int64  `json:"last_ok"`
	LastFail          int64  `json:"last_fail"`
	LastErr           string `json:"last_err,omitempty"`
	QueueLen          int    `json:"queue_len"`
	QueueCap          int    `json:"queue_cap"`
	ScannedOK         uint64 `json:"scanned_ok"`
	ScanErrors        uint64 `json:"scan_errors"`
	SkippedBreaker    uint64 `json:"skipped_breaker"`
	QueueDrops        uint64 `json:"queue_drops"`
	SkippedScope      uint64 `json:"skipped_scope"`      // uploads skipped: not an archive (scope=archives)
	SigIgnored        uint64 `json:"sig_ignored"`        // infected verdicts downgraded to log-only
	InlineBlocked     uint64 `json:"inline_blocked"`     // uploads 403'd by inline mode
	InlineDryRunHits  uint64 `json:"inline_dryrun_hits"` // dry-run verdicts that WOULD have blocked
}

func clamUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// GET /api/v1/clam/health — admin-only scanner status for the ClamAV page.
// Reports the global scan policy plus, when a manager is wired, the live
// reachability/breaker/queue/counter snapshot. Returns available=false (still
// 200) when ClamAV isn't wired (e.g. CLAMD_ENABLED=0) so the page can render a
// clean "not running" state rather than error.
func (e *Engine) handleClamHealth(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	_, scanDefault := clamScanPolicy()
	resp := clamHealthResponse{GlobalScanDefault: scanDefault}
	if e != nil && e.nginxBridge != nil {
		// available == the scanner is actually running and reporting live.
		// snap.Enabled is false once the manager is stopped, so a disabled
		// clam (whose stale manager pointer the bridge still holds — the disable
		// path never clears it) reports available=false → the page shows a clean
		// "not running" state instead of frozen counters.
		if snap, ok := e.nginxBridge.ClamHealth(); ok && snap.Enabled {
			resp.Available = true
			resp.Enabled = snap.Enabled
			resp.ScanScope = snap.ScanScope
			resp.ScanMode = snap.ScanMode
			resp.InlineDryRun = snap.InlineDryRun
			resp.BreakerOpen = snap.BreakerOpen
			resp.DownSince = clamUnix(snap.DownSince)
			resp.ConsecFails = snap.ConsecFails
			resp.LastOK = clamUnix(snap.LastOK)
			resp.LastFail = clamUnix(snap.LastFail)
			resp.LastErr = snap.LastErr
			resp.QueueLen = snap.QueueLen
			resp.QueueCap = snap.QueueCap
			resp.ScannedOK = snap.ScannedOK
			resp.ScanErrors = snap.ScanErrors
			resp.SkippedBreaker = snap.SkippedBreaker
			resp.QueueDrops = snap.QueueDrops
			resp.SkippedScope = snap.SkippedScope
			resp.SigIgnored = snap.SigIgnored
			resp.InlineBlocked = snap.InlineBlocked
			resp.InlineDryRunHits = snap.InlineDryRunHits
		}
	}
	writeJSON(w, http.StatusOK, resp)
}
