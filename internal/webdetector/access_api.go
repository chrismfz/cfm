package webdetector

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// handleAccessRecent serves the recent edge access-log ring
// (GET /api/v1/webdet/access-recent). Admin-only: it exposes requests across
// ALL vhosts, so it must never be reachable by a scoped (per-domain) user.
// Backs the MCP edge_access_tail tool — the raw request context around a WAF
// hit, for false-positive triage.
//
// Query params (all optional): ip, host, method, status (exact "403" or a class
// digit "4"→4xx), path (case-insensitive URI substring), since (duration, e.g.
// "10m" — only entries newer than now-since), limit (default 50, max 500).
func (e *Engine) handleAccessRecent(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	f := AccessFilter{
		IP:      strings.TrimSpace(q.Get("ip")),
		Host:    strings.TrimSpace(q.Get("host")),
		Method:  strings.TrimSpace(q.Get("method")),
		PathSub: strings.TrimSpace(q.Get("path")),
	}

	// status: a lone 1..5 is a class (4 → 4xx); otherwise an exact code.
	if s := strings.TrimSpace(q.Get("status")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			if len(s) == 1 && n >= 1 && n <= 5 {
				f.StatusClass = n
			} else {
				f.Status = n
			}
		}
	}

	if s := strings.TrimSpace(q.Get("since")); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			f.Since = float64(time.Now().Add(-d).Unix())
		}
	}

	if s := strings.TrimSpace(q.Get("limit")); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			f.Limit = n
		}
	}

	entries := e.RecentAccess(f)
	writeJSON(w, http.StatusOK, map[string]any{
		"schema":  "webdet.access_recent.v1",
		"count":   len(entries),
		"entries": entries,
	})
}
