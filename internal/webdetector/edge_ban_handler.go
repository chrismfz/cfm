package webdetector

import (
	"net"
	"net/http"
	"strings"
	"time"

	"cfm/internal/edgeban"
)

// handleEdgeBan records a manual ban in the edge ban store (internal/edgeban):
// the out-of-process `cfm block` writes nft itself and cannot reach the
// daemon's store, so it calls this after a successful block.
//
//	POST /api/v1/webdet/edge-ban?ip=1.2.3.4[&ttl=6h]   (no ttl: permanent)
//
// Admin-only. The store keeps the entry only while nft blocks the address
// (edgeban.Store.Reconcile), so a ban recorded here that nft does not hold is
// dropped at the next reconcile. Unbans go through force-unblock-ip.
func (e *Engine) handleEdgeBan(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	ip := net.ParseIP(strings.TrimSpace(r.URL.Query().Get("ip")))
	if ip == nil || ip.IsUnspecified() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or missing ip"})
		return
	}
	var ttl *time.Duration
	if v := strings.TrimSpace(r.URL.Query().Get("ttl")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ttl"})
			return
		}
		ttl = &d
	}
	edgeban.Ban(ip, ttl, "manual", true)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ip": ip.String(), "stored": edgeban.Default() != nil})
}
