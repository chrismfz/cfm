// internal/webdetector/force_unblock_handler.go
package webdetector

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"

	"cfm/internal/unblock"
)

// handleForceUnblockIP force-clears every per-IP WAF plane for an IP: the
// Go-side challenge/block state and the per-IP cfm_decisions shared-dict caches
// (throttle, decision cache, geo, ok-touch, waf-push).
//
//	POST /api/v1/webdet/force-unblock-ip?ip=1.2.3.4
//	(also accepts a JSON body {"ip":"1.2.3.4"})
//
// Admin-only. Returns an unblock.WAFResult describing what was found/cleared.
// This is the out-of-process entry point used by `cfm unblock` (via
// unblock.HTTPWAFCleaner); in-daemon callers use the bridge adapter directly.
func (e *Engine) handleForceUnblockIP(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		var body struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		ip = strings.TrimSpace(body.IP)
	}

	if net.ParseIP(ip) == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or missing ip"})
		return
	}

	// DNAT mode (no OpenResty bridge): nothing to clear, report empty.
	if e.nginxBridge == nil {
		writeJSON(w, http.StatusOK, unblock.WAFResult{})
		return
	}

	writeJSON(w, http.StatusOK, e.nginxBridge.ForceUnblock(ip))
}
