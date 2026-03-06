// internal/webdetector/challenge_manual_handlers.go
//
// Add these two handlers to http_api.go mux:
//   mux.HandleFunc("/api/v1/challenge/vhost/add",    e.handleChallengeVhostAdd)
//   mux.HandleFunc("/api/v1/challenge/vhost/remove", e.handleChallengeVhostRemove)

package webdetector

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type chalVhostAddRequest struct {
	Host   string `json:"host"`
	TTL    string `json:"ttl"`    // e.g. "30m", "1h" — optional, default 30m
	Reason string `json:"reason"` // optional, default "manual"
}

type chalVhostAddResponse struct {
	Host      string    `json:"host"`
	Status    string    `json:"status"`    // "active"
	ExpiresAt time.Time `json:"expires_at"`
	TTL       string    `json:"ttl"`
	Reason    string    `json:"reason"`
}

// POST /api/v1/challenge/vhost/add
// Body: { "host": "example.gr", "ttl": "30m", "reason": "manual" }
// Also accepts query params: ?host=example.gr&ttl=30m&reason=manual
func (e *Engine) handleChallengeVhostAdd(w http.ResponseWriter, r *http.Request) {
	var req chalVhostAddRequest

	// Accept both JSON body and query params.
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
	} else {
		req.Host   = r.URL.Query().Get("host")
		req.TTL    = r.URL.Query().Get("ttl")
		req.Reason = r.URL.Query().Get("reason")
	}

	req.Host = strings.TrimSpace(strings.ToLower(req.Host))
	if req.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	ttl := 30 * time.Minute
	if req.TTL != "" {
		if d, err := time.ParseDuration(req.TTL); err == nil && d > 0 {
			ttl = d
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ttl: " + req.TTL})
			return
		}
	}

	if req.Reason == "" {
		req.Reason = "manual"
	}

	e.ManualChallengeVhost(req.Host, ttl, req.Reason)

	writeJSON(w, http.StatusOK, chalVhostAddResponse{
		Host:      req.Host,
		Status:    "active",
		ExpiresAt: time.Now().Add(ttl),
		TTL:       ttl.String(),
		Reason:    req.Reason,
	})
}

// POST /api/v1/challenge/vhost/remove
// Body: { "host": "example.gr" }
// Also accepts: ?host=example.gr
func (e *Engine) handleChallengeVhostRemove(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		var body struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		host = body.Host
	}
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	e.ClearManualChallengeVhost(host)

	writeJSON(w, http.StatusOK, map[string]string{
		"host":   host,
		"status": "removed",
	})
}

// GET /api/v1/challenge/vhost/status?host=example.gr
// Returns whether host is manually challenged (and expiry if so).
func (e *Engine) handleChallengeVhostStatus(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("host")))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	active, expiresAt, reason := e.IsManualChallengeActive(host)

	// Also check chalAPI for auto-challenge status
	autoActive := false
	var autoSince time.Time
	if e.chalAPI != nil {
		if v, ok := e.chalAPI.GetVhost(host); ok && v.Status == "active" {
			autoActive = true
			autoSince = v.Since
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":          host,
		"manual_active": active,
		"expires_at":    expiresAt,
		"reason":        reason,
		"auto_active":   autoActive,
		"auto_since":    autoSince,
	})
}
