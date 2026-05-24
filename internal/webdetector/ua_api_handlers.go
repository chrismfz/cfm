// internal/webdetector/ua_api_handlers.go
//
// HTTP handlers for the bot-top control surface:
//
//   GET    /api/v1/webdet/ua-top                 — bot-top live rows
//   GET    /api/v1/webdet/ua-drill?ua=<name>     — drilldown for one normalized UA
//   GET    /api/v1/webdet/ua-emergency           — active emergency rules
//   POST   /api/v1/webdet/ua-emergency           — install rule (JSON body)
//   DELETE /api/v1/webdet/ua-emergency?ua=<name> — remove rule
//
// All endpoints are admin-only. Box-wide emergency rules are not appropriate
// for scoped (per-vhost) tokens since their effect crosses tenant boundaries.
package webdetector

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// uaEmergencyPostBody is the JSON shape accepted by POST /ua-emergency.
type uaEmergencyPostBody struct {
	UA         string `json:"ua"`
	Action     string `json:"action"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Reason     string `json:"reason,omitempty"`
	By         string `json:"by,omitempty"`     // optional operator identity tag
	Confirm    bool   `json:"confirm,omitempty"` // required when UA is a verified Google crawler
}

// handleUATop returns the bot-top live rows. Optional ?limit=N (default 20).
func (e *Engine) handleUATop(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rows := e.UATop(limit)
	writeJSON(w, http.StatusOK, rows)
}

// handleUADrill returns the drilldown for a single normalized UA. Query
// param ?ua=<name>. The name is normalized server-side so callers can pass
// either the canonical form or a raw UA string.
func (e *Engine) handleUADrill(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	ua := strings.TrimSpace(r.URL.Query().Get("ua"))
	if ua == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ua"})
		return
	}
	d := e.UADrill(ua)
	writeJSON(w, http.StatusOK, d)
}

// handleUAEmergency dispatches GET/POST/DELETE on /ua-emergency.
func (e *Engine) handleUAEmergency(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		e.uaEmergencyList(w, r)
	case http.MethodPost:
		e.uaEmergencyAdd(w, r)
	case http.MethodDelete:
		e.uaEmergencyRemove(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (e *Engine) uaEmergencyList(w http.ResponseWriter, _ *http.Request) {
	if e.uaEmergency == nil {
		writeJSON(w, http.StatusOK, []UAEmergencyRule{})
		return
	}
	writeJSON(w, http.StatusOK, e.uaEmergency.List())
}

func (e *Engine) uaEmergencyAdd(w http.ResponseWriter, r *http.Request) {
	if e.uaEmergency == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ua emergency store unavailable"})
		return
	}
	// Cap the request body so a single authenticated POST can't OOM the
	// daemon. The schema is tiny (ua + action + ttl + reason); 64 KiB
	// gives generous headroom for a long reason string.
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var body uaEmergencyPostBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json body"})
		return
	}

	body.UA = NormalizeUA(body.UA)
	body.Action = strings.ToLower(strings.TrimSpace(body.Action))

	// Google warn-list: refuse unless the caller explicitly confirmed.
	// Applied server-side so the TUI and any web UI inherit the guard.
	if IsGoogleVerifiedBot(body.UA) && !body.Confirm {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":           "google_verified_bot_requires_confirm",
			"ua":              body.UA,
			"message":         "This is a verified Google crawler. Re-submit with \"confirm\": true to proceed.",
			"google_verified": true,
		})
		return
	}

	ttl := time.Duration(body.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = UAEmergencyDefaultTTL
	}
	if ttl > UAEmergencyMaxTTL {
		ttl = UAEmergencyMaxTTL
	}

	by := strings.TrimSpace(body.By)
	if by == "" {
		by = "admin"
	}

	r2, err := e.uaEmergency.Set(body.UA, body.Action, by, body.Reason, ttl)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, r2)
}

func (e *Engine) uaEmergencyRemove(w http.ResponseWriter, r *http.Request) {
	if e.uaEmergency == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ua emergency store unavailable"})
		return
	}
	ua := NormalizeUA(r.URL.Query().Get("ua"))
	if ua == "" || ua == "-" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ua"})
		return
	}
	by := strings.TrimSpace(r.URL.Query().Get("by"))
	if by == "" {
		by = "admin"
	}
	removed, ok := e.uaEmergency.Delete(ua, by)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "rule not found"})
		return
	}
	writeJSON(w, http.StatusOK, removed)
}
