// internal/webdetector/challenge_manual_handlers.go

package webdetector

import (
	"encoding/json"
	"errors"
	"io"
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
	Status    string    `json:"status"` // "active"
	ExpiresAt time.Time `json:"expires_at"`
	TTL       string    `json:"ttl"`
	Reason    string    `json:"reason"`
}

// POST /api/v1/challenge/vhost/add
// Body: { "host": "example.gr", "ttl": "30m", "reason": "manual" }
// Also accepts query params: ?host=example.gr&ttl=30m&reason=manual
func (e *Engine) handleChallengeVhostAdd(w http.ResponseWriter, r *http.Request) {
	req := chalVhostAddRequest{
		Host:   r.URL.Query().Get("host"),
		TTL:    r.URL.Query().Get("ttl"),
		Reason: r.URL.Query().Get("reason"),
	}

	// Accept both JSON body and query params.
	ct := r.Header.Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		var bodyReq chalVhostAddRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&bodyReq); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if bodyReq.Host != "" {
			req.Host = bodyReq.Host
		}
		if bodyReq.TTL != "" {
			req.TTL = bodyReq.TTL
		}
		if bodyReq.Reason != "" {
			req.Reason = bodyReq.Reason
		}
	}

	req.Host = normalizeHost(req.Host)
	if req.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	// Scope check: scoped tokens may only challenge their own vhosts.
	if !vhostAllowed(req.Host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
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
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body)
		host = body.Host
	}

	host = normalizeHost(host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	// Scope check: scoped tokens may only remove challenge for their own vhosts.
	if !vhostAllowed(host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

	e.ClearManualChallengeVhost(host)

	writeJSON(w, http.StatusOK, map[string]string{
		"host":   host,
		"status": "removed",
	})
}

type chalVhostAttackRequest struct {
	Host string `json:"host"`
	On   *bool  `json:"on"`
}

// parseAttackOn resolves the desired override state from the query value (or a
// JSON body bool, which wins). Returns an error for a missing/unrecognised value
// so the operator can't accidentally no-op.
func parseAttackOn(q string, body *bool) (bool, error) {
	if body != nil {
		return *body, nil
	}
	switch strings.ToLower(strings.TrimSpace(q)) {
	case "1", "true", "on", "yes":
		return true, nil
	case "0", "false", "off", "no":
		return false, nil
	}
	return false, errors.New("missing or invalid 'on' (use on=1 to force under-attack, on=0 to clear)")
}

// POST /api/v1/challenge/vhost/attack?host=example.gr&on=1
// Operator override for Under-Attack Mode: on=1|true|on forces the vhost INTO
// UNDER_ATTACK; on=0|false|off leaves it and suppresses auto re-entry for the
// holddown. Body { "host": "...", "on": true } is also accepted. Scoped tokens
// may only override their own vhosts (vhostAllowed), mirroring vhost/add|remove.
func (e *Engine) handleChallengeVhostAttack(w http.ResponseWriter, r *http.Request) {
	host := normalizeHost(r.URL.Query().Get("host"))
	onStr := r.URL.Query().Get("on")

	var onBody *bool
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body chalVhostAttackRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if body.Host != "" {
			host = normalizeHost(body.Host)
		}
		onBody = body.On
	}

	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	on, err := parseAttackOn(onStr, onBody)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Scope check: scoped tokens may only override their own vhosts.
	if !vhostAllowed(host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	// The override only means anything while the detector is running. Fail loudly
	// rather than silently no-op (SetVhostAttackOverride is nil-safe when off).
	if e == nil || !e.cfg.UnderAttack {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "under-attack mode is disabled (UNDER_ATTACK=0)"})
		return
	}

	e.SetVhostAttackOverride(host, on, time.Now())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":   host,
		"attack": on,
	})
}

// GET /api/v1/challenge/vhost/status?host=example.gr
// Returns whether host is manually challenged (and expiry if so).
func (e *Engine) handleChallengeVhostStatus(w http.ResponseWriter, r *http.Request) {
	// normalizeHost (trim+lower+strip :port), matching the store keying and the
	// sibling /challenge/vhost endpoint — a raw or port-bearing host must not
	// resolve differently across the two query endpoints.
	host := normalizeHost(r.URL.Query().Get("host"))
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !vhostAllowed(host, vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

	// Use covering (not exact-key) so the www variant of an apex manual
	// challenge reports manual_active=true — matching what the bridge enforces
	// and what the vhost status list now shows (apex→www expansion).
	active, expiresAt, reason := e.manualChallengeCovering(host)

	// Also check chalAPI for auto-challenge status
	autoActive := false
	var autoSince time.Time
	if e.chalAPI != nil {
		// Gate on Mode=="auto": while a manual challenge owns the row the store
		// keeps Mode=="manual" (manual outranks the scorer), so an effectively-
		// active manual row must not be reported as an active AUTO challenge.
		if v, ok := e.chalAPI.GetVhost(host); ok && v.Mode == "auto" && vhostEffectivelyActive(&v, time.Now()) {
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
		// Scoped tokens reach the vhost list only through this endpoint, so the
		// farm mark, the shadow outlier count and the escalation state have to
		// ride along here too, or the badges would be admin-only. Single-sourced
		// via deriveVhostState / the mark stores.
		"solver_farm":     IsSolverFarm(host),
		"shadow_outliers": AbuseShadowOutliers(host),
		"state":           e.deriveVhostStateForHost(host, time.Now()),
	})
}
