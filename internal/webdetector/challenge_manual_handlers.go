// internal/webdetector/challenge_manual_handlers.go

package webdetector

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"cfm/internal/logging"
)

type chalVhostAddRequest struct {
	Host   string `json:"host"`
	TTL    string `json:"ttl"`    // e.g. "30m", "1h" — optional, default 30m
	Reason string `json:"reason"` // optional, default "manual"
	// Rung: "v1" (default; plain challenge) or "v2"/"challenge_v2"
	// (ChallengeV2: same challenge page, but a solve failing the Rung-1
	// humanity check earns NO clearance). Challenge-tier either way, so
	// scoped tokens may set it for their own vhosts like any manual
	// challenge — there is no deny here to escalate to.
	Rung string `json:"rung"`
}

type chalVhostAddResponse struct {
	Host      string    `json:"host"`
	Status    string    `json:"status"` // "active"
	ExpiresAt time.Time `json:"expires_at"`
	TTL       string    `json:"ttl"`
	Reason    string    `json:"reason"`
	Rung      string    `json:"rung"` // "v1" | "v2"
	// TTLCapped is set when a scoped caller asked for more than the scoped
	// TTL ceiling and the arm was clamped (slice D). The TTL/ExpiresAt
	// fields always carry the EFFECTIVE values, so a capped arm is visible,
	// never silent.
	TTLCapped bool `json:"ttl_capped,omitempty"`
}

// sanitizeAuditReason bounds the free-text reason a caller may attach to a
// manual arm: control characters (incl. CR/LF) are stripped so the value can
// never forge lines or key=value pairs in the flat audit logs (the log sites
// also %q-quote it — defence in depth), and the length is capped so an
// unbounded query-param reason cannot bloat the logs or the persist file
// (slice-D security review I1/M3).
func sanitizeAuditReason(s string) string {
	const maxLen = 200
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r < 0x20 || r == 0x7f {
			continue
		}
		// Byte-count BEFORE writing so a multibyte rune at the boundary
		// can never push past the cap (never splits a rune either —
		// the whole rune is simply dropped).
		if b.Len()+utf8.RuneLen(r) > maxLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// actorFromScope maps a request's vhost scope to the audit actor recorded on
// manual arm/disarm history events: nil scope = admin/loopback, non-nil =
// scoped token (vhostScopeFromContext semantics).
func actorFromScope(scope map[string]struct{}) string {
	if scope == nil {
		return "admin"
	}
	return "scoped"
}

// scopedMaxChallengeTTL caps how long a SCOPED (cPanel customer) token may arm
// a manual challenge on its own vhost (master plan slice D: the panic button
// is a temporary shield, not a permanent config — a customer who wants a
// standing challenge asks the operator). Admin/loopback callers are uncapped.
// Clamp-and-report, not reject: the panic-button UX must never fail because
// the customer typed "7d" — the response carries ttl_capped + the effective
// expiry instead.
const scopedMaxChallengeTTL = 24 * time.Hour

// normalizeRung maps the accepted spellings to the stored tier: "" for plain
// challenge, "v2" for ChallengeV2; ok=false for anything else (fail-closed on
// typos — silently arming the wrong tier is the failure mode).
func normalizeRung(s string) (rung string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "v1", "challenge":
		return "", true
	case "v2", "challenge_v2":
		return "v2", true
	}
	return "", false
}

// POST /api/v1/challenge/vhost/add
// Body: { "host": "example.gr", "ttl": "30m", "reason": "manual", "rung": "v2" }
// Also accepts query params: ?host=example.gr&ttl=30m&reason=manual&rung=v2
//
// Scoped tokens: own vhosts only (vhostAllowed, fail-closed), and the TTL is
// clamped to scopedMaxChallengeTTL (24h) with ttl_capped=true in the
// response. Admin/loopback callers are uncapped.
func (e *Engine) handleChallengeVhostAdd(w http.ResponseWriter, r *http.Request) {
	req := chalVhostAddRequest{
		Host:   r.URL.Query().Get("host"),
		TTL:    r.URL.Query().Get("ttl"),
		Reason: r.URL.Query().Get("reason"),
		Rung:   r.URL.Query().Get("rung"),
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
		if bodyReq.Rung != "" {
			req.Rung = bodyReq.Rung
		}
	}

	req.Host = normalizeHost(req.Host)
	if req.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	// Scope check: scoped tokens may only challenge their own vhosts.
	// (vhostScopeFromContext: nil = admin/loopback, non-nil = scoped —
	// including the fail-closed empty set for a scoped token with no scope.)
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(req.Host, scope) {
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
	// Scoped TTL ceiling (slice D): clamp, and say so in the response.
	ttlCapped := false
	if scope != nil && ttl > scopedMaxChallengeTTL {
		ttl = scopedMaxChallengeTTL
		ttlCapped = true
	}

	req.Reason = sanitizeAuditReason(req.Reason)
	if req.Reason == "" {
		req.Reason = "manual"
	}

	rung, ok := normalizeRung(req.Rung)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rung: " + req.Rung + " (use v1 or v2)"})
		return
	}
	// An ABSENT tier preserves an existing arm's rung: a TTL extension or
	// re-challenge from a rung-unaware surface (live view, bots drilldown,
	// plain CLI) must not silently disarm v2 (review finding). An explicit
	// rung=v1 still downgrades — that is the operator saying so.
	if strings.TrimSpace(req.Rung) == "" {
		rung = e.manualChal.rung(req.Host)
	}
	// Wildcard hosts (*.example.com / cpanel.*) are challengeable, but the
	// verify-side rung lookup is exact+www only — a wildcard v2 arm would
	// SERVE challenges on matching hosts while the v2 gate never fires, with
	// the status still claiming v2 (review finding: silent tier downgrade +
	// lying status). Fail closed until the rung lookup learns the bridge's
	// wildcard match. Runs on the EFFECTIVE rung (after the preserve above),
	// so even a stale preserved wildcard-v2 entry cannot be re-persisted.
	if rung == "v2" && strings.Contains(req.Host, "*") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rung=v2 is not supported on wildcard hosts yet — arm the concrete vhost(s)"})
		return
	}

	e.ManualChallengeVhostAs(req.Host, ttl, req.Reason, rung, actorFromScope(scope))

	writeJSON(w, http.StatusOK, chalVhostAddResponse{
		Host:      req.Host,
		Status:    "active",
		ExpiresAt: time.Now().Add(ttl),
		TTL:       ttl.String(),
		Reason:    req.Reason,
		Rung:      rungOrV1(rung),
		TTLCapped: ttlCapped,
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
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(host, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

	e.ClearManualChallengeVhostAs(host, actorFromScope(scope))

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
// may only override their own vhosts (vhostAllowed), mirroring vhost/add|remove,
// and a scoped on=1 is TTL-bound to scopedMaxChallengeTTL (24h) like the
// panic-button arm — the response then carries ttl + expires_at; admin
// overrides stay unbounded.
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
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(host, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	// The override only means anything while the detector is running. Fail loudly
	// rather than silently no-op (SetVhostAttackOverride is nil-safe when off).
	if e == nil || !e.cfg.UnderAttack {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "under-attack mode is disabled (UNDER_ATTACK=0)"})
		return
	}

	// A SCOPED forced-ON override is TTL-bound to the same 24h ceiling as the
	// panic-button arm (operator decision on the slice-D residual): the
	// customer shield is temporary, a standing override is the operator's
	// call. Admin overrides stay unbounded. `attack off` needs no bound (the
	// holddown already limits the suppression).
	var overrideTTL time.Duration
	if scope != nil && on {
		overrideTTL = scopedMaxChallengeTTL
	}
	e.SetVhostAttackOverride(host, on, time.Now(), overrideTTL)

	// Audit (slice-D security review I3): this override used to leave NO
	// trail beyond the generic api.log request line — a scoped customer
	// could force (or clear) UNDER_ATTACK on their vhost invisibly. Record
	// it like the manual arm/disarm: a CHALLENGES log line and a history
	// event, both carrying the actor. (The override itself stays un-TTL'd —
	// documented residual in the master plan, pending a TTL-or-admin-only
	// decision.)
	actor := actorFromScope(scope)
	reason := "attack_cleared"
	if on {
		reason = "attack_forced"
	}
	logging.LogfCHALLENGES(
		"[challenge][vhost] action=attack_override host=%s on=%v actor=%s",
		host, on, actorOrDash(actor),
	)
	payload := map[string]interface{}{"actor": actor, "on": on}
	if overrideTTL > 0 {
		payload["ttl_sec"] = int(overrideTTL / time.Second)
	}
	e.appendHistory(HistoryEvent{
		TsUnix:  time.Now().Unix(),
		Type:    "challenge_vhost_attack_override",
		Host:    host,
		Mode:    "manual",
		Reason:  reason,
		Payload: payload,
	})
	resp := map[string]interface{}{
		"host":   host,
		"attack": on,
	}
	if overrideTTL > 0 {
		resp["ttl"] = overrideTTL.String()
		resp["expires_at"] = time.Now().Add(overrideTTL)
	}
	writeJSON(w, http.StatusOK, resp)
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
		// The tier of the covering manual challenge ("v2" or "" for plain).
		// This is the ONE vhost surface scoped tokens can read, so a customer
		// who armed v2 on their own vhost can see it (review finding).
		"rung":        e.manualChallengeRung(host),
		"auto_active": autoActive,
		"auto_since":  autoSince,
		// Scoped tokens reach the vhost list only through this endpoint, so the
		// farm mark, the shadow outlier count, the facet cardinality, the cost
		// pressure, the datacenter fraction and the escalation state have to ride
		// along here too, or the badges would be admin-only. Single-sourced via
		// deriveVhostState / the mark stores.
		"solver_farm":       IsSolverFarm(host),
		"shadow_outliers":   AbuseShadowOutliers(host),
		"query_cardinality": FacetShadowCardinality(host),
		"cost_pressure":     CostShadowPressure(host),
		"dc_fraction":       DCFracShadowPercent(host),
		"state":             e.deriveVhostStateForHost(host, time.Now()),
	})
}
