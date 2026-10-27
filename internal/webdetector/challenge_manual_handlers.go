// internal/webdetector/challenge_manual_handlers.go

package webdetector

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
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
	// Lockdown: true puts the arm in LOCKDOWN (no client exemption at all,
	// vhost_lockdown.go) for LockdownTTL (default 30m, at most 6h, never past
	// the arm); false lifts it; absent keeps whatever the arm has. Query
	// form: lockdown=1|0 (true/false/on/off). Scoped tokens may set it on
	// their own vhosts: it only adds challenges, on a vhost they own.
	Lockdown    *bool  `json:"lockdown"`
	LockdownTTL string `json:"lockdown_ttl"`
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
	// Tier is the host's EFFECTIVE tier after the arm (challengeV2VhostTier):
	// a manual arm at v1 does not downgrade an automatic v2, so "rung":"v1"
	// alone could read as the tier the solves are held to when it is not.
	Tier map[string]string `json:"tier"`
	// Lockdown / LockdownUntil: the arm's lockdown after the call (kept,
	// set or lifted). LockdownCapped: the requested lockdown TTL was cut to
	// the 6h maximum or to the arm's expiry.
	Lockdown       bool       `json:"lockdown"`
	LockdownUntil  *time.Time `json:"lockdown_until,omitempty"`
	LockdownCapped bool       `json:"lockdown_capped,omitempty"`
}

// parseLockdownParam reads a lockdown flag from a query value: "" = absent.
func parseLockdownParam(v string) (val, set bool, err error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return false, false, nil
	case "1", "true", "on", "yes":
		return true, true, nil
	case "0", "false", "off", "no":
		return false, true, nil
	}
	return false, false, errors.New("invalid lockdown: " + v + " (use 1/0, true/false, on/off)")
}

// parseLockdownTTL reads a lockdown TTL ("" = defaultLockdownTTL).
func parseLockdownTTL(v string) (time.Duration, error) {
	if strings.TrimSpace(v) == "" {
		return defaultLockdownTTL, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return 0, errors.New("invalid lockdown_ttl: " + v)
	}
	return d, nil
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
// Body: { "host": "example.gr", "ttl": "30m", "reason": "manual", "rung": "v2", "lockdown": true, "lockdown_ttl": "30m" }
// Also accepts query params: ?host=example.gr&ttl=30m&reason=manual&rung=v2&lockdown=1&lockdown_ttl=30m
// lockdown absent keeps the arm's lockdown (a re-arm never lifts it); see
// vhost/lockdown for switching it on an armed vhost without re-arming.
//
// Scoped tokens: own vhosts only (vhostAllowed, fail-closed), and the TTL is
// clamped to scopedMaxChallengeTTL (24h) with ttl_capped=true in the
// response. Admin/loopback callers are uncapped.
func (e *Engine) handleChallengeVhostAdd(w http.ResponseWriter, r *http.Request) {
	req := chalVhostAddRequest{
		Host:        r.URL.Query().Get("host"),
		TTL:         r.URL.Query().Get("ttl"),
		Reason:      r.URL.Query().Get("reason"),
		Rung:        r.URL.Query().Get("rung"),
		LockdownTTL: r.URL.Query().Get("lockdown_ttl"),
	}
	if v, set, err := parseLockdownParam(r.URL.Query().Get("lockdown")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	} else if set {
		req.Lockdown = &v
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
		if bodyReq.Lockdown != nil {
			req.Lockdown = bodyReq.Lockdown
		}
		if bodyReq.LockdownTTL != "" {
			req.LockdownTTL = bodyReq.LockdownTTL
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
	// lockdown_ttl matters only when a lockdown is being set: a stale or
	// malformed one must not block a plain arm (or a lift).
	lockTTL := defaultLockdownTTL
	if req.Lockdown != nil && *req.Lockdown {
		var err error
		if lockTTL, err = parseLockdownTTL(req.LockdownTTL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	// The edge matches a lockdown on the exact host (cfm_lockdown.lua): a
	// wildcard lockdown would claim what it never enforces.
	if req.Lockdown != nil && *req.Lockdown && strings.Contains(req.Host, "*") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "lockdown is not supported on wildcard hosts — arm the concrete vhost(s)"})
		return
	}

	actor := actorFromScope(scope)
	e.ManualChallengeVhostAs(req.Host, ttl, req.Reason, rung, actor)
	lockCapped := false
	if req.Lockdown != nil {
		lt := time.Duration(0)
		if *req.Lockdown {
			lt = lockTTL
		}
		_, lockCapped, _, _ = e.SetManualChallengeLockdownAs(req.Host, lt, actor)
	}

	tier := e.challengeV2VhostTier(req.Host)
	resp := chalVhostAddResponse{
		Host:           req.Host,
		Status:         "active",
		ExpiresAt:      time.Now().Add(ttl),
		TTL:            ttl.String(),
		Reason:         req.Reason,
		Rung:           rungOrV1(rung),
		TTLCapped:      ttlCapped,
		Tier:           tierJSON(tier),
		LockdownCapped: lockCapped,
	}
	if lu := e.vhostLockdownUntil(req.Host); !lu.IsZero() {
		resp.Lockdown, resp.LockdownUntil = true, lockdownPtr(lu)
	}
	writeJSON(w, http.StatusOK, resp)
}

// POST /api/v1/challenge/vhost/lockdown
// Body: { "host": "example.gr", "lockdown": true, "ttl": "30m" }
// (also ?host=&lockdown=1|0&ttl=)
//
// Switches the LOCKDOWN (vhost_lockdown.go) of the ACTIVE manual challenge
// covering host, keeping the arm's expiry, reason and tier — unlike
// vhost/add, which re-arms. "Covering" is manualRungTarget (the host's own
// arm, else its apex's for a www. host), and the scope check covers that
// target too. ttl: default 30m, at most 6h, never past the arm (the response
// says lockdown_capped). lockdown is REQUIRED. 409 when no manual challenge is
// active: a lockdown is an attribute of a manual arm (arm with vhost/add
// lockdown=1 to do both at once). Lifting an absent lockdown is a no-op
// (changed=false, no audit row). Scope: as vhost/add — a scoped token may
// lock down its own vhost (it only adds challenges, on a vhost it owns).
func (e *Engine) handleChallengeVhostLockdown(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	type lockdownRequest struct {
		Host     string `json:"host"`
		Lockdown *bool  `json:"lockdown"`
		TTL      string `json:"ttl"`
	}
	req := lockdownRequest{Host: q.Get("host"), TTL: q.Get("ttl")}
	if v, set, err := parseLockdownParam(q.Get("lockdown")); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	} else if set {
		req.Lockdown = &v
	}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body lockdownRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return
		}
		if body.Host != "" {
			req.Host = body.Host
		}
		if body.Lockdown != nil {
			req.Lockdown = body.Lockdown
		}
		if body.TTL != "" {
			req.TTL = body.TTL
		}
	}
	host := normalizeHost(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(host, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if req.Lockdown == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing lockdown (use 1/0, true/false, on/off)"})
		return
	}
	ttl := time.Duration(0)
	if *req.Lockdown {
		var err error
		if ttl, err = parseLockdownTTL(req.TTL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	if *req.Lockdown && strings.Contains(host, "*") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "lockdown is not supported on wildcard hosts — arm the concrete vhost(s)"})
		return
	}
	target := e.manualRungTarget(host)
	if target == "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "no active manual challenge on " + host + " — a lockdown is part of a manual challenge (challenge/vhost/add lockdown=1 arms both)",
		})
		return
	}
	// The arm that changes may be the APEX of the requested www host: a scoped
	// token must hold it too (as vhost/rung).
	if target != host && !vhostAllowed(target, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the arm covering " + host + " is on " + target + ", which is not in scope"})
		return
	}
	_, capped, changed, ok := e.SetManualChallengeLockdownAs(target, ttl, actorFromScope(scope))
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the manual challenge on " + target + " expired"})
		return
	}
	// Report the EFFECTIVE lockdown of the host asked about: a www. host stays
	// locked while its apex's lockdown holds, whatever its own arm says.
	eff := e.vhostLockdownUntil(host)
	resp := map[string]interface{}{
		"host":     target,
		"lockdown": !eff.IsZero(),
		"changed":  changed,
	}
	if !eff.IsZero() {
		resp["lockdown_until"] = eff
		if !*req.Lockdown {
			apex := strings.TrimPrefix(host, "www.")
			resp["note"] = host + " stays locked down by the lockdown on " + apex + " (lift it there)"
		}
	}
	if capped {
		resp["lockdown_capped"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// tierJSON is the effective-tier block the tier-changing endpoints return.
func tierJSON(t vhostV2Tier) map[string]string {
	return map[string]string{"rung": rungOrV1(t.Rung), "source": t.Source, "trigger": t.Trigger}
}

// tierRequest is the host/rung(/ttl) request vhost/rung and vhost/tier share.
type tierRequest struct {
	Host string `json:"host"`
	Rung string `json:"rung"`
	TTL  string `json:"ttl"`
}

// decodeTierRequest reads a tierRequest from the query, overridden field by
// field by a JSON body (bounded; an empty body is fine). On a bad body it
// writes the 400 and returns ok=false. The ONE decoder for both endpoints.
func decodeTierRequest(w http.ResponseWriter, r *http.Request) (tierRequest, bool) {
	q := r.URL.Query()
	req := tierRequest{Host: q.Get("host"), Rung: q.Get("rung"), TTL: q.Get("ttl")}
	if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body tierRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
			return req, false
		}
		if body.Host != "" {
			req.Host = body.Host
		}
		if body.Rung != "" {
			req.Rung = body.Rung
		}
		if body.TTL != "" {
			req.TTL = body.TTL
		}
	}
	return req, true
}

// POST /api/v1/challenge/vhost/rung
// Body: { "host": "example.gr", "rung": "v2" }   (also ?host=&rung=)
//
// Switches the tier of the ACTIVE manual challenge covering host between v1
// and v2, keeping its expiry and reason (unlike vhost/add, which re-arms with
// a fresh TTL). "Covering" is manualRungTarget: the host's own arm, else its
// apex for a www. host — the same arm the verify gate reads — and the scope
// check covers that target too. Switching to the current tier is a no-op
// (changed=false, no audit row). 409 when no manual challenge is active — an
// automatic challenge's tier is a tier pin's job (vhost/tier). The response's
// `tier` is the host's EFFECTIVE tier after the switch: a manual arm switched
// to v1 stays v2 while an automatic v2 covers the host (a manual v1 arm never
// downgrades — challenge_v2_auto.go).
// rung is REQUIRED here: on vhost/add an absent rung means "preserve", so a
// missing one on the endpoint whose only job is changing it is a caller bug.
// Scope: same as vhost/add (vhostAllowed, fail-closed) — challenge-tier either
// way, so a scoped token may re-tier its own vhost's arm.
func (e *Engine) handleChallengeVhostRung(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeTierRequest(w, r)
	if !ok {
		return
	}
	host := normalizeHost(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	scope := vhostScopeFromContext(r.Context())
	if !vhostAllowed(host, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	if strings.TrimSpace(req.Rung) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing rung (use v1 or v2)"})
		return
	}
	rung, ok := normalizeRung(req.Rung)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rung: " + req.Rung + " (use v1 or v2)"})
		return
	}
	// Same fail-closed rule as vhost/add: the verify-side rung lookup is
	// exact+www only, so a wildcard v2 arm would claim a tier it never gates.
	if rung == "v2" && strings.Contains(host, "*") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rung=v2 is not supported on wildcard hosts yet — arm the concrete vhost(s)"})
		return
	}
	target := e.manualRungTarget(host)
	if target == "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "no active manual challenge on " + host + " — an automatic challenge's tier is set with a tier pin (challenge/vhost/tier rung=v1|v2|auto)",
		})
		return
	}
	// The arm that changes may be the APEX of the requested www host: a
	// scoped token must hold that host too, or re-tiering www.example.com
	// would downgrade an operator's v2 arm on example.com (fail-closed).
	if target != host && !vhostAllowed(target, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "the arm covering " + host + " is on " + target + ", which is not in scope"})
		return
	}
	prev, expires, changed, ok := e.SetManualChallengeRungAs(target, rung, actorFromScope(scope))
	if !ok {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the manual challenge on " + target + " expired"})
		return
	}
	// The EFFECTIVE tier after the switch: a manual arm switched to v1 on a
	// host an automatic v2 also covers stays v2 (a manual v1 arm never
	// downgrades — challenge_v2_auto.go). Say so, rather than let "rung":"v1"
	// read as done; the way down there is a v1 pin.
	tier := e.challengeV2VhostTier(host)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":       target,
		"rung":       rungOrV1(rung),
		"from":       rungOrV1(prev),
		"changed":    changed,
		"expires_at": expires,
		"tier":       tierJSON(tier),
	})
}

// POST /api/v1/challenge/vhost/tier
// Body: { "host": "example.gr", "rung": "v1" | "v2" | "auto", "ttl": "24h" }
// Also accepts query params. GET lists the live pins (admin only).
//
// Pins the tier of AUTOMATIC vhost challenges on host (challenge_v2_auto.go):
// v1 = never v2 here, whatever CHALLENGE_V2_AUTO_VHOST says (the "drop it back
// to v1" control); v2 = always v2 here; auto = remove the pin (the knob
// decides again). It never creates, extends or clears a challenge; a MANUAL
// arm at v2 stays v2 (switch that with vhost/rung), and one at v1 never
// downgrades what the pin/knob give — the response's `tier` is the effective
// result either way. ttl is optional (none = until
// cleared). Scoped tokens: own vhosts only (and, clearing a www. host, the
// apex pin that covers it); their pins are capped at scopedMaxChallengeTTL,
// so a tenant can never park a permanent tier; and a pin the operator set
// (actor != scoped) covering the host is theirs to keep — 403.
func (e *Engine) handleChallengeVhostTier(w http.ResponseWriter, r *http.Request) {
	scope := vhostScopeFromContext(r.Context())
	if r.Method == http.MethodGet {
		if !RequireAdmin(w, r) {
			return
		}
		type pinRow struct {
			Host      string     `json:"host"`
			Rung      string     `json:"rung"`
			ExpiresAt *time.Time `json:"expires_at,omitempty"` // absent = until cleared
			SetAt     time.Time  `json:"set_at"`
			Actor     string     `json:"actor,omitempty"`
		}
		rows := []pinRow{}
		for h, p := range e.ChallengeTierPins() {
			row := pinRow{Host: h, Rung: p.Rung, SetAt: p.SetAt, Actor: p.Actor}
			if !p.ExpiresAt.IsZero() {
				exp := p.ExpiresAt
				row.ExpiresAt = &exp
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Host < rows[j].Host })
		writeJSON(w, http.StatusOK, map[string]interface{}{"pins": rows})
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET or POST"})
		return
	}
	req, ok := decodeTierRequest(w, r)
	if !ok {
		return
	}
	host := normalizeHost(req.Host)
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	if !vhostAllowed(host, scope) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
	// The verify-side lookup is exact + www→apex only (like the manual tier),
	// so a wildcard pin would claim a tier it never applies.
	if strings.Contains(host, "*") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tier pins are not supported on wildcard hosts — pin the concrete vhost(s)"})
		return
	}
	// v1/v2 spellings are normalizeRung's (the one alias list, shared with
	// vhost/add and vhost/rung); "auto" (remove the pin) is this endpoint's own.
	var rung string
	switch v := strings.ToLower(strings.TrimSpace(req.Rung)); v {
	case "":
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing rung (use v1, v2 or auto)"})
		return
	case "auto", "clear", "default":
		rung = ""
	default:
		n, ok := normalizeRung(v)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid rung: " + req.Rung + " (use v1, v2 or auto)"})
			return
		}
		rung = rungOrV1(n)
	}
	var ttl time.Duration
	if t := strings.TrimSpace(req.TTL); t != "" && rung != "" {
		d, err := time.ParseDuration(t)
		if err != nil || d <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ttl: " + req.TTL})
			return
		}
		ttl = d
	}
	capped := false
	if scope != nil && rung != "" && (ttl <= 0 || ttl > scopedMaxChallengeTTL) {
		ttl = scopedMaxChallengeTTL
		capped = true
	}
	// The scope check on the pin a clear acts on (the covering one — the
	// host's own, else its apex's for a www. host), and the operator-pin
	// guard, run INSIDE the store's write lock (tierPinStore.apply), so a pin
	// that changes between check and write can never slip past either. An
	// operator's pin is the operator's decision: a scoped token may not
	// replace it, clear it, or shadow an apex one with its own www. pin (its
	// 24h cap would otherwise silently end a standing operator pin); its own
	// earlier pins it may change freely.
	actor := actorFromScope(scope)
	var protect func(tierPin) bool
	if scope != nil {
		protect = func(p tierPin) bool { return p.Actor != actor }
	}
	target, prev, changed, refusal, pin := e.setChallengeTierPinGet(host, rung, ttl, actor,
		func(t string) bool { return vhostAllowed(t, scope) }, protect)
	if refusal != "" {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": refusal})
		return
	}
	tier := e.challengeV2VhostTier(host)
	resp := map[string]interface{}{
		"host":    target,
		"pin":     rungOrAuto(rung),
		"from":    rungOrAuto(prev),
		"changed": changed,
		// The EFFECTIVE tier of the requested host after the change: a
		// manual arm outranks any pin, and a pin does nothing while no
		// automatic challenge covers the host — say so rather than let a
		// caller assume the pin took effect.
		"tier": tierJSON(tier),
	}
	if !pin.ExpiresAt.IsZero() {
		resp["expires_at"] = pin.ExpiresAt
	}
	if capped {
		resp["ttl_capped"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

// rungOrAuto renders a pin value for API/logs: "" (no pin) reads as "auto".
func rungOrAuto(rung string) string {
	if rung == "" {
		return "auto"
	}
	return rung
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
	// event, both carrying the actor (and ttl_sec when the override is
	// TTL-bound, see overrideTTL above).
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

	lockUntil := e.vhostLockdownUntil(host)
	lockUntilJSON := lockdownPtr(lockUntil)

	tier := e.challengeV2VhostTierForScope(host)
	// An automatic vhost challenge the store never records (uniqpaths_short
	// writes no row) is still live and still carries a tier: report it as
	// auto-active, or the pages drop the host — and its "→ v1 (pin)"
	// emergency control — while its solves are held to v2.
	if !autoActive && tier.Trigger != "" && tier.Trigger != autoV2UnderAttack {
		autoActive = true // a real automatic challenge (not a bare under_attack note)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"host":          host,
		"manual_active": active,
		"expires_at":    expiresAt,
		"reason":        reason,
		// The host's effective vhost tier ("v2" or "" for v1) and where it
		// comes from — challengeV2VhostTier, the verify gate's own resolver.
		// This is the ONE vhost surface scoped tokens can read, so a customer
		// can see (and switch) the tier on their own vhost (review finding).
		"rung":         tier.Rung,
		"rung_source":  tier.Source,
		"rung_trigger": tier.Trigger,
		"rung_pin":     tier.Pin,
		"rung_auto":    tier.AutoRung,
		// true when the caller is a scoped token and the operator set the
		// pin: the tenant's surfaces hide the pin controls (the write 403s).
		"rung_pin_locked":   tier.pinLockedFor(vhostScopeFromContext(r.Context())),
		"rung_unpin_locked": tier.unpinLockedFor(vhostScopeFromContext(r.Context())),
		// The covering manual arm's LOCKDOWN (vhost_lockdown.go): no client
		// exemption on this vhost until lockdown_until (null when none).
		"lockdown":       !lockUntil.IsZero(),
		"lockdown_until": lockUntilJSON,
		"auto_active":    autoActive,
		"auto_since":     autoSince,
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
