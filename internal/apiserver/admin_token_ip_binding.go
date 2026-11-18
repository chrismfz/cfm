package apiserver

import (
	"net/http"
	"strings"

	"cfm/internal/logging"
)

// Admin-token source-IP binding.
//
// The long-lived admin token (AUTH_TOKEN) is presented to a node only
// server-to-server: by cfm-web from its egress IP (== the API_URL host), and by
// the WHM plugin / panelauth over loopback. An operator's browser never carries
// the admin token — after SSO it holds the embed-admin cookie instead. So the
// admin-token auth branch can be bound to a source-IP allowlist without touching
// any interactive (cookie/session/scoped) path.
//
// This gate is a fail-safe control: it lives in the API itself, so a leaked
// AUTH_TOKEN used from a foreign IP is rejected even if the firewall is disabled
// or the admin port is opened. See docs/security/control-plane.md §4.
//
// NOTE: this closes direct-API use and SSO-code minting from a foreign IP. The
// admin SSO cookie is signed with a random per-node key (embed_admin_cookie_key.go),
// so a leaked AUTH_TOKEN cannot forge it. /mcp, which also accepts AUTH_TOKEN
// (read-only), applies the same binding (mcpStaticBearer). Not covered: the
// SCOPED embed cookie key is still derived from AUTH_TOKEN (embed_bootstrap.go),
// so a leak can forge a scoped viewer cookie.

const (
	adminIPModeOff     = "off"     // default — no source-IP check (behaviour unchanged)
	adminIPModeLogonly = "logonly" // burn-in — log would-block, still allow
	adminIPModeEnforce = "enforce" // reject (403) admin-token requests from a foreign source IP
)

// adminIPPolicy is the resolved source-IP binding policy for the admin token.
type adminIPPolicy struct {
	mode   string // adminIPMode* — normalized
	cfgDir string // config dir, for cfm.allow / cfm.dyndns
	apiURL string // API_URL — its host is resolved into the allowlist
}

func (p adminIPPolicy) active() bool {
	return p.mode == adminIPModeLogonly || p.mode == adminIPModeEnforce
}

// normalizeAdminIPMode maps a config value to a known mode. It fails OPEN on an
// unrecognized value (a typo must never lock the plane), but returns
// recognized=false so the caller can WARN — otherwise `ADMIN_TOKEN_IP_BINDING =
// enfroce` would silently disable the gate.
func normalizeAdminIPMode(s string) (mode string, recognized bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "0", "false", "no", "disable", "disabled":
		return adminIPModeOff, true
	case adminIPModeLogonly, "dryrun", "dry-run", "log", "log-only":
		return adminIPModeLogonly, true
	case adminIPModeEnforce, "on", "block", "true", "1":
		return adminIPModeEnforce, true
	default:
		return adminIPModeOff, false
	}
}

// tokenMiddlewareConfig carries the optional knobs of TokenMiddleware.
type tokenMiddlewareConfig struct {
	adminIP adminIPPolicy
}

// TokenMiddlewareOption configures optional TokenMiddleware behaviour. Existing
// callers pass none (all-defaults, admin-IP binding off), so the signature stays
// backward compatible.
type TokenMiddlewareOption func(*tokenMiddlewareConfig)

// WithAdminTokenIPBinding enables the admin-token source-IP gate. mode is
// off|logonly|enforce (see ADMIN_TOKEN_IP_BINDING); cfgDir and apiURL feed the
// allowlist (cfm.allow / cfm.dyndns / the API_URL host).
func WithAdminTokenIPBinding(mode, cfgDir, apiURL string) TokenMiddlewareOption {
	p := newAdminIPPolicy(mode, cfgDir, apiURL)
	return func(c *tokenMiddlewareConfig) {
		c.adminIP = p
	}
}

// newAdminIPPolicy resolves the binding policy. The /mcp static bearer uses the
// same one as TokenMiddleware (mcp_wire.go), so the admin token is bound the
// same way at both doors.
func newAdminIPPolicy(mode, cfgDir, apiURL string) adminIPPolicy {
	m, _ := normalizeAdminIPMode(mode)
	return adminIPPolicy{mode: m, cfgDir: cfgDir, apiURL: apiURL}
}

// adminTokenSourceAllowed reports whether r's source IP is within the admin
// allowlist: loopback ∪ selfIPs ∪ cfm.allow / cfm.dyndns ∪ the API_URL host.
// It keys on requestPeer(r).ClientIP (the forwarded real client behind a loopback
// edge hop), never RemoteAddr; an undeterminable/untrusted source fails closed.
func adminTokenSourceAllowed(r *http.Request, p adminIPPolicy) bool {
	clientIP, ok := effectiveClientIP(r)
	if !ok {
		return false // fail closed: no trustworthy client IP
	}
	if allowImmediate(clientIP) { // loopback or one of this host's own IPs
		return true
	}
	snap := loadAllowedSources(r.Context(), p.cfgDir, p.apiURL)
	return ipAllowed(clientIP, snap.ExactIPs, snap.CIDRNets)
}

// refuseForeignAdminToken applies the binding to a request that presented the
// valid admin token, for both doors that accept it (TokenMiddleware, kind
// "token"; the /mcp bearer gate, kind "mcp_token"). It reports true when the
// caller must refuse it (enforce, foreign source), after the audit line, the
// ADMIN_TOKEN_FOREIGN_IP anomaly and the anomaly reason have been recorded;
// the caller writes the 403. logonly logs would_block and allows. w may be
// nil (the reason then travels on the request's anomaly state only).
func refuseForeignAdminToken(w http.ResponseWriter, r *http.Request, p adminIPPolicy, kind string) bool {
	if !p.active() || adminTokenSourceAllowed(r, p) {
		return false
	}
	if p.mode != adminIPModeEnforce {
		// logonly (burn-in): record what enforce WOULD block, then allow.
		// Unsampled by design — expected volume is ~zero (only cfm-web and
		// the WHM plugin present the admin token, both allowlisted) and each
		// line is security evidence.
		logging.LogfAPI("[apiserver] admin_token_source_ip logonly=would_block src_ip=%s method=%s path=%q",
			realIPFromRequest(r), r.Method, r.URL.Path)
		return false
	}
	auditAuthAttempt(r, authAttemptAudit{Kind: kind, Result: "blocked_source_ip", AuthMech: string(authnMechanismTokenAdmin), Status: http.StatusForbidden})
	// A structured anomaly (enforce ONLY — logonly stays observe-only so a
	// burn-in never blocks/challenges the source): a leaked admin token used
	// even ONCE from a foreign IP alerts, instead of needing a forbidden
	// burst. classifierReason() lists "admin_token_source_ip" as a direct
	// event, so the generic burst signal does not count this 403 again.
	publishRequestAnomaly(r, "ADMIN_TOKEN_FOREIGN_IP", http.StatusForbidden)
	logging.LogfAPI("[apiserver] event=api_audit reason=admin_token_source_ip src_ip=%s method=%s path=%q status=%d",
		realIPFromRequest(r), r.Method, r.URL.Path, http.StatusForbidden)
	setAPIAnomalyReason(w, r, "admin_token_source_ip")
	return true
}
