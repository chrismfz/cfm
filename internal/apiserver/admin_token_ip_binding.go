package apiserver

import (
	"net/http"
	"strings"
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
// or the admin port is opened. See docs/security/admin-token-source-ip-binding.md.
//
// NOTE: this closes direct-API use and SSO-code minting from a foreign IP. It does
// NOT by itself stop cookie forgery, because the embed cookies are signed with a
// key derived from AUTH_TOKEN — that needs the companion change (decouple the
// cookie signing key from AUTH_TOKEN). See the doc.

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

// normalizeAdminIPMode maps a config value to a known mode, defaulting to off
// (fail-open on an unknown value: an admin never wants a typo to lock the plane).
func normalizeAdminIPMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case adminIPModeLogonly, "dryrun", "dry-run", "log", "log-only":
		return adminIPModeLogonly
	case adminIPModeEnforce, "on", "block", "true", "1":
		return adminIPModeEnforce
	default:
		return adminIPModeOff
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
	return func(c *tokenMiddlewareConfig) {
		c.adminIP = adminIPPolicy{mode: normalizeAdminIPMode(mode), cfgDir: cfgDir, apiURL: apiURL}
	}
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
