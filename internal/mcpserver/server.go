// Package mcpserver embeds a read-only Model Context Protocol (MCP) server inside
// the CFM daemon, exposed through the OpenResty edge under /cfm-admin/mcp. It lets
// an MCP client (notably the claude.ai remote "custom connector") read CFM's
// security telemetry — WAF hits, challenge state, suspicious traffic, firewall
// blocks, detector status, health — using the SAME /api/v1 read handlers the CLI
// and web UI already use.
//
// Design (see MCP.md for the as-built map + roadmap):
//   - Transport is the go-sdk streamable-HTTP handler in STATELESS + JSON mode
//     (plain POST→JSON, no SSE session), which is robust behind a reverse proxy
//     and needs no sticky sessions.
//   - Tools never touch subsystem internals. Each tool dispatches a GET to a
//     hard-coded, allow-listed /api/v1 read endpoint via the Dispatch closure the
//     apiserver supplies (an in-process handler call authenticated with the
//     daemon's own admin token). This reuses every existing handler + scope check
//     verbatim, tracks the hot-swappable webdetector engine, and is read-only by
//     construction (only GET, only allow-listed paths, only read tools).
//   - Auth is static MCP/admin bearer or OAuth 2.1 (oauth.go); minted OAuth tokens
//     are read-only and inert against /api/v1. CFM never sends the admin token to
//     an MCP client.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// DispatchFunc performs an in-process GET against a CFM read endpoint and returns
// the HTTP status and raw JSON body. path is an absolute, unprefixed route on the
// admin mux — almost always under /api/v1 (e.g. "/api/v1/waf/engine/summary"),
// though a few read routes live elsewhere (e.g. "/search", the ip_locate lookup);
// query holds the endpoint's params. err is reserved for internal wiring failures;
// an HTTP-level failure is conveyed via status + body.
type DispatchFunc func(ctx context.Context, path string, query url.Values) (status int, body []byte, err error)

// AuthAuditEvent is a secret-free authentication decision produced by the MCP
// bearer or OAuth-consent gate. The embedding apiserver owns log/event policy.
type AuthAuditEvent struct {
	Kind     string
	Result   string
	AuthMech string
	Status   int
}

// Deps is everything the apiserver injects to stand the MCP server up. The
// mcpserver package deliberately knows nothing about apiserver internals.
type Deps struct {
	Version  string // daemon version string, surfaced in the MCP initialize result
	MCPPath  string // MCP endpoint path under the edge prefix; defaults to "/mcp"
	Dispatch DispatchFunc

	// BaseURL returns the externally reachable origin+prefix for this request,
	// e.g. "https://panel.example.com/cfm-admin". Used to build every advertised
	// OAuth URL and the token audience.
	BaseURL func(*http.Request) string

	// ClientIP returns the canonical source identity for rate limiting and audit.
	// The embedding server owns proxy trust; forwarded headers must not be parsed
	// independently here. The fallback uses only the immediate network peer.
	ClientIP func(*http.Request) string

	// AuditAuth receives exactly one decision for each supplied MCP bearer or
	// consent credential. It must not receive raw credential material.
	AuditAuth func(*http.Request, AuthAuditEvent)

	// Authenticate validates the consent-page MCP_TOKEN. SigningSecret keys the
	// stateless OAuth artifacts (rotating it
	// revokes all issued MCP tokens).
	Authenticate  Authenticator
	SigningSecret string

	// StaticBearer reports whether a bearer presented directly at /mcp is an
	// accepted static credential (so a client can skip the OAuth dance by sending
	// Authorization: Bearer <token> itself). The wiring decides which tokens
	// qualify: the CFM apiserver accepts the MCP_TOKEN and additionally the admin
	// AUTH_TOKEN, so a fleet gateway that already holds AUTH_TOKEN can reach /mcp
	// without a separate MCP_TOKEN. This gate never grants /api/v1 access; the MCP
	// tool surface is read-only regardless of which token authenticated.
	// authMech is a safe classifier such as mcp_static or token_admin.
	StaticBearer func(string) (authMech string, ok bool)
}

// Handler is the mounted MCP surface: the OAuth authorization server plus the
// bearer-gated streamable MCP endpoint.
type Handler struct {
	deps    Deps
	oauth   *oauthServer
	mcpHTTP http.Handler
}

// statelessMCP runs the streamable-HTTP transport with no session state: each
// tool call is a self-contained POST→JSON exchange, so there is no stream to
// silently drop behind the edge. The tool set is static per deploy and we never
// push notifications, so statelessness costs nothing.
// statelessMCP configures the go-sdk streamable transport.
//
// DisableLocalhostProtection is REQUIRED here. The SDK's DNS-rebinding guard
// rejects (403) any request whose accepted-connection LocalAddr is loopback but
// whose Host header is not — a protection meant for localhost-only dev servers
// reached directly by a browser. CFM's MCP server is deliberately the opposite:
// it sits behind the OpenResty/Angie edge, which terminates TLS and upstreams to
// the daemon over loopback (127.0.0.1:6060) while forwarding the public Host
// (e.g. titan.example.com). That legitimate topology trips the guard, so an
// OAuth-authenticated client got 403 on every /mcp call AFTER a fully successful
// register→authorize→consent→token flow. We do not rely on Host/loopback for
// auth — the endpoint is gated by MCP_TOKEN / audience-bound OAuth and is not
// cookie/session (so not CSRF-reachable) — so the guard only breaks the real
// deployment. Disable it and let the bearer/OAuth gate be the sole authority.
var statelessMCP = &mcp.StreamableHTTPOptions{
	Stateless:                  true,
	JSONResponse:               true,
	DisableLocalhostProtection: true,
}

// New builds the MCP handler from deps.
func New(deps Deps) *Handler {
	if deps.MCPPath == "" {
		deps.MCPPath = "/mcp"
	}
	if deps.ClientIP == nil {
		deps.ClientIP = immediateIPFromRequestMCP
	}
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "cfm-mcp",
		Title:   "CFM security telemetry (read-only)",
		Version: deps.Version,
	}, &mcp.ServerOptions{
		Instructions: instructions,
		HasTools:     true,
	})
	registerTools(srv, deps)

	return &Handler{
		deps:  deps,
		oauth: newOAuthServer(deps.BaseURL, deps.ClientIP, deps.AuditAuth, deps.MCPPath, deps.SigningSecret, deps.Authenticate),
		mcpHTTP: mcp.NewStreamableHTTPHandler(
			func(*http.Request) *mcp.Server { return srv }, statelessMCP),
	}
}

// Register mounts the OAuth/discovery endpoints and the bearer-gated MCP endpoint
// on mux. All paths are UNPREFIXED (the edge strips /cfm-admin before the daemon
// sees them); advertised URLs re-add the prefix via BaseURL.
func (h *Handler) Register(mux *http.ServeMux) {
	h.oauth.register(mux)
	mux.Handle(h.deps.MCPPath, h.requireMCPBearer(h.mcpHTTP))
}

// requireMCPBearer gates /mcp on a static MCP/admin token or an OAuth access token
// this server minted. An unauthenticated request gets a 401 whose
// WWW-Authenticate points at the protected-resource metadata — the discovery
// entrypoint the claude.ai connector follows (RFC 9728 §5.1).
func (h *Handler) requireMCPBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oauthCORS(w, r) {
			return
		}
		tok := extractBearer(r)
		if tok != "" {
			if h.deps.StaticBearer != nil {
				if authMech, ok := h.deps.StaticBearer(tok); ok {
					h.auditAuth(r, AuthAuditEvent{Kind: "mcp_token", Result: "success", AuthMech: authMech, Status: http.StatusOK})
					next.ServeHTTP(w, r)
					return
				}
			}
			if h.oauth.validAccessToken(tok, r) {
				h.auditAuth(r, AuthAuditEvent{Kind: "mcp_token", Result: "success", AuthMech: "mcp_oauth", Status: http.StatusOK})
				next.ServeHTTP(w, r)
				return
			}
			h.auditAuth(r, AuthAuditEvent{Kind: "mcp_token", Result: "invalid", AuthMech: "unknown", Status: http.StatusUnauthorized})
		} else if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
			h.auditAuth(r, AuthAuditEvent{Kind: "mcp_token", Result: "malformed", AuthMech: "unknown", Status: http.StatusUnauthorized})
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+h.oauth.resourceMetadataURL(r)+`"`)
		oauthWriteErr(w, http.StatusUnauthorized, "invalid_token", "authorization required")
	})
}

func (h *Handler) auditAuth(r *http.Request, event AuthAuditEvent) {
	if h.deps.AuditAuth != nil {
		h.deps.AuditAuth(r, event)
	}
}

// ── tool dispatch + result helpers ────────────────────────────────────────────

// dispatchJSON runs an allow-listed read endpoint and returns its body as an MCP
// text result. A non-2xx HTTP status becomes a tool error (the SDK renders a
// handler error as an error result the model can read).
func dispatchJSON(ctx context.Context, d Deps, path string, query url.Values) (*mcp.CallToolResult, any, error) {
	status, body, err := d.Dispatch(ctx, path, query)
	if err != nil {
		return nil, nil, fmt.Errorf("dispatch %s: %w", path, err)
	}
	if status < 200 || status >= 300 {
		return nil, nil, fmt.Errorf("%s returned HTTP %d: %s", path, status, strings.TrimSpace(string(body)))
	}
	return textResult(body), nil, nil
}

func textResult(b []byte) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

// marshal renders v as indented JSON (used by tools that compose multiple reads).
func marshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func errRequired(field string) error { return fmt.Errorf("%s is required", field) }

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const p = "Bearer "
	if len(h) > len(p) && strings.EqualFold(h[:len(p)], p) {
		return strings.TrimSpace(h[len(p):])
	}
	return ""
}

func immediateIPFromRequestMCP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// instructions is the server-level guidance the MCP client shows the model.
const instructions = `CFM (Configurable Firewall Manager) security telemetry, READ-ONLY. These tools
report what CFM's edge WAF, challenge engine, log-driven web detector, nftables
firewall, and detector framework are seeing and doing right now. They only read —
nothing here blocks, unblocks, challenges, or changes configuration.

Orientation:
- whats_wrong is the triage entry point: one call that ranks concrete problems
  (health/disk/load, failed services, MySQL saturation, mail-queue backlog,
  suspected outbound-mail spikes, API-abuse bursts) most-severe first, each with
  the drill-down tool to use next. Start here for "is anything wrong right now?".
- security_overview gives the headline picture (health + recent WAF/challenge
  activity + active blocks); start there for "what's going on?".
- WAF: waf_activity (recent hits, top rules, per-hour histogram), waf_rules.
- Challenge engine: challenge_vhosts (which vhosts are challenged and why),
  challenge_events (recent arm/pass/fail).
- Traffic & attacks: suspicious_hosts (long-window scanners/attackers),
  top_talkers (request-rate leaders), hot_ips, host_drilldown / ip_drilldown for
  the "why" behind one host or IP, bots_top for user-agents.
- Durable log: detection_history (WAF/challenge/clam/… events over time).
- Enforcement & platform: firewall_blocks (active nft bans incl. WAF autoblocks),
  detectors_status, system_health.

Most drilldown tools take a host= or ip= selector; time-window tools take hours=;
list tools take limit=. Values come verbatim from the list/overview tools.`
