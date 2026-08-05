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
//   - Auth is OAuth 2.1 (oauth.go) minting a read-only, audience-bound token that
//     is inert against /api/v1 — the admin token never leaves the operator.
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

// DispatchFunc performs an in-process GET against a CFM /api/v1 read endpoint and
// returns the HTTP status and raw JSON body. path is an absolute, unprefixed API
// path (e.g. "/api/v1/waf/engine/summary"); query holds the endpoint's params.
// err is reserved for internal wiring failures; an HTTP-level failure is conveyed
// via status + body.
type DispatchFunc func(ctx context.Context, path string, query url.Values) (status int, body []byte, err error)

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

	// Authenticate validates the consent-page credential (the CFM admin API
	// token). SigningSecret keys the stateless OAuth artifacts (rotating it
	// revokes all issued MCP tokens).
	Authenticate  Authenticator
	SigningSecret string

	// AdminBearer reports whether a bearer presented directly at /mcp is the
	// static admin token (so Claude Code / API clients can skip the OAuth dance).
	AdminBearer func(string) bool
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
var statelessMCP = &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}

// New builds the MCP handler from deps.
func New(deps Deps) *Handler {
	if deps.MCPPath == "" {
		deps.MCPPath = "/mcp"
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
		oauth: newOAuthServer(deps.BaseURL, deps.MCPPath, deps.SigningSecret, deps.Authenticate),
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

// requireMCPBearer gates /mcp on either the static admin token or an OAuth access
// token this server minted. An unauthenticated request gets a 401 whose
// WWW-Authenticate points at the protected-resource metadata — the discovery
// entrypoint the claude.ai connector follows (RFC 9728 §5.1).
func (h *Handler) requireMCPBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if oauthCORS(w, r) {
			return
		}
		if tok := extractBearer(r); tok != "" {
			if (h.deps.AdminBearer != nil && h.deps.AdminBearer(tok)) || h.oauth.validAccessToken(tok, r) {
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+h.oauth.resourceMetadataURL(r)+`"`)
		oauthWriteErr(w, http.StatusUnauthorized, "invalid_token", "authorization required")
	})
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

func realIPFromRequestMCP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
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
