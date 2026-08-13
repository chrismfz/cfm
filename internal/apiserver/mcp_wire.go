package apiserver

// mcp_wire.go stands up the embedded read-only MCP server (internal/mcpserver)
// inside the apiserver and mounts it on the shared mux. It is the ONLY place that
// knows both the apiserver internals and the mcpserver package, keeping the MCP
// package free of apiserver coupling.
//
// The tool dispatch is an in-process handler call: a synthetic GET carrying the
// daemon's own admin token, run through TokenMiddleware(adminToken)(mux). That
// reuses every existing /api/v1 read handler and its scope/admin gate verbatim,
// tracks the hot-swappable webdetector engine, and can only ever perform the
// allow-listed GETs the tools issue. The admin token is used purely in-process;
// the MCP client only ever holds a read-only OAuth token that is inert here.

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"

	cfgpkg "cfm/internal/config"
	"cfm/internal/logging"
	"cfm/internal/mcpserver"
)

// minMCPTokenLen is the minimum MCP_TOKEN length we accept. The MCP endpoint is
// internet-reachable through the edge, so a short/weak token is treated as
// misconfiguration and the server stays disabled rather than expose a guessable
// credential.
const minMCPTokenLen = 24

// mcpTokenUsable reports whether an MCP_TOKEN is present and strong enough to arm
// the MCP server.
func mcpTokenUsable(tok string) bool {
	return len(strings.TrimSpace(tok)) >= minMCPTokenLen
}

// mcpStaticBearer reports whether a bearer presented directly at /mcp is an
// accepted static credential: the client-facing MCP_TOKEN OR the admin
// AUTH_TOKEN.
//
// Accepting AUTH_TOKEN is what lets a FLEET GATEWAY (e.g. the Laravel cfm-web,
// which already stores each node's AUTH_TOKEN to reach /api/v1) speak MCP to a
// node WITHOUT a second, separately-managed MCP_TOKEN in its agents table. It
// does NOT widen the MCP↔API boundary: MCP_TOKEN still cannot touch /api/v1, and
// the /mcp tool surface is read-only no matter which token authenticated — an
// AUTH_TOKEN holder can already do everything through /api/v1, so exposing the
// read-only subset to the same credential adds no privilege. An empty bearer
// never matches (the caller also guards, but ConstantTimeCompare("","") is true,
// so guard here too).
func mcpStaticBearer(tok, mcpTok, adminTok string) bool {
	if tok == "" {
		return false
	}
	return tokenMatch(tok, mcpTok) || tokenMatch(tok, adminTok)
}

// registerMCPServer mounts the MCP + OAuth endpoints on m. It is a no-op (with a
// warning) unless BOTH are true: an admin API token is configured (needed for the
// in-process read dispatch) AND a strong, distinct MCP_TOKEN is set (the
// client-facing credential). The admin token is never exposed to MCP clients.
func registerMCPServer(m *http.ServeMux, cfg *cfgpkg.Config, store *TokenStore) {
	adminTok := strings.TrimSpace(cfg.API.AuthToken)
	mcpTok := strings.TrimSpace(cfg.API.MCPToken)

	if adminTok == "" {
		logging.LogfAPI("[apiserver] mcp: AUTH_TOKEN not set — MCP server disabled")
		return
	}
	if mcpTok == "" {
		logging.LogfAPI("[apiserver] mcp: MCP_TOKEN not set — MCP server disabled (set a strong MCP_TOKEN in cfm.conf to enable)")
		return
	}
	if !mcpTokenUsable(mcpTok) {
		logging.LogfAPI("[apiserver] mcp: MCP_TOKEN too weak (need >= %d chars) — MCP server disabled", minMCPTokenLen)
		return
	}
	if mcpTok == adminTok {
		// Not fatal, but it defeats the point of a separate credential: an MCP
		// token leak would then equal an admin/API token leak.
		logging.LogfAPI("[apiserver] mcp: WARNING MCP_TOKEN equals AUTH_TOKEN — use a distinct MCP_TOKEN so an MCP leak is not an admin-token leak")
	}

	// dispatchHandler authenticates in-process reads as admin without exposing the
	// admin token to the network. Built once; m is fully populated by call time.
	// It deliberately wraps ONLY TokenMiddleware (not CSRF/MFA/session): these are
	// GET reads, CSRF guards mutations, and MFA rollout is session-oriented.
	dispatchHandler := TokenMiddleware(adminTok, store)(m)

	dispatch := func(ctx context.Context, path string, query url.Values) (int, []byte, error) {
		target := path
		if len(query) > 0 {
			target += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Bearer "+adminTok)
		req.RemoteAddr = "127.0.0.1:0" // loopback: satisfies trusted-proxy checks
		rec := &mcpRecorder{status: http.StatusOK, hdr: http.Header{}}
		dispatchHandler.ServeHTTP(rec, req)
		body := rec.buf.Bytes()
		// Defense-in-depth: the admin token is only ever an in-process request
		// header, but if any read handler were to echo the inbound Authorization
		// value into its body, scrub it so it can never surface in a tool result.
		if bytes.Contains(body, []byte(adminTok)) {
			body = bytes.ReplaceAll(body, []byte(adminTok), []byte("[redacted]"))
		}
		return rec.status, body, nil
	}

	// Client-facing auth. The OAuth consent credential + signing secret bind to
	// MCP_TOKEN (the read-only, /api/v1-inert credential). The STATIC bearer
	// additionally accepts the admin AUTH_TOKEN so a fleet gateway that already
	// holds it (cfm-web) can reach /mcp without a separate MCP_TOKEN — see
	// mcpStaticBearer for why that doesn't widen the boundary. The admin token is
	// used for the in-process dispatch above and is never handed to an MCP client.
	h := mcpserver.New(mcpserver.Deps{
		Version:       daemonVersion(),
		MCPPath:       "/mcp",
		Dispatch:      dispatch,
		BaseURL:       func(r *http.Request) string { return mcpRequestScheme(r) + "://" + r.Host + cfmBase(r) },
		Authenticate:  func(cred string) (string, bool) { return "", tokenMatch(cred, mcpTok) },
		SigningSecret: mcpTok,
		StaticBearer:  func(tok string) bool { return mcpStaticBearer(tok, mcpTok, adminTok) },
	})
	h.Register(m)
	logging.LogfAPI("[apiserver] mcp: read-only MCP server mounted at /mcp (edge: /cfm-admin/mcp)")
}

// mcpRequestScheme reports the externally visible scheme. Behind the TLS-
// terminating edge the daemon sees plain HTTP on loopback, so a trusted (loopback)
// proxy hop implies https. Forwarded headers are honoured ONLY from the loopback
// edge — the same trust rule as the prefix headers — so a direct non-loopback
// caller cannot spoof the advertised scheme.
func mcpRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if trustedProxyBase(r) != "" {
		if p := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); p != "" {
			return strings.ToLower(strings.TrimSpace(strings.Split(p, ",")[0]))
		}
		return "https"
	}
	return "http"
}

// DaemonVersion is the build version reported in the MCP initialize result. It is
// set from package main's ldflags-injected Version at startup (main.Version does
// NOT populate runtime/debug BuildInfo, so it must be plumbed explicitly). Left as
// "dev" for local/test builds that don't set it.
var DaemonVersion = "dev"

func daemonVersion() string {
	if v := strings.TrimSpace(DaemonVersion); v != "" {
		return v
	}
	return "dev"
}

// mcpRecorder is a minimal http.ResponseWriter capturing an in-process response.
// It buffers the whole body (no Flush/Hijack) — the allow-listed MCP read
// endpoints all return small buffered JSON, so streaming support is not needed.
type mcpRecorder struct {
	status int
	hdr    http.Header
	buf    bytes.Buffer
	wrote  bool
}

func (r *mcpRecorder) Header() http.Header { return r.hdr }

func (r *mcpRecorder) WriteHeader(status int) {
	if !r.wrote {
		r.status = status
		r.wrote = true
	}
}

func (r *mcpRecorder) Write(b []byte) (int, error) {
	r.wrote = true
	return r.buf.Write(b)
}
