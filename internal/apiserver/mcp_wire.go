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
	"runtime/debug"
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
		return rec.status, rec.buf.Bytes(), nil
	}

	// Client-facing auth (consent credential, static bearer, OAuth signing) binds
	// to MCP_TOKEN — never the admin token. The admin token is used only for the
	// in-process dispatch above and never reaches an MCP client.
	h := mcpserver.New(mcpserver.Deps{
		Version:       daemonVersion(),
		MCPPath:       "/mcp",
		Dispatch:      dispatch,
		BaseURL:       func(r *http.Request) string { return mcpRequestScheme(r) + "://" + r.Host + cfmBase(r) },
		Authenticate:  func(cred string) (string, bool) { return "", tokenMatch(cred, mcpTok) },
		SigningSecret: mcpTok,
		StaticBearer:  func(tok string) bool { return tokenMatch(tok, mcpTok) },
	})
	h.Register(m)
	logging.LogfAPI("[apiserver] mcp: read-only MCP server mounted at /mcp (edge: /cfm-admin/mcp)")
}

// mcpRequestScheme reports the externally visible scheme. Behind the TLS-
// terminating edge the daemon sees plain HTTP on loopback, so a trusted proxy
// prefix (or X-Forwarded-Proto) implies https.
func mcpRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); p != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(p, ",")[0]))
	}
	if trustedProxyBase(r) != "" {
		return "https"
	}
	return "http"
}

// daemonVersion is the informational version reported in the MCP initialize
// result. The binary's own version lives in package main (ldflags), so read it
// from the embedded build info; fall back to "dev".
func daemonVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if v := strings.TrimSpace(bi.Main.Version); v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

// mcpRecorder is a minimal http.ResponseWriter capturing an in-process response.
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
