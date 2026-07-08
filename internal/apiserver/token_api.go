// internal/apiserver/token_api.go
//
// Admin endpoints for scoped token management.
//
//	GET  /api/v1/tokens/list    — list all tokens (admin only, no token values)
//	POST /api/v1/tokens/revoke  — revoke by id (admin only)
//	GET  /api/v1/tokens/me      — calling token's own scope info (any valid token)
//	GET  /api/v1/admin/authcheck — admin-only auth probe for edge auth_request
//
// All are mounted by RegisterTokenManagementEndpoints(), called from
// apiserver.go alongside RegisterTokenEndpoint().
package apiserver

import (
	"encoding/json"
	"net/http"

	webdet "cfm/internal/webdetector"
)

// RegisterTokenManagementEndpoints adds list/revoke/me and the admin
// authcheck probe to the mux.
func RegisterTokenManagementEndpoints(m *http.ServeMux, store *TokenStore) {
	// ── GET /api/v1/tokens/list ───────────────────────────────────────────────
	m.HandleFunc("/api/v1/tokens/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !webdet.RequireAdmin(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.List())
	})

	// ── POST /api/v1/tokens/revoke ────────────────────────────────────────────
	m.HandleFunc("/api/v1/tokens/revoke", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !webdet.RequireAdmin(w, r) {
			return
		}
		var req struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil || req.ID == "" {
			apiJSONError(w, "id is required", http.StatusBadRequest)
			return
		}
		if !store.Revoke(req.ID) {
			apiJSONError(w, "token not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "revoked", "id": req.ID})
	})

	// ── GET /api/v1/tokens/me ─────────────────────────────────────────────────
	m.HandleFunc("/api/v1/tokens/me", func(w http.ResponseWriter, r *http.Request) {
		setAuthIdentityNoCacheHeaders(w)
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !webdet.RequireScopedOrAdmin(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Admin/session: return synthetic descriptor (no ID, no vhosts restriction).
		if webdet.IsAdminRequest(r) {
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"role":   "admin",
				"vhosts": nil,
				"scoped": false,
			})
			return
		}
		// Scoped token: look up to return its full metadata (still no token value).
		// Prefer bearer/header token when present; otherwise fall back to the
		// scoped token ID populated into the request context by the embed
		// bootstrap cookie auth path.
		var (
			st *ScopedToken
			ok bool
		)
		if tok, havetok := extractToken(r); havetok && tok != "" {
			st, ok = store.Lookup(tok)
		}
		if !ok {
			if id := scopedTokenIDFromContext(r.Context()); id != "" {
				st, ok = store.LookupByID(id)
			}
		}
		if !ok {
			apiJSONError(w, "token not found", http.StatusUnauthorized)
			return
		}
		vhosts := make([]string, 0, len(st.Vhosts))
		for v := range st.Vhosts {
			vhosts = append(vhosts, v)
		}
		dbUsers := sortedScopeKeys(st.DBUsers)
		databases := sortedScopeKeys(st.Databases)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":         st.ID,
			"label":      st.Label,
			"role":       st.Role,
			"vhosts":     vhosts,
			"db_users":   dbUsers,
			"databases":  databases,
			"expires_at": st.Expiry,
			"scoped":     true,
		})
	})

	// ── GET /api/v1/admin/authcheck ───────────────────────────────────────────
	// Admin-only auth probe for the edge proxy's `auth_request`. Admin endpoints
	// that are rendered entirely inside OpenResty/Angie (lua-stats: Go cannot read
	// nginx shdicts) delegate their admin gate to this endpoint — auth_request
	// only cares about the status line: 200 for an authenticated admin, 403 for a
	// scoped token or anonymous. Returns no data by design.
	//
	// Historically auth_request pointed at /api/v1/tokens/me, which is
	// scoped-OR-admin, so a scoped cPanel viewer passed the gate and received the
	// fleet-wide lua-stats blob (every tenant's WAF excludes + rule modes) — a
	// scoped-vs-admin boundary break (audit F01). This gate is admin-only.
	m.HandleFunc("/api/v1/admin/authcheck", func(w http.ResponseWriter, r *http.Request) {
		setAuthIdentityNoCacheHeaders(w)
		if r.Method != http.MethodGet {
			apiJSONError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !webdet.RequireAdmin(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})
}

func setAuthIdentityNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Vary", "Authorization, Cookie")
}

// apiJSONError writes a JSON error response. Named to avoid collision with
// any existing helpers in the apiserver package.
func apiJSONError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error":"`+msg+`"}`, code)
}
