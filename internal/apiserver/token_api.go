// internal/apiserver/token_api.go
//
// Admin endpoints for scoped token management.
//
//	GET  /api/v1/tokens/list    — list all tokens (admin only, no token values)
//	POST /api/v1/tokens/revoke  — revoke by id (admin only)
//	GET  /api/v1/tokens/me      — calling token's own scope info (any valid token)
//
// All three are mounted by RegisterTokenManagementEndpoints(), called from
// apiserver.go alongside RegisterTokenEndpoint().
package apiserver

import (
	"encoding/json"
	"net/http"

	webdet "cfm/internal/webdetector"
)

// RegisterTokenManagementEndpoints adds list/revoke/me to the mux.
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
		tok, _ := extractToken(r)
		st, ok := store.Lookup(tok)
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
