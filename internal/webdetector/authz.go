package webdetector

import "net/http"

const errForbidden = "forbidden"

// IsScopedOrAdminRequest returns true when auth middleware marked this request
// as authenticated and assigned either scoped or admin role.
func IsScopedOrAdminRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	authn, _ := r.Context().Value(CtxAuthnKey{}).(bool)
	if !authn {
		return false
	}
	role, _ := r.Context().Value(CtxRoleKey{}).(string)
	return role == CtxRoleAdmin || role == CtxRoleScoped
}

// RequireAdmin enforces authenticated admin role and writes a consistent 403.
func RequireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if IsAdminRequest(r) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": errForbidden})
	return false
}

// RequireScopedOrAdmin enforces authenticated scoped/admin role and writes
// a consistent 403 when authorization fails.
func RequireScopedOrAdmin(w http.ResponseWriter, r *http.Request) bool {
	if IsScopedOrAdminRequest(r) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": errForbidden})
	return false
}

// IsScopedRequest returns true when auth middleware marked this request as
// authenticated with the scoped (per-vhost cPanel/DA) role: a scoped bearer
// token or the scoped embed-bootstrap cookie. Admin requests are never scoped.
func IsScopedRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	authn, _ := r.Context().Value(CtxAuthnKey{}).(bool)
	if !authn {
		return false
	}
	role, _ := r.Context().Value(CtxRoleKey{}).(string)
	return role == CtxRoleScoped
}
