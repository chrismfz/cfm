// internal/webdetector/vhost_filter.go
//
// Scoped vhost filtering for the webdetector HTTP API.
//
// Any endpoint that returns per-vhost rows accepts an optional
// ?vhosts=domain1.com,domain2.com query parameter. When present,
// only rows whose Host matches an entry in the set are returned.
//
// When the apiserver token middleware has verified a scoped token it injects
// the token's vhost allowlist into the request context via CtxScopeKey{}.
// parseVhostFilter always checks context first — callers cannot escalate
// their scope by passing a broader ?vhosts= query param.
//
// Priority:
//  1. Scoped token in context  (set by apiserver middleware)
//  2. ?vhosts= query param     (used when admin token or loopback bypass)
//  3. nil                      (no filter — full results)
package webdetector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// CtxScopeKey is the context key used by the apiserver middleware to inject
// the vhost allowlist for scoped tokens. Exported so the middleware package
// can set it without an import cycle.
type CtxScopeKey struct{}

// CtxDBScopeKey is the context key used by the apiserver middleware to inject
// optional database-level scope for scoped tokens.
type CtxDBScopeKey struct{}

// CtxAuthnKey is set to true by auth middleware after successful authentication.
type CtxAuthnKey struct{}

// CtxRoleKey is set by auth middleware with the authenticated request role.
type CtxRoleKey struct{}

const (
	CtxRoleAdmin  = "admin"
	CtxRoleScoped = "scoped"
)

// ScopedDBScope carries explicit db-level allowlists attached to a scoped token.
// Nil maps mean "not explicitly set".
type ScopedDBScope struct {
	Users     map[string]struct{}
	Databases map[string]struct{}
}

// vhostScopeFromContext returns the scoped vhost set injected by the middleware,
// or nil if no scope is set (admin token or loopback bypass).
func vhostScopeFromContext(ctx context.Context) map[string]struct{} {
	v, _ := ctx.Value(CtxScopeKey{}).(map[string]struct{})
	return v
}

// parseVhostFilter returns the effective vhost filter for this request.
// Context scope (set by middleware) always wins over the query param.
// Returns nil when there is no restriction (admin / loopback / no param).
func parseVhostFilter(r *http.Request) map[string]struct{} {
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		return scope
	}
	return parseQueryVhostSet(r, "vhosts")
}

// validateScopedVhostQuery ensures scoped callers only request in-scope values
// in the given host/vhost query params. Returns nil for admin callers.
func validateScopedVhostQuery(r *http.Request, keys ...string) error {
	scope := vhostScopeFromContext(r.Context())
	if scope == nil {
		return nil
	}
	requested := parseQueryVhostSet(r, keys...)
	if len(requested) == 0 {
		return nil
	}
	for host := range requested {
		if !vhostAllowed(host, scope) {
			return fmt.Errorf("requested vhost %q is outside token scope", host)
		}
	}
	return nil
}

func parseQueryVhostSet(r *http.Request, keys ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, key := range keys {
		for _, raw := range r.URL.Query()[key] {
			for _, part := range strings.Split(raw, ",") {
				h := strings.ToLower(strings.TrimSpace(part))
				if h != "" {
					m[h] = struct{}{}
				}
			}
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// vhostAllowed returns true when filter is nil (no restriction)
// or the host is present in the filter set.
func vhostAllowed(host string, filter map[string]struct{}) bool {
	if filter == nil {
		return true
	}
	_, ok := filter[strings.ToLower(host)]
	return ok
}

// applyShortFilter filters []ShortRow in-place. No allocation when filter is nil.
func applyShortFilter(rows []ShortRow, filter map[string]struct{}) []ShortRow {
	if filter == nil {
		return rows
	}
	n := 0
	for _, row := range rows {
		if vhostAllowed(row.Host, filter) {
			rows[n] = row
			n++
		}
	}
	return rows[:n]
}

// applySuspiciousFilter filters []SuspiciousRow in-place. No allocation when filter is nil.
func applySuspiciousFilter(rows []SuspiciousRow, filter map[string]struct{}) []SuspiciousRow {
	if filter == nil {
		return rows
	}
	n := 0
	for _, row := range rows {
		if vhostAllowed(row.Host, filter) {
			rows[n] = row
			n++
		}
	}
	return rows[:n]
}

// IsAdminRequest returns true only when middleware explicitly marked the request
// as authenticated and assigned the admin role.
//
// Unauthenticated requests and middleware-misconfigured requests are always
// treated as non-admin to fail closed.
func IsAdminRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	authn, _ := r.Context().Value(CtxAuthnKey{}).(bool)
	if !authn {
		return false
	}
	role, _ := r.Context().Value(CtxRoleKey{}).(string)
	return role == CtxRoleAdmin
}
