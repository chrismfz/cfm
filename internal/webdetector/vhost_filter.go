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
//   1. Scoped token in context  (set by apiserver middleware)
//   2. ?vhosts= query param     (used when admin token or loopback bypass)
//   3. nil                      (no filter — full results)

package webdetector

import (
	"context"
	"net/http"
	"strings"
)

// CtxScopeKey is the context key used by the apiserver middleware to inject
// the vhost allowlist for scoped tokens. Exported so the middleware package
// can set it without an import cycle.
type CtxScopeKey struct{}

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
	// Scoped token in context takes priority — cannot be overridden by caller.
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		return scope
	}
	// Admin token or loopback bypass: honour optional ?vhosts= query param.
	raw := strings.TrimSpace(r.URL.Query().Get("vhosts"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	m := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			m[p] = struct{}{}
		}
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
