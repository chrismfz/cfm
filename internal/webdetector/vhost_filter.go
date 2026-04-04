// internal/webdetector/vhost_filter.go
//
// Scoped vhost filtering for the webdetector HTTP API.
//
// Any endpoint that returns per-vhost rows accepts an optional
// ?vhosts=domain1.com,domain2.com query parameter. When present,
// only rows whose Host matches an entry in the set are returned.
//
// When the parameter is absent the behaviour is identical to before —
// all rows are returned. No breaking changes.
//
// Usage in handlers:
//
//	f := parseVhostFilter(r)              // nil = no filter
//	rows = applyShortFilter(rows, f)
//	rows = applySuspiciousFilter(rows, f)
//
// For drilldown (single host request):
//
//	if !vhostAllowed(host, parseVhostFilter(r)) {
//	    writeJSON(w, http.StatusForbidden, ...)
//	    return
//	}

package webdetector

import (
	"net/http"
	"strings"
)

// parseVhostFilter parses ?vhosts=a.com,b.com into a lowercase lookup set.
// Returns nil when the parameter is absent — callers treat nil as "no filter".
func parseVhostFilter(r *http.Request) map[string]struct{} {
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

// applyShortFilter filters []ShortRow in-place. Returns the filtered slice.
// No allocation when filter is nil.
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

// applySuspiciousFilter filters []SuspiciousRow in-place. Returns the filtered slice.
// No allocation when filter is nil.
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
