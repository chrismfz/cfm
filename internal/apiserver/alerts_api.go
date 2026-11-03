package apiserver

// alerts_api.go — the node's alert store (internal/alerts) over HTTP:
//
//	GET /api/v1/alerts          newest-first rows matching the filters (cursor paging)
//	GET /api/v1/alerts/summary  the same filters, grouped (group_by=) with counts
//	GET /api/v1/alerts/stats    store size, retention and writer counters
//
// Admin-only: the store holds every detector's events for the whole server
// (other tenants' sites, client IPs, MySQL users). Backs the cfm-admin Alerts
// page, the MCP alerts / alerts_summary tools and cfm-web's fleet pull.

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cfm/internal/alerts"
)

// alertsMaxWindow bounds a query's time range: the store keeps 30 days by
// default; anything past it would only scan for nothing.
const alertsMaxWindow = 90 * 24 * time.Hour

func RegisterAlertsEndpoints(m *http.ServeMux) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/alerts", adminOnlyHandler(http.HandlerFunc(handleAlertsList)))
	m.Handle("/api/v1/alerts/summary", adminOnlyHandler(http.HandlerFunc(handleAlertsSummary)))
	m.Handle("/api/v1/alerts/stats", adminOnlyHandler(http.HandlerFunc(handleAlertsStats)))
}

func alertsStoreOr503(w http.ResponseWriter, r *http.Request) *alerts.Store {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return nil
	}
	s := alerts.Default()
	if s == nil {
		writeNotifierJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "alert store is not open on this node (see cfm.log: [alerts] init error)"})
		return nil
	}
	return s
}

func handleAlertsList(w http.ResponseWriter, r *http.Request) {
	s := alertsStoreOr503(w, r)
	if s == nil {
		return
	}
	f, err := alertsFilterFromQuery(r)
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if c := strings.TrimSpace(r.URL.Query().Get("cursor")); c != "" {
		cur, err := alerts.ParseCursor(c)
		if err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid cursor"})
			return
		}
		f.Before = &cur
	}
	page, err := s.List(f, clampInt(r.URL.Query().Get("limit"), 100, 1, 500))
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"from": unixOrZero(f.From), "to": unixOrZero(f.To),
		"rows": page.Rows, "limit": page.Limit, "has_more": page.HasMore, "next_cursor": page.NextCursor,
	})
}

func handleAlertsSummary(w http.ResponseWriter, r *http.Request) {
	s := alertsStoreOr503(w, r)
	if s == nil {
		return
	}
	f, err := alertsFilterFromQuery(r)
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	groupBy := splitList(r.URL.Query()["group_by"])
	sum, err := s.Summarize(f, groupBy, clampInt(r.URL.Query().Get("top"), 50, 1, 500))
	if err != nil {
		code := http.StatusInternalServerError
		if strings.Contains(err.Error(), "group_by") {
			code = http.StatusBadRequest
		}
		writeNotifierJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"from": unixOrZero(f.From), "to": unixOrZero(f.To),
		"group_by": sum.GroupBy, "total": sum.Total, "distinct_ips": sum.DistinctIPs,
		"groups": sum.Groups, "truncated": sum.Truncated,
	})
}

func handleAlertsStats(w http.ResponseWriter, r *http.Request) {
	s := alertsStoreOr503(w, r)
	if s == nil {
		return
	}
	st, err := s.Stats()
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, st)
}

// alertsFilterFromQuery reads the shared filter params. The window is
// from/to (RFC3339 or unix seconds) or hours back from now (default 24);
// list params (category, kind, delivery) take commas or repeats.
func alertsFilterFromQuery(r *http.Request) (alerts.Filter, error) {
	q := r.URL.Query()
	var f alerts.Filter
	now := time.Now()
	from, err := parseAlertsTime(q.Get("from"))
	if err != nil {
		return f, errors.New("invalid from; expected RFC3339 or unix seconds")
	}
	to, err := parseAlertsTime(q.Get("to"))
	if err != nil {
		return f, errors.New("invalid to; expected RFC3339 or unix seconds")
	}
	if from.IsZero() {
		hours := clampInt(q.Get("hours"), 24, 1, int(alertsMaxWindow/time.Hour))
		base := now
		if !to.IsZero() {
			base = to
		}
		from = base.Add(-time.Duration(hours) * time.Hour)
	}
	if !to.IsZero() && from.After(to) {
		return f, errors.New("from must be <= to")
	}
	end := to
	if end.IsZero() {
		end = now
	}
	if end.Sub(from) > alertsMaxWindow {
		from = end.Add(-alertsMaxWindow)
	}
	f.From, f.To = from, to
	f.Categories = splitList(q["category"])
	f.Kinds = splitList(q["kind"])
	f.Deliveries = splitList(q["delivery"])
	f.MinSeverity = strings.TrimSpace(q.Get("min_severity"))
	f.IP = strings.TrimSpace(q.Get("ip"))
	f.Country = strings.TrimSpace(q.Get("country"))
	f.ASN = strings.TrimSpace(q.Get("asn"))
	f.Vhost = strings.TrimSpace(q.Get("vhost"))
	f.Mode = strings.TrimSpace(q.Get("mode"))
	f.Query = strings.TrimSpace(q.Get("q"))
	return f, nil
}

func parseAlertsTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, raw)
}

func splitList(vals []string) []string {
	var out []string
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
