package apiserver

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"cfm/internal/traffic"
	webdet "cfm/internal/webdetector"
)

const trafficSchemaVersion = "traffic.v1"

type trafficSnapshotter interface {
	Snapshot() traffic.Snapshot
}

var (
	trafficSnapshotMu sync.RWMutex
	trafficSource     trafficSnapshotter
)

// SetTrafficSnapshotSource installs the shared traffic snapshot source used by
// /api/v1/traffic/* endpoints.
func SetTrafficSnapshotSource(src trafficSnapshotter) {
	trafficSnapshotMu.Lock()
	trafficSource = src
	trafficSnapshotMu.Unlock()
}

func RegisterTrafficEndpoints(m *http.ServeMux) {
	if m == nil {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/traffic/summary", handleTrafficSummary)
	mux.HandleFunc("/api/v1/traffic/top-ips", handleTrafficTopIPs)
	mux.HandleFunc("/api/v1/traffic/top-processes", handleTrafficTopProcesses)
	mux.HandleFunc("/api/v1/traffic/top-ports", handleTrafficTopPorts)
	mux.HandleFunc("/api/v1/traffic/protocols", handleTrafficProtocols)
	mux.HandleFunc("/api/v1/traffic/connections", handleTrafficConnections)
	mux.HandleFunc("/api/v1/traffic/history", handleTrafficHistory)

	m.Handle("/api/v1/traffic/", adminOnlyHandler(mux))
}

type trafficCapabilities struct {
	ProcessAttribution        bool `json:"process_attribution"`
	PartialProcessAttribution bool `json:"partial_process_attribution"`
}

func trafficCaps(s traffic.Snapshot) trafficCapabilities {
	return trafficCapabilities{
		ProcessAttribution:        s.ProcessSupported,
		PartialProcessAttribution: s.ProcessPartial,
	}
}

func trafficSnapshotOrUnavailable(w http.ResponseWriter) (traffic.Snapshot, bool) {
	trafficSnapshotMu.RLock()
	src := trafficSource
	trafficSnapshotMu.RUnlock()
	if src == nil {
		writeTrafficJSON(w, http.StatusServiceUnavailable, map[string]any{
			"schema_version": trafficSchemaVersion,
			"capabilities":   trafficCapabilities{},
			"error":          "traffic engine unavailable",
		})
		return traffic.Snapshot{}, false
	}
	return src.Snapshot(), true
}

func handleTrafficSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeTrafficJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s, ok := trafficSnapshotOrUnavailable(w)
	if !ok {
		return
	}
	writeTrafficJSON(w, http.StatusOK, map[string]any{
		"schema_version": trafficSchemaVersion,
		"capabilities":   trafficCaps(s),
		"ts_unix":        s.TsUnix,
		"window_sec":     s.WindowSec,
		"totals":         s.Totals,
	})
}

func handleTrafficTopIPs(w http.ResponseWriter, r *http.Request) {
	handleTrafficRows(w, r, func(s traffic.Snapshot, limit int, _ string) any {
		return clampIPSRows(s.TopIPs, limit)
	})
}

func handleTrafficTopProcesses(w http.ResponseWriter, r *http.Request) {
	handleTrafficRows(w, r, func(s traffic.Snapshot, limit int, _ string) any {
		return clampProcessRows(s.ProcessBuckets, limit)
	})
}

func handleTrafficTopPorts(w http.ResponseWriter, r *http.Request) {
	handleTrafficRows(w, r, func(s traffic.Snapshot, limit int, _ string) any {
		return clampPortsRows(s.Ports, limit)
	})
}

func handleTrafficProtocols(w http.ResponseWriter, r *http.Request) {
	handleTrafficRows(w, r, func(s traffic.Snapshot, limit int, _ string) any {
		return clampProtocolRows(s.Protocols, limit)
	})
}

func handleTrafficConnections(w http.ResponseWriter, r *http.Request) {
	handleTrafficRows(w, r, func(s traffic.Snapshot, limit int, sortBy string) any {
		rows := append([]traffic.FlowSnapshot(nil), s.Flows...)
		sortFlowRows(rows, sortBy)
		return clampFlowRows(rows, limit)
	})
}

func handleTrafficHistory(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeTrafficJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s, ok := trafficSnapshotOrUnavailable(w)
	if !ok {
		return
	}
	window := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("window")))
	if window == "" {
		window = "60s"
	}
	agg, found := s.Windows[window]
	if !found {
		writeTrafficJSON(w, http.StatusBadRequest, map[string]any{
			"schema_version": trafficSchemaVersion,
			"capabilities":   trafficCaps(s),
			"error":          "unknown window",
			"window":         window,
		})
		return
	}
	writeTrafficJSON(w, http.StatusOK, map[string]any{
		"schema_version": trafficSchemaVersion,
		"capabilities":   trafficCaps(s),
		"ts_unix":        s.TsUnix,
		"window":         window,
		"totals":         agg.Totals,
	})
}

func handleTrafficRows(w http.ResponseWriter, r *http.Request, rowFn func(traffic.Snapshot, int, string) any) {
	if r.Method != http.MethodGet {
		writeTrafficJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	s, ok := trafficSnapshotOrUnavailable(w)
	if !ok {
		return
	}
	limit := parseTrafficLimit(r.URL.Query().Get("limit"), 20, 200)
	rows := rowFn(s, limit, r.URL.Query().Get("sort"))
	writeTrafficJSON(w, http.StatusOK, map[string]any{
		"schema_version": trafficSchemaVersion,
		"capabilities":   trafficCaps(s),
		"ts_unix":        s.TsUnix,
		"window_sec":     s.WindowSec,
		"rows":           rows,
	})
}

func parseTrafficLimit(raw string, def, max int) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func clampIPSRows(in []traffic.IPSnapshot, limit int) []traffic.IPSnapshot {
	if limit > len(in) {
		limit = len(in)
	}
	return in[:limit]
}

func clampProcessRows(in []traffic.ProcessBucketSnapshot, limit int) []traffic.ProcessBucketSnapshot {
	if limit > len(in) {
		limit = len(in)
	}
	return in[:limit]
}

func clampPortsRows(in []traffic.PortSnapshot, limit int) []traffic.PortSnapshot {
	if limit > len(in) {
		limit = len(in)
	}
	return in[:limit]
}

func clampProtocolRows(in []traffic.ProtocolSnapshot, limit int) []traffic.ProtocolSnapshot {
	if limit > len(in) {
		limit = len(in)
	}
	return in[:limit]
}

func clampFlowRows(in []traffic.FlowSnapshot, limit int) []traffic.FlowSnapshot {
	if limit > len(in) {
		limit = len(in)
	}
	return in[:limit]
}

func sortFlowRows(rows []traffic.FlowSnapshot, sortBy string) {
	switch strings.ToLower(strings.TrimSpace(sortBy)) {
	case "last_seen", "last_seen_unix":
		sort.Slice(rows, func(i, j int) bool { return rows[i].LastSeenUnix > rows[j].LastSeenUnix })
	case "in_bps":
		sort.Slice(rows, func(i, j int) bool { return rows[i].InBPS > rows[j].InBPS })
	case "out_bps":
		sort.Slice(rows, func(i, j int) bool { return rows[i].OutBPS > rows[j].OutBPS })
	case "bytes", "total_bytes":
		sort.Slice(rows, func(i, j int) bool {
			li := rows[i].InBytes + rows[i].OutBytes
			lj := rows[j].InBytes + rows[j].OutBytes
			return li > lj
		})
	}
}

func writeTrafficJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Source", "cfm-traffic")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func trafficAdminCtx(req *http.Request) *http.Request {
	ctx := context.WithValue(req.Context(), webdet.CtxAuthnKey{}, true)
	ctx = context.WithValue(ctx, webdet.CtxRoleKey{}, webdet.CtxRoleAdmin)
	return req.WithContext(ctx)
}
