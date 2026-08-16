package apiserver

import (
	"encoding/json"
	"net/http"

	"cfm/internal/procstat"
	webdet "cfm/internal/webdetector"
)

const processHealthPath = "/api/v1/system/process-health"

// Register this staged read-only endpoint through the apiserver's generic route
// hook so this slice can stay isolated from the much larger system-status file.
// Production Start() is single-shot; Register queues the route before the mux is
// constructed and applies it when Start builds the shared mux.
func init() {
	Register(registerProcessHealthRoute)
}

func registerProcessHealthRoute(mux *http.ServeMux) {
	mux.HandleFunc(processHealthPath, handleSystemProcessHealth)
}

// handleSystemProcessHealth exposes the cheap single-scan procstat.Health()
// snapshot. It is intentionally descriptive only: no thresholds, anomaly
// classification, baseline comparison, or whats_wrong integration live here.
func handleSystemProcessHealth(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	snapshot, err := procstat.Health()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":             true,
		"schema":         "system.process_health.v1",
		"process_health": snapshot,
	})
}
