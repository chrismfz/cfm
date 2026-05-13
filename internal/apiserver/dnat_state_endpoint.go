package apiserver

import (
	"encoding/json"
	"net/http"

	"cfm/internal/dnat"
)

// dnatStateResponse is the JSON payload returned by /api/v1/dnat/state.
// The CLI status command (cfm dnat status / cfm dnat cpanel status)
// runs in a separate process from the daemon, so the in-process
// transition/probe maps in the dnat package are otherwise invisible —
// this endpoint exposes them to the CLI over the existing admin
// apiserver.
type dnatStateResponse struct {
	Web    dnat.StateSnapshot `json:"web"`
	CPanel dnat.StateSnapshot `json:"cpanel"`
}

// RegisterDNATState wires /api/v1/dnat/state behind the admin-only
// middleware. Read-only state snapshot; the CLI uses Bearer
// AUTH_TOKEN loaded from /etc/cfm/cfm.conf when calling it.
func RegisterDNATState(m *http.ServeMux) {
	if m == nil {
		return
	}
	m.Handle("/api/v1/dnat/state", adminOnlyHandler(http.HandlerFunc(handleDNATState)))
}

func handleDNATState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := dnatStateResponse{
		Web:    dnat.SnapshotScope(dnat.ScopeWeb),
		CPanel: dnat.SnapshotScope(dnat.ScopeCPanel),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(resp)
}
