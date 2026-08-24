package apiserver

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"cfm/internal/logging"
	"cfm/internal/telemetry"
	webdet "cfm/internal/webdetector"
)

type debugLiveResponse struct {
	Now       time.Time              `json:"now"`
	Version   string                 `json:"version"`
	Telemetry telemetry.LiveSnapshot `json:"telemetry"`
	Data      map[string]any         `json:"data"`
}

func RegisterDebugEndpoints(m *http.ServeMux) {
	if m == nil {
		return
	}

	m.Handle("/api/v1/debug/live", adminOnlyHandler(http.HandlerFunc(handleDebugLive)))
	m.Handle("/api/v1/debug/capture", adminOnlyHandler(http.HandlerFunc(handleDebugCaptureStart)))
	m.Handle("/api/v1/debug/capture/", adminOnlyHandler(http.HandlerFunc(handleDebugCaptureStatus)))
	m.Handle("/api/v1/debug/export", adminOnlyHandler(http.HandlerFunc(handleDebugExport)))
}

func writeDebugJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func handleDebugLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	logDebugAudit(r, "debug.live", "ok", "")
	writeDebugJSON(w, http.StatusOK, debugLiveResponse{
		Now:       time.Now().UTC(),
		Version:   "v1",
		Telemetry: telemetry.Snapshot(),
		Data:      map[string]any{"status": "available"},
	})
}

func handleDebugCaptureStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		DurationSec int `json:"duration_sec"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	if req.DurationSec == 0 {
		req.DurationSec = 20
	}
	rec, existing, err := globalDebugCapture.start(req.DurationSec)
	if err != nil {
		logDebugAudit(r, "debug.capture.start", "rejected", err.Error())
		writeDebugJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if existing {
		logDebugAudit(r, "debug.capture.start", "singleflight", rec.ID)
		writeDebugJSON(w, http.StatusAccepted, rec)
		return
	}
	logDebugAudit(r, "debug.capture.start", "started", rec.ID)
	writeDebugJSON(w, http.StatusAccepted, rec)
}

func handleDebugCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/debug/capture/")
	if id == "" {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}
	rec := globalDebugCapture.get(id)
	if rec == nil {
		writeDebugJSON(w, http.StatusNotFound, map[string]any{"error": "capture not found"})
		return
	}
	logDebugAudit(r, "debug.capture.status", "ok", id)
	writeDebugJSON(w, http.StatusOK, rec)
}

func handleDebugExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, `{"error":"missing id"}`, http.StatusBadRequest)
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	body, ctype, err := globalDebugCapture.export(id, format)
	if err != nil {
		logDebugAudit(r, "debug.capture.export", "rejected", err.Error())
		writeDebugJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	logDebugAudit(r, "debug.capture.export", "ok", id)
	w.Header().Set("Content-Type", ctype)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func logDebugAudit(r *http.Request, action, result, detail string) {
	srcIP := realIPFromRequest(r)
	role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
	role = strings.TrimSpace(role)
	if role == "" {
		role = "unknown"
	}

	payload := map[string]string{
		"event":  "debug_audit",
		"action": action,
		"result": result,
		"ip":     srcIP,
		"method": r.Method,
		"path":   r.URL.Path,
		"role":   role,
	}
	if detail != "" {
		payload["detail"] = detail
	}
	b, _ := json.Marshal(payload)
	logging.LogfAPI("[audit] %s", string(b))
}
