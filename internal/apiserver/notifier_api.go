package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"cfm/internal/notify"
)

func RegisterNotifierEndpoints(m *http.ServeMux, cfgDir string) {
	if m == nil {
		return
	}

	m.Handle("/api/v1/notifier/config", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierConfig(w, r, cfgDir)
	})))
	m.Handle("/api/v1/notifier/reload", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierReload(w, r, cfgDir)
	})))
	m.Handle("/api/v1/notifier/test", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierTest(w, r)
	})))
	m.Handle("/api/v1/notifier/metrics", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierMetrics(w, r, cfgDir)
	})))
}

func handleNotifierConfig(w http.ResponseWriter, r *http.Request, cfgDir string) {
	switch r.Method {
	case http.MethodGet:
		cfg, path, err := notify.LoadAdminConfig(cfgDir)
		if err != nil {
			writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeNotifierJSON(w, http.StatusOK, map[string]any{"config": cfg, "path": path})
	case http.MethodPut:
		var req struct {
			Config notify.AdminConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		if err := validateNotifierConfig(req.Config); err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		path, err := notify.SaveAdminConfig(cfgDir, req.Config)
		if err != nil {
			writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path})
	default:
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

func handleNotifierReload(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if err := notify.Reload(cfgDir); err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleNotifierTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Channel  string         `json:"channel"`
		Channels []string       `json:"channels"`
		Detector string         `json:"detector"`
		Sample   map[string]any `json:"sample"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}

	channels := req.Channels
	if channel := strings.TrimSpace(req.Channel); channel != "" {
		channels = append(channels, channel)
	}
	if len(channels) == 0 {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "channel is required"})
		return
	}
	ev := notify.BuildSyntheticTestEvent(req.Detector, req.Sample)
	results, err := notify.SendSyntheticTest(ev, channels)
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"results": results,
	})
}

func writeNotifierJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func validateNotifierConfig(c notify.AdminConfig) error {
	seen := map[string]struct{}{}
	for _, ch := range c.Channels {
		id := strings.TrimSpace(ch.ID)
		if id == "" {
			return errors.New("channel id is required")
		}
		if _, ok := seen[id]; ok {
			return errors.New("duplicate channel id: " + id)
		}
		seen[id] = struct{}{}
		typ := strings.TrimSpace(ch.Type)
		switch typ {
		case "sendmail", "smtp", "slack", "slack_webhook":
		default:
			return errors.New("unsupported channel type: " + typ)
		}
	}
	return nil
}
