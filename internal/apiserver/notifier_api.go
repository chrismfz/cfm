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
	m.Handle("/api/v1/notifier/history", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierHistory(w, r, cfgDir)
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
			Config            notify.AdminConfig             `json:"config"`
			Notifier          *notify.AdminNotifierConfig    `json:"notifier,omitempty"`
			Dedupe            *notify.AdminDedupeConfig      `json:"dedupe,omitempty"`
			ChannelMutations  []notify.AdminChannelMutation  `json:"channel_mutations,omitempty"`
			DetectorMutations []notify.AdminDetectorMutation `json:"detector_mutations,omitempty"`
			DeleteChannels    []string                       `json:"delete_channels,omitempty"`
			DeleteDetectors   []string                       `json:"delete_detectors,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		if len(req.ChannelMutations) > 0 || len(req.DetectorMutations) > 0 || len(req.DeleteChannels) > 0 || len(req.DeleteDetectors) > 0 || req.Notifier != nil || req.Dedupe != nil {
			if err := validateNotifierMutations(req.ChannelMutations, req.DetectorMutations); err != nil {
				writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
			path, err := notify.SaveAdminConfigMutations(cfgDir, notify.AdminMutations{
				Notifier:            req.Notifier,
				Dedupe:              req.Dedupe,
				Channels:            req.ChannelMutations,
				Detectors:           req.DetectorMutations,
				DeleteChannelIDs:    req.DeleteChannels,
				DeleteDetectorNames: req.DeleteDetectors,
			})
			if err != nil {
				writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
				return
			}
			writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path})
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

func validateNotifierMutations(chMut []notify.AdminChannelMutation, detMut []notify.AdminDetectorMutation) error {
	for _, m := range chMut {
		id := strings.TrimSpace(m.ID)
		if id == "" {
			return errors.New("channel mutation id is required")
		}
		if m.Delete {
			continue
		}
		if m.Type != nil {
			typ := strings.TrimSpace(*m.Type)
			switch typ {
			case "sendmail", "smtp", "slack", "slack_webhook":
			default:
				return errors.New("unsupported channel type: " + typ)
			}
		}
	}
	for _, m := range detMut {
		if strings.TrimSpace(m.Name) == "" {
			return errors.New("detector mutation name is required")
		}
	}
	return nil
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
