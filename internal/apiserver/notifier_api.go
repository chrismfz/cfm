package apiserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

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
	m.Handle("/api/v1/notifier/validate", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierValidate(w, r)
	})))
	m.Handle("/api/v1/notifier/preview", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleNotifierPreview(w, r, cfgDir)
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

type notifierValidationError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
	Code    string `json:"code,omitempty"`
}

func handleNotifierValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Config    *notify.AdminConfig                   `json:"config,omitempty"`
		Notifier  notify.AdminNotifierConfig            `json:"notifier"`
		Dedupe    notify.AdminDedupeConfig              `json:"dedupe"`
		Channels  []notify.AdminChannelConfig           `json:"channels"`
		Detectors map[string]notify.AdminDetectorConfig `json:"detectors"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	cfg := notify.AdminConfig{
		Notifier:  req.Notifier,
		Dedupe:    req.Dedupe,
		Channels:  req.Channels,
		Detectors: req.Detectors,
	}
	if req.Config != nil {
		cfg = *req.Config
	}
	errs := validateNotifierDraft(cfg)
	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"ok":     len(errs) == 0,
		"errors": errs,
	})
}

func validateNotifierDraft(c notify.AdminConfig) []notifierValidationError {
	errs := make([]notifierValidationError, 0)
	pushErr := func(path, message, code string) {
		errs = append(errs, notifierValidationError{Path: path, Message: message, Code: code})
	}

	validateDuration := func(path, raw string) {
		v := strings.TrimSpace(raw)
		if v == "" {
			return
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			pushErr(path, "invalid duration", "invalid_duration")
		}
	}

	validateDuration("notifier.default_cooldown", c.Notifier.DefaultCooldown)
	validateDuration("dedupe.cooldown", c.Dedupe.Cooldown)

	channelSeen := map[string]int{}
	channelExists := map[string]struct{}{}
	for i, ch := range c.Channels {
		id := strings.TrimSpace(ch.ID)
		base := "channels[" + strconv.Itoa(i) + "]"
		if id == "" {
			pushErr(base+".id", "channel id is required", "required")
			continue
		}
		idKey := strings.ToLower(id)
		if prev, ok := channelSeen[idKey]; ok {
			pushErr(base+".id", "duplicate channel id (already used at channels["+strconv.Itoa(prev)+"].id)", "duplicate")
		} else {
			channelSeen[idKey] = i
		}
		channelExists[idKey] = struct{}{}

		typ := strings.ToLower(strings.TrimSpace(ch.Type))
		switch typ {
		case "sendmail":
			if strings.TrimSpace(ch.Path) == "" {
				pushErr(base+".path", "sendmail path is required", "required")
			}
		case "smtp":
			if strings.TrimSpace(ch.Host) == "" {
				pushErr(base+".host", "smtp host is required", "required")
			}
			if strings.TrimSpace(ch.From) == "" {
				pushErr(base+".from", "smtp from is required", "required")
			}
			if len(ch.To) == 0 {
				pushErr(base+".to", "smtp to is required", "required")
			}
		case "slack", "slack_webhook":
			if strings.TrimSpace(ch.WebhookURL) == "" {
				pushErr(base+".webhook_url", "slack webhook_url is required", "required")
			}
		default:
			pushErr(base+".type", "unsupported channel type", "unsupported_type")
		}
	}

	for detectorName, d := range c.Detectors {
		detPath := "detectors['" + detectorName + "']"
		validateDuration(detPath+".cooldown", d.Cooldown)
		ms := strings.ToLower(strings.TrimSpace(d.MinSeverity))
		switch ms {
		case "", "info", "warn", "warning", "critical":
		default:
			pushErr(detPath+".min_severity", "unsupported min_severity", "invalid_min_severity")
		}
		for i, chID := range d.Channels {
			if _, ok := channelExists[strings.ToLower(strings.TrimSpace(chID))]; !ok {
				pushErr(detPath+".channels["+strconv.Itoa(i)+"]", "channel reference does not exist", "unknown_channel")
			}
		}
	}

	return errs
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

func handleNotifierPreview(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Config notify.AdminConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	currentCfg, _, err := notify.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	currentText, err := notify.RenderAdminConfig(cfgDir, currentCfg)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	draftText, err := notify.RenderAdminConfig(cfgDir, req.Config)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{
		"diff": unifiedTextDiff("notify.conf", currentText, draftText),
	})
}

func unifiedTextDiff(fileName, before, after string) string {
	if before == after {
		return "--- " + fileName + "\n+++ " + fileName + "\n@@ -1,0 +1,0 @@\n"
	}
	a := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
	b := strings.Split(strings.TrimSuffix(after, "\n"), "\n")
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out strings.Builder
	out.WriteString("--- " + fileName + "\n")
	out.WriteString("+++ " + fileName + "\n")
	out.WriteString("@@ -1," + strconv.Itoa(len(a)) + " +1," + strconv.Itoa(len(b)) + " @@\n")
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			out.WriteString(" " + a[i] + "\n")
			i++
			j++
			continue
		}
		if dp[i+1][j] >= dp[i][j+1] {
			out.WriteString("-" + a[i] + "\n")
			i++
		} else {
			out.WriteString("+" + b[j] + "\n")
			j++
		}
	}
	for i < len(a) {
		out.WriteString("-" + a[i] + "\n")
		i++
	}
	for j < len(b) {
		out.WriteString("+" + b[j] + "\n")
		j++
	}
	return out.String()
}
