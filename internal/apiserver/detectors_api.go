package apiserver

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cfm/internal/detectorscfg"
)

func RegisterDetectorsEndpoints(m *http.ServeMux, cfgDir string) {
	m.Handle("/api/v1/detectors/config", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsConfig(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/validate", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsValidate(w, r)
	})))
	m.Handle("/api/v1/detectors/preview", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsPreview(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/reload", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsReload(w, r)
	})))
	m.Handle("/api/v1/detectors/backups", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsBackups(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/backups/diff", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsBackupDiff(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/backups/restore", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsBackupRestore(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/test", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsTest(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/live", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsLive(w, r, cfgDir)
	})))
}

func handleDetectorsConfig(w http.ResponseWriter, r *http.Request, cfgDir string) {
	switch r.Method {
	case http.MethodGet:
		cfg, path, err := detectorscfg.LoadAdminConfig(cfgDir)
		if err != nil {
			writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeNotifierJSON(w, http.StatusOK, map[string]any{"config": cfg, "path": path})
	case http.MethodPut:
		var req struct {
			Config detectorscfg.AdminConfig `json:"config"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
			return
		}
		errs := validateDetectorDraft(req.Config)
		if len(errs) > 0 {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "validation failed", "errors": errs})
			return
		}
		path, backupID, err := detectorscfg.SaveAdminConfigWithBackup(cfgDir, req.Config)
		if err != nil {
			writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path, "backup_id": backupID})
	default:
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

type detectorValidationError struct {
	Path, Message, Code string
}

func validateDetectorDraft(c detectorscfg.AdminConfig) []detectorValidationError {
	errList := []detectorValidationError{}
	push := func(path, msg, code string) {
		errList = append(errList, detectorValidationError{Path: path, Message: msg, Code: code})
	}
	checkDur := func(path, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		d, err := time.ParseDuration(strings.Trim(strings.TrimSpace(v), `"`))
		if err != nil || d <= 0 {
			push(path, "invalid duration", "invalid_duration")
		}
	}
	for k, v := range c.Global {
		if strings.Contains(strings.ToUpper(k), "TIMEOUT") || strings.Contains(strings.ToUpper(k), "COOLDOWN") || strings.Contains(strings.ToUpper(k), "EVERY") {
			checkDur("global."+k, v)
		}
	}
	all := append(append([]detectorscfg.AdminSection{}, c.Core...), c.Leniency...)
	for i, sec := range all {
		if strings.TrimSpace(sec.Name) == "" {
			push("sections["+strconv.Itoa(i)+"].name", "section name required", "required")
		}
		for k, v := range sec.Keys {
			u := strings.ToUpper(k)
			if strings.Contains(u, "TIMEOUT") || strings.Contains(u, "COOLDOWN") || strings.Contains(u, "EVERY") || strings.Contains(u, "WINDOW") || strings.Contains(u, "TTL") || strings.Contains(u, "BLOCK") && strings.Contains(v, "m") {
				checkDur(sec.Name+"."+k, v)
			}
			if strings.Contains(v, "\n") {
				for _, ln := range strings.Split(v, "\n") {
					if strings.Count(ln, ":") > 0 && strings.TrimSpace(ln) == ":" {
						push(sec.Name+"."+k, "malformed multiline rule", "invalid_multiline")
					}
				}
			}
		}
	}
	return errList
}

func handleDetectorsValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Config detectorscfg.AdminConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	errs := validateDetectorDraft(req.Config)
	writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": len(errs) == 0, "errors": errs})
}

func handleDetectorsPreview(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Config detectorscfg.AdminConfig `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	current, _, err := detectorscfg.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	before, err := detectorscfg.RenderAdminConfig(cfgDir, current)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	after, err := detectorscfg.RenderAdminConfig(cfgDir, req.Config)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"diff": unifiedTextDiff("detectorscfg.conf", before, after), "summary": map[string]any{"core_sections": len(req.Config.Core), "leniency_sections": len(req.Config.Leniency)}})
}

func handleDetectorsReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	if err := detectorscfg.ReloadNow(); err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleDetectorsBackups(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	b, err := detectorscfg.ListAdminConfigBackups(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"backups": b})
}

func handleDetectorsBackupDiff(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("id"))
	btxt, err := detectorscfg.ReadAdminConfigBackup(cfgDir, id)
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	cur, _, err := detectorscfg.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	ctxt, _ := detectorscfg.RenderAdminConfig(cfgDir, cur)
	writeNotifierJSON(w, http.StatusOK, map[string]any{"id": id, "diff": unifiedTextDiff("detectorscfg.conf", btxt, ctxt)})
}

func handleDetectorsBackupRestore(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		ID     string `json:"id"`
		Reload bool   `json:"reload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	path, rid, err := detectorscfg.RestoreAdminConfigBackup(cfgDir, req.ID)
	if err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if req.Reload {
		_ = detectorscfg.ReloadNow()
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": true, "path": path, "restored_id": req.ID, "backup_id": rid, "reloaded_detectors": req.Reload})
}

func handleDetectorsTest(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodPost {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	var req struct {
		Source, File string `json:"source"`
		Autofind     bool   `json:"autofind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}
	if req.Autofind && req.File == "" {
		req.File = "/var/log/auth.log"
	}
	ok := true
	if req.Source == "file" {
		safePath, err := resolveSafeDetectorPath(strings.TrimSpace(req.File), cfgDir)
		if err != nil {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// #nosec G304 -- safePath is canonicalized and constrained by resolveSafeDetectorPath.
		_, err = os.Stat(safePath)
		ok = err == nil
		req.File = safePath
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"ok": ok, "source": req.Source, "file": req.File, "autofind": req.Autofind})
}

func handleDetectorsLive(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	requestedFile := strings.TrimSpace(r.URL.Query().Get("file"))
	candidates := configuredDetectorFiles(cfgDir)
	if requestedFile != "" {
		filtered := make([]string, 0, 1)
		for _, c := range candidates {
			if samePath(c, requestedFile) {
				filtered = append(filtered, c)
				break
			}
		}
		if len(filtered) == 0 {
			writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "file is not configured in detectors.conf"})
			return
		}
		candidates = filtered
	}
	live := false
	liveFile := ""
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.Size() > 0 {
			live = true
			liveFile = c
			break
		}
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"live": live, "file": liveFile, "candidates": candidates})
}

func resolveSafeDetectorPath(rawPath, cfgDir string) (string, error) {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return "", os.ErrInvalid
	}
	allowedRoots := []string{"/var/log", "/var/lib", "/etc/cfm"}
	if cfgDir != "" {
		allowedRoots = append(allowedRoots, cfgDir)
	}
	absTarget, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	canonicalTarget := absTarget
	if evalTarget, err := filepath.EvalSymlinks(absTarget); err == nil {
		canonicalTarget = evalTarget
	}
	for _, root := range allowedRoots {
		absRoot, err := filepath.Abs(filepath.Clean(root))
		if err != nil {
			continue
		}
		canonicalRoot := absRoot
		if evalRoot, err := filepath.EvalSymlinks(absRoot); err == nil {
			canonicalRoot = evalRoot
		}
		rel, err := filepath.Rel(canonicalRoot, canonicalTarget)
		if err != nil {
			continue
		}
		if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)) {
			return canonicalTarget, nil
		}
	}
	return "", os.ErrPermission
}

func configuredDetectorFiles(cfgDir string) []string {
	cfg, _, err := detectorscfg.LoadAdminConfig(cfgDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(cfg.Core))
	for _, sec := range cfg.Core {
		p := strings.TrimSpace(sec.Keys["LOG_PATH"])
		if p == "" {
			continue
		}
		safe, err := resolveSafeDetectorPath(p, cfgDir)
		if err != nil {
			continue
		}
		out = append(out, safe)
	}
	return out
}

func samePath(a, b string) bool {
	ac := filepath.Clean(strings.TrimSpace(a))
	bc := filepath.Clean(strings.TrimSpace(b))
	return ac == bc
}
