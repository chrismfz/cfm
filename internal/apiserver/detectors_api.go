package apiserver

import (
	"cfm/internal/detconf"
	"cfm/internal/detectors/meta"
	"cfm/internal/detectorstatus"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"cfm/internal/detectorscfg"
)

// DetectorSourceRow is one section's dry-run source resolution: which log
// source (journald unit / file / docker container) the section would use on
// this host right now, and why. Rows are computed by the detectors package
// via the SAME planners its registers use (injected below — the detectors
// package imports apiserver, so apiserver cannot import it back).
type DetectorSourceRow struct {
	Section    string            `json:"section"`
	Type       string            `json:"type"`
	Enabled    bool              `json:"enabled"`
	Engine     string            `json:"engine"` // srcresolve | legacy-auto | n/a
	Configured map[string]string `json:"configured,omitempty"`
	// Kind: journal|file|docker (resolved), as-configured (explicit keys /
	// package-internal resolution used verbatim), provisional targets keep
	// their resolved kind with provisional=true, disabled (section would
	// self-disable), unreported (legacy-auto), none.
	Kind         string `json:"kind"`
	Target       string `json:"target,omitempty"` // unit / path / container
	Reason       string `json:"reason,omitempty"`
	Provisional  bool   `json:"provisional,omitempty"`
	WouldDisable bool   `json:"would_disable,omitempty"`
	Note         string `json:"note,omitempty"`
}

// detectorSourceReport is injected by the detectors package at init.
var detectorSourceReport func(cfgDir string) ([]DetectorSourceRow, time.Time, error)

// SetDetectorSourceReport wires the detectors package's dry-run source
// resolution into GET /api/v1/detectors/source-resolution.
func SetDetectorSourceReport(fn func(cfgDir string) ([]DetectorSourceRow, time.Time, error)) {
	detectorSourceReport = fn
}

func RegisterDetectorsEndpoints(m *http.ServeMux, cfgDir string) {
	// GET /api/v1/detectors/source-resolution — admin-only, read-only dry run:
	// per section, which log source would resolve right now and why (probes
	// run; nothing starts or changes). Backs `cfm detectors-srcresolve`, the
	// cfm-admin card and the detectors_srcresolve MCP tool.
	m.Handle("/api/v1/detectors/source-resolution", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}
		if detectorSourceReport == nil {
			http.Error(w, `{"error":"source resolution not available"}`, http.StatusServiceUnavailable)
			return
		}
		rows, at, err := detectorSourceReport(cfgDir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "generated_at": at, "rows": rows,
		})
	})))
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
	m.Handle("/api/v1/detectors/status", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsStatus(w, r, cfgDir)
	})))
	m.Handle("/api/v1/detectors/catalog", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsCatalog(w, r)
	})))
	m.Handle("/api/v1/detectors/coverage", adminOnlyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleDetectorsCoverage(w, r)
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
		_, statErr := os.Stat(path)
		writeNotifierJSON(w, http.StatusOK, map[string]any{"config": cfg, "path": path, "exists": statErr == nil})
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

func handleDetectorsCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeNotifierJSON(w, http.StatusOK, map[string]any{"catalog": meta.Catalog()})
}

type detectorValidationError struct {
	Path, Message, Code, Expected string
}

const maxCustomFailRegexRules = 128

func validateDetectorDraft(c detectorscfg.AdminConfig) []detectorValidationError {
	errList := []detectorValidationError{}
	push := func(path, msg, code, expected string) {
		errList = append(errList, detectorValidationError{Path: path, Message: msg, Code: code, Expected: expected})
	}
	allowedBool := map[string]struct{}{"0": {}, "1": {}, "no": {}, "yes": {}, "false": {}, "true": {}, "off": {}, "on": {}}
	allowedBlockMode := map[string]struct{}{"0": {}, "no": {}, "off": {}, "dryrun": {}, "alert": {}, "permanent": {}, "perm": {}}
	enumByKey := map[string]map[string]struct{}{
		"ENABLED":           allowedBool,
		"SEND_TO_API":       allowedBool,
		"ENRICH":            allowedBool,
		"PTR":               allowedBool,
		"LOG_IGNORED":       allowedBool,
		"DRY_RUN":           allowedBool,
		"MODE":              {"journal": {}, "file": {}, "docker": {}},
		"SEND_TO_BLOCKLIST": {"lenient": {}, "blacklist": {}},
	}
	isDurationKey := func(key string) bool {
		u := strings.ToUpper(strings.TrimSpace(key))
		// Enum keys are validated by value, never as durations — even when the
		// name contains a token like BLOCK/TTL/WINDOW (e.g. SEND_TO_BLOCKLIST).
		if _, ok := enumByKey[u]; ok {
			return false
		}
		// BLOCK is duration_OR_enum: named modes (dryrun/permanent/alert) are
		// legal, so plain duration checking here rejected every named mode as
		// "invalid duration". validateKnownEnum owns the BLOCK grammar.
		if u == "BLOCK" {
			return false
		}
		return strings.Contains(u, "TIMEOUT") || strings.Contains(u, "COOLDOWN") || strings.Contains(u, "EVERY") || strings.Contains(u, "WINDOW") || strings.Contains(u, "TTL") || strings.Contains(u, "BLOCK")
	}
	isIntegerKey := func(key string) bool {
		u := strings.ToUpper(strings.TrimSpace(key))
		if strings.Contains(u, "MAX") || strings.Contains(u, "LIMIT") || strings.Contains(u, "THRESHOLD") {
			return true
		}
		switch u {
		case "SEND_TO_API", "ENABLED", "ENRICH", "PTR", "DRY_RUN", "LOG_IGNORED":
			return false
		default:
			return false
		}
	}
	validateKnownEnum := func(path, key, raw string) {
		normalized := strings.ToLower(strings.Trim(strings.TrimSpace(raw), `"`))
		if normalized == "" {
			// SEND_TO_BLOCKLIST is optional; an empty value means "unset"
			// (destination defers to SEND_TO_API / the global blocklist).
			if strings.EqualFold(key, "SEND_TO_BLOCKLIST") {
				return
			}
			push(path, "empty value for required enum key", "required", "one of the allowed enum values")
			return
		}
		if strings.EqualFold(key, "BLOCK") {
			if _, ok := allowedBlockMode[normalized]; ok {
				return
			}
			// Same grammar the runtime's parseBlockPolicy accepts — including
			// the days extension ("7d"). Plain time.ParseDuration here would
			// reject values the detector runs fine on (false invalid-block-mode).
			if _, err := detconf.ParseCfgDuration(normalized); err == nil {
				return
			}
			push(path, "invalid enum/duration for BLOCK", "invalid_enum", "BLOCK expects one of no/off/0/dryrun/alert/permanent/perm or a duration like 30m / 7d")
			return
		}
		allowed, ok := enumByKey[strings.ToUpper(strings.TrimSpace(key))]
		if !ok {
			return
		}
		if _, exists := allowed[normalized]; !exists {
			push(path, "invalid enum value", "invalid_enum", "allowed values are: "+strings.Join(mapKeys(allowed), ", "))
		}
	}
	checkDur := func(path, v string) {
		if strings.TrimSpace(v) == "" {
			return
		}
		d, err := detconf.ParseCfgDuration(strings.Trim(strings.TrimSpace(v), `"`))
		if err != nil || d <= 0 {
			push(path, "invalid duration", "invalid_duration", "positive duration, e.g. 30s, 10m, 1h30m, 7d")
		}
	}
	for k, v := range c.Global {
		if isDurationKey(k) {
			checkDur("global."+k, v)
		}
		validateKnownEnum("global."+k, k, v)
		if isIntegerKey(k) {
			n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"`))
			if err != nil {
				push("global."+k, "invalid integer value", "invalid_int", "integer >= 0")
			} else if n < 0 {
				push("global."+k, "negative numbers are not allowed", "negative_number", "integer >= 0")
			}
		}
	}
	seenSections := map[string]string{}
	sectionGroups := []struct {
		Name     string
		Sections []detectorscfg.AdminSection
	}{
		{Name: "core", Sections: c.Core},
		{Name: "leniency", Sections: c.Leniency},
		{Name: "advanced", Sections: c.Advanced},
	}
	for _, group := range sectionGroups {
		for idx, sec := range group.Sections {
			trimmed := strings.TrimSpace(sec.Name)
			if trimmed == "" {
				continue
			}
			key := strings.ToLower(trimmed)
			currentPath := group.Name + "[" + strconv.Itoa(idx) + "].name"
			if firstPath, ok := seenSections[key]; ok {
				push(currentPath, "duplicate section name (already defined at "+firstPath+")", "duplicate_section_name", "unique section name")
				continue
			}
			seenSections[key] = currentPath
		}
	}
	all := append(append([]detectorscfg.AdminSection{}, c.Core...), c.Leniency...)
	all = append(all, c.Advanced...)
	for i, sec := range all {
		if strings.TrimSpace(sec.Name) == "" {
			push("sections["+strconv.Itoa(i)+"].name", "section name required", "required", "non-empty section name")
		}
		if isCustomSection(sec.Name) {
			validateCustomSectionRules(push, sec)
		}
		for k, v := range sec.Keys {
			if strings.TrimSpace(v) == "" && (strings.EqualFold(k, "ENABLED") || strings.EqualFold(k, "BLOCK")) {
				push(sec.Name+"."+k, "empty required key", "required", "non-empty value")
				continue
			}
			if isDurationKey(k) {
				checkDur(sec.Name+"."+k, v)
			}
			validateKnownEnum(sec.Name+"."+k, k, v)
			if isIntegerKey(k) {
				n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(v), `"`))
				if err != nil {
					push(sec.Name+"."+k, "invalid integer value", "invalid_int", "integer >= 0")
				} else if n < 0 {
					push(sec.Name+"."+k, "negative numbers are not allowed", "negative_number", "integer >= 0")
				}
			}
			if strings.Contains(v, "\n") {
				for _, ln := range strings.Split(v, "\n") {
					if strings.Count(ln, ":") > 0 && strings.TrimSpace(ln) == ":" {
						push(sec.Name+"."+k, "malformed multiline rule", "invalid_multiline", "each multiline entry should be non-empty and not just ':'")
					}
				}
			}
		}
	}
	return errList
}

func isCustomSection(sectionName string) bool {
	parts := strings.FieldsFunc(strings.TrimSpace(sectionName), func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t'
	})
	if len(parts) == 0 {
		return false
	}
	return strings.EqualFold(parts[0], "custom")
}

func customRegexLines(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func validateCustomSectionRules(push func(path, msg, code, expected string), sec detectorscfg.AdminSection) {
	raw, ok := sec.Keys["FAIL_REGEX"]
	if !ok {
		push(sec.Name+".FAIL_REGEX", "FAIL_REGEX is required for custom sections", "required", "at least one regex rule")
		return
	}
	lines := customRegexLines(raw)
	if len(lines) == 0 {
		push(sec.Name+".FAIL_REGEX", "FAIL_REGEX must include at least one non-empty regex", "empty_regex_list", "1-"+strconv.Itoa(maxCustomFailRegexRules)+" regex entries")
		return
	}
	if len(lines) > maxCustomFailRegexRules {
		push(sec.Name+".FAIL_REGEX", "FAIL_REGEX has too many entries", "regex_list_too_long", "at most "+strconv.Itoa(maxCustomFailRegexRules)+" regex entries")
		return
	}

	matchTarget := strings.ToLower(strings.TrimSpace(sec.Keys["MATCH_TARGET"]))
	hasIPCapture := false
	hasUserCapture := false
	for idx, reStr := range lines {
		re, err := regexp.Compile(reStr)
		path := sec.Name + ".FAIL_REGEX[" + strconv.Itoa(idx) + "]"
		if err != nil {
			push(path, "regex does not compile: "+err.Error(), "invalid_regex", "valid regular expression")
			continue
		}
		hasIP := re.SubexpIndex("ip") > 0
		hasUser := re.SubexpIndex("user") > 0
		hasIPCapture = hasIPCapture || hasIP
		hasUserCapture = hasUserCapture || hasUser
		switch matchTarget {
		case "ip":
			if !hasIP {
				push(path, "MATCH_TARGET=ip requires named (?P<ip>...) capture", "missing_capture", "include named capture: ip")
			}
		case "user":
			if !hasUser {
				push(path, "MATCH_TARGET=user requires named (?P<user>...) capture", "missing_capture", "include named capture: user")
			}
		case "both":
			if !hasIP || !hasUser {
				push(path, "MATCH_TARGET=both requires both (?P<ip>...) and (?P<user>...) captures", "missing_capture", "include both named captures: ip and user")
			}
		}
	}

	strategyOK := hasIPCapture || (matchTarget == "user" && hasUserCapture)
	if !strategyOK {
		push(sec.Name+".FAIL_REGEX", "no target capture strategy found", "missing_target_capture_strategy", "add named (?P<ip>...) capture, or set MATCH_TARGET=user and capture (?P<user>...)")
	}
}

func mapKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
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
		Source   string `json:"source"`
		File     string `json:"file"`
		Autofind bool   `json:"autofind"`
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

func handleDetectorsStatus(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	writeNotifierJSON(w, http.StatusOK, detectorstatus.GetSnapshot())
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
