package panelauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	defaultSockPath = "/var/run/cfm-auth.sock"
	expectedAud     = "cfm-plugin-cpanel"
	maxSessionFiles = 64
)

var (
	cpsessRE               = regexp.MustCompile(`^/cpsess[0-9A-Za-z]{8,128}$`)
	safeSessionComponentRE = regexp.MustCompile(`^[a-z0-9._-]+$`)
	defaultSessionDirs     = []string{"/var/cpanel/sessions/cache", "/var/cpanel/sessions/raw"}
	sessionLookupDirs      = loadSessionLookupDirs()
)

type issueReq struct {
	Panel  string `json:"panel"`
	User   string `json:"user"`
	CPSess string `json:"cpsess"`
	TS     int64  `json:"ts"`
	Nonce  string `json:"nonce"`
}

type issueResp struct {
	Assertion string `json:"assertion,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Error     string `json:"error,omitempty"`
}

var replay sync.Map

func Serve(ctx context.Context, sockPath string) error {
	if strings.TrimSpace(sockPath) == "" {
		sockPath = defaultSockPath
	}
	logging.Logf("[panel-auth] session lookup dirs=%s", strings.Join(sessionLookupDirs, ","))
	_ = os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	_ = os.Chmod(sockPath, 0o660) // #nosec G302 -- plugin callers need group socket access
	if g, err := user.LookupGroup("nobody"); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(sockPath, 0, gid)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth/issue", handleIssue)
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
		_ = os.Remove(sockPath)
	}()
	logging.Logf("[panel-auth] unix server listening on %s", sockPath)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func handleIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	var req issueReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeIssue(w, http.StatusBadRequest, issueResp{Error: "bad request", Reason: "bad_json"})
		return
	}
	userName, reason, debugMeta := validateCpanelRequest(req, time.Now().UTC())
	if reason != "" {
		uid, euid, gid, egid, procUser, procGroup := processIdentity()
		cpsessMasked := maskCPSess(strings.TrimSpace(req.CPSess))
		if reason == "session_not_found" {
			debugJSON := "{}"
			if len(debugMeta) > 0 {
				if b, err := json.Marshal(debugMeta); err == nil {
					debugJSON = string(b)
				}
			}
			logging.Logf("[panel-auth] issue denied panel=%s user=%s reason=%s cpsess=%q ts=%d nonce_len=%d uid=%d euid=%d gid=%d egid=%d proc_user=%q proc_group=%q session_debug=%s",
				strings.TrimSpace(req.Panel), strings.TrimSpace(req.User), reason, cpsessMasked, req.TS, len(strings.TrimSpace(req.Nonce)),
				uid, euid, gid, egid, procUser, procGroup, debugJSON)
		} else {
			logging.Logf("[panel-auth] issue denied panel=%s user=%s reason=%s cpsess=%q ts=%d nonce_len=%d uid=%d euid=%d gid=%d egid=%d proc_user=%q proc_group=%q",
				strings.TrimSpace(req.Panel), strings.TrimSpace(req.User), reason, cpsessMasked, req.TS, len(strings.TrimSpace(req.Nonce)),
				uid, euid, gid, egid, procUser, procGroup)
		}
		writeIssue(w, http.StatusUnauthorized, issueResp{Error: "authorization required", Reason: reason})
		return
	}
	secret, derr := DerivePluginAssertionKey()
	if derr != nil {
		logging.Logf("[panel-auth] derived assertion key unavailable reason=%v", derr)
	}
	if len(secret) == 0 {
		legacySecret := strings.TrimSpace(os.Getenv("CFM_CPANEL_ASSERTION_SECRET"))
		if legacySecret == "" {
			legacySecret = strings.TrimSpace(os.Getenv("CPANEL_PLUGIN_ASSERTION_SECRET"))
		}
		if legacySecret != "" {
			secret = []byte(legacySecret)
		}
	}
	if len(secret) == 0 {
		logging.Logf("[panel-auth] issue denied panel=%s user=%s reason=secret_missing", strings.TrimSpace(req.Panel), userName)
		writeIssue(w, http.StatusUnauthorized, issueResp{Error: "authorization required", Reason: "secret_missing"})
		return
	}
	assertion, err := signAssertion(userName, req.Nonce, secret, time.Now().UTC())
	if err != nil {
		logging.Logf("[panel-auth] issue failed panel=%s user=%s reason=issue_failed err=%v", strings.TrimSpace(req.Panel), userName, err)
		writeIssue(w, http.StatusInternalServerError, issueResp{Error: "internal error", Reason: "issue_failed"})
		return
	}
	if logging.DebugEnabled() && len(debugMeta) > 0 {
		if matchedFile, _ := debugMeta["matched_file"].(string); matchedFile != "" {
			logging.Logf("[panel-auth] issue debug panel=%s user=%s matched_file=%q", strings.TrimSpace(req.Panel), userName, matchedFile)
		}
	}
	logging.Logf("[panel-auth] issue ok panel=%s user=%s", strings.TrimSpace(req.Panel), userName)
	writeIssue(w, http.StatusOK, issueResp{Assertion: assertion})
}

func writeIssue(w http.ResponseWriter, code int, resp issueResp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func validateCpanelRequest(req issueReq, now time.Time) (string, string, map[string]any) {
	if !strings.EqualFold(strings.TrimSpace(req.Panel), "cpanel") {
		return "", "panel_unsupported", nil
	}
	userName := strings.ToLower(strings.TrimSpace(req.User))
	if userName == "" {
		return "", "token_missing", nil
	}
	cpsess := strings.TrimSpace(req.CPSess)
	if !cpsessRE.MatchString(cpsess) {
		return "", "token_malformed", nil
	}
	if req.TS == 0 || req.Nonce == "" {
		return "", "token_missing", nil
	}
	nowUnix := now.Unix()
	if req.TS < nowUnix-15 || req.TS > nowUnix+15 {
		return "", "token_expired", nil
	}
	if _, exists := replay.LoadOrStore(req.Nonce, nowUnix+60); exists {
		return "", "token_replay", nil
	}
	replay.Range(func(k, v interface{}) bool {
		ks, okK := k.(string)
		vu, okV := v.(int64)
		if !okK || !okV || vu <= nowUnix {
			replay.Delete(ks)
		}
		return true
	})
	sid := strings.TrimPrefix(cpsess, "/cpsess")
	ok, debug := validateSessionFile(userName, sid, cpsess)
	if !ok {
		return "", "session_not_found", debug
	}
	return userName, "", debug
}

func validateSessionFile(userName, sid, cpsess string) (bool, map[string]any) {
	debug := map[string]any{
		"paths":                 []map[string]any{},
		"probed_dirs":           append([]string(nil), sessionLookupDirs...),
		"any_candidate_exists":  false,
		"candidate_path_count":  0,
		"configured_dirs_count": len(sessionLookupDirs),
		"scan_limit":            maxSessionFiles,
		"scanned_file_count":    0,
		"match_reason":          "no_match",
		"files_enumerated":      0,
		"files_read_ok":         0,
		"files_parse_json":      0,
		"files_parse_kv":        0,
		"token_matches":         0,
		"final_category":        "no_user_files",
	}
	_ = sid // sid comes from cpsess and is intentionally not used for content-based matching.
	pathEntries := make([]map[string]any, 0, maxSessionFiles)
	filesReadOK := 0
	filesParseJSON := 0
	filesParseKV := 0
	tokenMatches := 0
	parseErrors := 0
	if !isSafeSessionComponent(userName) {
		debug["invalid_component"] = true
		debug["paths"] = pathEntries
		return false, debug
	}
	paths, totalCandidates := buildSessionCandidatePaths(userName, sessionLookupDirs, maxSessionFiles)
	debug["files_enumerated"] = totalCandidates
	debug["candidate_path_count"] = totalCandidates
	debug["scan_truncated"] = totalCandidates > len(paths)
	anyCandidateExists := totalCandidates > 0
	for _, p := range paths {
		entry := map[string]any{
			"path": p,
		}
		b, err := os.ReadFile(p)
		if err != nil {
			entry["read_error"] = err.Error()
			entry["exists"] = !errors.Is(err, os.ErrNotExist)
			if entry["exists"] == true {
				anyCandidateExists = true
			}
			pathEntries = append(pathEntries, entry)
			continue
		}
		entry["exists"] = true
		anyCandidateExists = true
		filesReadOK++
		rowUser, token, parseMode, parseErr := parseSessionRecord(b)
		if parseErr != nil {
			parseErrors++
			entry["parse_error"] = parseErr.Error()
			pathEntries = append(pathEntries, entry)
			continue
		}
		switch parseMode {
		case "json":
			filesParseJSON++
		case "kv":
			filesParseKV++
		}
		entry["parse_mode"] = parseMode
		rowUserMatched := rowUser == "" || strings.EqualFold(rowUser, userName)
		tokenMatched := token == cpsess
		if tokenMatched {
			tokenMatches++
		}
		entry["row_user"] = rowUser
		entry["row_user_matched"] = rowUserMatched
		entry["cp_security_token_matched"] = tokenMatched
		pathEntries = append(pathEntries, entry)
		if rowUserMatched && tokenMatched {
			debug["paths"] = pathEntries
			debug["any_candidate_exists"] = anyCandidateExists
			debug["scanned_file_count"] = len(pathEntries)
			debug["match_reason"] = "matched_by_content"
			debug["parse_mode"] = parseMode
			debug["files_read_ok"] = filesReadOK
			debug["files_parse_json"] = filesParseJSON
			debug["files_parse_kv"] = filesParseKV
			debug["token_matches"] = tokenMatches
			debug["final_category"] = "token_found_user_match"
			debug["matched_file"] = sanitizeSessionFilename(p)
			return true, debug
		}
	}
	debug["paths"] = pathEntries
	debug["any_candidate_exists"] = anyCandidateExists
	debug["scanned_file_count"] = len(pathEntries)
	debug["files_read_ok"] = filesReadOK
	debug["files_parse_json"] = filesParseJSON
	debug["files_parse_kv"] = filesParseKV
	debug["token_matches"] = tokenMatches
	switch {
	case totalCandidates == 0:
		debug["final_category"] = "no_user_files"
	case filesReadOK > 0 && filesReadOK == parseErrors:
		debug["final_category"] = "parse_errors_only"
	case tokenMatches > 0:
		debug["final_category"] = "token_found_user_mismatch"
	default:
		debug["final_category"] = "user_files_present_no_token_match"
	}
	return false, debug
}

func sanitizeSessionFilename(path string) string {
	base := filepath.Base(strings.TrimSpace(path))
	if base == "." || base == "/" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(base))
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.', r == '_', r == '-', r == ':':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

func loadSessionLookupDirs() []string {
	// Config from environment or env-pointed file (for distro-specific overrides).
	// If nothing valid is configured, keep legacy defaults.
	parts := splitSessionDirList(os.Getenv("CFM_CPANEL_SESSION_DIRS"))
	if len(parts) == 0 {
		parts = splitSessionDirList(os.Getenv("CPANEL_SESSION_DIRS"))
	}
	if len(parts) == 0 {
		if filePath := strings.TrimSpace(os.Getenv("CFM_CPANEL_SESSION_DIRS_FILE")); filePath != "" {
			if b, err := os.ReadFile(filePath); err == nil {
				parts = splitSessionDirList(string(b))
			}
		}
	}
	if len(parts) == 0 {
		return append([]string(nil), defaultSessionDirs...)
	}
	return parts
}

func splitSessionDirList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0, 4)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n'
	}) {
		dir := strings.TrimSpace(part)
		if dir == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			continue
		}
		dir = filepath.Clean(dir)
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		out = append(out, dir)
	}
	return out
}

func buildSessionCandidatePaths(userName string, baseDirs []string, maxFiles int) ([]string, int) {
	type candidate struct {
		path    string
		modTime time.Time
	}
	candidates := make([]candidate, 0, maxFiles)
	totalCandidates := 0
	for _, dir := range baseDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), userName+":") {
				continue
			}
			totalCandidates++
			info, err := entry.Info()
			if err != nil {
				continue
			}
			candidates = append(candidates, candidate{
				path:    filepath.Join(dir, entry.Name()),
				modTime: info.ModTime(),
			})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].modTime.After(candidates[j].modTime)
	})
	if maxFiles > 0 && len(candidates) > maxFiles {
		candidates = candidates[:maxFiles]
	}
	paths := make([]string, 0, len(candidates))
	for _, c := range candidates {
		paths = append(paths, c.path)
	}
	return paths, totalCandidates
}

func parseSessionRecord(raw []byte) (string, string, string, error) {
	var row struct {
		User            string `json:"user"`
		CPSecurityToken string `json:"cp_security_token"`
	}
	if err := json.Unmarshal(raw, &row); err == nil {
		return strings.TrimSpace(row.User), strings.TrimSpace(row.CPSecurityToken), "json", nil
	}

	var (
		userName string
		token    string
	)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "user":
			userName = value
		case "cp_security_token":
			token = value
		}
	}
	if userName == "" && token == "" {
		return "", "", "", errors.New("unsupported session format")
	}
	return userName, token, "kv", nil
}

func processIdentity() (int, int, int, int, string, string) {
	uid := os.Getuid()
	euid := os.Geteuid()
	gid := os.Getgid()
	egid := os.Getegid()
	procUser := "unknown"
	procGroup := "unknown"
	if u, err := user.Current(); err == nil {
		if strings.TrimSpace(u.Username) != "" {
			procUser = strings.TrimSpace(u.Username)
		}
		if grp, err := user.LookupGroupId(u.Gid); err == nil && strings.TrimSpace(grp.Name) != "" {
			procGroup = strings.TrimSpace(grp.Name)
		} else if strings.TrimSpace(u.Gid) != "" {
			procGroup = strings.TrimSpace(u.Gid)
		}
	}
	return uid, euid, gid, egid, procUser, procGroup
}

func maskCPSess(cpsess string) string {
	clean := strings.TrimSpace(cpsess)
	n := len(clean)
	if n == 0 {
		return "len=0"
	}
	if n <= 12 {
		return "len=" + strconv.Itoa(n)
	}
	return clean[:8] + "..." + clean[n-4:] + " (len=" + strconv.Itoa(n) + ")"
}

func isSafeSessionComponent(v string) bool {
	if v == "" {
		return false
	}
	if strings.Contains(v, "/") || strings.Contains(v, "\\") || strings.Contains(v, "..") || strings.ContainsRune(v, '\x00') {
		return false
	}
	return safeSessionComponentRE.MatchString(v)
}

func signAssertion(sub, nonce string, secret []byte, now time.Time) (string, error) {
	headJSON := []byte(`{"alg":"HS256","typ":"JWT"}`)
	claims := map[string]interface{}{
		"sub":   sub,
		"aud":   expectedAud,
		"iat":   now.Unix(),
		"exp":   now.Add(2 * time.Minute).Unix(),
		"nonce": nonce,
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	h := base64.RawURLEncoding.EncodeToString(headJSON)
	p := base64.RawURLEncoding.EncodeToString(payloadJSON)
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(h + "." + p))
	s := base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	return h + "." + p + "." + s, nil
}
