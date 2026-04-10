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
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

const (
	defaultSockPath = "/var/run/cfm-auth.sock"
	expectedAud     = "cfm-plugin-cpanel"
)

var (
	cpsessRE               = regexp.MustCompile(`^/cpsess[0-9A-Za-z]{8,128}$`)
	safeSessionComponentRE = regexp.MustCompile(`^[a-z0-9._-]+$`)
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
	userName, reason := validateCpanelRequest(req, time.Now().UTC())
	if reason != "" {
		cpsessPrefix := strings.TrimSpace(req.CPSess)
		if len(cpsessPrefix) > 18 {
			cpsessPrefix = cpsessPrefix[:18] + "..."
		}
		logging.Logf("[panel-auth] issue denied panel=%s user=%s reason=%s cpsess_prefix=%q ts=%d nonce_len=%d",
			strings.TrimSpace(req.Panel), strings.TrimSpace(req.User), reason, cpsessPrefix, req.TS, len(strings.TrimSpace(req.Nonce)))
		writeIssue(w, http.StatusUnauthorized, issueResp{Error: "authorization required", Reason: reason})
		return
	}
	secret := strings.TrimSpace(os.Getenv("CFM_CPANEL_ASSERTION_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("CPANEL_PLUGIN_ASSERTION_SECRET"))
	}
	if secret == "" {
		logging.Logf("[panel-auth] issue denied panel=%s user=%s reason=secret_missing", strings.TrimSpace(req.Panel), userName)
		writeIssue(w, http.StatusUnauthorized, issueResp{Error: "authorization required", Reason: "secret_missing"})
		return
	}
	assertion, err := signAssertion(userName, req.Nonce, []byte(secret), time.Now().UTC())
	if err != nil {
		logging.Logf("[panel-auth] issue failed panel=%s user=%s reason=issue_failed err=%v", strings.TrimSpace(req.Panel), userName, err)
		writeIssue(w, http.StatusInternalServerError, issueResp{Error: "internal error", Reason: "issue_failed"})
		return
	}
	logging.Logf("[panel-auth] issue ok panel=%s user=%s", strings.TrimSpace(req.Panel), userName)
	writeIssue(w, http.StatusOK, issueResp{Assertion: assertion})
}

func writeIssue(w http.ResponseWriter, code int, resp issueResp) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(resp)
}

func validateCpanelRequest(req issueReq, now time.Time) (string, string) {
	if !strings.EqualFold(strings.TrimSpace(req.Panel), "cpanel") {
		return "", "panel_unsupported"
	}
	userName := strings.ToLower(strings.TrimSpace(req.User))
	if userName == "" {
		return "", "token_missing"
	}
	cpsess := strings.TrimSpace(req.CPSess)
	if !cpsessRE.MatchString(cpsess) {
		return "", "token_malformed"
	}
	if req.TS == 0 || req.Nonce == "" {
		return "", "token_missing"
	}
	nowUnix := now.Unix()
	if req.TS < nowUnix-15 || req.TS > nowUnix+15 {
		return "", "token_expired"
	}
	if _, exists := replay.LoadOrStore(req.Nonce, nowUnix+60); exists {
		return "", "token_replay"
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
	if !validateSessionFile(userName, sid, cpsess) {
		return "", "session_not_found"
	}
	return userName, ""
}

func validateSessionFile(userName, sid, cpsess string) bool {
	if !isSafeSessionComponent(userName) || !isSafeSessionComponent(sid) {
		return false
	}
	paths := []string{
		filepath.Join("/var/cpanel/sessions/cache", userName+":"+sid),
		filepath.Join("/var/cpanel/sessions/raw", userName+":"+sid),
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var row struct {
			User            string `json:"user"`
			CPSecurityToken string `json:"cp_security_token"`
		}
		if err := json.Unmarshal(b, &row); err != nil {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(row.User), userName) && strings.TrimSpace(row.CPSecurityToken) == cpsess {
			return true
		}
	}
	return false
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
