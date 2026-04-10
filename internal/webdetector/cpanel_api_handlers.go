// internal/webdetector/cpanel_api_handlers.go
//
// GET /api/v1/cpanel/user-info?user=X
//
// Admin-only endpoint used by the cPanel plugin (bootstrap.php) to
// discover the domains and DB users belonging to a cPanel account.
// Called server-side from the plugin via loopback curl with an actor assertion.
// Runs as root inside cfm so it can read all cPanel metadata files.
package webdetector

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type cpanelUserInfo struct {
	User      string   `json:"user"`
	Domains   []string `json:"domains"`
	DBUsers   []string `json:"db_users"`
	Databases []string `json:"databases"`
}

// RegisterCpanelHTTP wires the cPanel helper endpoints onto the mux.
// Call from RegisterHTTP or from apiserver after auth middleware is in place.
func (e *Engine) RegisterCpanelHTTP(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/cpanel/user-info", e.handleCpanelUserInfo)
}

func (e *Engine) handleCpanelUserInfo(w http.ResponseWriter, r *http.Request) {
	tokenUser, authStatus, authErr, authDebug := authorizePluginAssertion(r)
	if authErr != nil {
		if authDebug != "" && cfmDebugEnabledForRequest(r) {
			writeJSON(w, authStatus, map[string]string{"error": authErr.Error(), "debug": authDebug})
			return
		}
		writeJSON(w, authStatus, map[string]string{"error": authErr.Error()})
		return
	}

	requestedUser := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if requestedUser != "" && requestedUser != tokenUser {
		if cfmDebugEnabledForRequest(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "actor mismatch",
				"debug": "actor_mismatch",
			})
			return
		}
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "actor mismatch"})
		return
	}
	user := tokenUser

	info, dataStatus, dataErr, dataDebug := loadUserMetadata(user)
	if dataErr != nil {
		if dataDebug != "" && cfmDebugEnabledForRequest(r) {
			writeJSON(w, dataStatus, map[string]string{
				"error": dataErr.Error(),
				"debug": dataDebug,
			})
			return
		}
		writeJSON(w, dataStatus, map[string]string{"error": dataErr.Error()})
		return
	}

	writeJSON(w, http.StatusOK, info)
}

func loadUserMetadata(user string) (cpanelUserInfo, int, error, string) {
	// Validate: must be a real cPanel user (file exists under /var/cpanel/users/).
	if !cpanelUserExists(user) {
		return cpanelUserInfo{}, http.StatusNotFound, fmt.Errorf("%s", "user not found"), "data-phase: cpanel user metadata file does not exist"
	}

	info := cpanelUserInfo{User: user}
	// Metadata phase intentionally reads from filesystem only:
	// /etc/userdatadomains, /etc/userdomains, /var/cpanel/userdata/<user>, /var/cpanel/databases/<user>.json.
	info.Domains = cpanelDomainsForUser(user)
	info.DBUsers, info.Databases = cpanelDBInfoForUser(user)
	return info, http.StatusOK, nil, ""
}

type pluginActorClaims struct {
	Sub   string      `json:"sub"`
	Aud   interface{} `json:"aud"`
	Iat   int64       `json:"iat"`
	Exp   int64       `json:"exp"`
	Nonce string      `json:"nonce"`
}

var pluginAssertionReplayCache sync.Map // nonce -> expUnix

func authorizePluginAssertion(r *http.Request) (string, int, error, string) {
	raw := strings.TrimSpace(r.Header.Get("X-CFM-Actor-Assertion"))
	if raw == "" {
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(auth, "Bearer ") {
			raw = strings.TrimSpace(auth[7:])
		}
	}
	if raw == "" {
		return "", http.StatusUnauthorized, fmt.Errorf("%s", "authorization required"), "token_missing"
	}
	secret := strings.TrimSpace(os.Getenv("CFM_CPANEL_ASSERTION_SECRET"))
	if secret == "" {
		secret = strings.TrimSpace(os.Getenv("CPANEL_PLUGIN_ASSERTION_SECRET"))
	}
	if secret == "" {
		return "", http.StatusUnauthorized, fmt.Errorf("%s", "authorization required"), "token_invalid_signature"
	}
	claims, reason := verifyPluginAssertion(raw, []byte(secret), time.Now().UTC())
	if reason != "" {
		switch reason {
		case "token_expired":
			return "", http.StatusUnauthorized, fmt.Errorf("%s", "authorization required"), reason
		case "token_replay":
			return "", http.StatusUnauthorized, fmt.Errorf("%s", "authorization required"), reason
		case "actor_mismatch":
			return "", http.StatusForbidden, fmt.Errorf("%s", "actor mismatch"), reason
		default:
			return "", http.StatusUnauthorized, fmt.Errorf("%s", "authorization required"), "token_invalid_signature"
		}
	}
	return claims.Sub, http.StatusOK, nil, ""
}

func verifyPluginAssertion(raw string, secret []byte, now time.Time) (pluginActorClaims, string) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	payloadMAC := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	m := hmac.New(sha256.New, secret)
	m.Write(payloadMAC)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	var claims pluginActorClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	claims.Sub = strings.ToLower(strings.TrimSpace(claims.Sub))
	if !isValidCpanelUsername(claims.Sub) {
		return pluginActorClaims{}, "actor_mismatch"
	}
	if !pluginAssertionAudienceOK(claims.Aud) {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	if claims.Iat <= 0 || claims.Exp <= 0 || claims.Exp <= claims.Iat {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	nowUnix := now.Unix()
	if nowUnix < claims.Iat-30 || nowUnix >= claims.Exp {
		return pluginActorClaims{}, "token_expired"
	}
	if claims.Nonce == "" || len(claims.Nonce) > 160 {
		return pluginActorClaims{}, "token_invalid_signature"
	}
	if isReplayNonce(claims.Nonce, claims.Exp, nowUnix) {
		return pluginActorClaims{}, "token_replay"
	}
	return claims, ""
}

func pluginAssertionAudienceOK(aud interface{}) bool {
	const expected = "cfm-plugin-cpanel"
	switch t := aud.(type) {
	case string:
		return strings.TrimSpace(t) == expected
	case []interface{}:
		for _, v := range t {
			s, ok := v.(string)
			if ok && strings.TrimSpace(s) == expected {
				return true
			}
		}
	}
	return false
}

func isReplayNonce(nonce string, expUnix, nowUnix int64) bool {
	pluginAssertionReplayCache.Range(func(k, v interface{}) bool {
		key, okK := k.(string)
		exp, okV := v.(int64)
		if !okK || !okV || exp <= nowUnix {
			pluginAssertionReplayCache.Delete(key)
		}
		return true
	})
	if _, exists := pluginAssertionReplayCache.LoadOrStore(nonce, expUnix); exists {
		return true
	}
	return false
}

func cfmDebugEnabledForRequest(r *http.Request) bool {
	if r == nil {
		return true
	}
	raw := strings.ToLower(strings.TrimSpace(r.Header.Get("X-CFM-Debug")))
	switch raw {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// cpanelUserExists checks /var/cpanel/users/<user> exists.
func cpanelUserExists(user string) bool {
	if !isValidCpanelUsername(user) {
		return false
	}
	_, err := os.Stat("/var/cpanel/users/" + user)
	return err == nil
}

// isValidCpanelUsername rejects anything that isn't a safe cPanel username.
var cpanelUsernameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_]{0,15}$`)

func isValidCpanelUsername(user string) bool {
	return cpanelUsernameRE.MatchString(user)
}

// cpanelDomainsForUser reads /etc/userdatadomains (fast, root-readable).
// Falls back to /etc/userdomains then /var/cpanel/userdata/<user>/.
func cpanelDomainsForUser(user string) []string {
	domains := parseUserDataDomains(user)
	if len(domains) > 0 {
		return domains
	}
	domains = parseUserDomains(user)
	if len(domains) > 0 {
		return domains
	}
	return scanUserdataDir(user)
}

func parseUserDataDomains(user string) []string {
	f, err := os.Open("/etc/userdatadomains")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		// format: domain.tld: cpaneluser==role==...
		colon := strings.Index(line, ":")
		domain := strings.ToLower(strings.TrimSpace(line[:colon]))
		rest := strings.TrimSpace(line[colon+1:])
		parts := strings.SplitN(rest, "==", 2)
		if len(parts) == 0 {
			continue
		}
		lineUser := strings.ToLower(strings.TrimSpace(parts[0]))
		if lineUser != user {
			continue
		}
		if domain != "" && !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out
}

func parseUserDomains(user string) []string {
	f, err := os.Open("/etc/userdomains")
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		lineUser := strings.ToLower(strings.TrimSpace(parts[1]))
		if lineUser != user || domain == "" {
			continue
		}
		if !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out
}

func scanUserdataDir(user string) []string {
	dir := "/var/cpanel/userdata/" + user
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	skip := map[string]bool{
		"main": true, "cache": true, "userdata.cache": true,
		"cache.json": true, "nginx-cache.json": true,
	}
	skipSuffixes := []string{"_ssl", "_SSL", ".cache", ".json", ".tmp", ".bak"}

	var out []string
	seen := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if skip[name] {
			continue
		}
		bad := false
		for _, s := range skipSuffixes {
			if strings.HasSuffix(name, s) {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		domain := strings.ToLower(name)
		if strings.Contains(domain, ".") && !seen[domain] {
			seen[domain] = true
			out = append(out, domain)
		}
	}
	sort.Strings(out)
	return out
}

// cpanelDBInfoForUser reads /var/cpanel/databases/<user>.json.
func cpanelDBInfoForUser(user string) (dbUsers []string, databases []string) {
	path := "/var/cpanel/databases/" + user + ".json"
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}

	var root struct {
		MYSQL struct {
			DBs     map[string]interface{} `json:"dbs"`
			DBUsers map[string]interface{} `json:"dbusers"`
		} `json:"MYSQL"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, nil
	}

	seenU := map[string]bool{}
	seenD := map[string]bool{}

	for dbUser := range root.MYSQL.DBUsers {
		// Skip cPanel internal session users (cpses_*)
		if strings.HasPrefix(dbUser, "cpses_") {
			continue
		}
		if !seenU[dbUser] {
			seenU[dbUser] = true
			dbUsers = append(dbUsers, dbUser)
		}
	}
	for db := range root.MYSQL.DBs {
		if !seenD[db] {
			seenD[db] = true
			databases = append(databases, db)
		}
	}

	sort.Strings(dbUsers)
	sort.Strings(databases)
	return
}
