// internal/webdetector/cpanel_api_handlers.go
//
// GET /api/v1/cpanel/user-info?user=X
//
// Admin-only endpoint used by the cPanel plugin (bootstrap.php) to
// discover the domains and DB users belonging to a cPanel account.
// Called server-side from the plugin via loopback curl with AUTH_TOKEN.
// Runs as root inside cfm so it can read all cPanel metadata files.
package webdetector

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
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
	// Admin-only — scoped tokens must not access this.
	if !IsAdminRequest(r) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return
	}

	user := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("user")))
	if user == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user parameter required"})
		return
	}

	// Validate: must be a real cPanel user (file exists under /var/cpanel/users/).
	if !cpanelUserExists(user) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}

	info := cpanelUserInfo{User: user}
	info.Domains = cpanelDomainsForUser(user)
	info.DBUsers, info.Databases = cpanelDBInfoForUser(user)

	writeJSON(w, http.StatusOK, info)
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
