package webdetector

import (
	"bufio"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type webdetVhostControlRow struct {
	Host                    string `json:"host"`
	ChallengeEnabled        bool   `json:"challenge_enabled"`
	WAFEnabled              bool   `json:"waf_enabled"`
	ChallengeToggleable     bool   `json:"challenge_toggleable"`
	WAFToggleable           bool   `json:"waf_toggleable"`
	ChallengeMatchedExclude string `json:"challenge_matched_exclude,omitempty"`
	WAFMatchedExclude       string `json:"waf_matched_exclude,omitempty"`
}

type webdetVhostControlResponse struct {
	Rows []webdetVhostControlRow `json:"rows"`
}

func (e *Engine) handleWebdetVhosts(w http.ResponseWriter, r *http.Request) {
	if err := validateScopedVhostQuery(r, "vhosts", "vhost"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "vhost not in scope"})
		return
	}

	filter := parseVhostFilterWithAliases(r)
	hosts := e.collectKnownVhosts()

	challengeEntries := hostExcludeValues(e.ChallengeExcludeList())
	for _, val := range challengeEntries {
		h := normalizeControlHost(val)
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	wafEntries := hostExcludeValues(e.WAFExcludeList())
	for _, val := range wafEntries {
		h := normalizeControlHost(val)
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	list := make([]string, 0, len(hosts))
	for host := range hosts {
		if vhostAllowed(host, filter) {
			list = append(list, host)
		}
	}
	sort.Strings(list)

	rows := make([]webdetVhostControlRow, 0, len(list))
	for _, host := range list {
		challengeMatched, challengeValue, challengeExact := matchHostExclude(challengeEntries, host)
		wafMatched, wafValue, wafExact := matchHostExclude(wafEntries, host)

		rows = append(rows, webdetVhostControlRow{
			Host:                    host,
			ChallengeEnabled:        !challengeMatched,
			WAFEnabled:              !wafMatched,
			ChallengeToggleable:     !challengeMatched || challengeExact,
			WAFToggleable:           !wafMatched || wafExact,
			ChallengeMatchedExclude: challengeValue,
			WAFMatchedExclude:       wafValue,
		})
	}

	writeJSON(w, http.StatusOK, webdetVhostControlResponse{Rows: rows})
}

func hostExcludeValues(entries []excludeEntry) []string {
	out := make([]string, 0, len(entries))
	for _, row := range entries {
		if strings.EqualFold(strings.TrimSpace(row.Type), "host") {
			v := normalizeControlHost(row.Value)
			if v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

func matchHostExclude(excludes []string, host string) (matched bool, matchedValue string, exact bool) {
	host = normalizeControlHost(host)
	if host == "" {
		return false, "", false
	}
	for _, ex := range excludes {
		ok, err := filepath.Match(ex, host)
		if err == nil && ok {
			return true, ex, ex == host
		}
		if !strings.ContainsAny(ex, "*?") {
			if host == ex {
				return true, ex, true
			}
			if strings.HasSuffix(host, "."+ex) {
				return true, ex, false
			}
		}
	}
	return false, "", false
}

func parseVhostFilterWithAliases(r *http.Request) map[string]struct{} {
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		return scope
	}

	m := parseQueryVhostSet(r, "vhosts", "vhost")
	if len(m) == 0 {
		return nil
	}

	normalized := make(map[string]struct{}, len(m))
	for host := range m {
		h := normalizeControlHost(host)
		if h != "" {
			normalized[h] = struct{}{}
		}
	}
	if len(normalized) == 0 {
		return nil
	}

	return normalized
}

func normalizeControlHost(v string) string {
	h := strings.ToLower(strings.TrimSpace(v))
	h = strings.TrimSuffix(h, ".")
	return h
}

func (e *Engine) collectKnownVhosts() map[string]struct{} {
	hosts := map[string]struct{}{}

	for host := range readHostsFromUserDataDomains() {
		hosts[host] = struct{}{}
	}
	for host := range readHostsFromUserDomains() {
		hosts[host] = struct{}{}
	}

	for _, row := range e.TopShort(5000) {
		h := normalizeControlHost(row.Host)
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	if e.chalAPI != nil {
		for _, row := range e.chalAPI.ListVhosts("all", "all", 5000) {
			h := normalizeControlHost(row.Host)
			if h != "" {
				hosts[h] = struct{}{}
			}
		}
	}

	return hosts
}

func readHostsFromUserDataDomains() map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open("/etc/userdatadomains")
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		left, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		h := normalizeControlHost(left)
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

func readHostsFromUserDomains() map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open("/etc/userdomains")
	if err != nil {
		return out
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		left, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		h := normalizeControlHost(left)
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}
