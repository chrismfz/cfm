package webdetector

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strings"
)

type webdetVhostControlRow struct {
	Host             string `json:"host"`
	ChallengeEnabled bool   `json:"challenge_enabled"`
	WAFEnabled       bool   `json:"waf_enabled"`
}

type webdetVhostControlResponse struct {
	Rows []webdetVhostControlRow `json:"rows"`
}

func (e *Engine) handleWebdetVhosts(w http.ResponseWriter, r *http.Request) {
	filter := parseVhostFilterWithAliases(r)
	hosts := e.collectKnownVhosts()

	challengeExcluded := map[string]bool{}
	for _, row := range e.ChallengeExcludeList() {
		if strings.EqualFold(strings.TrimSpace(row.Type), "host") {
			h := normalizeControlHost(row.Value)
			if h != "" {
				challengeExcluded[h] = true
				hosts[h] = struct{}{}
			}
		}
	}

	wafExcluded := map[string]bool{}
	for _, row := range e.WAFExcludeList() {
		if strings.EqualFold(strings.TrimSpace(row.Type), "host") {
			h := normalizeControlHost(row.Value)
			if h != "" {
				wafExcluded[h] = true
				hosts[h] = struct{}{}
			}
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
		rows = append(rows, webdetVhostControlRow{
			Host:             host,
			ChallengeEnabled: !challengeExcluded[host],
			WAFEnabled:       !wafExcluded[host],
		})
	}

	writeJSON(w, http.StatusOK, webdetVhostControlResponse{Rows: rows})
}

func parseVhostFilterWithAliases(r *http.Request) map[string]struct{} {
	if scope := vhostScopeFromContext(r.Context()); scope != nil {
		return scope
	}

	raw := strings.TrimSpace(r.URL.Query().Get("vhosts"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("vhost"))
	}
	if raw == "" {
		return nil
	}

	m := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		h := normalizeControlHost(part)
		if h != "" {
			m[h] = struct{}{}
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

func normalizeControlHost(v string) string {
	h := strings.ToLower(strings.TrimSpace(v))
	h = strings.TrimSuffix(h, ".")
	return h
}

func (e *Engine) collectKnownVhosts() map[string]struct{} {
	hosts := map[string]struct{}{}

	for _, path := range []string{"/etc/userdatadomains", "/etc/userdomains"} {
		for host := range readHostsFromColonFile(path) {
			hosts[host] = struct{}{}
		}
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

func readHostsFromColonFile(path string) map[string]struct{} {
	out := map[string]struct{}{}
	f, err := os.Open(path)
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
