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
	HTTP3Enabled            bool   `json:"http3_enabled"`
	ChallengeToggleable     bool   `json:"challenge_toggleable"`
	WAFToggleable           bool   `json:"waf_toggleable"`
	HTTP3Toggleable         bool   `json:"http3_toggleable"`
	ChallengeMatchedExclude string `json:"challenge_matched_exclude,omitempty"`
	WAFMatchedExclude       string `json:"waf_matched_exclude,omitempty"`
	HTTP3MatchedOptIn       string `json:"http3_matched_optin,omitempty"`

	// ClamAV upload-scan (async, notify-only). Effective state is
	// globallyEnabled && (scanDefault XOR override). ClamEnabled is that
	// resolved decision; ClamOverridePresent says an EXACT per-vhost override
	// exists (so the UI toggle knows add-vs-remove — flipping membership always
	// flips the resolved state, whatever the global default); ClamToggleable is
	// false only when ClamAV is globally off.
	ClamEnabled         bool `json:"clam_enabled"`
	ClamToggleable      bool `json:"clam_toggleable"`
	ClamOverridePresent bool `json:"clam_override_present"`

	// ClamAV scan MODE (async vs inline). Resolved the same XOR way against
	// the global CLAM_SCAN_MODE and the separate mode-override store. Mode is
	// meaningless for a vhost that isn't scanned, so ClamModeToggleable is
	// clamGlobal && ClamEnabled.
	ClamModeInline          bool `json:"clam_mode_inline"`
	ClamModeToggleable      bool `json:"clam_mode_toggleable"`
	ClamModeOverridePresent bool `json:"clam_mode_override_present"`
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

	// Only whole-WAF excludes (RuleIDs empty) toggle the WAFEnabled flag.
	// Rule-scoped excludes still leave the WAF active for that host — they
	// just suppress specific rule IDs — so they must not flip this toggle.
	wafEntries := hostExcludeValues(filterWholeWAFEntries(e.WAFExcludeList()))
	for _, val := range wafEntries {
		h := normalizeControlHost(val)
		if h != "" {
			hosts[h] = struct{}{}
		}
	}

	// HTTP/3 opt-in list. Opposite semantics from WAF/Challenge:
	// presence in the store = host is enabled. We still surface every
	// opt-in host as a UI row so the owner can toggle it off, even if
	// the host doesn't appear in cPanel userdata or recent traffic.
	//
	// NOTE: we deliberately do NOT use matchHostExclude here. That
	// helper's suffix-expansion semantics (treat "cdn.example.com" as
	// matching every "*.cdn.example.com") would lie about the runtime
	// behavior — the Lua data path in cfm_h3_config.lua matches only
	// exact hosts and explicit "*.suffix" wildcards. Use the store's
	// MatchInfo, which mirrors the Lua matcher exactly.
	for _, h := range e.HTTP3OverrideHosts() {
		hn := normalizeControlHost(h)
		if hn != "" {
			hosts[hn] = struct{}{}
		}
	}

	// ClamAV per-vhost override set. Like HTTP/3 (and unlike the WAF/Challenge
	// columns) we match EXACT hosts only — cfm_clamav.lua keys its override set
	// by exact hostname, so matchHostExclude's suffix expansion would lie about
	// runtime behaviour. Surface every override host as a row so the owner can
	// toggle it even without recent traffic.
	clamOverride := make(map[string]struct{})
	for _, val := range hostExcludeValues(e.ClamOverrideList()) {
		if h := normalizeControlHost(val); h != "" {
			clamOverride[h] = struct{}{}
			hosts[h] = struct{}{}
		}
	}
	clamModeOverride := make(map[string]struct{})
	for _, val := range hostExcludeValues(e.ClamModeOverrideList()) {
		if h := normalizeControlHost(val); h != "" {
			clamModeOverride[h] = struct{}{}
			hosts[h] = struct{}{}
		}
	}
	clamGlobal, clamScanDefault := clamScanPolicy()
	clamInline := clamInlineDefault()

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
		http3Matched, http3Pattern, http3Exact := e.HTTP3OverrideMatchInfo(host)

		// Normalize the lookup key: collectKnownVhosts seeds some hosts
		// (cPanel userdata) un-normalized, and matchHostExclude normalizes its
		// host internally — the exact clam membership check must too, or a
		// mixed-case/trailing-dot host would miss its own override.
		_, clamPresent := clamOverride[normalizeControlHost(host)]
		// XOR: an override flips the vhost relative to the global default.
		clamEnabled := clamGlobal && (clamScanDefault != clamPresent)
		_, clamModePresent := clamModeOverride[normalizeControlHost(host)]
		clamModeInline := clamEnabled && (clamInline != clamModePresent)

		rows = append(rows, webdetVhostControlRow{
			Host:                    host,
			ChallengeEnabled:        !challengeMatched,
			WAFEnabled:              !wafMatched,
			HTTP3Enabled:            http3Matched,
			ChallengeToggleable:     !challengeMatched || challengeExact,
			WAFToggleable:           !wafMatched || wafExact,
			HTTP3Toggleable:         !http3Matched || http3Exact,
			ChallengeMatchedExclude: challengeValue,
			WAFMatchedExclude:       wafValue,
			HTTP3MatchedOptIn:       http3Pattern,
			ClamEnabled:             clamEnabled,
			ClamToggleable:          clamGlobal, // every clam override is exact
			ClamOverridePresent:     clamPresent,
			ClamModeInline:          clamModeInline,
			ClamModeToggleable:      clamGlobal && clamEnabled,
			ClamModeOverridePresent: clamModePresent,
		})
	}

	writeJSON(w, http.StatusOK, webdetVhostControlResponse{Rows: rows})
}

// filterWholeWAFEntries returns only entries that exclude the whole WAF
// (RuleIDs empty). Rule-scoped entries are dropped — they don't disable the
// WAF for the host, they just suppress specific rule IDs.
func filterWholeWAFEntries(entries []excludeEntry) []excludeEntry {
	out := make([]excludeEntry, 0, len(entries))
	for _, e := range entries {
		if len(e.RuleIDs) == 0 {
			out = append(out, e)
		}
	}
	return out
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
