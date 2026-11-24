package webdetector

import (
	"bufio"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
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

	// Under-Attack Mode operator override (I1b). UnderAttack is the vhost's
	// current escalation state (true = UNDER_ATTACK, including an operator force);
	// the controls knob toggles it via /api/v1/challenge/vhost/attack. Unlike the
	// Challenge/WAF columns this is a force-on/off override, not an opt-out.
	// UnderAttackToggleable is false when the UNDER_ATTACK detector is globally
	// disabled (there is nothing to override).
	UnderAttack           bool `json:"under_attack"`
	UnderAttackToggleable bool `json:"under_attack_toggleable"`

	// ChallengeRung is the vhost's effective ChallengeV2 tier ("v2" or "")
	// with what decided it (manual / pin / auto) and the automatic source —
	// challengeV2VhostTier, the verify gate's own resolver — so an
	// under-attack row can show it is already strict instead of offering to
	// arm what the node default already armed.
	ChallengeRung        string `json:"challenge_rung,omitempty"`
	ChallengeRungSource  string `json:"challenge_rung_source,omitempty"`
	ChallengeRungTrigger string `json:"challenge_rung_trigger,omitempty"`
	// ChallengeLockdownUntil: the covering manual arm is in LOCKDOWN (no
	// client exemption, vhost_lockdown.go) until then; absent = none.
	ChallengeLockdownUntil *time.Time `json:"challenge_lockdown_until,omitempty"`

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
	in := e.vhostControlInputs()

	// Every host an exclude or override names gets a row, so the owner can
	// toggle it even without recent traffic. The HTTP/3 and ClamAV columns
	// match exact hosts (and "*.suffix" for HTTP/3) only, as their Lua data
	// paths do; see vhostControlRow.
	for _, val := range in.challengeEntries {
		hosts[val] = struct{}{}
	}
	for _, val := range in.wafEntries {
		hosts[val] = struct{}{}
	}
	for _, h := range e.HTTP3OverrideHosts() {
		if hn := normalizeControlHost(h); hn != "" {
			hosts[hn] = struct{}{}
		}
	}
	for h := range in.clamOverride {
		hosts[h] = struct{}{}
	}
	for h := range in.clamModeOverride {
		hosts[h] = struct{}{}
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
		rows = append(rows, e.vhostControlRow(in, host))
	}

	writeJSON(w, http.StatusOK, webdetVhostControlResponse{Rows: rows})
}

// vhostControlInputs is what every row of the controls table is computed
// from, read once per request.
type vhostControlInputs struct {
	// Host values of the challenge excludes and of the WHOLE-WAF excludes
	// (rule-scoped entries leave the WAF on for the host: they suppress
	// specific rule IDs, so they must not flip the WAF column).
	challengeEntries []string
	wafEntries       []string
	// ClamAV per-vhost overrides, EXACT hosts: cfm_clamav.lua keys its
	// override set by exact hostname, so the exclude matcher's subdomain suffix
	// expansion would lie about runtime behaviour.
	clamOverride     map[string]struct{}
	clamModeOverride map[string]struct{}
	clamGlobal       bool
	clamScanDefault  bool
	clamInline       bool
}

func (e *Engine) vhostControlInputs() vhostControlInputs {
	in := vhostControlInputs{
		challengeEntries: hostExcludeValues(e.ChallengeExcludeList()),
		wafEntries:       hostExcludeValues(filterWholeWAFEntries(e.WAFExcludeList())),
		clamOverride:     make(map[string]struct{}),
		clamModeOverride: make(map[string]struct{}),
	}
	for _, val := range hostExcludeValues(e.ClamOverrideList()) {
		in.clamOverride[val] = struct{}{}
	}
	for _, val := range hostExcludeValues(e.ClamModeOverrideList()) {
		in.clamModeOverride[val] = struct{}{}
	}
	in.clamGlobal, in.clamScanDefault = clamScanPolicy()
	in.clamInline = clamInlineDefault()
	return in
}

// vhostControlRow is one host's row of the controls table (and the controls
// block of the vhost profile).
func (e *Engine) vhostControlRow(in vhostControlInputs, host string) webdetVhostControlRow {
	// The challenge and WAF columns follow the decision's own tests
	// (MatchChallenge / MatchWAFRules, scope_hosts included). A value-only
	// match read a tenant's exclude on example.com as covering
	// www.example.com, which is still challenged, and a scoped whole-WAF
	// exclude as switching the WAF off on sub-hosts the edge still guards.
	chEntry, challengeMatched := e.challengeExcludes.FirstChallengeHostMatch(normalizeControlHost(host))
	challengeValue, challengeExact := "", false
	if challengeMatched {
		challengeValue = chEntry.Value
		challengeExact = chEntry.Value == normalizeControlHost(host)
	}
	wafEntry, wafMatched := e.wafExcludes.FirstWAFHostMatch(normalizeControlHost(host))
	wafValue, wafExact := "", false
	if wafMatched {
		wafValue = wafEntry.Value
		wafExact = wafEntry.Value == normalizeControlHost(host)
	}
	// HTTP/3 does NOT use the exclude matcher: its suffix expansion (treat
	// "cdn.example.com" as matching every "*.cdn.example.com") would lie
	// about the runtime behaviour — cfm_h3_config.lua matches only exact
	// hosts and explicit "*.suffix" wildcards. The store's MatchInfo mirrors
	// the Lua matcher exactly. Presence in the store = host is enabled.
	http3Matched, http3Pattern, http3Exact := e.HTTP3OverrideMatchInfo(host)

	// Normalize the lookup key: collectKnownVhosts seeds some hosts
	// (cPanel userdata) un-normalized, and the exclude stores normalize their
	// host internally — the exact clam membership check must too, or a
	// mixed-case/trailing-dot host would miss its own override.
	_, clamPresent := in.clamOverride[normalizeControlHost(host)]
	// XOR: an override flips the vhost relative to the global default.
	clamEnabled := in.clamGlobal && (in.clamScanDefault != clamPresent)
	_, clamModePresent := in.clamModeOverride[normalizeControlHost(host)]
	clamModeInline := clamEnabled && (in.clamInline != clamModePresent)

	// Under-Attack override state (reflects a just-issued force immediately).
	underAttack, _, _ := e.VhostAttackState(host)
	tier := e.challengeV2VhostTier(host)

	return webdetVhostControlRow{
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
		ClamToggleable:          in.clamGlobal, // every clam override is exact
		ClamOverridePresent:     clamPresent,
		ClamModeInline:          clamModeInline,
		ClamModeToggleable:      in.clamGlobal && clamEnabled,
		ClamModeOverridePresent: clamModePresent,
		UnderAttack:             underAttack,
		UnderAttackToggleable:   e.cfg.UnderAttack,
		ChallengeRung:           tier.Rung,
		ChallengeRungSource:     tier.Source,
		ChallengeRungTrigger:    tier.Trigger,
		ChallengeLockdownUntil:  lockdownPtr(e.vhostLockdownUntil(host)),
	}
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
