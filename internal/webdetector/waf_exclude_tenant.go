package webdetector

// waf_exclude_tenant.go: what a SCOPED (cPanel) token may do to the WAF on
// its own sites, and how the operator hears about it.
//
// Three writes, all through POST /api/v1/waf/exclude/add:
//
//   - the switch (type=host, no rule_ids): the WAF off for one of its vhosts.
//     Stored with KeepCritical, so the rules of wafTenantKeptFamilies keep
//     running. No expiry: it is the Vhost controls switch, and stays until
//     switched back.
//   - one rule on a host (type=host, rule_ids=<one id>, ttl=)
//   - one rule on a path (type=path, rule_ids=<one id>, ttl=[, scope_hosts=])
//
// The two rule writes are the "this request is mine, let it through" answer to
// a false positive: ONE rule (no ranges, no groups), never one of
// wafTenantKeptFamilies, and always with an expiry between scopedWAFExcludeMinTTL
// and scopedWAFExcludeMaxTTL: a fix the site owner applies while it is being
// looked at, not a standing hole. A path write is pinned to the token's
// LITERAL vhosts, like a challenge path exclude.
//
// Every scoped write (and remove) is published as a TenantPolicyEvent
// (SetTenantPolicySink), which the detectors wire to the notifier and the
// alert log (internal/detectors/webdetector_register.go).

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// wafTenantKeptFamilies are the WAF reason families a tenant can neither
// exclude by rule nor switch off with its site's WAF switch: a named
// vulnerability being exploited, or a webshell being reached, is never the
// site's own traffic. Decided 2026-11-25 (the operator keeps full control: an
// operator's exclude has no such limit). The edge twin is
// cfm_waf.lua WAF_TENANT_KEPT_REASONS; TestWAFTenantKeptFamilies_LuaParity
// keeps the two equal.
var wafTenantKeptFamilies = map[string]struct{}{
	"WAF_CVE":      {},
	"WAF_WEBSHELL": {},
}

// WAFFamilyKeptForTenant reports whether reason (a WAF reason, or its family)
// belongs to a family a tenant cannot switch off.
func WAFFamilyKeptForTenant(reason string) bool {
	fam, _, _ := strings.Cut(strings.TrimSpace(reason), ":")
	_, ok := wafTenantKeptFamilies[fam]
	return ok
}

const (
	scopedWAFExcludeMinTTL = time.Hour
	scopedWAFExcludeMaxTTL = 7 * 24 * time.Hour
	// adminWAFExcludeMaxTTL bounds an operator's optional ttl= (a typo guard).
	adminWAFExcludeMaxTTL = 366 * 24 * time.Hour
	excludeByScoped       = "scoped"
	// scopedWAFRuleExcludeMax caps the live rule excludes the sites of one
	// scoped token may hold. The edge walks every exclude row for each
	// inspected request, and each write notifies the operator, so the number
	// one account can create is bounded; renewing an existing one stays
	// allowed at the cap.
	scopedWAFRuleExcludeMax = 40
	// scopedWAFPathMaxLen bounds a site owner's path value.
	scopedWAFPathMaxLen = 255
)

// plainExcludeValue: a tenant's WAF path exclude is a literal path (a file,
// or a folder and what is under it), never a glob: what it lets through must
// be readable from the entry itself. No control byte either (the value goes
// into log lines, the history and the notifier), and a bounded length.
func plainExcludeValue(value string) bool {
	if len(value) > scopedWAFPathMaxLen || strings.ContainsAny(value, "*?[]\\") || strings.Contains(value, "..") {
		return false
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// scopedWAFRuleExcludeRoom reports whether a scoped caller with scope may add
// the rule exclude (typ, value, ruleIDs): its sites hold fewer than
// scopedWAFRuleExcludeMax live scoped-written rule excludes, or this very
// entry is among them (a renewal).
func scopedWAFRuleExcludeRoom(entries []excludeEntry, scope map[string]struct{}, typ, value string, ruleIDs []int) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if typ == "path" && !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	want := ruleIDsKey(normalizeRuleIDs(ruleIDs))
	n := 0
	for _, e := range entries {
		if e.By != excludeByScoped || len(e.RuleIDs) == 0 {
			continue
		}
		mine := false
		for _, h := range e.ScopeHosts {
			if _, ok := scope[h]; ok {
				mine = true
				break
			}
		}
		if !mine {
			continue
		}
		if e.Type == typ && e.Value == value && ruleIDsKey(e.RuleIDs) == want {
			return true
		}
		n++
	}
	return n < scopedWAFRuleExcludeMax
}

// parseExcludeTTL reads a ttl= value: a Go duration ("24h", "90m") or whole
// days ("7d"). Empty is (0, nil): no expiry asked.
func parseExcludeTTL(v string) (time.Duration, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 || n > 3660 {
			return 0, fmt.Errorf("invalid ttl %q", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid ttl %q", v)
	}
	return d, nil
}

// scopedWAFRuleExclude checks the rule and the ttl of a scoped rule exclude.
// It returns the HTTP status and message of the refusal, or 0.
func scopedWAFRuleExclude(ruleIDs []int, ttl time.Duration) (int, string) {
	if len(ruleIDs) != 1 {
		return 400, "name exactly one rule (rule_ids=<id>): a site owner's exclude covers one rule at a time"
	}
	rule, ok := WAFRuleByID(ruleIDs[0])
	if !ok {
		return 400, "unknown WAF rule " + strconv.Itoa(ruleIDs[0])
	}
	if WAFFamilyKeptForTenant(rule.ReasonFamily) {
		return 403, fmt.Sprintf("rule %d (%s) cannot be excluded by a site owner; ask the administrator", rule.ID, rule.ReasonFamily)
	}
	if ttl == 0 {
		return 400, "a rule exclude needs an expiry: ttl=24h or ttl=7d"
	}
	if ttl < scopedWAFExcludeMinTTL || ttl > scopedWAFExcludeMaxTTL {
		return 400, "ttl must be between 1h and 7d"
	}
	return 0, ""
}

// TenantPolicyEvent is one change a scoped (cPanel) token made to the
// protection of its own sites.
type TenantPolicyEvent struct {
	Kind         string   // "waf_exclude"
	Action       string   // "add" | "remove"
	Hosts        []string // the vhosts the entry applies to (sorted)
	Type         string   // "host" | "path"
	Value        string
	RuleIDs      []int // empty = the whole WAF (the switch)
	KeepCritical bool
	ExpiresUnix  int64
	Remote       string
}

// Summary is the one-line description used by the log, the history row and
// the notifier.
func (ev TenantPolicyEvent) Summary() string {
	what := "the WAF"
	if len(ev.RuleIDs) == 0 && ev.Action == "add" {
		what += " (CVE and webshell rules stay on)"
	}
	if len(ev.RuleIDs) > 0 {
		ids := make([]string, len(ev.RuleIDs))
		for i, id := range ev.RuleIDs {
			ids[i] = strconv.Itoa(id)
		}
		what = "WAF rule " + strings.Join(ids, ",")
		if r, ok := WAFRuleByID(ev.RuleIDs[0]); ok && len(ev.RuleIDs) == 1 {
			what += " (" + r.ReasonFamily + ")"
		}
	}
	where := strings.Join(ev.Hosts, ", ")
	if ev.Type == "path" {
		where = "path " + ev.Value + " of " + where
	}
	verb := "switched off"
	if ev.Action == "remove" {
		verb = "switched back on"
	}
	s := "site owner " + verb + " " + what + " on " + where
	if ev.Action == "add" && ev.ExpiresUnix > 0 {
		s += " until " + time.Unix(ev.ExpiresUnix, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	return s
}

var (
	tenantPolicySinkMu sync.RWMutex
	tenantPolicySink   func(TenantPolicyEvent)
)

// SetTenantPolicySink sets the ONE receiver of every change a scoped token
// makes to its sites' protection (nil = none). Replace, not append: the
// detectors set it again on each config reload, which builds a new Engine.
// The sink runs on the API request's goroutine: keep it cheap.
func SetTenantPolicySink(fn func(TenantPolicyEvent)) {
	tenantPolicySinkMu.Lock()
	tenantPolicySink = fn
	tenantPolicySinkMu.Unlock()
}

func publishTenantPolicyEvent(ev TenantPolicyEvent) {
	tenantPolicySinkMu.RLock()
	fn := tenantPolicySink
	tenantPolicySinkMu.RUnlock()
	if fn != nil {
		fn(ev)
	}
}

// recordTenantWAFExclude logs a scoped WAF exclude change, writes its history
// row (one per host, so each site's own history shows it) and publishes it.
func (e *Engine) recordTenantWAFExclude(ev TenantPolicyEvent) {
	sort.Strings(ev.Hosts)
	ev.Kind = "waf_exclude"
	if e != nil {
		payload := map[string]interface{}{
			"actor": excludeByScoped, "action": ev.Action, "type": ev.Type, "value": ev.Value,
		}
		if len(ev.RuleIDs) > 0 {
			payload["rule_ids"] = ev.RuleIDs
		}
		if ev.KeepCritical {
			payload["keep_critical"] = true
		}
		if ev.ExpiresUnix > 0 {
			payload["expires_unix"] = ev.ExpiresUnix
		}
		for i, h := range ev.Hosts {
			if i == 8 {
				break // an account with many vhosts: the notifier names them all
			}
			e.appendHistory(HistoryEvent{
				TsUnix: time.Now().Unix(), Type: "waf_exclude_change", Host: h,
				Mode: excludeByScoped, Reason: ev.Summary(), Payload: payload,
			})
		}
	}
	publishTenantPolicyEvent(ev)
}
