package webdetector

import (
	"net/http"
)

// handleWAFRules returns the canonical cfm_waf rule registry: stable IDs,
// CFG keys, semantic group, and reason family. Used by:
//   - the panel (rule glossary in the WAF page; multi-select source for the
//     planned per-vhost per-rule exclusion UI in PR B)
//   - `cfm webtop waf rules` CLI
//   - PR B's CLI/API to validate operator-supplied --rule IDs
//
// GET /api/v1/waf/rules
//
// Response: { "rules": [ {id, name, group, group_name, reason_family,
//                         default_mode}, ... ], "groups": { "1": "path", ... } }
func (e *Engine) handleWAFRules(w http.ResponseWriter, r *http.Request) {
	if !RequireScopedOrAdmin(w, r) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	groups := make(map[string]string, len(wafRuleGroupNames))
	for digit, name := range wafRuleGroupNames {
		groups[itoa(digit)] = name
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"rules":  WAFRules(),
		"groups": groups,
	})
}

// itoa avoids pulling strconv into this small handler when we only need
// single-digit conversion. Kept tiny for readability.
func itoa(n int) string {
	if n >= 0 && n <= 9 {
		return string(rune('0' + n))
	}
	// Fall back to a manual conversion for >9 (not currently used; reserved
	// for the rare case future groups exceed 9).
	if n < 0 {
		return "-" + itoa(-n)
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
