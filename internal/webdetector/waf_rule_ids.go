// Package webdetector — Go-side mirror of the cfm_waf RULE_IDS table.
//
// Source of truth lives in configs/lua/cfm_waf.lua (the RULE_IDS local table).
// Drift between Lua and Go is caught by TestWAFRuleIDs_LuaParity in
// waf_rule_ids_test.go, which parses cfm_waf.lua at test time.
//
// Stable numeric IDs grouped by first digit:
//   1xx path / traversal
//   2xx client identity (UA)
//   3xx injection (SQLi, XSS, RCE, b64, deserialization, XXE, shellshock, …)
//   4xx upload / malware / obfuscation
//   5xx auth abuse / brute force
//   6xx header / protocol anomaly
//   7xx SSRF / external interaction
//   8xx info disclosure / debug
//   9xx reserved (behavioural rules)
//   10xxx named-vulnerability (CVE) detectors — see WAF_CVE_PLAN.md (the 9xx
//         band is too small for long-term CVE coverage). rule_log4shell keeps
//         its historical 328; new CVE rules use 10000+.
//
// NEVER renumber an existing ID — operators reference these in per-vhost
// exclusions, dashboards, and tickets.

package webdetector

import "sort"

// WAFRule describes one cfm_waf rule entry exposed to operators.
type WAFRule struct {
	ID            int    `json:"id"`             // stable numeric handle
	Name          string `json:"name"`           // CFG key, e.g. "rule_traversal"
	Group         int    `json:"group"`          // ID / 100, e.g. 3 for the injection family
	GroupName     string `json:"group_name"`     // "injection", "upload", …
	ReasonFamily  string `json:"reason_family"`  // canonical WAF_* prefix the rule emits
	DefaultMode   string `json:"default_mode"`   // built-in default mode in Lua CFG (informational)
}

// wafRuleIDs is the in-process registry. Keep entries sorted by ID — the
// /api/v1/waf/rules endpoint and `cfm webtop waf rules` CLI both rely on
// stable iteration order.
var wafRuleIDs = []WAFRule{
	// 1xx path / traversal
	{ID: 101, Name: "rule_traversal", ReasonFamily: "WAF_TRAVERSAL", DefaultMode: "logonly"},
	{ID: 102, Name: "rule_long_path_segment", ReasonFamily: "WAF_LONG_PATH", DefaultMode: "logonly"},

	// 2xx client identity
	{ID: 201, Name: "rule_bad_ua", ReasonFamily: "WAF_BAD_UA", DefaultMode: "challenge"},

	// 3xx injection
	{ID: 301, Name: "rule_sqli", ReasonFamily: "WAF_SQLI", DefaultMode: "block"},
	{ID: 309, Name: "rule_sqli_blind_lexical", ReasonFamily: "WAF_SQLI_LEXICAL", DefaultMode: "challenge"},
	{ID: 319, Name: "rule_sqli_union_variant", ReasonFamily: "WAF_SQLI_UNION_VARIANT", DefaultMode: "logonly"},
	{ID: 318, Name: "rule_superglobal_override", ReasonFamily: "WAF_SUPERGLOBAL", DefaultMode: "logonly"},
	{ID: 302, Name: "rule_xss", ReasonFamily: "WAF_XSS", DefaultMode: "challenge"},
	{ID: 303, Name: "rule_js_proto", ReasonFamily: "WAF_JS_PROTO", DefaultMode: "challenge"},
	{ID: 304, Name: "rule_b64_injection", ReasonFamily: "WAF_B64_INJECT", DefaultMode: "challenge"},
	{ID: 305, Name: "rule_php_wrappers", ReasonFamily: "WAF_PHP_WRAPPER", DefaultMode: "challenge"},
	{ID: 306, Name: "rule_serialize", ReasonFamily: "WAF_SERIALIZE", DefaultMode: "challenge"},
	{ID: 307, Name: "rule_xxe", ReasonFamily: "WAF_XXE", DefaultMode: "challenge"},
	{ID: 308, Name: "rule_shellshock", ReasonFamily: "WAF_SHELLSHOCK", DefaultMode: "challenge"},
	{ID: 310, Name: "rule_cmd_params", ReasonFamily: "WAF_CMD_PARAM", DefaultMode: "challenge"},
	{ID: 311, Name: "rule_cmd_payload", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 312, Name: "rule_cmd_payload_semi_cmd", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 313, Name: "rule_cmd_payload_pipe_wget", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 314, Name: "rule_cmd_payload_pipe_curl", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 315, Name: "rule_cmd_payload_pipe_bash", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 316, Name: "rule_cmd_payload_pipe_sh", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 317, Name: "rule_cmd_payload_backtick", ReasonFamily: "WAF_CMD_PAYLOAD", DefaultMode: "challenge"},
	{ID: 320, Name: "rule_rce", ReasonFamily: "WAF_RCE", DefaultMode: "block"},
	{ID: 321, Name: "rule_proxy_header_sqli", ReasonFamily: "WAF_PROXY_HDR", DefaultMode: "challenge"},
	{ID: 322, Name: "rule_reverse_shell", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 323, Name: "rule_persistence", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 324, Name: "rule_rootkit_artifacts", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 325, Name: "rule_lolbin", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 326, Name: "rule_java_deserialize", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 327, Name: "rule_coinminer", ReasonFamily: "WAF_RCE", DefaultMode: "logonly"},
	{ID: 328, Name: "rule_log4shell", ReasonFamily: "WAF_CVE", DefaultMode: "logonly"},

	// 4xx upload / malware
	{ID: 401, Name: "rule_upload_filename", ReasonFamily: "WAF_UPLOAD_FNAME", DefaultMode: "block"},
	{ID: 402, Name: "rule_upload_content", ReasonFamily: "WAF_UPLOAD_CONTENT", DefaultMode: "block"},
	{ID: 403, Name: "rule_upload_obfuscation", ReasonFamily: "WAF_UPLOAD_OBFUSCATION", DefaultMode: "challenge"},
	{ID: 404, Name: "rule_php_webshell_body", ReasonFamily: "WAF_PHP_WEBSHELL_BODY", DefaultMode: "challenge"},
	{ID: 405, Name: "rule_script_obfuscation", ReasonFamily: "WAF_SCRIPT_OBFUSCATION", DefaultMode: "challenge"},
	{ID: 410, Name: "rule_webshell_path", ReasonFamily: "WAF_WEBSHELL", DefaultMode: "challenge"},
	{ID: 411, Name: "rule_webshell_ping", ReasonFamily: "WAF_WEBSHELL", DefaultMode: "challenge"},
	{ID: 412, Name: "rule_polyglot_upload", ReasonFamily: "WAF_UPLOAD_CONTENT", DefaultMode: "challenge"},
	{ID: 413, Name: "rule_webshell_path_known", ReasonFamily: "WAF_WEBSHELL", DefaultMode: "block"},
	// 414: PHP webshell hidden inside an uploaded .zip (ZIP entry-name scan).
	// Shares the WAF_UPLOAD_FNAME family with 401 so it inherits that family's
	// block + waf_security autoblock intent. Scoped to Joomla asset uploads
	// (option=com_ + task=asset.upload*), where a php-bearing zip is never
	// legitimate — so it ships at `block`.
	{ID: 414, Name: "rule_upload_archive_php", ReasonFamily: "WAF_UPLOAD_FNAME", DefaultMode: "block"},
	{ID: 421, Name: "rule_php_split_string_canary", ReasonFamily: "WAF_DROPPER", DefaultMode: "logonly"},
	{ID: 422, Name: "rule_php_dropper_wget_curl", ReasonFamily: "WAF_DROPPER", DefaultMode: "logonly"},
	{ID: 423, Name: "rule_php_dropper_markers", ReasonFamily: "WAF_DROPPER", DefaultMode: "logonly"},
	{ID: 424, Name: "rule_php_filesize_recon", ReasonFamily: "WAF_DROPPER", DefaultMode: "logonly"},
	{ID: 425, Name: "rule_php_touch_antiforensic", ReasonFamily: "WAF_DROPPER", DefaultMode: "logonly"},
	{ID: 430, Name: "rule_htaccess_poisoning", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 431, Name: "rule_php_char_pool_obfuscation", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 432, Name: "rule_php_polyglot_full_body", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 433, Name: "rule_php_eval_loader_b64", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 434, Name: "rule_php_superglobal_callable", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 435, Name: "rule_php_concat_funcname_eval", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 436, Name: "rule_php_decode_chain", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},
	{ID: 437, Name: "rule_php_encoded_opener", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "challenge"},
	{ID: 438, Name: "rule_php_encoded_opener_b64", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "challenge"},

	// 5xx auth abuse
	{ID: 501, Name: "rule_auth_burst", ReasonFamily: "WAF_AUTH_BURST", DefaultMode: "challenge"},
	{ID: 502, Name: "rule_auth_wp_checks", ReasonFamily: "WAF_AUTH_BURST", DefaultMode: "challenge"},
	{ID: 510, Name: "rule_xmlrpc_multicall", ReasonFamily: "WAF_AUTH_BURST", DefaultMode: "challenge"},
	{ID: 511, Name: "rule_xmlrpc_pingback", ReasonFamily: "WAF_AUTH_BURST", DefaultMode: "challenge"},
	{ID: 512, Name: "rule_xmlrpc_post_burst", ReasonFamily: "WAF_AUTH_BURST", DefaultMode: "challenge"},

	// 6xx header / protocol anomaly
	{ID: 601, Name: "rule_ctrl_chars", ReasonFamily: "WAF_CTRL_CHARS", DefaultMode: "challenge"},
	{ID: 602, Name: "rule_ip_host", ReasonFamily: "WAF_IP_HOST", DefaultMode: "challenge"},
	{ID: 603, Name: "rule_header_vulns", ReasonFamily: "WAF_HEADER_VULN", DefaultMode: "challenge"},
	{ID: 604, Name: "rule_content_type_anomaly", ReasonFamily: "WAF_CT_ANOMALY", DefaultMode: "logonly"},
	{ID: 605, Name: "rule_crlf_injection", ReasonFamily: "WAF_CRLF", DefaultMode: "challenge"},
	{ID: 606, Name: "rule_http_smuggling", ReasonFamily: "WAF_HTTP_SMUGGLING", DefaultMode: "logonly"},
	{ID: 607, Name: "rule_exploit_methods", ReasonFamily: "WAF_EXPLOIT_METHOD", DefaultMode: "challenge"},
	{ID: 608, Name: "rule_smuggling_cl", ReasonFamily: "WAF_HTTP_SMUGGLING", DefaultMode: "logonly"},
	{ID: 609, Name: "rule_header_flood", ReasonFamily: "WAF_HEADER_FLOOD", DefaultMode: "challenge"},
	{ID: 610, Name: "rule_range_abuse", ReasonFamily: "WAF_RANGE_ABUSE", DefaultMode: "logonly"},
	{ID: 611, Name: "rule_bad_utf8", ReasonFamily: "WAF_BAD_UTF8", DefaultMode: "logonly"},

	// 7xx SSRF
	{ID: 701, Name: "rule_ssrf", ReasonFamily: "WAF_SSRF", DefaultMode: "logonly"},
	{ID: 702, Name: "rule_c2_tunnel", ReasonFamily: "WAF_C2", DefaultMode: "logonly"},

	// 8xx info disclosure / debug
	{ID: 801, Name: "rule_debug_toggles", ReasonFamily: "WAF_DEBUG_TOGGLE", DefaultMode: "challenge"},

	// 10xxx named-vulnerability (CVE) detectors — see WAF_CVE.md.
	{ID: 10001, Name: "rule_cve_simple_file_list_upload", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10002, Name: "rule_cve_joomla_jce_profile_import", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10003, Name: "rule_cve_ninja_forms_fu_upload", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10004, Name: "rule_cve_litespeed_hash_privesc", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10005, Name: "rule_cve_revslider", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10006, Name: "rule_cve_w3tc", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
	{ID: 10007, Name: "rule_cve_post_smtp", ReasonFamily: "WAF_CVE", DefaultMode: "block"},
}

// wafRuleGroupNames maps the leading digit (id/100) to a human-readable label.
// Used by /api/v1/waf/rules and the CLI "rules" subcommand.
var wafRuleGroupNames = map[int]string{
	1: "path",
	2: "client_identity",
	3: "injection",
	4: "upload_malware",
	5: "auth_abuse",
	6: "header_protocol",
	7: "ssrf",
	8:   "info_disclosure",
	9:   "reserved",
	100: "cve", // id/100 for the 10000+ named-vulnerability band
}

// WAFRules returns a copy of the rule registry with Group / GroupName filled
// in. Sorted by ID. Safe to expose to API/CLI consumers.
func WAFRules() []WAFRule {
	out := make([]WAFRule, len(wafRuleIDs))
	for i, r := range wafRuleIDs {
		r.Group = r.ID / 100
		r.GroupName = wafRuleGroupNames[r.Group]
		out[i] = r
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// WAFRuleByID looks up a rule by ID. Returns the zero value and false when
// the ID is unknown.
func WAFRuleByID(id int) (WAFRule, bool) {
	for _, r := range wafRuleIDs {
		if r.ID == id {
			r.Group = r.ID / 100
			r.GroupName = wafRuleGroupNames[r.Group]
			return r, true
		}
	}
	return WAFRule{}, false
}

// WAFRuleByName looks up a rule by its CFG key (e.g. "rule_traversal").
func WAFRuleByName(name string) (WAFRule, bool) {
	for _, r := range wafRuleIDs {
		if r.Name == name {
			r.Group = r.ID / 100
			r.GroupName = wafRuleGroupNames[r.Group]
			return r, true
		}
	}
	return WAFRule{}, false
}

// WAFReasonFamilies returns the sorted, distinct set of WAF reason-families
// (the `WAF_*` prefix a rule emits, e.g. "WAF_SQLI"). It is the authoritative
// family list — the waf_security detector maps every one of these to a per-IP
// autoblock threshold, so a family added to the registry is automatically a
// configurable knob (and a coverage test asserts none is silently dropped).
func WAFReasonFamilies() []string {
	seen := make(map[string]struct{}, len(wafRuleIDs))
	out := make([]string, 0, len(wafRuleIDs))
	for _, r := range wafRuleIDs {
		if r.ReasonFamily == "" {
			continue
		}
		if _, ok := seen[r.ReasonFamily]; ok {
			continue
		}
		seen[r.ReasonFamily] = struct{}{}
		out = append(out, r.ReasonFamily)
	}
	sort.Strings(out)
	return out
}

// WAFFamilyHasBlockRule reports whether any rule in the given reason-family
// ships at edge action `block`. Only these families can feed the Phase-1
// waf_security autoblock (which is scoped to edge-block hits); the rest are
// challenge/logonly and stay edge-only until a later phase.
func WAFFamilyHasBlockRule(family string) bool {
	for _, r := range wafRuleIDs {
		if r.ReasonFamily == family && r.DefaultMode == "block" {
			return true
		}
	}
	return false
}
