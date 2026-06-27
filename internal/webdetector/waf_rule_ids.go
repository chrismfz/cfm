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
//   9xx reserved (future CVE detectors, behavioural rules)
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
	{ID: 301, Name: "rule_sqli", ReasonFamily: "WAF_SQLI", DefaultMode: "challenge"},
	{ID: 309, Name: "rule_sqli_blind_lexical", ReasonFamily: "WAF_SQLI_LEXICAL", DefaultMode: "logonly"},
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
	{ID: 410, Name: "rule_webshell_path", ReasonFamily: "WAF_WEBSHELL", DefaultMode: "logonly"},
	{ID: 411, Name: "rule_webshell_ping", ReasonFamily: "WAF_WEBSHELL", DefaultMode: "logonly"},
	{ID: 412, Name: "rule_polyglot_upload", ReasonFamily: "WAF_UPLOAD_CONTENT", DefaultMode: "logonly"},
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
	{ID: 437, Name: "rule_php_encoded_opener", ReasonFamily: "WAF_BACKDOOR", DefaultMode: "logonly"},

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
	8: "info_disclosure",
	9: "reserved",
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
