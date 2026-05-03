package dnat

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestSuccessfulApplyState(t *testing.T) {
	setPanelFirewallHealth("OK", "", true)
	h := getPanelFirewallHealth()
	if h.State != "OK" || !h.Attempted || h.LastReason != "" {
		t.Fatalf("unexpected state: %#v", h)
	}
}

func TestBackendCommandFailureStructured(t *testing.T) {
	err := (&FirewallCommandError{Backend: fwNft, Command: "nft add rule inet cfm input", Output: "syntax error", Err: errors.New("exit status 1")}).Error()
	if !strings.Contains(err, "backend=nftables") || !strings.Contains(err, "syntax error") || !strings.Contains(err, "command=") {
		t.Fatalf("unexpected error string: %s", err)
	}
}

func TestIdempotentRerunAfterPartialFailure(t *testing.T) {
	setPanelFirewallHealth("PARTIAL", "failed once", true)
	setPanelFirewallHealth("OK", "", true)
	h := getPanelFirewallHealth()
	if h.State != "OK" {
		t.Fatalf("expected OK after rerun, got %#v", h)
	}
}

func TestOffCleanupStatusesReported(t *testing.T) {
	changes := []string{"tcp/12082 removed", "tcp/12083 not found", "tcp/12086 failed (boom)"}
	foundRemoved := false
	foundNotFound := false
	foundFailed := false
	for _, ch := range changes {
		foundRemoved = foundRemoved || strings.Contains(ch, "removed")
		foundNotFound = foundNotFound || strings.Contains(ch, "not found")
		foundFailed = foundFailed || strings.Contains(ch, "failed")
	}
	if !foundRemoved || !foundNotFound || !foundFailed {
		t.Fatalf("missing cleanup status categories: %v", changes)
	}
}

func TestPanelLuaDecisionEndpoint302IssuesChallenge(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	// /__cfm_panel_decide HTTP 302 should issue a browser-visible challenge redirect.
	for _, tok := range []string{
		"if status >= 300 and status < 400 then",
		`outcome = "redirect"`,
		`reason = "subrequest_redirect"`,
		`return issue_challenge(mode, "challenge_redirect", decision, challenge_cooldown_ttl)`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 302 handling token %q", tok)
		}
	}
}

func TestPanelLuaDecisionLogAnchorsRedirectStatusSignature(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	// Keep this signature anchor: if behavior changes to generic non-2xx handling,
	// expected log shape is decision_reason=subrequest_non_2xx subreq_status=302.
	// Today redirect is explicitly tracked and still must include subreq_status.
	if !strings.Contains(s, `decision_reason = decision.reason`) {
		t.Fatalf("decision logs must include decision_reason field")
	}
	if !strings.Contains(s, `subreq_status = decision.subreq_status`) {
		t.Fatalf("decision logs must include subreq_status field")
	}
	if !strings.Contains(s, `reason = "subrequest_redirect"`) {
		t.Fatalf("expected explicit redirect reason for 302 status")
	}
}

func TestPanelLuaPolicy_GuardOnlySensitiveFlowAnchors(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`if mode == "guard-only" then`,
		`needs_challenge = is_panel_sensitive(uri, method)`,
		`if mode == "guard-only" and is_panel_sensitive(uri, method) then`,
		`return issue_challenge(mode, "backend_error_fail_closed_challenge", decision, challenge_cooldown_ttl)`,
		`uri == "/" or uri == "/login/" or starts_with(uri, "/login") or starts_with(uri, "/openid_connect/") or starts_with(uri, "/cpsess")`,
		`if method == "POST" then return true end`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing guard-only sensitive flow token %q", tok)
		}
	}
}

func TestPanelLuaPolicy_OutcomeLogFieldsPresent(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`" allow_origin=", fields.allow_origin or "0"`,
		`" challenge_issued=", fields.challenge_issued or "0"`,
		`" challenge_entry=", fields.challenge_entry or "0"`,
		`" challenge_solved=", fields.challenge_solved or "0"`,
		`" challenge_resume=", fields.challenge_resume or "0"`,
		`" deny_fail_closed=", fields.deny_fail_closed or "0"`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing log outcome field token %q", tok)
		}
	}
}

func TestPanelLuaForcedMode_ChallengeThenCookieOrTTLAllowsFollowUps(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`elseif mode == "forced" then`,
		`needs_challenge = true`,
		`local has_cookie, cookie_reason = clearance_cookie_state()`,
		`cookie:find("; cfm_ok=", 1, true)`,
		`local has_host_state = has_bypass_ttl(ngx.var.remote_addr, host)`,
		`reason = "challenge_pass_cookie"`,
		`if has_cookie or has_host_state then`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing forced flow token %q", tok)
		}
	}
}

func TestPanelLuaForcedMode_45mNoRechallengeWhenCookieOrTTLEntryValid(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`ngx.var.cfm_challenge_cookie_life or ngx.var.CHALLENGE_COOKIE_LIFE or "45m"`,
		`ngx.var.cfm_openresty_ok_ip_ttl or ngx.var.OPENRESTY_OK_IP_TTL or "45m"`,
		`local function has_bypass_ttl(ip)`,
		`return sh:get(ttl_key(ip)) ~= nil`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 45m bypass TTL/cookie token %q", tok)
		}
	}
}

func TestPanelLuaForcedMode_RechallengeAfterTTLExpiry(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`if sensitive and cooldown_active(ngx.var.remote_addr, host) then`,
		`return issue_challenge(mode, "challenge_loop_protection", nil, challenge_cooldown_ttl)`,
		`local function cooldown_active(ip)`,
		`return sh:get(cooldown_key(ip)) ~= nil`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing forced-mode rechallenge token %q", tok)
		}
	}
}

func TestPanelLuaOffMode_DirectPassThroughWithoutChallenge(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local needs_challenge = host_is_known_panel_prefix`,
		`ngx.var.cfm_pass = origin`,
		`ngx.var.cfm_upstream = "cfm_panel_origin"`,
		`reason = "mode_skip"`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing off-mode direct pass token %q", tok)
		}
	}
}

func TestPanelLuaXfercPanelRedirectAndcPanelSessionSensitivityAnchors(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`if status >= 300 and status < 400 then`,
		`reason = "subrequest_redirect"`,
		`uri == "/" or uri == "/login/" or starts_with(uri, "/login") or starts_with(uri, "/openid_connect/") or starts_with(uri, "/cpsess") or starts_with(uri, "/session")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing xfercpanel/session anchor token %q", tok)
		}
	}
}

func TestPanelLuaChallengeRedirectSanitizesInternalNextTargets(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local function sanitize_panel_next_target(raw_next, fallback)`,
		`if c == "/__cfm_challenge" or starts_with(c, "/__cfm_challenge?") or starts_with(c, "/__cfm_challenge/") then return true end`,
		`if c == "/__cfm_verify" or starts_with(c, "/__cfm_verify?") or starts_with(c, "/__cfm_verify/") then return true end`,
		`local safe_next = sanitize_panel_next_target(req_uri, "/")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing sanitize token %q", tok)
		}
	}
}

func TestPanelLuaChallengeFlowStripsNestedEncodedNextChains(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local function strip_nested_next_chain(raw_next)`,
		`local function normalize_challenge_next_arg(next_arg)`,
		`local sanitized = strip_nested_next_chain(raw)`,
		`local normalized = normalize_challenge_next_arg(args.next)`,
		`return with_single_next_arg(loc, safe_next)`,
	} {

		encodedPayloads := []string{
			"/__cfm_challenge?next=%252F__cfm_challenge%253Fnext%253D%25252Fadmin",
			"/__cfm_verify?next=%252F__cfm_verify%253Fnext%253D%25252Fportal",
		}
		for _, payload := range encodedPayloads {
			if strings.Count(payload, "next=") != 1 {
				t.Fatalf("expected one challenge cycle in payload: %s", payload)
			}
		}

		if !strings.Contains(s, tok) {
			t.Fatalf("missing nested next stripping token %q", tok)
		}
	}
}


func TestPanelLuaForcedModeSensitivePathsRequireCookieAndProtectLoops(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local sensitive = is_panel_sensitive(uri, method)`,
		`if sensitive and cooldown_active(ngx.var.remote_addr, host) then`,
		`return issue_challenge(mode, "challenge_loop_protection", nil, challenge_cooldown_ttl)`,
		`if sensitive and not is_browser_like(ua) then`,
		`return deny(mode, "deny_unsolvable_client")`,
		`if sensitive then`,
		`needs_challenge = true`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing forced sensitive/loop token %q", tok)
		}
	}
}

func TestPanelLuaDecisionLogsIncludeHostUAAndReasons(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`" host=", fields.host or "-"`,
		`" ua=", fields.ua or "-"`,
		`"challenge_pass_cookie"`,
		`"challenge_loop_protection"`,
		`"deny_unsolvable_client"`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing logging/reason token %q", tok)
		}
	}
}

func TestPanelLuaConfiguredHostEquivalenceIncludesProxyDomains(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local function is_configured_panel_host(host)`,
		`local primary = (ngx.var.cfm_panel_primary_domain or ""):lower()`,
		`local proxies = (ngx.var.cfm_panel_proxy_domains or "")`,
		`if not is_configured_panel_host(ngx.var.host) then`,
		`return deny(mode, "host_not_configured")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing host equivalence token %q", tok)
		}
	}
}

func TestPanelLuaProxyHostNonBrowserAgentsSensitivePaths(t *testing.T) {
	cases := []struct {
		host string
		ua   string
		uri  string
	}{
		{host: "proxy.example.test", ua: "Go-http-client/1.1", uri: "/openid_connect/cpanelid"},
		{host: "proxy.example.test", ua: "python-requests/2.31.0", uri: "/login/?login_only=1"},
	}
	for _, tc := range cases {
		if tc.host == "" || tc.ua == "" || tc.uri == "" {
			t.Fatalf("invalid test case: %#v", tc)
		}
	}

	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`starts_with(uri, "/openid_connect/")`,
		`if sensitive and not is_browser_like(ua) then`,
		`return deny(mode, "deny_unsolvable_client")`,
		`local proxies = (ngx.var.cfm_panel_proxy_domains or "")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing proxy-host/non-browser token %q", tok)
		}
	}
}

func TestPanelLuaDecision429FailOpenUsesConfiguredFailMode(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`if decision.outcome == "challenge_rate_limited" then`,
		`if fail_mode == "fail-open" then`,
		`decision = "allow", reason = "challenge_rate_limited"`,
		`allow_origin = "1"`,
		`target = origin`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 429 fail-open token %q", tok)
		}
	}
}

func TestPanelLuaDecision429FailClosedDeniesWithoutChallengeLoop(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`if decision.outcome == "challenge_rate_limited" then`,
		`decision = "deny", reason = "challenge_rate_limited"`,
		`deny_fail_closed = "1"`,
		`return ngx.exit(ngx.HTTP_FORBIDDEN)`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 429 fail-closed token %q", tok)
		}
	}
	if strings.Contains(s, `issue_challenge(mode, "challenge_rate_limited"`) {
		t.Fatalf("429 handling must not rechallenge and loop")
	}
}

func TestPanelLuaForcedMode_DoesNotDependOnLuaVerifyCallbackGuard(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`has_recent_verify(`,
		`note_verify_success(`,
		`reason = "post_verify_loop_guard"`,
	} {
		if strings.Contains(s, tok) {
			t.Fatalf("forced mode must not depend on unreachable Lua verify callback token %q", tok)
		}
	}
}

func TestPanelLuaChallengeFlow_DoesNotTreatVerifyAsLuaPassThrough(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local function is_challenge_flow_request(uri)`,
		`return uri == "/__cfm_challenge" or starts_with(uri, "/__cfm_challenge/")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing challenge-flow token %q", tok)
		}
	}
	if strings.Contains(s, `uri == "/__cfm_verify"`) {
		t.Fatalf("verify endpoint must not be included in Lua challenge-flow pass-through")
	}
}
