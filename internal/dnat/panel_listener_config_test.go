package dnat

import (
	"os"
	"strings"
	"testing"
)

func TestPanelListenerConfig_HasLuaGuardAndNoDefaultBypass(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)
	if strings.Count(s, "server {") < 3 {
		t.Fatalf("expected server blocks")
	}
	for _, tok := range []string{"set $cfm_panel_challenge_mode", "access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua", "proxy_pass $cfm_pass", "set $cfm_pass \"\";"} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing token %q", tok)
		}
	}
}

func TestPanelListenerConfig_TLSListenersHavePlainHTTPHelpAndHSTS(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)
	for listenPort, publicPort := range map[string]string{
		"12083": "2083",
		"12087": "2087",
		"12096": "2096",
		"12222": "2222",
	} {
		listen := "listen " + listenPort + " ssl;"
		start := strings.Index(s, listen)
		if start < 0 {
			t.Fatalf("missing TLS listener %s", listen)
		}
		block := s[start:]
		if next := strings.Index(block[len(listen):], "server {"); next > 0 {
			block = block[:len(listen)+next]
		}
		for _, tok := range []string{
			`add_header Strict-Transport-Security "max-age=86400" always;`,
			`error_page 497 = @cfm_plain_http_panel_https;`,
			`location @cfm_plain_http_panel_https {`,
			`access_by_lua_block { return; }`,
			`add_header Refresh "3; url=https://$host:` + publicPort + `$request_uri" always;`,
			`background:#0b1020`,
			`border-top-color:#4da3ff`,
			`Redirecting to the secure URL in 3 seconds...`,
		} {
			if !strings.Contains(block, tok) {
				t.Fatalf("TLS listener %s missing token %q", listenPort, tok)
			}
		}
	}
}

func TestPanelListenerConfig_HasExactDecideLocationAndDoesNotFallThroughToRootProxy(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)

	exact := "location = /__cfm_panel_decide"
	root := "location / { proxy_pass $cfm_pass;"
	if !strings.Contains(s, exact) {
		t.Fatalf("missing exact location block %q", exact)
	}
	if strings.Contains(s, "location /__cfm_panel_decide") {
		t.Fatalf("found non-exact decide location; this can route via generic location /")
	}

	exactCount := strings.Count(s, exact)
	rootCount := strings.Count(s, root)
	if exactCount == 0 || exactCount != rootCount {
		t.Fatalf("expected matching exact/root locations per server block, got exact=%d root=%d", exactCount, rootCount)
	}
	const expectedPanelListenerCount = 7
	if exactCount != expectedPanelListenerCount {
		t.Fatalf("expected exact decide location for all panel listeners, got exact=%d want=%d", exactCount, expectedPanelListenerCount)
	}

	// Regression note: when /__cfm_panel_decide incorrectly falls through `location /`
	// with proxy_pass $cfm_pass and $cfm_pass is empty, nginx errors include:
	// invalid URL prefix in "".
	searchFrom := 0
	for i := 0; i < exactCount; i++ {
		exactAt := strings.Index(s[searchFrom:], exact)
		if exactAt < 0 {
			t.Fatalf("could not locate exact location occurrence %d", i+1)
		}
		exactAt += searchFrom
		rootAt := strings.Index(s[exactAt:], root)
		if rootAt < 0 {
			t.Fatalf("missing root proxy location after exact decide location occurrence %d", i+1)
		}
		rootAt += exactAt
		if exactAt > rootAt {
			t.Fatalf("exact decide location must appear before root proxy in each server block (occurrence %d)", i+1)
		}
		searchFrom = rootAt + len(root)
	}
}

func TestPanelLuaPolicy_DocumentsExemptionsAndModes(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{"guard-only", "browser", "is_exempt_path", "clearance_cookie_state", "backend_error_fail_closed", "backend_unavailable_fail_open", "cfm_panel_fail_mode or \"fail-open\""} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing policy token %q", tok)
		}
	}
}

func TestPanelLuaPolicy_QueryDecisionApiDoesNotMapAllNon5xxToDeny(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		"if status >= 500 then",
		"if status >= 300 and status < 400 then",
		"if status == 204 then",
		"if status < 200 or status >= 300 then",
		`return { outcome = "redirect", reason = "subrequest_redirect"`,
		`return { outcome = "allow", reason = "backend_allow_204"`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing query_decision_api guard token %q", tok)
		}
	}

	if strings.Contains(s, `if status < 500 then return { outcome = "deny"`) {
		t.Fatalf("query_decision_api appears to unconditionally deny non-5xx statuses")
	}
}

func TestPanelLuaPolicy_ChallengeFlowDetectionDoesNotUseNextParam(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	start := strings.Index(s, "local function is_challenge_flow_request(uri)")
	if start < 0 {
		t.Fatalf("missing is_challenge_flow_request function")
	}
	end := strings.Index(s[start:], "\n\nlocal function append_set_cookie")
	if end < 0 {
		t.Fatalf("could not find end of is_challenge_flow_request function")
	}
	body := s[start : start+end]
	if strings.Contains(body, "next_points_to_challenge(") {
		t.Fatalf("is_challenge_flow_request must not call next_points_to_challenge")
	}
	for _, tok := range []string{"uri == \"/__cfm_challenge\"", "starts_with(uri, \"/__cfm_challenge/\")"} {
		if !strings.Contains(body, tok) {
			t.Fatalf("missing challenge-flow check token %q", tok)
		}
	}
}

func TestPanelLuaPolicy_VerifyEndpointGuardIsScopedToInternalHandling(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `if uri == decision_uri or uri == "/__cfm_verify" then`) {
		t.Fatalf("missing internal-only guard branch for decision/verify endpoints")
	}
	if !strings.Contains(s, `return ngx.exit(ngx.HTTP_NOT_FOUND or ngx.HTTP_FORBIDDEN)`) {
		t.Fatalf("internal-only guard branch must deny non-internal traffic")
	}
}

func TestPanelLuaPolicy_CookieDetectionUsesDelimitedNames(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		`local raw = ngx.var.http_cookie or ""`,
		`local cookie = "; " .. raw`,
		`cookie:find("; cfm_ok=", 1, true)`,
		`cookie:find("; cfm_clearance=", 1, true)`,
		`local clearance = cookie:match(";%s*cfm_clearance=([^;]*)")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing delimited cookie detection token %q", tok)
		}
	}

	for _, tok := range []string{
		`cookie:find("; cf_clearance=", 1, true)`,
		`cookie:find("; cp_security_token=", 1, true)`,
	} {
		if strings.Contains(s, tok) {
			t.Fatalf("third-party cookie token %q must not be accepted as direct clearance", tok)
		}
	}

	if strings.Contains(s, `cookie:find("cfm_ok=", 1, true)`) {
		t.Fatalf("raw cfm_ok cookie detection without delimiter may cause substring false positives")
	}
}

func TestPanelLuaPolicy_ChallengeVerifyFlowNeverResumesToInternalDecisionRoute(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	// Regression path:
	// GET / -> challenge redirect -> /__cfm_challenge?next=/__cfm_panel_decide&next=/ -> verify.
	// Lua must normalize this chain so post-verify resume target is never /__cfm_panel_decide.
	for _, tok := range []string{
		`if c:find("/__cfm_panel_decide", 1, true) then return true end`,
		`if is_internal_decision_uri(loc) then`,
		`req_uri = strip_nested_next_chain(req_uri)`,
		`if dk ~= "next" then`,
		`local nested = sanitize_panel_next_target(value, "")`,
		`if nested ~= "" and not is_internal_guard_uri(nested) then`,
		`if is_internal_guard_uri(safe_next) or is_internal_decision_uri(safe_next) then safe_next = "/" end`,
		`local decoded = sanitize_panel_next_target(next_arg, "")`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing verify/next-chain hardening token %q", tok)
		}
	}
}

func TestPanelListenerConfig_DecideRouteIsInternalOnlyWhileChallengeAndVerifyStayReachable(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)

	exactDecide := "location = /__cfm_panel_decide { internal;"
	exactChallenge := "location = /__cfm_challenge { access_by_lua_block { return; } proxy_pass http://cfm_challenge;"
	exactVerify := "location = /__cfm_verify { access_by_lua_block { return; } proxy_pass http://cfm_challenge;"

	decideCount := strings.Count(s, exactDecide)
	challengeCount := strings.Count(s, exactChallenge)
	verifyCount := strings.Count(s, exactVerify)
	if decideCount == 0 || challengeCount == 0 || verifyCount == 0 {
		t.Fatalf("missing expected decide/challenge/verify locations: decide=%d challenge=%d verify=%d", decideCount, challengeCount, verifyCount)
	}
	if decideCount != challengeCount || decideCount != verifyCount {
		t.Fatalf("decide must stay internal while challenge/verify remain reachable per listener: decide=%d challenge=%d verify=%d", decideCount, challengeCount, verifyCount)
	}
}

func TestPanelListenerConfig_DirectAdminListenerUsesTLSOriginAndHeaders(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		"listen 12222 ssl;",
		"ssl_protocols TLSv1.2 TLSv1.3;",
		"ssl_certificate /var/lib/cfm/certs/selfsigned/fullchain.pem;",
		"ssl_certificate_key /var/lib/cfm/certs/selfsigned/privkey.pem;",
		`ssl_certificate_by_lua_block { local sc = require "sslcollector"; sc.set_cert() }`,
		`set $cfm_panel_origin "https://127.0.0.1:2222";`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing directadmin tls token %q", tok)
		}
	}

	daIdx := strings.Index(s, "listen 12222 ssl;")
	if daIdx < 0 {
		t.Fatalf("directadmin listener start not found")
	}
	daBlock := s[daIdx:]
	nextServer := strings.Index(daBlock[len("listen 12222 ssl;"):], "server {")
	if nextServer > 0 {
		daBlock = daBlock[:len("listen 12222 ssl;")+nextServer]
	}
	if strings.Count(daBlock, "X-Forwarded-Proto https;") != 4 {
		t.Fatalf("expected https forwarded proto in decide/challenge/verify/root locations for directadmin block")
	}
}

func TestPanelLuaPolicy_NoTopLevelVerifyOrChallengeArgRewrite(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`if uri == "/__cfm_challenge" or uri == "/__cfm_verify" then`,
		`local normalized_next = normalize_challenge_next_arg(args.next)`,
		`args.next = normalized_next`,
		`ngx.req.set_uri_args(args)`,
	} {
		if strings.Contains(s, tok) {
			t.Fatalf("unexpected top-level endpoint-specific uri-arg rewrite token %q", tok)
		}
	}
}

func TestPanelLuaPolicy_ChallengeRedirectNeverReturnsInternalDecisionLocationOn303(t *testing.T) {
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`if status >= 300 and status < 400 then`,
		`if is_internal_decision_uri(loc) then`,
		`return challenge_location`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing 303/internal-location guard token %q", tok)
		}
	}
}
