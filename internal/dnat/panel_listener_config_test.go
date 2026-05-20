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

func assertPanelLuaBridgeContract(t *testing.T) {
	t.Helper()
	b, err := os.ReadFile("../../configs/lua/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{
		`local _BRIDGE_TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"`,
		`local panel_bridge_token = load_token(_BRIDGE_TOKEN_FILE, "bridge token file")`,
		`local _BRIDGE_CONFIG_FILE = "/var/lib/cfm/lua/cfm_bridge_config.lua"`,
		`local chunk = loadfile(_BRIDGE_CONFIG_FILE)`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing bridge-file contract token %q", tok)
		}
	}
}

func TestPanelLuaRuntimeBridgeContract(t *testing.T) {
	assertPanelLuaBridgeContract(t)
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

// TestPanelListenerConfig_TunnelEndpointPrecedesStreamingLocation verifies
// that the /acctxferrsync bidirectional-tunnel location is wired into every
// cPanel-facing server block AND placed before the broader /acctxfer
// streaming-location regex, so nginx's first-match-wins regex semantics
// route /acctxferrsync to the Lua tunnel (cfm_panel_tunnel.lua) instead of
// the HTTP proxy fallback. The DirectAdmin listener (12222) intentionally
// does not get the tunnel because DA does not expose /acctxferrsync.
func TestPanelListenerConfig_TunnelEndpointPrecedesStreamingLocation(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)

	tunnel := "location ~ ^/acctxferrsync(/|$) { access_by_lua_block { return; } content_by_lua_file /var/lib/cfm/lua/cfm_panel_tunnel.lua; }"
	streaming := "location ~ ^/(acctxfer|cgi/live_tail_log|cgi/transfer) {"

	const expectedCPanelListenerCount = 6
	if got := strings.Count(s, tunnel); got != expectedCPanelListenerCount {
		t.Fatalf("expected tunnel location on %d cPanel listeners, got %d", expectedCPanelListenerCount, got)
	}
	if got := strings.Count(s, streaming); got != expectedCPanelListenerCount {
		t.Fatalf("expected streaming-fallback location on %d cPanel listeners, got %d", expectedCPanelListenerCount, got)
	}

	// In each server block tunnel must appear BEFORE the streaming regex,
	// otherwise nginx will match the broader pattern first and route
	// /acctxferrsync through the HTTP proxy (which deadlocks).
	searchFrom := 0
	for i := 0; i < expectedCPanelListenerCount; i++ {
		tunnelAt := strings.Index(s[searchFrom:], tunnel)
		if tunnelAt < 0 {
			t.Fatalf("could not locate tunnel occurrence %d", i+1)
		}
		tunnelAt += searchFrom
		streamingAt := strings.Index(s[tunnelAt:], streaming)
		if streamingAt < 0 {
			t.Fatalf("missing streaming-fallback location after tunnel occurrence %d", i+1)
		}
		streamingAt += tunnelAt
		searchFrom = streamingAt + len(streaming)
	}

	// DA block must NOT have the tunnel — DA doesn't use this endpoint.
	daIdx := strings.Index(s, "listen 12222 ssl;")
	if daIdx < 0 {
		t.Fatalf("directadmin listener start not found")
	}
	daBlock := s[daIdx:]
	if nextServer := strings.Index(daBlock[len("listen 12222 ssl;"):], "server {"); nextServer > 0 {
		daBlock = daBlock[:len("listen 12222 ssl;")+nextServer]
	}
	if strings.Contains(daBlock, tunnel) {
		t.Fatalf("directadmin listener should not have the cpanel rsync tunnel location")
	}
}
