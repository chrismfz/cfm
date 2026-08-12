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
		// The selftest hook deliberately probes the raw token file on disk
		// (install preflight), so the path constant must stay.
		`local _BRIDGE_TOKEN_FILE = "/var/lib/cfm/lua/cfm_bridge_token.lua"`,
		// Token and bridge config are read via the canonical cached
		// accessor (which owns the /var/lib/cfm/lua/cfm_bridge_*.lua
		// paths), not inline per-request loadfile copies — see
		// configs/lua/cfm_bridge_cfg.lua.
		`pcall(require, "cfm_bridge_cfg")`,
		`panel_bridge_cfg = bc.get()`,
		`local tok, terr = bc.token()`,
		`panel_bridge_token = tok`,
	} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing bridge-file contract token %q", tok)
		}
	}

	// The accessor module must keep owning the canonical paths the daemon
	// writes (internal/detectors/manager.go bridgeConfigPath / bridgeTokenPath).
	bc, err := os.ReadFile("../../configs/lua/cfm_bridge_cfg.lua")
	if err != nil {
		t.Fatalf("read cfm_bridge_cfg.lua: %v", err)
	}
	for _, tok := range []string{
		`local PATH = "/var/lib/cfm/lua/cfm_bridge_config.lua"`,
		`local TOKEN_PATH = "/var/lib/cfm/lua/cfm_bridge_token.lua"`,
	} {
		if !strings.Contains(string(bc), tok) {
			t.Fatalf("cfm_bridge_cfg.lua no longer reads canonical path %q", tok)
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
	// The verify location stamps the client's TLS ClientHello (X-CFM-TLS) so
	// panel solves carry a fingerprint like web solves do — see Phase 2b in
	// docs/edge-unification-plan.md. The clear-then-pcall(stamp) shape mirrors
	// the web `/__cfm_verify` block in openresty.conf/angie.conf.
	exactVerify := `location = /__cfm_verify { access_by_lua_block { ngx.req.clear_header("X-CFM-TLS") pcall(function() require("cfm_tlsfp").stamp() end) } proxy_pass http://cfm_challenge;`

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

// TestPanelListenerConfig_VerifyStampsTLSFingerprint verifies that every panel
// /__cfm_verify location stamps the client's TLS ClientHello (X-CFM-TLS) before
// proxying to the challenge server, so panel solves carry a fingerprint instead
// of tls_fp=- (edge-unification Phase 2b; docs/roadmaps/challenge-engine.md §6
// flagged panel scopes as the fingerprint's one structural blind spot). The
// stamp is verify-only, matching the web edge: the /__cfm_challenge location
// records no solve, so it stays bare — stamping it would be dead work and would
// diverge from web.
func TestPanelListenerConfig_VerifyStampsTLSFingerprint(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)

	const stamp = `access_by_lua_block { ngx.req.clear_header("X-CFM-TLS") pcall(function() require("cfm_tlsfp").stamp() end) }`
	const verifyStamped = "location = /__cfm_verify { " + stamp
	const expectedPanelListenerCount = 7

	// Every verify location carries the stamp; none is left bare.
	if got := strings.Count(s, verifyStamped); got != expectedPanelListenerCount {
		t.Fatalf("expected %d stamped verify locations, got %d", expectedPanelListenerCount, got)
	}
	if strings.Contains(s, "location = /__cfm_verify { access_by_lua_block { return; }") {
		t.Fatalf("a verify location is still bare; every verify must stamp X-CFM-TLS")
	}

	// The clear MUST precede the pcall'd stamp: if the module fails to load the
	// pcall is a no-op, and only the explicit clear then stops a client-supplied
	// X-CFM-TLS from reaching the daemon. Guard the ordering, not just presence.
	clearTok := `ngx.req.clear_header("X-CFM-TLS")`
	stampTok := `require("cfm_tlsfp").stamp()`
	if ci, si := strings.Index(s, clearTok), strings.Index(s, stampTok); ci < 0 || si < 0 || ci > si {
		t.Fatalf("clear_header must precede stamp() in the verify block (clear=%d stamp=%d)", ci, si)
	}

	// Challenge location stays bare (web parity: no solve, no fingerprint).
	if got := strings.Count(s, "location = /__cfm_challenge { access_by_lua_block { return; }"); got != expectedPanelListenerCount {
		t.Fatalf("expected %d bare challenge locations (verify-only stamping), got %d", expectedPanelListenerCount, got)
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
// that the /acctxfer(rsync|dsync) bidirectional-tunnel location is wired into
// every cPanel-facing server block AND placed before the broader /acctxfer
// streaming-location regex, so nginx's first-match-wins regex semantics
// route /acctxferrsync and /acctxferdsync to the Lua tunnel
// (cfm_panel_tunnel.lua) instead of the HTTP proxy fallback. The DirectAdmin
// listener (12222) intentionally does not get the tunnel because DA does not
// expose these endpoints.
func TestPanelListenerConfig_TunnelEndpointPrecedesStreamingLocation(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	s := string(b)

	tunnel := "location ~ ^/acctxfer(rsync|dsync)(/|$) { access_by_lua_block { return; } lingering_close off; content_by_lua_file /var/lib/cfm/lua/cfm_panel_tunnel.lua; }"
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
