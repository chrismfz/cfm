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

	exactCount := strings.Count(s, exact)
	rootCount := strings.Count(s, root)
	if exactCount == 0 || exactCount != rootCount {
		t.Fatalf("expected matching exact/root locations per server block, got exact=%d root=%d", exactCount, rootCount)
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
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{"guard-only", "browser", "is_exempt_path", "has_clearance_cookie", "backend_error_fail_closed", "backend_error_fail_open"} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing policy token %q", tok)
		}
	}
}

func TestPanelLuaPolicy_QueryDecisionApiDoesNotMapAllNon5xxToDeny(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)

	for _, tok := range []string{
		"if status >= 500 then",
		"if status == 204 then",
		"if status < 200 or status >= 300 then",
		`return { outcome = "backend_unavailable", reason = "subrequest_non_2xx"`,
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
