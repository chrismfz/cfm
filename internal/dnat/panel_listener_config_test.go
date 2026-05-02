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

func TestPanelLuaPolicy_DocumentsExemptionsAndModes(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm_panel.lua")
	if err != nil {
		t.Fatalf("read lua: %v", err)
	}
	s := string(b)
	for _, tok := range []string{"guard-only", "browser", "is_exempt_path", "has_clearance_cookie", "backend_unavailable_fail_closed", "backend_unavailable_fail_open"} {
		if !strings.Contains(s, tok) {
			t.Fatalf("missing policy token %q", tok)
		}
	}
}
