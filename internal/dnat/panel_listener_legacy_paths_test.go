package dnat

import (
	"os"
	"strings"
	"testing"
)

func TestPanelListenerTemplate_DoesNotUseLegacyLuaPaths(t *testing.T) {
	b, err := os.ReadFile("../../configs/cfm-panel-listeners.conf.in")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	s := string(b)
	for _, legacy := range []string{"/etc/angie/lua/", "/usr/local/openresty/nginx/lua/"} {
		if strings.Contains(s, legacy) {
			t.Fatalf("template contains legacy Lua path %q", legacy)
		}
	}
	if !strings.Contains(s, "access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua;") {
		t.Fatalf("template missing shared panel guard path")
	}
	if strings.Contains(s, "ssl_certificate_by_lua_file") {
		t.Fatalf("template should use module-based sslcollector hook")
	}
	if !strings.Contains(s, `require "sslcollector"`) {
		t.Fatalf("template missing module-based sslcollector require")
	}
}
