package dnat

import (
	"os"
	"strings"
	"testing"
)

func TestPanelListenerTemplates_DoNotUseLegacyLuaPaths(t *testing.T) {
	templates := []string{
		"../../configs/angie-cfm-panel-listeners.conf",
		"../../configs/openresty-cfm-panel-listeners.conf",
	}
	for _, tpl := range templates {
		b, err := os.ReadFile(tpl)
		if err != nil {
			t.Fatalf("read %s: %v", tpl, err)
		}
		s := string(b)
		for _, legacy := range []string{"/etc/angie/lua/", "/usr/local/openresty/nginx/lua/"} {
			if strings.Contains(s, legacy) {
				t.Fatalf("template %s contains legacy Lua path %q", tpl, legacy)
			}
		}
		if !strings.Contains(s, "access_by_lua_file /var/lib/cfm/lua/cfm_panel.lua;") {
			t.Fatalf("template %s is missing shared panel guard path", tpl)
		}
		if strings.Contains(s, "ssl_certificate_by_lua_file") {
			t.Fatalf("template %s should use module-based sslcollector hook", tpl)
		}
		if !strings.Contains(s, `require "sslcollector"`) {
			t.Fatalf("template %s is missing module-based sslcollector require", tpl)
		}
	}
}
