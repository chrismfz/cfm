package dnat

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func withPanelListenerService(t *testing.T, service string, paths []string) {
	t.Helper()
	oldDetector := panelListenerServiceDetector
	oldPaths := panelListenerChallengeConfigPaths
	t.Cleanup(func() {
		panelListenerServiceDetector = oldDetector
		panelListenerChallengeConfigPaths = oldPaths
	})
	panelListenerServiceDetector = func() string { return service }
	if paths != nil {
		panelListenerChallengeConfigPaths = paths
	}
}

func TestOrderedPanelListenerConfigPathsPrefersActiveService(t *testing.T) {
	angie := "/etc/angie/cfm-panel-listeners.conf"
	oresty := "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf"
	fallback := "configs/cfm-panel-listeners.conf.in"
	paths := []string{angie, oresty, fallback}

	cases := []struct {
		name string
		svc  string
		want []string
	}{
		{"openresty active", "openresty", []string{oresty, angie, fallback}},
		{"angie active", "angie", []string{angie, oresty, fallback}},
		{"ambiguous keeps order", panelListenerServiceAmbiguous, []string{angie, oresty, fallback}},
		{"no service keeps order", "", []string{angie, oresty, fallback}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPanelListenerService(t, tc.svc, paths)
			got := orderedPanelListenerConfigPaths()
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPanelLuaGuardPathPrefersActiveServiceConfig(t *testing.T) {
	tmp := t.TempDir()
	angieLua := filepath.ToSlash(filepath.Join(tmp, "angie", "cfm_panel.lua"))
	orestyLua := filepath.ToSlash(filepath.Join(tmp, "openresty", "cfm_panel.lua"))
	angieConf := tmp + "/etc/angie/cfm-panel-listeners.conf"
	orestyConf := tmp + "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf"
	for _, c := range []struct{ path, lua string }{
		{angieConf, angieLua},
		{orestyConf, orestyLua},
	} {
		if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.path, []byte("access_by_lua_file "+c.lua+";\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	paths := []string{angieConf, orestyConf}

	withPanelListenerService(t, "openresty", paths)
	if got := panelLuaGuardPath(); got != orestyLua {
		t.Fatalf("openresty active: got %q, want %q", got, orestyLua)
	}
	withPanelListenerService(t, "angie", paths)
	if got := panelLuaGuardPath(); got != angieLua {
		t.Fatalf("angie active: got %q, want %q", got, angieLua)
	}
}

func TestPanelLuaSelftestScriptCoversSharedDict(t *testing.T) {
	s := panelLuaSelftestScript()
	for _, want := range []string{
		"shared=setmetatable({},{__index=function(t,k)",
		"get=function() return nil end",
		"set=function() return true end",
		"add=function() return true end",
		"incr=function() return nil end",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("selftest stub missing %q; a module touching ngx.shared.<dict> at load time would fail the guard check again", want)
		}
	}
}

func TestCheckPanelLuaGuardLoadTimeSharedAccess(t *testing.T) {
	tmp := t.TempDir()
	luaPath := filepath.Join(tmp, "cfm_panel.lua")
	src := "local shd = ngx.shared.cfm_decisions\n" +
		"if type(shd) ~= 'table' then error('shared dict missing') end\n" +
		"function cfm_panel_selftest() return true end\n" +
		"if os.getenv('CFM_PANEL_SELFTEST_ONLY') == '1' then return cfm_panel_selftest() end\n"
	if err := os.WriteFile(luaPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeResty := filepath.Join(tmp, "resty")
	if err := os.WriteFile(fakeResty, []byte("#!/bin/sh\n[ \"$CFM_PANEL_SELFTEST_ONLY\" = 1 ] || exit 8\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	oldPath := os.Getenv("PATH")
	oldLookPath := lookPath
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPath)
		lookPath = oldLookPath
	})
	_ = os.Setenv("PATH", tmp)
	lookPath = exec.LookPath

	st := checkPanelLuaGuard(luaPath)
	if st.LoadState != "true" {
		t.Fatalf("LoadState=%q LoadError=%q", st.LoadState, st.LoadError)
	}
	if st.LoadError != "" {
		t.Fatalf("unexpected LoadError=%q", st.LoadError)
	}
}
