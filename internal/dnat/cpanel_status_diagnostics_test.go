package dnat

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestOrderedPanelListenerConfigPathsPrefersOnlyActiveService(t *testing.T) {
	angie := "/etc/angie/cfm-panel-listeners.conf"
	oresty := "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf"
	fallback := "configs/cfm-panel-listeners.conf.in"
	paths := []string{angie, oresty, fallback}

	cases := []struct {
		name string
		svc  string
		want []string
	}{
		{"openresty active", "openresty", []string{oresty}},
		{"angie active", "angie", []string{angie}},
		{"ambiguous has no authoritative config", panelListenerServiceAmbiguous, nil},
		{"no service keeps only neutral fallback", "", []string{fallback}},
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

func TestActiveConfigMissingDoesNotFallBackToInactiveEngine(t *testing.T) {
	tmp := t.TempDir()
	angieConf := tmp + "/etc/angie/cfm-panel-listeners.conf"
	orestyConf := tmp + "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf"
	if err := os.MkdirAll(filepath.Dir(angieConf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(angieConf, []byte("location = /__cfm_panel_decide { return 204; }\naccess_by_lua_file /stale/cfm_panel.lua;\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	withPanelListenerService(t, "openresty", []string{angieConf, orestyConf})
	if got := panelLuaGuardPath(); got != "" {
		t.Fatalf("expected missing active OpenResty config to stay missing, got stale Lua path %q", got)
	}
	p := probePanelDecisionEndpoint(orderedPanelListenerConfigPaths())
	if p.Status != "MISSING" || p.Path != "" {
		t.Fatalf("expected missing active listener endpoint without stale fallback, got %+v", p)
	}
}

func TestPanelLuaSelftestScriptCoversSharedDictAndEnvPath(t *testing.T) {
	s := panelLuaSelftestScript()
	for _, want := range []string{
		"CFM_PANEL_SELFTEST_PATH",
		"shared=setmetatable({},{__index=function(t,k)",
		"get=function() return nil end",
		"set=function() return true end",
		"add=function() return true end",
		"incr=function() return nil end",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("selftest stub missing %q", want)
		}
	}
	if strings.Contains(s, "dofile(arg[1])") {
		t.Fatal("selftest must not depend on positional arg[1]; plain lua auto-executes trailing file arguments")
	}
}

func TestCheckPanelLuaGuardLoadTimeSharedAccess(t *testing.T) {
	luaJIT, err := exec.LookPath("luajit")
	if err != nil {
		t.Skip("luajit not installed; CI installs it before Go tests")
	}
	tmp := t.TempDir()
	luaPath := filepath.Join(tmp, "cfm_panel.lua")
	src := "local shd = ngx.shared.cfm_decisions\n" +
		"if type(shd) ~= 'table' then error('shared dict missing') end\n" +
		"function cfm_panel_selftest() return true end\n" +
		"if os.getenv('CFM_PANEL_SELFTEST_ONLY') == '1' then return cfm_panel_selftest() end\n"
	if err := os.WriteFile(luaPath, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	oldLookPath := lookPath
	t.Cleanup(func() { lookPath = oldLookPath })
	lookPath = func(name string) (string, error) {
		if name == "luajit" {
			return luaJIT, nil
		}
		return "", exec.ErrNotFound
	}

	st := checkPanelLuaGuard(luaPath)
	if st.LoadState != "true" {
		t.Fatalf("LoadState=%q LoadError=%q", st.LoadState, st.LoadError)
	}
	if st.LoadError != "" {
		t.Fatalf("unexpected LoadError=%q", st.LoadError)
	}
}

func TestInstallerPanelLuaSelftestsStayInSync(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "../.."))
	for _, rel := range []string{"scripts/install-openresty.sh", "scripts/install-angie.sh"} {
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		for _, want := range []string{
			"CFM_PANEL_SELFTEST_PATH",
			"shared=setmetatable({},{__index=function(t,k)",
			"CFM_PANEL_SELFTEST_ONLY=1 CFM_PANEL_SELFTEST_PATH=\"$lua_path\"",
		} {
			if !strings.Contains(s, want) {
				t.Fatalf("%s selftest missing %q", rel, want)
			}
		}
		if strings.Contains(s, `-e "$selftest" "$lua_path"`) {
			t.Fatalf("%s still passes the Lua module as a positional argument", rel)
		}
	}
}
