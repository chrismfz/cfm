package edgeengine

import (
	"reflect"
	"sort"
	"testing"
)

// The lists below are the literals the callers carried before Profiles
// existed. Each derived value must equal its old literal EXACTLY (order
// included): the refactor that moved them here is behaviour-neutral by
// construction, and this is what proves it. A change to Profiles that alters
// one of these is a behaviour change: update the expectation knowingly.

func TestProfilesDerivedListsMatchTheOldLiterals(t *testing.T) {
	cases := []struct {
		name string
		got  any
		want any
	}{
		{"ServiceCandidates (Detect order)", ServiceCandidates, []string{"angie", "openresty"}},
		{"BinaryPaths", BinaryPaths, map[string][]string{
			"angie":     {"/usr/sbin/angie", "/usr/bin/angie"},
			"openresty": {"/usr/local/openresty/nginx/sbin/nginx", "/opt/openresty/nginx/sbin/nginx"},
		}},
		{"Units", Units(), []string{"angie.service", "openresty.service"}},
		{"LuaTokenCandidates", LuaTokenCandidates(), []string{
			"/var/lib/cfm/lua/cfm_token.lua",
			"/usr/local/openresty/nginx/lua/cfm_token.lua",
			"/etc/angie/lua/cfm_token.lua",
		}},
		{"ConfFileCandidates(trusted_proxies.conf)", ConfFileCandidates("trusted_proxies.conf"), []string{
			"/usr/local/openresty/nginx/conf/trusted_proxies.conf",
			"/etc/angie/trusted_proxies.conf",
		}},
		{"LogFileCandidates(access.log)", LogFileCandidates("access.log"), []string{
			"/usr/local/openresty/nginx/logs/access.log",
			"/var/log/angie/access.log",
		}},
		{"LogFileCandidates(error.log)", LogFileCandidates("error.log"), []string{
			"/usr/local/openresty/nginx/logs/error.log",
			"/var/log/angie/error.log",
		}},
	}
	for _, tc := range cases {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s:\n got  %#v\n want %#v", tc.name, tc.got, tc.want)
		}
	}
}

// fileOrder must name exactly the engines in Profiles: adding an engine to one
// and not the other would silently drop it from every file-precedence list.
func TestFileOrderIsAPermutationOfProfiles(t *testing.T) {
	a := append([]string(nil), fileOrder...)
	b := Names()
	sort.Strings(a)
	sort.Strings(b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("fileOrder %v and Profiles %v name different engines", fileOrder, Names())
	}
	if len(InFileOrder()) != len(Profiles) {
		t.Fatalf("InFileOrder() lost a profile: %d of %d", len(InFileOrder()), len(Profiles))
	}
}

func TestProfilesAreComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Profiles {
		if p.Name == "" || seen[p.Name] {
			t.Fatalf("empty or duplicate profile name %q", p.Name)
		}
		seen[p.Name] = true
		for field, v := range map[string]string{"ConfDir": p.ConfDir, "MainConf": p.MainConf, "LogDir": p.LogDir, "LegacyLuaDir": p.LegacyLuaDir} {
			if v == "" {
				t.Errorf("%s: %s is empty", p.Name, field)
			}
		}
		if len(p.Binaries) == 0 || len(p.Commands) == 0 || len(p.ProcessAliases) == 0 || len(p.ConfigHookPaths) == 0 {
			t.Errorf("%s: a list field is empty: %+v", p.Name, p)
		}
	}
}

// Exact, like the equality checks it replaced: a caller uses the string as
// given afterwards (unit names, reload commands).
func TestLookupIsExact(t *testing.T) {
	for _, in := range []string{"angie", "openresty"} {
		if !IsEdge(in) {
			t.Errorf("IsEdge(%q) = false", in)
		}
	}
	for _, in := range []string{"", "nginx", "httpd", "angie2", "open", "Angie", " openresty ", "openresty.service"} {
		if IsEdge(in) {
			t.Errorf("IsEdge(%q) = true", in)
		}
	}
}
