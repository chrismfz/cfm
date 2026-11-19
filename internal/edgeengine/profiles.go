package edgeengine

import "strings"

// Profiles: everything CFM's Go code knows about each in-path edge engine, in
// ONE place. Before this table the same facts (unit names, binaries, conf and
// log dirs, the legacy Lua token path, process aliases) were copied into a
// dozen packages, so adding or changing an edge meant finding every copy, and
// a missed one silently mis-detected the engine (CLAUDE.md §5). A caller that
// needs an edge fact reads it from here; adding an edge is one Profile.
//
// Two orders exist on purpose, and profiles_test.go pins that both name the
// same engines:
//   - Profiles is the DETECTION order (Detect: the first active unit wins;
//     `-t` probes; display order).
//   - fileOrder is the FILE-PRECEDENCE order of the lists where the first
//     readable file wins (trusted_proxies.conf, the worker `user` line, the
//     legacy Lua token, the edge logs' equal-mtime tiebreak). It has always
//     been OpenResty first there, and keeping it is what makes this refactor
//     behaviour-neutral.
//
// cfm-edge is LAST in both orders: on every node without it the lists are the
// old ones plus a trailing entry that matches nothing. On a node switched to
// cfm-edge with the old engine still installed, a first-readable list takes
// the old engine's copy: that is right only while CFM's sidecar deploy
// refreshes every installed engine's copy, cfm-edge's included (the
// packaging change that adopts cfm-edge must do it). The logs are picked by
// mtime.

// Profile is one in-path edge engine as CFM installs and manages it.
type Profile struct {
	// Name is the engine's name and its systemd unit's base name.
	Name string
	// Binaries are where the engine binary lives; `-v` is read from the first
	// that exists.
	Binaries []string
	// Commands are the engine's command names in PATH (`<cmd> -t`).
	Commands []string
	// ConfDir is where CFM's edge config and its sidecars live
	// (cfm-panel-listeners.conf, trusted_proxies.conf, ...).
	ConfDir string
	// PathMarker attributes a config path to this engine (dnat's panel
	// listener files): a path containing it is the engine's. Deliberately the
	// marker the attribution always used, which is wider than ConfDir for
	// OpenResty (any "/openresty/" path, e.g. under /opt/openresty).
	PathMarker string
	// MainConf is the engine's main config file.
	MainConf string
	// LogDir holds the edge's access/error logs.
	LogDir string
	// LegacyLuaDir is where CFM's Lua (and cfm_token.lua) lived before the
	// shared /var/lib/cfm/lua; still read as a fallback. Empty for an engine
	// that never had one.
	LegacyLuaDir string
	// ConfigHookPaths are files whose presence says CFM is wired into this
	// engine (health's frontend detection scores them).
	ConfigHookPaths []string
	// ProcessAliases are the process names this engine's processes show.
	ProcessAliases []string
}

// Unit is the engine's systemd unit name.
func (p Profile) Unit() string { return p.Name + ".service" }

// ConfPath is name inside the engine's config directory.
func (p Profile) ConfPath(name string) string { return p.ConfDir + "/" + name }

// LogPath is name inside the engine's log directory.
func (p Profile) LogPath(name string) string { return p.LogDir + "/" + name }

// Profiles, in detection order (see the package comment above).
var Profiles = []Profile{
	{
		Name:            "angie",
		Binaries:        []string{"/usr/sbin/angie", "/usr/bin/angie"},
		Commands:        []string{"angie"},
		ConfDir:         "/etc/angie",
		PathMarker:      "/etc/angie/",
		MainConf:        "/etc/angie/angie.conf",
		LogDir:          "/var/log/angie",
		LegacyLuaDir:    "/etc/angie/lua",
		ConfigHookPaths: []string{"/etc/angie/conf.d/cfm.conf", "/etc/angie/conf.d/nginx-cfm.conf", "/etc/angie/angie.conf"},
		ProcessAliases:  []string{"angie", "nginx"},
	},
	{
		Name:            "openresty",
		Binaries:        []string{"/usr/local/openresty/nginx/sbin/nginx", "/opt/openresty/nginx/sbin/nginx"},
		Commands:        []string{"openresty"},
		ConfDir:         "/usr/local/openresty/nginx/conf",
		PathMarker:      "/openresty/",
		MainConf:        "/usr/local/openresty/nginx/conf/nginx.conf",
		LogDir:          "/usr/local/openresty/nginx/logs",
		LegacyLuaDir:    "/usr/local/openresty/nginx/lua",
		ConfigHookPaths: []string{"/usr/local/openresty/nginx/conf/nginx-cfm.conf", "/usr/local/openresty/nginx/conf/openresty-cfm-tsv.conf", "/usr/local/openresty/nginx/conf/nginx.conf"},
		ProcessAliases:  []string{"openresty", "nginx"},
	},
	{
		// cfm-edge: CFM's own edge package (nginx.org nginx + the OpenResty Lua
		// set, chrismfz/cfm-edge), laid out like a distro package. CFM's Lua
		// lives in the shared /var/lib/cfm/lua from day one, so it has no
		// legacy Lua dir. Its config hook is a CFM sidecar, not nginx.conf:
		// the package ships a placeholder nginx.conf, so that file says
		// nothing about CFM being wired in.
		Name:            "cfm-edge",
		Binaries:        []string{"/usr/sbin/cfm-edge"},
		Commands:        []string{"cfm-edge"},
		ConfDir:         "/etc/cfm-edge",
		PathMarker:      "/etc/cfm-edge/",
		MainConf:        "/etc/cfm-edge/nginx.conf",
		LogDir:          "/var/log/cfm-edge",
		LegacyLuaDir:    "",
		ConfigHookPaths: []string{"/etc/cfm-edge/trusted_proxies.conf"},
		ProcessAliases:  []string{"cfm-edge", "nginx"},
	},
}

// fileOrder is the file-precedence order (see the package comment above).
var fileOrder = []string{"openresty", "angie", "cfm-edge"}

// CanonicalLuaToken is the shared, current location of cfm_token.lua.
const CanonicalLuaToken = "/var/lib/cfm/lua/cfm_token.lua"

// Names returns the engine names in detection order.
func Names() []string {
	out := make([]string, 0, len(Profiles))
	for _, p := range Profiles {
		out = append(out, p.Name)
	}
	return out
}

// Lookup returns the profile of the engine named EXACTLY name (the canonical,
// lowercase engine name, e.g. "angie"). Exact on purpose: the checks it
// replaced were exact, and callers go on to use the string as given (unit
// names, reload commands); a caller that wants leniency normalises first.
func Lookup(name string) (Profile, bool) {
	for _, p := range Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// NameList is the engine names joined for a message ("angie/openresty/…").
func NameList() string { return strings.Join(Names(), "/") }

// IsEdge reports whether name is exactly a CFM edge engine's name.
func IsEdge(name string) bool {
	_, ok := Lookup(name)
	return ok
}

// InFileOrder returns the profiles in file-precedence order.
func InFileOrder() []Profile {
	out := make([]Profile, 0, len(fileOrder))
	for _, n := range fileOrder {
		if p, ok := Lookup(n); ok {
			out = append(out, p)
		}
	}
	return out
}

// LuaTokenCandidates is where cfm_token.lua is looked for: the shared path
// first, then each engine's legacy Lua dir in file-precedence order.
func LuaTokenCandidates() []string {
	out := []string{CanonicalLuaToken}
	for _, p := range InFileOrder() {
		if p.LegacyLuaDir == "" {
			continue // an engine that never had a legacy Lua dir (cfm-edge)
		}
		out = append(out, p.LegacyLuaDir+"/cfm_token.lua")
	}
	return out
}

// ConfFileCandidates is name inside each engine's config dir, in
// file-precedence order.
func ConfFileCandidates(name string) []string {
	out := make([]string, 0, len(fileOrder))
	for _, p := range InFileOrder() {
		out = append(out, p.ConfPath(name))
	}
	return out
}

// LogFileCandidates is name inside each engine's log dir, in file-precedence
// order.
func LogFileCandidates(name string) []string {
	out := make([]string, 0, len(fileOrder))
	for _, p := range InFileOrder() {
		out = append(out, p.LogPath(name))
	}
	return out
}

// Units returns the engines' systemd unit names in detection order.
func Units() []string {
	out := make([]string, 0, len(Profiles))
	for _, p := range Profiles {
		out = append(out, p.Unit())
	}
	return out
}
