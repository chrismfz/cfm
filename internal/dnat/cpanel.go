package dnat

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/firewall"
	"cfm/internal/systemdunit"
)

var panelMap = panelMappingMap()
var panelTargetPorts = panelMappingTargetPorts()

var challengeHTTPPortRe = regexp.MustCompile(`(?:^|\s)port=(\d+)`)
var panelChallengeModeLineRe = regexp.MustCompile(`set \$cfm_panel_challenge_mode "[^"]*";`)

type panelPortAccessStats struct {
	HitsRecent           map[int]int
	LastSeenByPort       map[int]time.Time
	XferRedirect2083Seen bool
}

func readPanelPortAccessStats(path string, now time.Time, recentWindow time.Duration) panelPortAccessStats {
	stats := panelPortAccessStats{HitsRecent: map[int]int{}, LastSeenByPort: map[int]time.Time{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return stats
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "[challenge_http]") {
			continue
		}
		if strings.Contains(line, "uri=/xfercpanel") || strings.Contains(line, "uri=/xfercpsess") {
			if strings.Contains(line, "host=") && strings.Contains(line, ":2083") {
				stats.XferRedirect2083Seen = true
			}
		}
		m := challengeHTTPPortRe.FindStringSubmatch(line)
		if len(m) != 2 {
			continue
		}
		port, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		if !isPanelTargetPort(port) {
			continue
		}
		ts, ok := parseChallengeHTTPLineTime(line)
		if !ok {
			continue
		}
		if ts.After(stats.LastSeenByPort[port]) {
			stats.LastSeenByPort[port] = ts
		}
		if now.Sub(ts) <= recentWindow {
			stats.HitsRecent[port]++
		}
	}
	return stats
}

func parseChallengeHTTPLineTime(line string) (time.Time, bool) {
	if len(line) < len("2006-01-02 15:04:05") {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", line[:19], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

func isPanelTargetPort(port int) bool {
	for _, p := range panelTargetPorts {
		if p == port {
			return true
		}
	}
	return false
}

type panelOpts struct {
	mode      string
	priority  int
	challenge string
}

const panelChallengeEnabledMode = "forced"
const panelChallengeDisabledMode = "off"
const defaultPanelChallengeMode = panelChallengeEnabledMode

var panelChallengeEnabledStatePath = "/var/lib/cfm/panel_challenge_enabled"
var panelChallengeModeStatePath = panelChallengeEnabledStatePath

func setPanelChallengeModeInConfig(content, mode string) string {
	repl := fmt.Sprintf(`set $cfm_panel_challenge_mode %q;`, mode)
	return panelChallengeModeLineRe.ReplaceAllStringFunc(content, func(string) string { return repl })
}

func applyPanelChallengeModeToPaths(mode string, paths []string) error {
	enabled := mode != panelChallengeDisabledMode
	mode = panelChallengeMode(enabled)
	replaced := false
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		updated := setPanelChallengeModeInConfig(string(b), mode)
		if updated == string(b) {
			continue
		}
		replaced = true
		if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
			return fmt.Errorf("update %s: %w", path, err)
		}
	}
	if !replaced {
		return nil
	}
	return nil
}

func persistPanelChallengeEnabled(enabled bool) error {
	if err := os.MkdirAll(filepath.Dir(panelChallengeModeStatePath), cfmStateDirMode); err != nil {
		return err
	}
	v := "0\n"
	if enabled {
		v = "1\n"
	}
	return os.WriteFile(panelChallengeModeStatePath, []byte(v), 0o644)
}

func loadPersistedPanelChallengeEnabled() bool {
	b, err := os.ReadFile(panelChallengeModeStatePath)
	if err != nil {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(string(b)))
	return v == "1" || v == "true" || v == "on" || v == panelChallengeEnabledMode
}

func panelChallengeMode(enabled bool) string {
	if enabled {
		return panelChallengeEnabledMode
	}
	return panelChallengeDisabledMode
}

func panelChallengeModeChoices() string {
	return strings.Join([]string{panelChallengeDisabledMode, panelChallengeEnabledMode}, "|")
}

func persistPanelChallengeMode(mode string) error {
	return persistPanelChallengeEnabled(mode != panelChallengeDisabledMode)
}

func loadPersistedPanelChallengeMode() string {
	return panelChallengeMode(loadPersistedPanelChallengeEnabled())
}

func runOut(name string, args ...string) string {
	c := exec.Command(name, args...)
	var b bytes.Buffer
	c.Stdout = &b
	c.Stderr = &b
	_ = c.Run()
	return b.String()
}

func panelStatus() (bool, string, error) { return panelStatusWithBackend(defaultPanelBackend()) }

func panelStatusWithBackend(backend firewall.Backend) (bool, string, error) {
	if backend == nil {
		return false, "", fmt.Errorf("backend does not support panel DNAT")
	}
	return backend.PanelDNATStatus()
}

func panelOn(priority int) error { return panelOnWithBackend(defaultPanelBackend(), priority) }

func panelOnWithBackend(backend firewall.Backend, priority int) error {
	if backend == nil {
		return fmt.Errorf("backend does not support panel DNAT")
	}
	return backend.PanelDNATOn(priority)
}

func panelListenerState(port int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
	if err != nil {
		return "down"
	}
	_ = conn.Close()
	return "listening"
}

func detectedImunifyMappings() []string {
	rules := runOut("nft", "-a", "list", "ruleset") + "\n" + runOut("iptables-save", "-t", "nat") + "\n" + runOut("ip6tables-save", "-t", "nat")
	pairs := map[string]string{"2087": "52227", "2083": "52229", "2096": "52231", "2082": "52230", "2086": "52228", "2095": "52232", "443": "52223", "80": "52224"}
	var got []string
	for s, d := range pairs {
		if strings.Contains(rules, s) && strings.Contains(rules, d) {
			got = append(got, fmt.Sprintf("%s->%s", s, d))
		}
	}
	sort.Strings(got)
	return got
}

func panelListenerGuardState() (string, bool) {
	mode, loaded, _ := panelListenerGuardStateFromPaths(orderedPanelListenerConfigPaths())
	return mode, loaded
}

func panelListenerGuardStateFromPaths(paths []string) (string, bool, string) {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(b)
		mode := panelChallengeDisabledMode
		if i := strings.Index(s, "set $cfm_panel_challenge_mode "); i >= 0 {
			line := s[i:]
			if j := strings.Index(line, "\n"); j >= 0 {
				line = line[:j]
			}
			if q := strings.Split(line, "\""); len(q) >= 2 {
				mode = q[1]
			}
		}
		loaded := strings.Contains(s, "access_by_lua_file") && strings.Contains(s, "cfm_panel.lua")
		return mode, loaded, p
	}
	return "unknown", false, ""
}

type panelDecisionEndpointProbe struct {
	Status string
	Path   string
	Detail string
}

func probePanelDecisionEndpoint(paths []string) panelDecisionEndpointProbe {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(b)
		hasExact := strings.Contains(s, "location = /__cfm_panel_decide")
		hasLoose := strings.Contains(s, "location /__cfm_panel_decide")
		if hasExact && !hasLoose {
			return panelDecisionEndpointProbe{Status: "OK", Path: p}
		}
		if hasLoose && !hasExact {
			return panelDecisionEndpointProbe{Status: "MISROUTED", Path: p, Detail: "non-exact location stanza detected; expected `location = /__cfm_panel_decide`"}
		}
		if !hasExact {
			return panelDecisionEndpointProbe{Status: "MISSING", Path: p, Detail: "exact location stanza not found"}
		}
		return panelDecisionEndpointProbe{Status: "MISROUTED", Path: p, Detail: "conflicting endpoint stanzas detected"}
	}
	return panelDecisionEndpointProbe{Status: "MISSING", Detail: "listener config not found"}
}

func reloadPanelListenerService() error {
	active := panelListenerServiceDetector()
	if active == panelListenerServiceAmbiguous {
		return fmt.Errorf("ambiguous active panel listener services: both angie and openresty are active/enabled; exactly one edge service must be active and enabled")
	}
	if active == "" {
		return fmt.Errorf("no authoritative angie/openresty edge service detected; exactly one should be active+enabled (or uniquely enabled while stopped)")
	}
	candidates := panelListenerServiceCandidates(active)
	var lastErr error
	primary := active
	fallbackSucceeded := false
	for _, c := range candidates {
		svc := c[2]
		if err := execCommand(c[0], c[1:]...).Run(); err == nil {
			if primary == "" || svc == primary {
				return nil
			}
			fallbackSucceeded = true
			if panelListenerServiceIsConfirmedActive(svc) {
				return nil
			}
			continue
		} else {
			lastErr = err
		}
	}
	if fallbackSucceeded {
		return fmt.Errorf("reload/restart listener service for active service %q failed despite fallback service success from an unconfirmed fallback service", primary)
	}
	if lastErr == nil {
		return fmt.Errorf("no angie/openresty service command candidates")
	}
	return fmt.Errorf("reload/restart listener service failed: %w", lastErr)
}

var panelListenerServiceDetector = detectActiveEdgeService
var panelListenerProcessDetector = detectEdgeService
var panelSystemdUnitProbe = systemdunit.Probe

const panelListenerServiceAmbiguous = "__ambiguous__"

func panelServiceUnit(service string) string {
	service = strings.TrimSpace(service)
	if strings.HasSuffix(service, ".service") {
		return service
	}
	return service + ".service"
}

func systemctlServiceIsActive(service string) bool {
	st, ok := panelSystemdUnitProbe(panelServiceUnit(service))
	return ok && st.Active
}

func panelListenerServiceIsConfirmedActive(service string) bool {
	if systemctlServiceIsActive(service) {
		return true
	}
	return panelListenerProcessDetector() == service
}

func panelListenerConfigPathsForService(service string, paths []string) []string {
	var servicePaths []string
	for _, path := range paths {
		if panelListenerConfigPathService(path) == service {
			servicePaths = append(servicePaths, path)
		}
	}
	return servicePaths
}

func panelListenerConfigPathService(path string) string {
	switch {
	case strings.Contains(path, "/etc/angie/"):
		return "angie"
	case strings.Contains(path, "/openresty/"):
		return "openresty"
	default:
		return ""
	}
}

// detectActiveEdgeService uses the same active/enabled systemd model surfaced
// by `cfm health`. A normal node may have both engines installed, but exactly
// one is expected to be active+enabled. If neither is active, a unique enabled
// service is the intended engine and may be restarted. If systemd is unavailable
// we fall back to the running-process detector; stale config files are never used
// to decide which engine is live. Both web DNAT and panel DNAT consume this resolver.
func detectActiveEdgeService() string {
	services := []string{"angie", "openresty"}
	states := make(map[string]systemdunit.Status, len(services))
	systemdAvailable := false
	for _, service := range services {
		st, ok := panelSystemdUnitProbe(panelServiceUnit(service))
		if !ok {
			continue
		}
		systemdAvailable = true
		states[service] = st
	}
	if systemdAvailable {
		var activeEnabled []string
		var active []string
		var enabled []string
		for _, service := range services {
			st := states[service]
			if st.Enabled {
				enabled = append(enabled, service)
			}
			if st.Active {
				active = append(active, service)
				if st.Enabled {
					activeEnabled = append(activeEnabled, service)
				}
			}
		}
		switch len(activeEnabled) {
		case 1:
			return activeEnabled[0]
		case 2:
			return panelListenerServiceAmbiguous
		}
		switch len(active) {
		case 1:
			// Tolerate a manually-started service or a transient enable-state
			// mismatch, but runtime activity still wins over stale files.
			return active[0]
		case 2:
			return panelListenerServiceAmbiguous
		}
		if len(enabled) == 1 {
			return enabled[0]
		}
		return ""
	}

	if service := panelListenerProcessDetector(); service == "angie" || service == "openresty" {
		return service
	}
	return ""
}

// Kept as a compatibility/test seam for the existing panel-specific callers.
func detectActivePanelListenerService() string { return detectActiveEdgeService() }

func panelListenerServiceCandidates(active string) [][]string {
	if active == panelListenerServiceAmbiguous {
		return nil
	}
	serviceCommands := func(service string) [][]string {
		return [][]string{
			{"systemctl", "reload", service},
			{"service", service, "reload"},
			{"systemctl", "restart", service},
			{"service", service, "restart"},
		}
	}
	if active == "angie" {
		return append(serviceCommands("angie"), serviceCommands("openresty")...)
	}
	if active == "openresty" {
		return append(serviceCommands("openresty"), serviceCommands("angie")...)
	}
	return append(serviceCommands("angie"), serviceCommands("openresty")...)
}

type panelLuaGuardStatus struct {
	Path      string
	Exists    bool
	Readable  bool
	LoadState string
	LoadError string
}

var lookPath = exec.LookPath

func cmdExists(name string) bool {
	_, err := lookPath(name)
	return err == nil
}

// orderedPanelListenerConfigPaths is intentionally strict once the live edge
// engine is known: diagnostics may inspect only that engine's listener config.
// An installed-but-inactive peer must never become a fallback "active file".
// When no service is detectable we retain only service-neutral repo/test paths;
// an ambiguous dual-active state yields no authoritative config at all.
func orderedPanelListenerConfigPaths() []string {
	active := panelListenerServiceDetector()
	if active == "angie" || active == "openresty" {
		return panelListenerConfigPathsForService(active, panelListenerChallengeConfigPaths)
	}
	if active == panelListenerServiceAmbiguous {
		return nil
	}
	var neutral []string
	for _, p := range panelListenerChallengeConfigPaths {
		if panelListenerConfigPathService(p) == "" {
			neutral = append(neutral, p)
		}
	}
	return neutral
}

func panelLuaGuardPath() string {
	for _, p := range orderedPanelListenerConfigPaths() {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(b)
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "access_by_lua_file ") && strings.Contains(line, "cfm_panel.lua") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "access_by_lua_file "))
				return strings.TrimSuffix(v, ";")
			}
		}
	}
	return ""
}

func checkPanelLuaGuard(path string) panelLuaGuardStatus {
	st := panelLuaGuardStatus{Path: path}
	if path == "" {
		st.LoadError = "path not configured"
		return st
	}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		st.Exists = true
	} else if err != nil {
		st.LoadError = err.Error()
		return st
	} else {
		st.LoadError = "path is a directory, expected lua file"
		return st
	}
	if f, err := os.Open(path); err == nil {
		_ = f.Close()
		st.Readable = true
	} else {
		st.LoadError = err.Error()
		return st
	}
	cmdPath := path
	if !filepath.IsAbs(cmdPath) {
		if abs, err := filepath.Abs(cmdPath); err == nil {
			cmdPath = abs
		}
	}
	return runPanelLuaGuardProbe(st, cmdPath)
}

type panelLuaProbe struct {
	Name   string
	Args   []string
	Syntax bool
	UseEnv bool
}

// panelLuaSelftestScript is shared in contract with the two proxy installers.
// The target module path is supplied via CFM_PANEL_SELFTEST_PATH instead of as
// a positional Lua argument: plain lua/luajit otherwise auto-execute the file
// after `-e`, and arg[] semantics differ from resty's runner. The generic
// ngx.shared fake covers any load-time shared-dict access, not only the current
// cfm_decisions dictionary.
func panelLuaSelftestScript() string {
	return `package.path='/var/lib/cfm/lua/?.lua;'..package.path; local path=os.getenv('CFM_PANEL_SELFTEST_PATH'); if not path or path=='' then error('CFM_PANEL_SELFTEST_PATH missing') end; ngx={log=function() end,ERR=3,WARN=4,NOTICE=5,INFO=6,HTTP_FORBIDDEN=403,HTTP_INTERNAL_SERVER_ERROR=500,HTTP_NOT_FOUND=404,time=os.time,now=os.time,escape_uri=function(s) return tostring(s or '') end,unescape_uri=function(s) return tostring(s or '') end,var={},header={},ctx={},shared=setmetatable({},{__index=function(t,k) local d={get=function() return nil end,set=function() return true end,add=function() return true end,replace=function() return false end,delete=function() return true end,incr=function() return nil end,len=function() return 0 end,touch=function() return true end,flush_all=function() return true end,flush_expired=function() return 0 end,capacity=function() return 0 end,free_space=function() return 0 end}; rawset(t,k,d); return d end}),req={get_method=function() return 'GET' end,is_internal=function() return true end},exit=function(code) return code end}; local ok,a,b=pcall(dofile,path); if not ok then error(a) end; if a==false then error(b or 'selftest failed') end; return`
}

func panelLuaGuardProbes() []panelLuaProbe {
	selftest := panelLuaSelftestScript()
	return []panelLuaProbe{
		{Name: "resty", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "luajit", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "lua", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "lua5.1", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "lua5.4", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "lua5.3", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "lua5.2", Args: []string{"-e", selftest}, UseEnv: true},
		{Name: "luac", Args: []string{"-p"}, Syntax: true},
		{Name: "luac5.1", Args: []string{"-p"}, Syntax: true},
		{Name: "luac5.4", Args: []string{"-p"}, Syntax: true},
		{Name: "luac5.3", Args: []string{"-p"}, Syntax: true},
		{Name: "luac5.2", Args: []string{"-p"}, Syntax: true},
	}
}

func runPanelLuaGuardProbe(st panelLuaGuardStatus, cmdPath string) panelLuaGuardStatus {
	st.LoadState = "unknown"
	for _, probe := range panelLuaGuardProbes() {
		if !cmdExists(probe.Name) {
			continue
		}
		args := append([]string{}, probe.Args...)
		if probe.Syntax {
			args = append(args, cmdPath)
		}
		cmd := execCommand(probe.Name, args...)
		if probe.UseEnv {
			cmd.Env = append(os.Environ(), "CFM_PANEL_SELFTEST_ONLY=1", "CFM_PANEL_SELFTEST_PATH="+cmdPath)
		}
		out, err := cmd.CombinedOutput()
		msg := strings.TrimSpace(string(out))
		if err == nil {
			if probe.Syntax {
				st.LoadError = "selftest interpreter unavailable; " + probe.Name + " syntax check passed"
				return st
			}
			if strings.Contains(msg, "CFM_PANEL_SELFTEST_HOOK_MISSING") {
				st.LoadState = "unknown"
				st.LoadError = ""
				return st
			}
			st.LoadState = "true"
			st.LoadError = ""
			return st
		}
		st.LoadState = "false"
		if msg == "" {
			msg = err.Error()
		}
		st.LoadError = probe.Name + " failed: " + msg
		return st
	}
	for _, probe := range []string{"angie", "openresty"} {
		if !cmdExists(probe) {
			continue
		}
		out, err := execCommand(probe, "-t").CombinedOutput()
		if err == nil {
			st.LoadError = "selftest interpreter unavailable; relying on " + probe + " -t"
			return st
		}
		st.LoadState = "false"
		st.LoadError = strings.TrimSpace(string(out))
		if st.LoadError == "" {
			st.LoadError = err.Error()
		}
		return st
	}
	st.LoadError = "selftest interpreter unavailable; no resty/lua/luajit/luac or angie/openresty config test found"
	return st
}

func panelLuaReadableByWorker(path string) (bool, string) {
	u, err := user.Lookup("cfm")
	if err != nil {
		return false, "worker user cfm not present"
	}
	out, err := exec.Command("sudo", "-u", u.Username, "test", "-r", path).CombinedOutput()
	if err == nil {
		return true, ""
	}
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		msg = err.Error()
	}
	return false, msg
}