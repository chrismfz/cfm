package dnat

import (
	"bytes"
	"fmt"
	"io"
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
)

var panelMap = map[int]int{2082: 12082, 2083: 12083, 2086: 12086, 2087: 12087, 2095: 12095, 2096: 12096, 2222: 12222}
var panelTargetPorts = []int{12082, 12083, 12086, 12087, 12095, 12096, 12222}

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
	if err := os.MkdirAll(filepath.Dir(panelChallengeModeStatePath), 0o755); err != nil {
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

func panelStatus() (bool, string, error) {
	out := runOut("nft", "list", "table", "inet", "cfm_panel_redirect")
	if strings.Contains(out, "No such file") || strings.Contains(out, "does not exist") {
		return false, "", nil
	}
	if strings.TrimSpace(out) == "" {
		return false, "", nil
	}
	return true, out, nil
}

func panelScript(priority int) string {
	ports := []int{2082, 2083, 2086, 2087, 2095, 2096, 2222}
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet cfm_panel_redirect\n")
	fmt.Fprintf(&b, "add chain inet cfm_panel_redirect prerouting { type nat hook prerouting priority %d; policy accept; }\n", priority)
	b.WriteString("add rule inet cfm_panel_redirect prerouting iif \"lo\" accept\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "add rule inet cfm_panel_redirect prerouting tcp dport %d dnat to :%d\n", p, panelMap[p])
	}
	return b.String()
}

func panelOn(priority int) error {
	_ = exec.Command("nft", "delete", "table", "inet", "cfm_panel_redirect").Run()
	s := panelScript(priority)
	c := exec.Command("nft", "-f", "-")
	in, _ := c.StdinPipe()
	go func() { _, _ = io.WriteString(in, s); _ = in.Close() }()
	return c.Run()
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
	paths := []string{"/etc/angie/cfm-panel-listeners.conf", "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf", "configs/cfm-panel-listeners.conf.in"}
	mode, loaded, _ := panelListenerGuardStateFromPaths(paths)
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
		return fmt.Errorf("ambiguous active panel listener services: both angie and openresty are active and the loaded panel listener config is not unique")
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

var panelListenerServiceDetector = detectActivePanelListenerService
var panelListenerProcessDetector = detectEdgeService

const panelListenerServiceAmbiguous = "__ambiguous__"

func systemctlServiceIsActive(service string) bool {
	return execCommand("systemctl", "is-active", "--quiet", service).Run() == nil
}

func panelListenerServiceIsConfirmedActive(service string) bool {
	if systemctlServiceIsActive(service) {
		return true
	}
	return panelListenerProcessDetector() == service
}

func activePanelListenerServicesFromSystemd() []string {
	var active []string
	for _, service := range []string{"angie", "openresty"} {
		if systemctlServiceIsActive(service) {
			active = append(active, service)
		}
	}
	return active
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

func detectActivePanelListenerService() string {
	active := activePanelListenerServicesFromSystemd()
	switch len(active) {
	case 1:
		return active[0]
	case 2:
		var loadedServices []string
		for _, service := range active {
			_, loaded, _ := panelListenerGuardStateFromPaths(panelListenerConfigPathsForService(service, panelListenerChallengeConfigPaths))
			if loaded {
				loadedServices = append(loadedServices, service)
			}
		}
		if len(loadedServices) == 1 {
			return loadedServices[0]
		}
		return panelListenerServiceAmbiguous
	}

	_, _, path := panelListenerGuardStateFromPaths(panelListenerChallengeConfigPaths)
	return panelListenerConfigPathService(path)
}

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

func panelLuaGuardPath() string {
	for _, p := range []string{"/etc/angie/cfm-panel-listeners.conf", "/usr/local/openresty/nginx/conf/cfm-panel-listeners.conf", "configs/cfm-panel-listeners.conf.in"} {
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

func panelLuaGuardProbes() []panelLuaProbe {
	selftest := `package.path='/var/lib/cfm/lua/?.lua;'..package.path; ngx={log=function() end,ERR=3,WARN=4,NOTICE=5,INFO=6,HTTP_FORBIDDEN=403,HTTP_INTERNAL_SERVER_ERROR=500,HTTP_NOT_FOUND=404,time=os.time,now=os.time,escape_uri=function(s) return tostring(s or '') end,unescape_uri=function(s) return tostring(s or '') end,var={},header={},ctx={},req={get_method=function() return 'GET' end,is_internal=function() return true end},exit=function(code) return code end}; local ok,a,b=pcall(dofile,arg[1]); if not ok then error(a) end; if a==false then error(b or 'selftest failed') end; return`
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
		args := append(append([]string{}, probe.Args...), cmdPath)
		cmd := execCommand(probe.Name, args...)
		if probe.UseEnv {
			cmd.Env = append(os.Environ(), "CFM_PANEL_SELFTEST_ONLY=1")
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
