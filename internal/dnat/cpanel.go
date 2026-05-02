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
	"sort"
	"strings"
	"time"
)

var panelMap = map[int]int{2082: 12082, 2083: 12083, 2086: 12086, 2087: 12087, 2095: 12095, 2096: 12096, 2222: 12222}
var panelTargetPorts = []int{12082, 12083, 12086, 12087, 12095, 12096, 12222}

type panelOpts struct {
	mode      string
	priority  int
	challenge string
}

const defaultPanelChallengeMode = "guard-only"

var supportedPanelChallengeModes = []string{defaultPanelChallengeMode}
var panelChallengeModeStatePath = "/var/lib/cfm/panel_challenge_mode"

func isSupportedPanelChallengeMode(mode string) bool {
	for _, m := range supportedPanelChallengeModes {
		if mode == m {
			return true
		}
	}
	return false
}

func persistPanelChallengeMode(mode string) error {
	if !isSupportedPanelChallengeMode(mode) {
		return fmt.Errorf("unsupported challenge mode %q (supported: %s)", mode, strings.Join(supportedPanelChallengeModes, ", "))
	}
	if err := os.MkdirAll(filepath.Dir(panelChallengeModeStatePath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(panelChallengeModeStatePath, []byte(mode+"\n"), 0o644)
}

func loadPersistedPanelChallengeMode() string {
	b, err := os.ReadFile(panelChallengeModeStatePath)
	if err != nil {
		return ""
	}
	mode := strings.TrimSpace(string(b))
	if !isSupportedPanelChallengeMode(mode) {
		return ""
	}
	return mode
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
	return panelListenerGuardStateFromPaths(paths)
}

func panelListenerGuardStateFromPaths(paths []string) (string, bool) {
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := string(b)
		mode := "unknown"
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
		return mode, loaded
	}
	return "unknown", false
}

type panelLuaGuardStatus struct {
	Path      string
	Exists    bool
	Readable  bool
	LoadState string
	LoadError string
}

func cmdExists(name string) bool {
	_, err := exec.LookPath(name)
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
	st.LoadState = "unknown"
	if cmdExists("luajit") {
		out, err := exec.Command("luajit", "-bl", cmdPath).CombinedOutput()
		if err == nil {
			st.LoadState = "true"
			return st
		}
		st.LoadState = "false"
		st.LoadError = strings.TrimSpace(string(out))
		if st.LoadError == "" {
			st.LoadError = err.Error()
		}
		return st
	}
	if cmdExists("resty") {
		out, err := exec.Command("resty", "-e", "assert(loadfile(arg[1]))", cmdPath).CombinedOutput()
		if err == nil {
			st.LoadState = "true"
			return st
		}
		st.LoadState = "false"
		st.LoadError = strings.TrimSpace(string(out))
		if st.LoadError == "" {
			st.LoadError = err.Error()
		}
		return st
	}
	for _, probe := range []string{"angie", "openresty"} {
		if !cmdExists(probe) {
			continue
		}
		out, err := exec.Command(probe, "-t").CombinedOutput()
		if err == nil {
			st.LoadError = "interpreter unavailable; relying on " + probe + " -t"
			return st
		}
		st.LoadState = "false"
		st.LoadError = strings.TrimSpace(string(out))
		if st.LoadError == "" {
			st.LoadError = err.Error()
		}
		return st
	}
	st.LoadError = "interpreter unavailable; no angie/openresty config test found"
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
