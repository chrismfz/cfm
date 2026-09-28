package webdetector

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"time"
)

// Decision-side mirror of cfm.lua Step 0d (CLAUDE.md §6: a path-based
// challenge exemption needs both sides). The edge passes cPanel's own session
// API on a proxy subdomain straight to cpsrvd; the engine keeps the same
// requests out of per-IP scoring (Engine.ingest).
//
// The three lists mirror configs/lua/cfm_panel_hosts.lua (PROXY_PREFIXES,
// SESSION_KINDS, SECOND_LEVEL_LABELS). panel_session_api_test.go reads them out
// of the .lua file and compares the sets, and runs the shared vectors in
// scripts/tests/fixtures/panel_session_api.txt that cfm_panel_hosts_test.lua
// runs too. So neither side can change alone.
var (
	panelProxyPrefixes = map[string]bool{"cpanel": true, "whm": true, "webmail": true}
	panelSessionKinds  = map[string]bool{"json-api": true, "execute": true, "xml-api": true, "login": true, "websocket": true}
	panelSecondLevel   = map[string]bool{
		"com": true, "net": true, "org": true, "edu": true, "gov": true, "co": true, "ac": true, "or": true,
		"ne": true, "go": true, "mil": true, "nom": true, "gen": true, "biz": true, "info": true,
	}
)

// isPanelSessionAPIChallengeExempt reports whether a request is cPanel's own
// session API on a cPanel proxy subdomain: the host and path gates of Step 0d.
// Pure; the node-config gate is panelProxyHostsReachPanel.
func isPanelSessionAPIChallengeExempt(host, p string) bool {
	return isPanelProxyHost(host) && isPanelSessionAPIPath(p)
}

// isPanelProxyHost mirrors cfm_panel_hosts.is_proxy_panel_host: a cpanel./
// whm./webmail. prefix on a registrable domain. At least three labels, and
// exactly three only if the middle one is not a second-level name under a
// two-letter ccTLD (`cpanel.com.gr` is a tenant's own domain). A port or an
// empty label (trailing dot) fails it.
func isPanelProxyHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if strings.Contains(h, ":") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < 3 || !panelProxyPrefixes[labels[0]] {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	if len(labels) == 3 && panelSecondLevel[labels[1]] && len(labels[2]) == 2 {
		return false
	}
	return true
}

// isPanelSessionAPIPath mirrors cfm_panel_hosts.is_session_api:
// /cpsess<digits>/{json-api,execute,xml-api,login,websocket}/…, case-
// insensitive (the log parser lowercases every URI, so the edge matches
// case-insensitively too). It sees the RAW request target, unlike the edge's
// nginx-decoded one, so the query string is stripped and any `%` or `..`
// refuses the exemption (as isWellKnownChallengeExempt does).
func isPanelSessionAPIPath(p string) bool {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	lp := strings.ToLower(p)
	if strings.Contains(lp, "%") || strings.Contains(lp, "..") || !strings.HasPrefix(lp, "/cpsess") {
		return false
	}
	lp = lp[len("/cpsess"):]
	n := 0
	for n < len(lp) && lp[n] >= '0' && lp[n] <= '9' {
		n++
	}
	if n == 0 || n >= len(lp) || lp[n] != '/' {
		return false
	}
	lp = lp[n+1:]
	slash := strings.IndexByte(lp, '/')
	if slash <= 0 {
		return false
	}
	return panelSessionKinds[lp[:slash]]
}

// cpanelConfigPath is a var so tests point it at a temp file (CLAUDE.md §5:
// tests never touch live system paths).
var cpanelConfigPath = "/var/cpanel/cpanel.config"

const panelProxyReachTTL = 60 * time.Second

var panelProxyReach struct {
	mu sync.Mutex
	at time.Time
	on bool
}

// panelProxyHostsReachPanel mirrors cfm_panel_hosts.proxy_hosts_reach_panel:
// true only when cpanel.config has proxysubdomains=1 AND
// proxysubdomainsoverride=0. Only then does every cpanel./whm./webmail. Host
// reach cpsrvd. Anywhere else the edge does NOT pass these requests through,
// and exempting them here would let a spoofed Host hide a flood or a scan from
// the engine. Fail closed: an unreadable file or an absent key reads as off.
// Cached for panelProxyReachTTL.
func panelProxyHostsReachPanel(now time.Time) bool {
	panelProxyReach.mu.Lock()
	defer panelProxyReach.mu.Unlock()
	if !panelProxyReach.at.IsZero() && now.Sub(panelProxyReach.at) < panelProxyReachTTL {
		return panelProxyReach.on
	}
	panelProxyReach.at, panelProxyReach.on = now, readPanelProxyReach(cpanelConfigPath)
	return panelProxyReach.on
}

func readPanelProxyReach(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var proxy, override string
	var haveProxy, haveOverride bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "proxysubdomains":
			proxy, haveProxy = v, true
		case "proxysubdomainsoverride":
			override, haveOverride = v, true
		}
		if haveProxy && haveOverride {
			break
		}
	}
	return proxy == "1" && override == "0"
}

// resetPanelProxyReachForTest drops the cached answer.
func resetPanelProxyReachForTest() {
	panelProxyReach.mu.Lock()
	panelProxyReach.at, panelProxyReach.on = time.Time{}, false
	panelProxyReach.mu.Unlock()
}
