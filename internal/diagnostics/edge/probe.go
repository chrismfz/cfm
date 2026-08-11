package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type LuaTokenProbe struct {
	Token          string
	Present, Valid bool
}
type SSLCollectorProbe struct{ Path, UID, GID, Mode, Category, ErrorText, StatsSummary string }
type BridgeRuntimeConfig struct {
	Enabled                                     bool
	SocketPath, DisplaySocketPath, SocketSource string
}
type BridgeRuntimeProbe struct {
	Status, Details, TokenPath, ModeText string
	HTTPStatus                           int
}

func (p BridgeRuntimeProbe) Summary() string {
	if strings.TrimSpace(p.Details) == "" {
		return p.Status
	}
	return p.Status + " (" + p.Details + ")"
}

const CanonicalBridgeTokenPath = "/var/lib/cfm/lua/cfm_bridge_token.lua"

var luaReturnRe = regexp.MustCompile(`(?m)^\s*return\s+["']([^"']+)["']\s*$`)
var badTokenRe = regexp.MustCompile(`(?i)^(supersecret|changeme|secret|password|default|token|test|demo|placeholder)$`)

func ResolveLuaToken(paths []string) LuaTokenProbe {
	for _, p := range paths {
		t := ReadLuaToken(p)
		if t.Present {
			return t
		}
	}
	return LuaTokenProbe{}
}
func ReadLuaToken(path string) LuaTokenProbe {
	b, err := os.ReadFile(path)
	if err != nil {
		return LuaTokenProbe{}
	}
	m := luaReturnRe.FindSubmatch(b)
	if len(m) < 2 {
		return LuaTokenProbe{Present: true}
	}
	tok := strings.TrimSpace(string(m[1]))
	return LuaTokenProbe{Token: tok, Present: true, Valid: IsStrongToken(tok)}
}
func IsStrongToken(tok string) bool {
	t := strings.TrimSpace(tok)
	return len(t) >= 32 && !badTokenRe.MatchString(t)
}
func TokenHealth(t LuaTokenProbe) string {
	if !t.Present {
		return "MISSING"
	}
	if !t.Valid {
		return "INVALID"
	}
	return "OK"
}

func ReadDetectorSectionKV(path, section string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	want := strings.ToLower(strings.TrimSpace(section))
	current := ""
	for _, raw := range strings.Split(string(b), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if end := strings.Index(line, "]"); end > 1 {
				current = strings.ToLower(strings.TrimSpace(line[1:end]))
			}
			continue
		}
		if current != want {
			continue
		}
		i := strings.Index(line, "=")
		if i <= 0 {
			continue
		}
		key := strings.ToUpper(strings.TrimSpace(line[:i]))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(line[i+1:])
	}
	return out
}

func ReadChallengeTokenProbe(path string) LuaTokenProbe {
	if tok := strings.TrimSpace(os.Getenv("CHALLENGE_TOKEN")); tok != "" {
		return LuaTokenProbe{Token: tok, Present: true, Valid: IsStrongToken(tok)}
	}
	kv := ReadDetectorSectionKV(path, "webdetector")
	if v, ok := kv["CHALLENGE_TOKEN"]; ok {
		if clean := strings.Trim(strings.TrimSpace(stripInlineComment(v)), `"'`); clean != "" {
			return LuaTokenProbe{Token: clean, Present: true, Valid: IsStrongToken(clean)}
		}
	}
	return LuaTokenProbe{}
}

func ReadBridgeTokenProbe(path string) LuaTokenProbe {
	if t := ReadLuaToken(path); t.Present {
		return t
	}
	if tok := strings.TrimSpace(os.Getenv("OPENRESTY_TOKEN")); tok != "" {
		return LuaTokenProbe{Token: tok, Present: true, Valid: IsStrongToken(tok)}
	}
	if tok := strings.TrimSpace(os.Getenv("BRIDGE_TOKEN")); tok != "" {
		return LuaTokenProbe{Token: tok, Present: true, Valid: IsStrongToken(tok)}
	}
	return LuaTokenProbe{}
}

func ResolveBridgeRuntimeConfig(path string) BridgeRuntimeConfig {
	return ResolveBridgeRuntimeConfigWithStat(path, os.Stat)
}

func ResolveBridgeRuntimeConfigWithStat(path string, statFn func(string) (os.FileInfo, error)) BridgeRuntimeConfig {
	const (
		defaultSockPath = "/var/run/cfm/cfm_nginx.sock"
		legacySockPath  = "/var/run/cfm_nginx.sock"
	)
	// Edge mode is the only mode: the bridge is always on, so the probe always
	// runs. OPENRESTY_MODE is deprecated and ignored (only OPENRESTY_SOCK is
	// still honored for a custom socket path).
	cfg := BridgeRuntimeConfig{Enabled: true, SocketPath: defaultSockPath, SocketSource: "fallback"}
	kv := ReadDetectorSectionKV(path, "webdetector")
	if v, ok := kv["OPENRESTY_SOCK"]; ok {
		if clean := strings.Trim(strings.TrimSpace(stripInlineComment(v)), `"'`); clean != "" {
			cfg.SocketPath = clean
			cfg.SocketSource = "config"
		}
	}
	if cfg.SocketSource == "fallback" {
		if _, err := statFn(cfg.SocketPath); err != nil {
			if _, legacyErr := statFn(legacySockPath); legacyErr == nil {
				cfg.SocketPath = legacySockPath
			}
		}
	}
	cfg.DisplaySocketPath = NormalizeRunPathForDisplay(cfg.SocketPath)
	return cfg
}

func NormalizeRunPathForDisplay(path string) string {
	trim := strings.TrimSpace(path)
	if trim == "/run" || strings.HasPrefix(trim, "/run/") {
		return "/var" + trim
	}
	if trim == "/var/run" || strings.HasPrefix(trim, "/var/run/") {
		return trim
	}
	return trim
}

func stripInlineComment(s string) string {
	inQuote := false
	var q rune
	prevNonSpace := -1
	for i, c := range s {
		if c == '\'' || c == '"' {
			if !inQuote {
				inQuote = true
				q = c
			} else if q == c {
				inQuote = false
			}
			if c != ' ' && c != '	' {
				prevNonSpace = i
			}
			continue
		}
		if inQuote {
			if c != ' ' && c != '	' {
				prevNonSpace = i
			}
			continue
		}
		if c == ';' || c == '#' {
			return strings.TrimSpace(s[:i])
		}
		if c == '/' && i+1 < len(s) && s[i+1] == '/' {
			if prevNonSpace >= 0 && s[prevNonSpace] == ':' {
				// probably URL
			} else if i == 0 || s[i-1] == ' ' || s[i-1] == '	' {
				return strings.TrimSpace(s[:i])
			}
		}
		if c != ' ' && c != '	' {
			prevNonSpace = i
		}
	}
	return strings.TrimSpace(s)
}

func ProbeSSLCollector(path string, token LuaTokenProbe) SSLCollectorProbe {
	out := SSLCollectorProbe{Path: path, UID: "-", GID: "-", Mode: "-", Category: "MISSING"}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out
		}
		out.Category = "INVALID"
		out.ErrorText = ": " + shortErr(err)
		return out
	}
	mode := st.Mode().Perm()
	out.Mode = fmt.Sprintf("0%03o", mode)
	if st.Mode()&os.ModeSocket == 0 {
		out.Category = "INVALID"
		out.ErrorText = ": not a unix socket"
		return out
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		out.Category = "INVALID"
		out.ErrorText = ": stat metadata unavailable"
		return out
	}
	out.UID = uidText(stat.Uid)
	out.GID = gidText(stat.Gid)
	if !socketPermsOK(stat, mode) {
		out.Category = "FS_PERM_WARN"
		out.ErrorText = ": expected root:cfm 0660"
		return out
	}
	if !token.Valid {
		out.Category = "AUTH_FAIL"
		out.ErrorText = ": token missing/invalid"
		return out
	}
	c, s, e := probeSSLCollectorHTTP(path, token.Token)
	out.Category = c
	out.StatsSummary = s
	if e != "" {
		out.ErrorText = ": " + e
	}
	return out
}
func ProbeNginxBridgeRuntime(cfg BridgeRuntimeConfig, bridgeToken LuaTokenProbe) BridgeRuntimeProbe {
	out := BridgeRuntimeProbe{Status: "DISABLED", TokenPath: CanonicalBridgeTokenPath, ModeText: "disabled"}
	if cfg.Enabled {
		out.ModeText = "enabled"
	} else {
		return out
	}
	if !bridgeToken.Present {
		return BridgeRuntimeProbe{Status: "TOKEN_MISSING", Details: "canonical bridge token not found", TokenPath: out.TokenPath, ModeText: out.ModeText}
	}
	if !bridgeToken.Valid {
		return BridgeRuntimeProbe{Status: "TOKEN_INVALID", Details: "canonical bridge token failed policy", TokenPath: out.TokenPath, ModeText: out.ModeText}
	}
	st, err := os.Stat(cfg.SocketPath)
	if err != nil {
		if os.IsNotExist(err) {
			return BridgeRuntimeProbe{Status: "MISSING", Details: "socket path missing", TokenPath: out.TokenPath, ModeText: out.ModeText}
		}
		return BridgeRuntimeProbe{Status: "CONNECT_FAIL", Details: shortErr(err), TokenPath: out.TokenPath, ModeText: out.ModeText}
	}
	if st.Mode()&os.ModeSocket == 0 {
		return BridgeRuntimeProbe{Status: "MISSING", Details: "path exists but is not unix socket", TokenPath: out.TokenPath, ModeText: out.ModeText}
	}
	h, b, err := probeNginxBridgeSocket(cfg.SocketPath, bridgeToken.Token)
	if err != nil {
		return BridgeRuntimeProbe{Status: "CONNECT_FAIL", Details: shortErr(err), TokenPath: out.TokenPath, ModeText: out.ModeText}
	}
	if h == 200 {
		return BridgeRuntimeProbe{Status: "OK", Details: b, TokenPath: out.TokenPath, ModeText: out.ModeText, HTTPStatus: h}
	}
	if h == 401 || h == 403 {
		return BridgeRuntimeProbe{Status: "AUTH_FAIL", Details: fmt.Sprintf("http %d", h), TokenPath: out.TokenPath, ModeText: out.ModeText, HTTPStatus: h}
	}
	return BridgeRuntimeProbe{Status: "CONNECT_FAIL", Details: fmt.Sprintf("http %d", h), TokenPath: out.TokenPath, ModeText: out.ModeText, HTTPStatus: h}
}
func probeSSLCollectorHTTP(path, token string) (string, string, string) {
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Timeout: 3 * time.Second, Transport: tr}
	req, _ := http.NewRequest(http.MethodGet, "http://unix/stats", nil)
	req.Header.Set("X-SSLCollector-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return "CONNECT_FAIL", "", shortErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return "AUTH_FAIL", "", fmt.Sprintf("http %d", resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return "CONNECT_FAIL", "", fmt.Sprintf("http %d", resp.StatusCode)
	}
	var st struct{ UniquePairs, ExactHosts, WildcardZones, KnownFiles int }
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return "OK", "unavailable", shortErr(err)
	}
	return "OK", fmt.Sprintf("pairs=%d exact_hosts=%d wildcards=%d files=%d", st.UniquePairs, st.ExactHosts, st.WildcardZones, st.KnownFiles), ""
}
func probeNginxBridgeSocket(sockPath, token string) (int, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	tr := &http.Transport{DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", sockPath)
	}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/nginx/status", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-CFM-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return resp.StatusCode, "", nil
	}
	var payload map[string]any
	if err := json.Unmarshal(b, &payload); err != nil {
		return resp.StatusCode, "invalid json", nil
	}
	if len(payload) == 0 {
		return resp.StatusCode, "empty json", nil
	}
	return resp.StatusCode, "json ok", nil
}
func shortErr(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 120 {
		return msg[:120] + "..."
	}
	return msg
}
func socketPermsOK(st *syscall.Stat_t, mode os.FileMode) bool {
	cfm, err := user.LookupGroup("cfm")
	if err != nil {
		return st.Uid == 0 && st.Gid == 0 && mode == 0o660
	}
	cfmGID, err := strconv.ParseUint(cfm.Gid, 10, 32)
	if err != nil {
		return st.Uid == 0 && mode == 0o660
	}
	return st.Uid == 0 && st.Gid == uint32(cfmGID) && mode == 0o660
}
func uidText(uid uint32) string {
	s := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(s); err == nil && u.Username != "" {
		return fmt.Sprintf("%s(%s)", u.Username, s)
	}
	return s
}
func gidText(gid uint32) string {
	s := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(s); err == nil && g.Name != "" {
		return fmt.Sprintf("%s(%s)", g.Name, s)
	}
	return s
}

// ── TSV access-log probe ─────────────────────────────────────────────────────

// TSVLogProbe describes the webdetector TSV access log referenced by
// detectors.conf [webdetector] LOG_PATH. Liveness ("is it filling?") is left to
// the caller, which combines ModAgeSec with the ingest-socket arbiter state (a
// missing/stale file is expected and harmless while the socket is the live
// source — see the socket-only ingest design).
type TSVLogProbe struct {
	Path       string // cleaned LOG_PATH (empty when unset / folder mode)
	Configured bool
	Exists     bool
	IsFile     bool
	SizeBytes  int64
	ModAgeSec  int64 // seconds since last write; -1 when unknown
}

// ProbeTSVLog stats the configured TSV access log. `raw` is the LOG_PATH value
// straight from ReadDetectorSectionKV (surrounding quotes and a trailing inline
// ;/# comment are tolerated).
func ProbeTSVLog(raw string) TSVLogProbe {
	p := cleanConfValue(raw)
	out := TSVLogProbe{Path: p, ModAgeSec: -1}
	if p == "" {
		return out
	}
	out.Configured = true
	fi, err := os.Stat(p)
	if err != nil {
		return out
	}
	out.Exists = true
	out.IsFile = fi.Mode().IsRegular()
	out.SizeBytes = fi.Size()
	if age := time.Since(fi.ModTime()); age >= 0 {
		out.ModAgeSec = int64(age.Seconds())
	} else {
		out.ModAgeSec = 0
	}
	return out
}

// cleanConfValue strips surrounding quotes and a trailing inline ;/# comment
// from a detectors.conf scalar. Paths never legitimately contain ; or #.
func cleanConfValue(v string) string {
	s := strings.TrimSpace(v)
	for _, c := range []string{";", "#"} {
		if i := strings.Index(s, c); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
	}
	return strings.TrimSpace(strings.Trim(s, `"'`))
}

// ── Origin real-IP / trusted-proxy probe ─────────────────────────────────────

// OriginRealIPProbe reports whether the origin web server (behind the edge)
// trusts 127.0.0.1 as a real-IP proxy, so its access logs record the client IP
// instead of the edge's loopback address.
type OriginRealIPProbe struct {
	Stack     string // normalized origin: "apache" | "litespeed" | "nginx" | "unknown"
	Trusted   bool   // a 127.0.0.1 (or ::1) trust directive/marker was found
	Directive string // what matched (e.g. "RemoteIP{Internal,Trusted}Proxy 127.0.0.1")
	Source    string // file where it was found
	Note      string // context when not trusted / unknown
}

// loopbackTrust matches the ways an operator trusts the edge's loopback address:
// the bare host, its /32 (or /128 for v6), and the whole-loopback 127.0.0.0/8.
// It deliberately does NOT match 127.0.0.100 etc. (127\.0\.0\.1 is anchored, not
// a prefix). Shared by the Apache and nginx directives so they agree.
const loopbackTrust = `(?:127\.0\.0\.1(?:/\d{1,2})?|127\.0\.0\.0/\d{1,2}|::1(?:/\d{1,3})?)`

var (
	// The `^\s*` anchor makes a `#`-commented directive line not match.
	apacheRemoteIPRe = regexp.MustCompile(`(?im)^\s*RemoteIP(?:Internal|Trusted)Proxy\s+` + loopbackTrust + `\b`)
	nginxRealIPRe    = regexp.MustCompile(`(?im)^\s*set_real_ip_from\s+` + loopbackTrust + `\s*;`)
	// LiteSpeed's httpd_config.xml uses XML comments, not `#`, so the caller
	// strips `<!-- ... -->` before matching (see lsNativeMatch) to avoid a
	// false "trusted" on a commented-out directive.
	lsNativeRealIPRe = regexp.MustCompile(`(?is)<useIpInProxyHeader>\s*[12]\s*</useIpInProxyHeader>`)
	xmlCommentRe     = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// lsNativeMatch reports whether an XML config enables useIpInProxyHeader (1|2)
// outside of an XML comment.
func lsNativeMatch(b []byte) bool {
	return lsNativeRealIPRe.Match(xmlCommentRe.ReplaceAll(b, nil))
}

// Candidate config locations, cPanel + DirectAdmin/plain. Globbed; missing
// paths are simply skipped.
var apacheRealIPGlobs = []string{
	"/etc/apache2/conf.d/includes/*.conf", // cPanel pre_main_*/post_* includes
	"/etc/apache2/conf.d/httpd-cfm.conf",  // CFM's own drop-in
	"/usr/local/apache/conf/includes/*.conf",
	"/etc/httpd/conf.d/*.conf", // plain / DirectAdmin
	"/etc/httpd/conf/extra/*.conf",
	"/usr/local/directadmin/data/templates/custom/*.conf",
}
var nginxRealIPGlobs = []string{
	"/etc/nginx/conf.d/*.conf",
	"/etc/nginx/conf.d/server-includes/*.conf",
	"/etc/nginx/nginx.conf",
}
var lsNativeConfPaths = []string{"/usr/local/lsws/conf/httpd_config.xml"}

// grepMaxBytes caps per-file reads in grepGlobsFunc (origin configs are far
// smaller). A var so tests can shrink it.
var grepMaxBytes int64 = 8 << 20 // 8 MiB

func normalizeOriginStack(upstream string) string {
	s := strings.ToLower(strings.TrimSpace(upstream))
	switch {
	case strings.Contains(s, "lshttpd") || strings.Contains(s, "litespeed") || strings.Contains(s, "lsws"):
		return "litespeed"
	case strings.Contains(s, "httpd") || strings.Contains(s, "apache"):
		return "apache"
	case strings.Contains(s, "nginx"):
		return "nginx"
	default:
		return "unknown"
	}
}

// Origin-server install markers (dirs). Used to resolve the true origin stack
// when the collector's upstream hint is unreliable — notably on OpenResty boxes
// (the edge is nginx-based), where a LiteSpeed/Apache origin gets misreported as
// "nginx".
var (
	litespeedMarkers = []string{"/usr/local/lsws"}
	apacheMarkers    = []string{"/etc/apache2", "/usr/local/apache", "/etc/httpd"}
	nginxMarkers     = []string{"/etc/nginx"}
)

// ProbeOriginRealIP checks the origin real-IP trust for `upstream` (the origin
// service the health collector detected: httpd/lshttpd/nginx).
func ProbeOriginRealIP(upstream string) OriginRealIPProbe {
	stack := resolveOriginStack(upstream, litespeedMarkers, apacheMarkers, nginxMarkers)
	return probeOriginRealIPForStack(stack, apacheRealIPGlobs, nginxRealIPGlobs, lsNativeConfPaths)
}

// resolveOriginStack picks the origin web-server family. The collector's upstream
// hint is only trusted when the corresponding stack is actually installed:
// LiteSpeed being present wins outright (it is frequently misreported as "nginx"
// because the OpenResty edge is nginx-based, and the collector's process/marker
// detection doesn't recognize the "litespeed" process), and an nginx/apache hint
// that matches nothing on disk falls back to whatever IS installed.
func resolveOriginStack(upstream string, lsMarkers, apMarkers, ngMarkers []string) string {
	hint := normalizeOriginStack(upstream)
	lsPresent := anyDirExists(lsMarkers)
	apPresent := anyDirExists(apMarkers)
	ngPresent := anyDirExists(ngMarkers)
	switch {
	case lsPresent:
		return "litespeed"
	case hint == "litespeed":
		return "litespeed" // confident hint even if the default marker path differs
	case hint == "apache" && apPresent:
		return "apache"
	case hint == "nginx" && ngPresent:
		return "nginx"
	case apPresent:
		return "apache"
	case ngPresent:
		return "nginx"
	default:
		return "unknown"
	}
}

func probeOriginRealIPForStack(stack string, apacheGlobs, nginxGlobs, lsPaths []string) OriginRealIPProbe {
	switch stack {
	case "apache":
		if f := grepGlobs(apacheGlobs, apacheRemoteIPRe); f != "" {
			return OriginRealIPProbe{Stack: "apache", Trusted: true, Directive: "RemoteIP{Internal,Trusted}Proxy 127.0.0.1", Source: f}
		}
		return OriginRealIPProbe{Stack: "apache", Note: "no RemoteIP{Internal,Trusted}Proxy 127.0.0.1 in Apache includes"}
	case "litespeed":
		// LiteSpeed resolves real IP either natively (useIpInProxyHeader) or via
		// the Apache RemoteIP conf it loads (loadApacheConf=1).
		if f := grepGlobsFunc(lsPaths, lsNativeMatch); f != "" {
			return OriginRealIPProbe{Stack: "litespeed", Trusted: true, Directive: "useIpInProxyHeader", Source: f}
		}
		if f := grepGlobs(apacheGlobs, apacheRemoteIPRe); f != "" {
			return OriginRealIPProbe{Stack: "litespeed", Trusted: true, Directive: "RemoteIP{Internal,Trusted}Proxy 127.0.0.1 (loadApacheConf)", Source: f}
		}
		return OriginRealIPProbe{Stack: "litespeed", Note: "no useIpInProxyHeader (1|2) and no Apache RemoteIP trust"}
	case "nginx":
		if f := grepGlobs(nginxGlobs, nginxRealIPRe); f != "" {
			return OriginRealIPProbe{Stack: "nginx", Trusted: true, Directive: "set_real_ip_from 127.0.0.1", Source: f}
		}
		return OriginRealIPProbe{Stack: "nginx", Note: "no set_real_ip_from 127.0.0.1 in nginx conf.d"}
	default:
		return OriginRealIPProbe{Stack: "unknown", Note: "no apache/litespeed/nginx origin detected on disk"}
	}
}

func anyDirExists(dirs []string) bool {
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return true
		}
	}
	return false
}

// grepGlobs returns the first regular file (expanded from globs) whose contents
// match re, or "" if none.
func grepGlobs(globs []string, re *regexp.Regexp) string {
	return grepGlobsFunc(globs, re.Match)
}

// grepGlobsFunc is grepGlobs with an arbitrary content matcher (used by the
// LiteSpeed check, which must strip XML comments before matching). Each file
// read is size-capped for safety.
func grepGlobsFunc(globs []string, match func([]byte) bool) string {
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, f := range matches {
			fi, err := os.Stat(f)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() > grepMaxBytes {
				continue
			}
			b, err := os.ReadFile(f) // #nosec G304 -- fixed system config globs
			if err != nil {
				continue
			}
			if match(b) {
				return f
			}
		}
	}
	return ""
}
