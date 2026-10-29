// Package originrealip checks, and on request fixes, the origin web server's
// trust of the CFM edge, so that the origin records the visitor's IP instead of
// the edge's loopback address.
//
// The edge (Angie / OpenResty) proxies every web request to the origin (Apache,
// LiteSpeed or nginx) from 127.0.0.1, and hands it the client in three headers:
// X-Real-IP, X-Forwarded-For (the client appended last) and CF-Connecting-IP,
// all set to the edge's $remote_addr on every origin location. Unless the
// origin trusts the loopback to name the client, its access logs and PHP's
// REMOTE_ADDR read 127.0.0.1. On most of the fleet Imunify360's
// i360.remoteip.conf carried the Apache trust; qualityweb (2026-10-29, cPanel
// without Imunify360) had none and every site logged 127.0.0.1.
//
// Only the loopback is ever trusted, never the server's public address: a
// process on the server (a tenant's PHP calling its own site) could otherwise
// set the header and pose as any client. From outside the header cannot be
// spoofed either way, since the edge overwrites X-Real-IP / CF-Connecting-IP and
// appends the real peer to X-Forwarded-For.
//
// The probe reads configuration only. Apply (fix.go) writes it, and only
// through a config test and a graceful reload, with a rollback on failure.
package originrealip

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Panel and stack names reported by the probe.
const (
	PanelCPanel      = "cpanel"
	PanelDirectAdmin = "directadmin"
	PanelNGM         = "ngm"
	PanelPlain       = "plain"

	StackApache    = "apache"
	StackLiteSpeed = "litespeed"
	StackNginx     = "nginx"
	StackUnknown   = "unknown"
)

// Probe is the origin's real-IP trust as its configuration states it.
type Probe struct {
	Panel     string `json:"panel"`               // cpanel | directadmin | ngm | plain
	Stack     string `json:"stack"`               // apache | litespeed | nginx | unknown
	Trusted   bool   `json:"trusted"`             // the loopback is trusted AND the client header is one the edge sets
	Directive string `json:"directive,omitempty"` // what made it trusted
	Source    string `json:"source,omitempty"`    // file holding the loopback trust
	Header    string `json:"header,omitempty"`    // the header the origin reads the client from, when known
	Note      string `json:"note,omitempty"`      // why it is not trusted, or other context
}

// edgeHeaders are the headers every edge origin location sets to the client
// (configs/openresty.conf, configs/angie.conf), lower-cased.
var edgeHeaders = map[string]bool{
	"x-real-ip":        true,
	"x-forwarded-for":  true,
	"cf-connecting-ip": true,
}

// loopbackTrust matches the ways an operator trusts the edge's loopback address:
// the bare host, its /32 (or /128 for v6), and the whole-loopback 127.0.0.0/8.
// It deliberately does NOT match 127.0.0.100 etc.
const loopbackTrust = `(?:127\.0\.0\.1(?:/\d{1,2})?|127\.0\.0\.0/\d{1,2}|::1(?:/\d{1,3})?)`

var (
	// The `^\s*` anchor makes a `#`-commented directive line not match.
	apacheRemoteIPRe    = regexp.MustCompile(`(?im)^\s*RemoteIP(?:Internal|Trusted)Proxy\s+` + loopbackTrust + `\b`)
	apacheRemoteIPHdrRe = regexp.MustCompile(`(?im)^\s*RemoteIPHeader\s+(\S+)`)
	nginxRealIPRe       = regexp.MustCompile(`(?im)^\s*set_real_ip_from\s+` + loopbackTrust + `\s*;`)
	nginxRealIPHdrRe    = regexp.MustCompile(`(?im)^\s*real_ip_header\s+([^;\s]+)\s*;`)
	// LiteSpeed's httpd_config.xml uses XML comments, not `#`, so lsNativeMatch
	// strips `<!-- ... -->` before matching.
	lsNativeRealIPRe = regexp.MustCompile(`(?is)<useIpInProxyHeader>\s*([12])\s*</useIpInProxyHeader>`)
	// "Trusted IP Only" (2) honours the header only from an address the
	// Access Control allow list marks trusted with a trailing T (127.0.0.1T),
	// as mars has it.
	lsTrustedLoopbackRe = regexp.MustCompile(`(?is)<allow>[^<]*\b127\.0\.0\.1(?:/32)?T\b[^<]*</allow>`)
	xmlCommentRe        = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// layout is where a host keeps each piece; system is the real one, and tests
// build their own under a temp dir.
type layout struct {
	cpanelMarkers, daMarkers, ngmMarkers []string // panel install markers (dirs or files)
	lsMarkers, apMarkers, ngMarkers      []string // origin install markers (dirs)
	apacheGlobs, nginxGlobs, lsPaths     []string // config files the probe reads

	// activeStack names the origin family whose service is running, or "".
	// Running beats installed: a DirectAdmin or NGM host running nginx keeps a
	// leftover /etc/httpd (avgerinos, ngm.myip.gr).
	activeStack func() string

	// fix targets (fix.go)
	cpanelApacheDir  string // cPanel: conf.d, included by httpd.conf
	debApacheMain    string // Debian/Ubuntu main conf
	debApacheDir     string // its IncludeOptional conf-enabled dir
	elApacheMain     string // EL main conf
	elApacheDir      string // its IncludeOptional conf.d dir
	daApacheIncludes string // DirectAdmin: the operator include file httpd.conf loads
	nginxMain        string
	nginxConfD       string
	daNginxIncludes  string // DirectAdmin: the operator include file nginx.conf loads in http{}
}

var system = layout{
	cpanelMarkers: []string{"/usr/local/cpanel"},
	daMarkers:     []string{"/usr/local/directadmin"},
	ngmMarkers:    []string{"/etc/ngm", "/opt/ngm/bin/ngm"},
	lsMarkers:     []string{"/usr/local/lsws"},
	apMarkers:     []string{"/etc/apache2", "/usr/local/apache", "/etc/httpd"},
	ngMarkers:     []string{"/etc/nginx"},
	apacheGlobs: []string{
		"/etc/apache2/conf.d/*.conf",          // cPanel drop-ins (i360.remoteip.conf, cfm-remoteip.conf)
		"/etc/apache2/conf.d/includes/*.conf", // cPanel pre_main_*/post_* includes, cloudflare.conf
		"/etc/apache2/conf/httpd.conf",
		"/usr/local/apache/conf/includes/*.conf",
		"/etc/apache2/apache2.conf", // Debian/Ubuntu
		"/etc/apache2/conf-enabled/*.conf",
		"/etc/httpd/conf/httpd.conf", // EL + DirectAdmin
		"/etc/httpd/conf.d/*.conf",
		"/etc/httpd/conf/extra/*.conf", // DirectAdmin includes
		"/usr/local/directadmin/data/templates/custom/*.conf",
	},
	nginxGlobs: []string{
		"/etc/nginx/nginx.conf",
		"/etc/nginx/*.conf", // DirectAdmin keeps its http{} includes here
		"/etc/nginx/conf.d/*.conf",
		"/etc/nginx/conf.d/*/*.conf",
		"/etc/nginx/sites-enabled/*",
		"/etc/nginx/conf/sites/*.conf", // NGM
	},
	lsPaths:          []string{"/usr/local/lsws/conf/httpd_config.xml"},
	activeStack:      activeOriginStack,
	cpanelApacheDir:  "/etc/apache2/conf.d",
	debApacheMain:    "/etc/apache2/apache2.conf",
	debApacheDir:     "/etc/apache2/conf-enabled",
	elApacheMain:     "/etc/httpd/conf/httpd.conf",
	elApacheDir:      "/etc/httpd/conf.d",
	daApacheIncludes: "/etc/httpd/conf/extra/httpd-includes.conf",
	nginxMain:        "/etc/nginx/nginx.conf",
	nginxConfD:       "/etc/nginx/conf.d",
	daNginxIncludes:  "/etc/nginx/nginx-includes.conf",
}

// grepMaxBytes caps per-file reads (origin configs are far smaller). A var so
// tests can shrink it.
var grepMaxBytes int64 = 8 << 20 // 8 MiB

// ProbeSystem checks this host. upstream is the origin service the health
// collector detected (httpd / lshttpd / nginx), a hint only.
func ProbeSystem(upstream string) Probe {
	return system.probe(upstream)
}

func (l layout) probe(upstream string) Probe {
	if l.activeStack != nil && !anyExists(l.lsMarkers) {
		if running := l.activeStack(); running != "" {
			upstream = running
		}
	}
	p := l.probeStack(resolveOriginStack(upstream, l.lsMarkers, l.apMarkers, l.ngMarkers))
	p.Panel = l.panel()
	if !p.Trusted && p.Panel == PanelNGM && p.Stack == StackNginx {
		p.Note += "; NGM renders nginx itself, so the trust has to come from NGM's templates (a hand-written file is overwritten on apply)"
	}
	return p
}

func (l layout) panel() string {
	switch {
	case anyExists(l.cpanelMarkers):
		return PanelCPanel
	case anyExists(l.daMarkers):
		return PanelDirectAdmin
	case anyExists(l.ngmMarkers):
		return PanelNGM
	default:
		return PanelPlain
	}
}

func (l layout) probeStack(stack string) Probe {
	switch stack {
	case StackApache:
		return probeApache(StackApache, l.apacheGlobs)
	case StackLiteSpeed:
		// LiteSpeed resolves the client natively (useIpInProxyHeader) or through
		// the Apache RemoteIP conf it loads (loadApacheConf=1).
		if f := grepGlobsFunc(l.lsPaths, lsNativeMatch); f != "" {
			return Probe{Stack: StackLiteSpeed, Trusted: true, Directive: "useIpInProxyHeader", Source: f}
		}
		if ap := probeApache(StackLiteSpeed, l.apacheGlobs); ap.Trusted {
			ap.Directive += " (loadApacheConf)"
			return ap
		}
		return Probe{Stack: StackLiteSpeed, Note: "httpd_config.xml has no useIpInProxyHeader 1, or 2 with 127.0.0.1T in the allow list, and no Apache RemoteIP trust of 127.0.0.1"}
	case StackNginx:
		return probeNginx(l.nginxGlobs)
	default:
		return Probe{Stack: StackUnknown, Note: "no apache/litespeed/nginx origin detected on disk"}
	}
}

// probeApache: mod_remoteip needs BOTH the loopback trusted and a RemoteIPHeader
// naming a header the edge sets; one without the other leaves 127.0.0.1.
func probeApache(stack string, globs []string) Probe {
	trustFile := grepGlobs(globs, apacheRemoteIPRe)
	headers := collect(globs, apacheRemoteIPHdrRe)
	if trustFile == "" {
		return Probe{Stack: stack, Header: strings.Join(headers, ","), Note: "no RemoteIPInternalProxy/RemoteIPTrustedProxy 127.0.0.1 in the Apache config"}
	}
	if len(headers) == 0 {
		return Probe{Stack: stack, Source: trustFile, Note: "127.0.0.1 is trusted but no RemoteIPHeader is set, so mod_remoteip reads no header"}
	}
	if bad := foreignHeaders(headers); len(bad) > 0 {
		return Probe{Stack: stack, Source: trustFile, Header: strings.Join(headers, ","),
			Note: "RemoteIPHeader " + strings.Join(bad, ",") + " is not a header the edge sets (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)"}
	}
	return Probe{Stack: stack, Trusted: true, Directive: "RemoteIP{Internal,Trusted}Proxy 127.0.0.1", Source: trustFile, Header: strings.Join(headers, ",")}
}

// probeNginx: set_real_ip_from 127.0.0.1 is enough with nginx's default
// real_ip_header (X-Real-IP), or with one the edge sets.
func probeNginx(globs []string) Probe {
	trustFile := grepGlobs(globs, nginxRealIPRe)
	headers := collect(globs, nginxRealIPHdrRe)
	header := "X-Real-IP (default)"
	if len(headers) > 0 {
		header = strings.Join(headers, ",")
	}
	if trustFile == "" {
		return Probe{Stack: StackNginx, Header: header, Note: "no set_real_ip_from 127.0.0.1 in the nginx config"}
	}
	if bad := foreignHeaders(headers); len(bad) > 0 {
		return Probe{Stack: StackNginx, Source: trustFile, Header: header,
			Note: "real_ip_header " + strings.Join(bad, ",") + " is not a header the edge sets (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)"}
	}
	return Probe{Stack: StackNginx, Trusted: true, Directive: "set_real_ip_from 127.0.0.1", Source: trustFile, Header: header}
}

func foreignHeaders(headers []string) []string {
	var bad []string
	for _, h := range headers {
		if !edgeHeaders[strings.ToLower(h)] {
			bad = append(bad, h)
		}
	}
	return bad
}

// lsNativeMatch reports whether an XML config makes LiteSpeed take the client
// from the edge's header, outside of an XML comment: useIpInProxyHeader 1 (from
// any peer), or 2 (trusted peers only) with 127.0.0.1 marked trusted.
func lsNativeMatch(b []byte) bool {
	b = xmlCommentRe.ReplaceAll(b, nil)
	m := lsNativeRealIPRe.FindSubmatch(b)
	if m == nil {
		return false
	}
	return string(m[1]) == "1" || lsTrustedLoopbackRe.Match(b)
}

// originUnits maps the origin services to their family, LiteSpeed first. The
// CFM edge runs as angie / openresty, never as nginx.service.
var originUnits = []struct{ unit, stack string }{
	{"lsws", StackLiteSpeed}, {"lshttpd", StackLiteSpeed},
	{"httpd", StackApache}, {"apache2", StackApache},
	{"nginx", StackNginx},
}

// activeOriginStack is the family of the first origin service systemd reports
// active, or "".
func activeOriginStack() string {
	for _, u := range originUnits {
		if _, err := runCmd("systemctl", "is-active", "--quiet", u.unit); err == nil {
			return u.stack
		}
	}
	return ""
}

func normalizeOriginStack(upstream string) string {
	s := strings.ToLower(strings.TrimSpace(upstream))
	switch {
	case strings.Contains(s, "lshttpd") || strings.Contains(s, "litespeed") || strings.Contains(s, "lsws"):
		return StackLiteSpeed
	case strings.Contains(s, "httpd") || strings.Contains(s, "apache"):
		return StackApache
	case strings.Contains(s, "nginx"):
		return StackNginx
	default:
		return StackUnknown
	}
}

// resolveOriginStack picks the origin web-server family. The collector's
// upstream hint is only trusted when the corresponding stack is actually
// installed: LiteSpeed being present wins outright (it is frequently misreported
// as "nginx" because the edge is nginx-based), and an nginx/apache hint that
// matches nothing on disk falls back to whatever IS installed.
func resolveOriginStack(upstream string, lsMarkers, apMarkers, ngMarkers []string) string {
	hint := normalizeOriginStack(upstream)
	lsPresent := anyExists(lsMarkers)
	apPresent := anyExists(apMarkers)
	ngPresent := anyExists(ngMarkers)
	switch {
	case lsPresent:
		return StackLiteSpeed
	case hint == StackLiteSpeed:
		return StackLiteSpeed // confident hint even if the default marker path differs
	case hint == StackApache && apPresent:
		return StackApache
	case hint == StackNginx && ngPresent:
		return StackNginx
	case apPresent:
		return StackApache
	case ngPresent:
		return StackNginx
	default:
		return StackUnknown
	}
}

func anyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
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

// grepGlobsFunc is grepGlobs with an arbitrary content matcher. Each file read
// is size-capped.
func grepGlobsFunc(globs []string, match func([]byte) bool) string {
	found := ""
	eachFile(globs, func(f string, b []byte) bool {
		if match(b) {
			found = f
			return false
		}
		return true
	})
	return found
}

// collect returns the distinct first capture group of re across globs, sorted.
func collect(globs []string, re *regexp.Regexp) []string {
	seen := map[string]bool{}
	eachFile(globs, func(_ string, b []byte) bool {
		for _, m := range re.FindAllSubmatch(b, -1) {
			seen[string(m[1])] = true
		}
		return true
	})
	out := make([]string, 0, len(seen))
	for h := range seen {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// eachFile calls fn for every regular file the globs expand to (each path once,
// size-capped) until fn returns false.
func eachFile(globs []string, fn func(path string, body []byte) bool) {
	seen := map[string]bool{}
	for _, g := range globs {
		matches, _ := filepath.Glob(g)
		for _, f := range matches {
			if seen[f] {
				continue
			}
			seen[f] = true
			fi, err := os.Stat(f)
			if err != nil || !fi.Mode().IsRegular() || fi.Size() > grepMaxBytes {
				continue
			}
			b, err := os.ReadFile(f) // #nosec G304 -- fixed system config globs
			if err != nil {
				continue
			}
			if !fn(f, b) {
				return
			}
		}
	}
}
