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
// What the trust lets through: from outside, nothing (the edge overwrites
// X-Real-IP / CF-Connecting-IP and appends the real peer to X-Forwarded-For).
// From the server itself, a process connecting to the origin directly on the
// loopback can name any client; that is inherent in trusting the loopback, and
// i360.remoteip.conf has the same exposure. The fix writes X-Real-IP rather
// than X-Forwarded-For so that a local process going THROUGH the edge cannot:
// the edge sets X-Real-IP to the peer (127.0.0.1 then), while mod_remoteip
// walks an X-Forwarded-For past the trusted 127.0.0.1 hop to a forged entry.
// The server's public address is never trusted.
//
// The probe reads configuration only, following the servers' own include
// chains. Apply (fix.go) writes it, and only through a config test and a
// graceful reload, with a rollback on failure.
package originrealip

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
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
	Trusted   bool   `json:"trusted"`             // the loopback is trusted AND the effective client header is one the edge sets
	Directive string `json:"directive,omitempty"` // what made it trusted
	Source    string `json:"source,omitempty"`    // file holding the loopback trust
	Header    string `json:"header,omitempty"`    // the effective header the origin reads the client from, when known
	Note      string `json:"note,omitempty"`      // why it is not trusted, or other context
}

// edgeHeaders are the headers every edge origin location sets to the client
// (configs/openresty.conf, configs/angie.conf), lower-cased.
var edgeHeaders = map[string]bool{
	"x-real-ip":        true,
	"x-forwarded-for":  true,
	"cf-connecting-ip": true,
}

var (
	// LiteSpeed's httpd_config.xml uses XML comments, so lsNativeMatch strips
	// `<!-- ... -->` before matching.
	lsNativeRealIPRe = regexp.MustCompile(`(?is)<useIpInProxyHeader>\s*([12])\s*</useIpInProxyHeader>`)
	// "Trusted IP Only" (2) honours the header only from an address the
	// Access Control allow list marks trusted with a trailing T (127.0.0.1T),
	// as mars has it.
	lsTrustedLoopbackRe = regexp.MustCompile(`(?is)<allow>[^<]*\b127\.0\.0\.1(?:/32)?T\b[^<]*</allow>`)
	xmlCommentRe        = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// layout is where a host keeps each piece, as logical paths; root prefixes
// every one of them (empty on a real host, a temp dir in tests).
type layout struct {
	root string

	cpanelMarkers, daMarkers, ngmMarkers []string // panel install markers (dirs or files)
	lsMarkers, apMarkers, ngMarkers      []string // origin install markers

	apacheMains []apacheMain // the first that exists is the server's main config
	nginxMain   string
	nginxPrefix string // what relative nginx includes resolve against
	lsConfig    string

	// activeStack names the origin family that is serving, or "", and whether
	// that came from the :80 listener (decisive) or only from systemd unit
	// state. Serving beats installed: DirectAdmin and NGM hosts running nginx
	// keep a leftover /etc/httpd, and a host can keep a leftover /usr/local/lsws.
	activeStack func() (stack string, fromListener bool)

	// fix targets (fix.go)
	cpanelApacheDir  string // cPanel: conf.d, included by httpd.conf
	debApacheDir     string // Debian/Ubuntu: conf-enabled
	elApacheDir      string // EL: conf.d
	daApacheIncludes string // DirectAdmin: the operator include file httpd.conf loads
	nginxConfD       string
	daNginxIncludes  string // DirectAdmin: the operator include file nginx.conf loads in http{}
}

type apacheMain struct{ conf, serverRoot string }

var system = layout{
	cpanelMarkers: []string{"/usr/local/cpanel"},
	daMarkers:     []string{"/usr/local/directadmin"},
	ngmMarkers:    []string{"/etc/ngm", "/opt/ngm/bin/ngm"},
	lsMarkers:     []string{"/usr/local/lsws"},
	apMarkers:     []string{"/etc/apache2", "/etc/httpd"},
	ngMarkers:     []string{"/etc/nginx"},
	apacheMains: []apacheMain{
		{"/etc/apache2/conf/httpd.conf", "/etc/apache2"}, // cPanel (EA4)
		{"/etc/apache2/apache2.conf", "/etc/apache2"},    // Debian / Ubuntu
		{"/etc/httpd/conf/httpd.conf", "/etc/httpd"},     // EL, DirectAdmin
	},
	nginxMain:        "/etc/nginx/nginx.conf",
	nginxPrefix:      "/etc/nginx",
	lsConfig:         "/usr/local/lsws/conf/httpd_config.xml",
	activeStack:      activeOriginStack,
	cpanelApacheDir:  "/etc/apache2/conf.d",
	debApacheDir:     "/etc/apache2/conf-enabled",
	elApacheDir:      "/etc/httpd/conf.d",
	daApacheIncludes: "/etc/httpd/conf/extra/httpd-includes.conf",
	nginxConfD:       "/etc/nginx/conf.d",
	daNginxIncludes:  "/etc/nginx/nginx-includes.conf",
}

// fs maps a logical path to where it is on disk.
func (l layout) fs(p string) string {
	if l.root == "" {
		return p
	}
	return filepath.Join(l.root, p)
}

func (l layout) anyExists(paths []string) bool {
	for _, p := range paths {
		if _, err := os.Stat(l.fs(p)); err == nil {
			return true
		}
	}
	return false
}

// display strips the test root from a rooted path.
func (l layout) display(p string) string {
	if l.root == "" {
		return p
	}
	if rel, err := filepath.Rel(l.root, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "/" + rel
	}
	return p
}

// grepMaxBytes caps per-file reads. A var so tests can shrink it.
var grepMaxBytes int64 = 8 << 20 // 8 MiB

// probeTimeout bounds each command the probe runs (systemctl, ss): edge_health
// runs the probe inside an HTTP handler.
const probeTimeout = 5 * time.Second

// ProbeSystem checks this host. upstream is the origin service the health
// collector detected (httpd / lshttpd / nginx), a hint only.
func ProbeSystem(upstream string) Probe {
	return system.probe(upstream)
}

func (l layout) probe(upstream string) Probe {
	stack := ""
	if l.activeStack != nil {
		running, fromListener := l.activeStack()
		switch {
		case running != "" && fromListener:
			stack = running
		case running != "":
			upstream = running
		}
	}
	if stack == "" {
		stack = l.resolveOriginStack(upstream)
	}
	p := l.probeStack(stack)
	p.Panel = l.panel()
	if !p.Trusted && p.Panel == PanelNGM && p.Stack == StackNginx {
		p.Note += "; NGM renders nginx itself, so the trust has to come from NGM's templates (a hand-written file is overwritten on apply)"
	}
	return p
}

func (l layout) panel() string {
	switch {
	case l.anyExists(l.cpanelMarkers):
		return PanelCPanel
	case l.anyExists(l.daMarkers):
		return PanelDirectAdmin
	case l.anyExists(l.ngmMarkers):
		return PanelNGM
	default:
		return PanelPlain
	}
}

func (l layout) probeStack(stack string) Probe {
	switch stack {
	case StackApache:
		return l.probeApache(StackApache)
	case StackLiteSpeed:
		// LiteSpeed resolves the client natively (useIpInProxyHeader) or through
		// the Apache RemoteIP conf it loads (loadApacheConf=1).
		if b, err := os.ReadFile(l.fs(l.lsConfig)); err == nil && lsNativeMatch(b) {
			return Probe{Stack: StackLiteSpeed, Trusted: true, Directive: "useIpInProxyHeader", Source: l.lsConfig}
		}
		if ap := l.probeApache(StackLiteSpeed); ap.Trusted {
			ap.Directive += " (loadApacheConf)"
			return ap
		}
		return Probe{Stack: StackLiteSpeed, Note: "httpd_config.xml has no useIpInProxyHeader 1, or 2 with 127.0.0.1T in the allow list, and no Apache RemoteIP trust of 127.0.0.1"}
	case StackNginx:
		return l.probeNginx()
	default:
		return Probe{Stack: StackUnknown, Note: "no apache/litespeed/nginx origin detected on disk"}
	}
}

// probeApache: mod_remoteip needs BOTH the loopback trusted and a RemoteIPHeader
// naming a header the edge sets, at server level (Apache's last RemoteIPHeader
// wins). The config is read along Apache's own Include chain, so a file it never
// loads does not count, and a <VirtualHost>'s own settings do not stand for the
// server.
func (l layout) probeApache(stack string) Probe {
	var main *apacheMain
	for i := range l.apacheMains {
		if _, err := os.Stat(l.fs(l.apacheMains[i].conf)); err == nil {
			main = &l.apacheMains[i]
			break
		}
	}
	if main == nil {
		return Probe{Stack: stack, Note: "no Apache main config found"}
	}
	ds := l.apacheDirectives(main.conf, main.serverRoot, "remoteipinternalproxy", "remoteiptrustedproxy", "remoteipheader")
	trust, header, scoped := "", "", 0
	for _, d := range ds {
		switch {
		case d.scoped:
			scoped++
		case d.name == "remoteipheader" && len(d.args) > 0:
			header = d.args[0]
		case trust == "" && anyLoopback(d.args):
			trust = l.display(d.file)
		}
	}
	p := Probe{Stack: stack, Source: trust, Header: header}
	switch {
	case trust == "":
		p.Note = "no server-level RemoteIPInternalProxy/RemoteIPTrustedProxy 127.0.0.1 in the Apache config it loads"
	case header == "":
		p.Note = "127.0.0.1 is trusted but no server-level RemoteIPHeader is set, so mod_remoteip reads no header"
	case !edgeHeaders[strings.ToLower(header)]:
		p.Note = "RemoteIPHeader " + header + " is not a header the edge sets (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)"
	default:
		p.Trusted, p.Directive = true, "RemoteIP{Internal,Trusted}Proxy 127.0.0.1"
	}
	if scoped > 0 {
		p.Note = joinNote(p.Note, strconv.Itoa(scoped)+" RemoteIP directive(s) inside <VirtualHost> blocks override the server-level ones for those sites")
	}
	return p
}

// probeNginx: set_real_ip_from 127.0.0.1 at http level is enough with nginx's
// default real_ip_header (X-Real-IP), or with one the edge sets. Read along
// nginx's include chain; a server{}'s own set_real_ip_from REPLACES the http
// list for that site.
func (l layout) probeNginx() Probe {
	ds := l.nginxDirectives(l.nginxMain, l.nginxPrefix, "set_real_ip_from", "real_ip_header")
	trust, header, scoped := "", "", 0
	for _, d := range ds {
		switch {
		case d.scoped:
			if d.name == "set_real_ip_from" {
				scoped++
			}
		case d.name == "real_ip_header" && len(d.args) > 0:
			header = d.args[0]
		case d.name == "set_real_ip_from" && trust == "" && anyLoopback(d.args):
			trust = l.display(d.file)
		}
	}
	shown := header
	if shown == "" {
		shown = "X-Real-IP (default)"
	}
	p := Probe{Stack: StackNginx, Source: trust, Header: shown}
	switch {
	case trust == "":
		p.Note = "no http-level set_real_ip_from 127.0.0.1 in the nginx config"
	case header != "" && !edgeHeaders[strings.ToLower(header)]:
		p.Note = "real_ip_header " + header + " is not a header the edge sets (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)"
	default:
		p.Trusted, p.Directive = true, "set_real_ip_from 127.0.0.1"
	}
	if scoped > 0 {
		p.Note = joinNote(p.Note, strconv.Itoa(scoped)+" set_real_ip_from line(s) inside server{} blocks replace the http-level list for those sites")
	}
	return p
}

// anyLoopback reports whether one of a trust directive's arguments covers the
// edge's address: 127.0.0.1 or ::1, alone or as a loopback-only network
// (127.0.0.0/8 .. /32, ::1/128). 127.0.0.1/1 covers half the internet and is
// not a loopback trust.
func anyLoopback(args []string) bool {
	for _, a := range args {
		if ip := net.ParseIP(a); ip != nil {
			if ip.Equal(net.ParseIP("127.0.0.1")) || ip.Equal(net.IPv6loopback) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		ones, bits := n.Mask.Size()
		switch bits {
		case 32:
			if ones >= 8 && n.IP.IsLoopback() && n.Contains(net.ParseIP("127.0.0.1")) {
				return true
			}
		case 128:
			if ones == 128 && n.IP.Equal(net.IPv6loopback) {
				return true
			}
		}
	}
	return false
}

func joinNote(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
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

// listenerNames maps the process names that can own :80 to their family. The
// CFM edge (angie / openresty) listens on its own ports and is never the origin.
var listenerNames = map[string]string{
	"litespeed": StackLiteSpeed, "lshttpd": StackLiteSpeed,
	"httpd": StackApache, "apache2": StackApache,
	"nginx": StackNginx,
}

var ssUserRe = regexp.MustCompile(`\("([^"]+)",pid=`)

// originUnits is the systemd fallback when the listener cannot be read,
// LiteSpeed first.
var originUnits = []struct{ unit, stack string }{
	{"lsws", StackLiteSpeed}, {"lshttpd", StackLiteSpeed},
	{"httpd", StackApache}, {"apache2", StackApache},
	{"nginx", StackNginx},
}

// activeOriginStack names the family of the process listening on :80 — the
// port the edge proxies to, so the one serving even when Apache and nginx both
// run (DirectAdmin nginx_apache, cPanel ea-nginx) — or, when that cannot be
// read, the first origin unit systemd reports active.
func activeOriginStack() (string, bool) {
	if out, err := runCmd(probeTimeout, "ss", "-Hltnp", "sport = :80"); err == nil {
		for _, m := range ssUserRe.FindAllStringSubmatch(out, -1) {
			if s, ok := listenerNames[m[1]]; ok {
				return s, true
			}
		}
	}
	for _, u := range originUnits {
		if _, err := runCmd(probeTimeout, "systemctl", "is-active", "--quiet", u.unit); err == nil {
			return u.stack, false
		}
	}
	return "", false
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

// resolveOriginStack picks the origin family from a hint and the disk, when
// the listener could not say: an installed LiteSpeed wins (it is often
// misreported as "nginx" because the edge is nginx-based), and a hint that
// matches nothing installed falls back to whatever is.
func (l layout) resolveOriginStack(upstream string) string {
	hint := normalizeOriginStack(upstream)
	apPresent := l.anyExists(l.apMarkers)
	ngPresent := l.anyExists(l.ngMarkers)
	switch {
	case l.anyExists(l.lsMarkers):
		return StackLiteSpeed
	case hint == StackLiteSpeed:
		return StackLiteSpeed
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
