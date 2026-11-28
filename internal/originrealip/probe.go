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
	"bufio"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"cfm/internal/edgeengine"
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
	Warning   string `json:"warning,omitempty"`   // trusted now, but something will undo it (OpenLiteSpeed on DirectAdmin: rewrite_confs)

	// nginx: the site server{} blocks read, and how many of them do not trust
	// the edge (0 and 0 when the http-level settings decided).
	Servers          int `json:"servers,omitempty"`
	UntrustedServers int `json:"untrusted_servers,omitempty"`

	// EdgeIPv6: the edge listens on IPv6 (scripts/cfm-edge-listen-v6.sh wrote
	// its listen files: EdgeIPv6Listening), or will as soon as the origin
	// trusts ::1 (the host can do IPv6). An IPv6 visitor's hop reaches the
	// origin from ::1, so Trusted requires ::1 as well as 127.0.0.1.
	EdgeIPv6          bool `json:"edge_ipv6,omitempty"`
	EdgeIPv6Listening bool `json:"edge_ipv6_listening,omitempty"`

	ng  *nginxVerdict // nginx: what the plan needs
	ols *olsVerdict   // OpenLiteSpeed: where its settings were read (the plan names those files)

	v6Only bool // untrusted only on the ::1 pass: 127.0.0.1 is trusted (Verdict's wording)
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
	// The same for ::1, the source of an IPv6 hop (::1T).
	lsTrustedLoopback6Re = regexp.MustCompile(`(?is)<allow>(?:[^<]*[\s,])?::1(?:/128)?T\b[^<]*</allow>`)
	xmlCommentRe         = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// layout is where a host keeps each piece, as logical paths; root prefixes
// every one of them (empty on a real host, a temp dir in tests).
type layout struct {
	root string

	// loopIP is the edge source address this probe checks the trust of:
	// "" (127.0.0.1) or "::1" (the second pass when the edge listens on IPv6).
	loopIP string
	// edgeV6Files: the edge's IPv6 listen files (scripts/cfm-edge-listen-v6.sh);
	// any of them present means the edge listens on IPv6.
	edgeV6Files []string
	// Where IPv6 is allowed, the edge listens on IPv6 by itself wherever the
	// host can (scripts/cfm-edge-listen-v6.sh), but only once the origin
	// trusts ::1. So the ::1 trust is required as soon as the host CAN (a global IPv6 address, the
	// origin listening on IPv6 on 80 and 443), before any listen file exists:
	// the script asks `cfm realip` before it writes them, and `cfm realip fix`
	// must then write the ::1 trust instead of answering "already trusted" on
	// a 127.0.0.1-only origin, which would leave the edge on IPv4 for good.
	// cfmConf: EDGE_LISTEN_V6 there allows or forbids IPv6 (edgeIPv6Wanted;
	// absent = edgeIPv6Default, on since IPv6 /64 grouping).
	cfmConf, procIfInet6, procTCP6 string

	cpanelMarkers, daMarkers, ngmMarkers []string // panel install markers (dirs or files)
	lsMarkers, apMarkers, ngMarkers      []string // origin install markers

	apacheMains []apacheMain // the first that exists is the server's main config
	nginxMain   string
	nginxPrefix string    // what relative nginx includes resolve against
	lsConfig    string    // LiteSpeed Enterprise
	culpritsOut *[]string // olsRewriteCulprits: where olsRewriteWarning reports them
	olsConfig   string    // OpenLiteSpeed (ols.go)

	// activeStack names the origin family that is serving, or "", and whether
	// that came from the :80 listener (decisive) or only from systemd unit
	// state. Serving beats installed: DirectAdmin and NGM hosts running nginx
	// keep a leftover /etc/httpd, and a host can keep a leftover /usr/local/lsws.
	activeStack func() (stack string, fromListener bool)

	// fix targets (fix.go)
	cpanelApacheDir           string // cPanel: conf.d, included by httpd.conf
	debApacheDir              string // Debian/Ubuntu: conf-enabled
	elApacheDir               string // EL: conf.d
	daApacheIncludes          string // DirectAdmin: the operator include file httpd.conf loads
	nginxConfD                string
	cpanelNginxServerIncludes string // cPanel ea-nginx: included by every site server{} block
	daNginxIncludes           string // DirectAdmin: the operator include file nginx.conf loads in http{}
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
	nginxMain:                 "/etc/nginx/nginx.conf",
	nginxPrefix:               "/etc/nginx",
	lsConfig:                  "/usr/local/lsws/conf/httpd_config.xml",
	olsConfig:                 "/usr/local/lsws/conf/httpd_config.conf",
	activeStack:               activeOriginStack,
	cpanelApacheDir:           "/etc/apache2/conf.d",
	debApacheDir:              "/etc/apache2/conf-enabled",
	elApacheDir:               "/etc/httpd/conf.d",
	daApacheIncludes:          "/etc/httpd/conf/extra/httpd-includes.conf",
	nginxConfD:                "/etc/nginx/conf.d",
	cpanelNginxServerIncludes: "/etc/nginx/conf.d/server-includes",
	daNginxIncludes:           "/etc/nginx/nginx-includes.conf",
	edgeV6Files:               edgeV6ListenFiles(),
	cfmConf:                   "/etc/cfm/cfm.conf",
	procIfInet6:               "/proc/net/if_inet6",
	procTCP6:                  "/proc/net/tcp6",
}

// edgeIPv6Default is the decision with no EDGE_LISTEN_V6 in cfm.conf: true
// since the per-IP defences group an IPv6 client by its /64 (docs/edge-ipv6.md
// "IPv6 /64 grouping"). scripts/cfm-edge-listen-v6.sh V6_DEFAULT is the same
// switch; check_edge_listen_v6.sh pins them equal.
const edgeIPv6Default = true

// edgeIPv6: the edge listens on IPv6 (its listen files exist, or the kernel
// shows a root IPv6 listener on its ports: a `listen [::]` added by hand), or
// it would as soon as the origin trusts ::1 (IPv6 allowed on this node and
// hostCanIPv6).
func (l layout) edgeIPv6() bool {
	return l.edgeListensIPv6() || (l.edgeIPv6Wanted() && l.hostCanIPv6())
}

func (l layout) edgeListensIPv6() bool {
	return l.anyExists(l.edgeV6Files) || l.edgeV6KernelListen()
}

// edgeV6Ports are the edge's listener ports (scripts/cfm-edge-listen-v6.sh
// V6_HTTP_PORT / V6_HTTPS_PORT).
var edgeV6Ports = map[uint64]bool{9080: true, 9043: true}

// edgeV6KernelListen: a root-owned socket LISTENs on a global IPv6 address on
// one of the edge's ports (/proc/net/tcp6; the edge's master binds as root).
// Catches an IPv6 listen the script did not write (an operator's hand-added
// `listen [::]:9043`): its visitors reach the origin from ::1 all the same.
func (l layout) edgeV6KernelListen() bool {
	if l.procTCP6 == "" {
		return false
	}
	fh, err := os.Open(l.fs(l.procTCP6))
	if err != nil {
		return false
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[3] != "0A" || f[7] != "0" {
			continue
		}
		addr, port, ok := strings.Cut(f[1], ":")
		if !ok || len(addr) != 32 || !globalV6Hex(addr) {
			continue
		}
		if p, err := strconv.ParseUint(port, 16, 16); err == nil && edgeV6Ports[p] {
			return true
		}
	}
	return false
}

// globalV6Hex: a /proc/net/tcp6 address (32 hex digits, the kernel's
// per-word host byte order, so ::1 reads 00000000000000000000000001000000 on
// x86) is not ::1, v4-mapped (::ffff:a.b.c.d) or link-local (fe80::/10),
// which serve no global IPv6 address.
func globalV6Hex(addr string) bool {
	addr = strings.ToUpper(addr)
	return addr != "00000000000000000000000001000000" && !strings.HasPrefix(addr, "0000000000000000FFFF0000") && !strings.HasPrefix(addr, "000080FE")
}

// edgeIPv6Wanted: EDGE_LISTEN_V6 in cfm.conf allows IPv6 on this node, read
// like scripts/cfm-edge-listen-v6.sh mode(): last uncommented line wins, an
// inline ; or # comment and quotes stripped, case-insensitive; on / yes /
// true / 1 / auto / enable / enabled = yes, absent = edgeIPv6Default,
// anything else = no.
const asciiSpace = " \t\r\n\v\f"

func (l layout) edgeIPv6Wanted() bool {
	conf := ""
	if l.cfmConf != "" {
		if b, err := os.ReadFile(l.fs(l.cfmConf)); err == nil {
			conf = string(b)
		}
	}
	return EdgeListenV6Allowed(conf)
}

// EdgeListenV6Line reports whether line is an active EDGE_LISTEN_V6
// assignment and its value as the script reads it: an inline ; or # comment
// cut, ASCII whitespace trimmed (CR included), ONE matching pair of quotes
// stripped, lowercased. The one reader in Go (`cfm edge ipv6` edits the
// lines it matches); scripts/tests/fixtures/edge_listen_v6_mode.txt pins it
// to the script's mode().
func EdgeListenV6Line(line string) (value string, ok bool) {
	// ASCII whitespace only, as the script's [[:space:]] (it runs LC_ALL=C):
	// strings.TrimSpace would also take a NBSP / NEL the script keeps.
	k, v, found := strings.Cut(strings.TrimLeft(line, asciiSpace), "=")
	if !found || strings.TrimRight(k, asciiSpace) != "EDGE_LISTEN_V6" {
		return "", false
	}
	if i := strings.IndexAny(v, ";#"); i >= 0 {
		v = v[:i]
	}
	v = strings.Trim(v, asciiSpace)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	}
	return strings.ToLower(v), true
}

// EdgeListenV6Allowed is the decision cfm.conf's text makes: the last active
// line wins; on / yes / true / 1 / auto / enable / enabled = yes, absent or
// empty = edgeIPv6Default, anything else = no (the script's mode()).
func EdgeListenV6Allowed(conf string) bool {
	mode := ""
	for _, line := range strings.Split(conf, "\n") {
		if v, ok := EdgeListenV6Line(line); ok {
			mode = v
		}
	}
	switch mode {
	case "":
		return edgeIPv6Default
	case "on", "yes", "true", "1", "auto", "enable", "enabled":
		return true
	}
	return false
}

// hostCanIPv6: the host has a global IPv6 address and something listens on a
// global IPv6 address (not ::1, v4-mapped or link-local) on both 80 and 443, read from
// /proc/net/tcp6 (state 0A = LISTEN; addresses in the kernel's per-word host
// byte order, so ::1 reads 00000000000000000000000001000000 on x86).
func (l layout) hostCanIPv6() bool {
	if l.procIfInet6 == "" || l.procTCP6 == "" {
		return false
	}
	// A global IPv6 address on an interface (scope 00): the stack alone is
	// not enough (earth, mars: if_inet6 present but empty, the origin on
	// [::] all the same, and no IPv6 visitor can reach the node).
	ifs, err := os.ReadFile(l.fs(l.procIfInet6))
	if err != nil {
		return false
	}
	global := false
	for _, line := range strings.Split(string(ifs), "\n") {
		if f := strings.Fields(line); len(f) >= 4 && f[3] == "00" {
			global = true
			break
		}
	}
	if !global {
		return false
	}
	// Streamed, stopping once both are seen: the file lists every IPv6 (and,
	// with a dual-stack origin, v4-mapped) connection too, MBs on a busy node.
	fh, err := os.Open(l.fs(l.procTCP6))
	if err != nil {
		return false
	}
	defer fh.Close()
	ports := map[uint64]bool{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() && !(ports[80] && ports[443]) {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != "0A" {
			continue
		}
		addr, port, ok := strings.Cut(f[1], ":")
		if !ok || len(addr) != 32 {
			continue
		}
		if !globalV6Hex(addr) {
			continue
		}
		if p, err := strconv.ParseUint(port, 16, 16); err == nil {
			ports[p] = true
		}
	}
	return ports[80] && ports[443]
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
	panel := l.panel()
	p := l.probeStack(stack, panel)
	p.Panel = panel
	if l.loopIP == "" && l.edgeIPv6() {
		// The edge listens on IPv6 too: an IPv6 visitor's hop comes from ::1,
		// so the same trust has to hold for ::1. Same reading, second address;
		// the verdict is trusted only when both are.
		p.EdgeIPv6, p.EdgeIPv6Listening = true, l.edgeListensIPv6()
		if p.Trusted {
			l6 := l
			l6.loopIP = "::1"
			if p6 := l6.probeStack(stack, panel); !p6.Trusted {
				p.Trusted, p.v6Only = false, true
				p.Note = joinNote(p.Note, "the edge also listens on IPv6 and an IPv6 visitor reaches the origin from ::1, which is not trusted: "+l6.loopNote(p6.Note))
				// The plan (fix.go) fixes what the ::1 reading found missing.
				// (The header in effect does not depend on the address read.)
				p.ng, p.Servers, p.UntrustedServers = p6.ng, p6.Servers, p6.UntrustedServers
			}
		}
	}
	if !p.Trusted && p.Panel == PanelNGM && p.Stack == StackNginx {
		p.Note += "; NGM renders nginx itself and trusts the loopback while CFM is installed (NGM 2026-11-28 and later): run ngm trusted-proxies refresh"
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

func (l layout) probeStack(stack, panel string) Probe {
	switch stack {
	case StackApache:
		return l.probeApache(StackApache)
	case StackLiteSpeed:
		// OpenLiteSpeed: a plain-text config and no httpd_config.xml (ols.go).
		// It loads no Apache config, so no RemoteIP fallback.
		if !isFile(l.fs(l.lsConfig)) && isFile(l.fs(l.olsConfig)) {
			return l.probeOLS()
		}
		// LiteSpeed Enterprise resolves the client natively (useIpInProxyHeader)
		// or through the Apache RemoteIP conf it loads (loadApacheConf=1).
		if b, err := os.ReadFile(l.fs(l.lsConfig)); err == nil && l.lsNativeMatch(b) {
			return Probe{Stack: StackLiteSpeed, Trusted: true, Directive: "useIpInProxyHeader", Source: l.lsConfig}
		}
		if ap := l.probeApache(StackLiteSpeed); ap.Trusted {
			ap.Directive += " (loadApacheConf)"
			return ap
		}
		return Probe{Stack: StackLiteSpeed, Note: "httpd_config.xml has no useIpInProxyHeader 1, or 2 with 127.0.0.1T in the allow list, and no Apache RemoteIP trust of 127.0.0.1"}
	case StackNginx:
		return l.probeNginx(panel)
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
	ds, truncated := l.apacheDirectives(main.conf, main.serverRoot, "remoteipinternalproxy", "remoteiptrustedproxy", "remoteipheader")
	trust, header, scoped := "", "", 0
	for _, d := range ds {
		switch {
		case d.scoped:
			scoped++
		case d.name == "remoteipheader" && len(d.args) > 0:
			header = d.args[0]
		case trust == "" && l.anyLoopback(d.args):
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
	if truncated {
		p.Note = joinNote(p.Note, truncatedNote)
	}
	return p
}

// probeNginx: nginx resolves the client per server{}. A server{} with its own
// set_real_ip_from list uses that list, and the http-level one only when it has
// none; its own real_ip_header likewise beats the http-level one (default
// X-Real-IP). So the verdict is per server{} block: each must end up trusting
// 127.0.0.1 with a header the edge sets. cPanel's ea-nginx includes
// cloudflare.conf (Cloudflare's ranges + real_ip_header CF-Connecting-IP) in
// every server{}, so an http-level trust reaches none of them; what reaches the
// site blocks is a file in conf.d/server-includes/ (Imunify360's webshield
// file, or the one `cfm realip fix` writes). earth (2026-11-17) logged real IPs
// through that file while the http-level reading warned. On cPanel the
// proxy-subdomain blocks (cpanel. / webmail. / whm. ...) do not include
// server-includes/; they proxy to cpsrvd, and only ea-nginx's own log reads
// 127.0.0.1 for them, so they are reported, not counted. Read along nginx's
// include chain. With no server{} block found, the http-level settings decide.
func (l layout) probeNginx(panel string) Probe {
	ds, servers, truncated := l.nginxDirectives(l.nginxMain, l.nginxPrefix, "set_real_ip_from", "real_ip_header")
	trust, header, inLocation, httpList := "", "", 0, false
	type own struct {
		list, loopback bool
		src, header    string
	}
	per := make([]own, len(servers))
	for _, d := range ds {
		switch {
		case d.location:
			if d.name == "set_real_ip_from" {
				inLocation++
			}
		case d.server >= 0:
			o := &per[d.server]
			switch {
			case d.name == "real_ip_header" && len(d.args) > 0:
				o.header = d.args[0]
			case d.name == "set_real_ip_from":
				o.list = true
				if !o.loopback && l.anyLoopback(d.args) {
					o.loopback, o.src = true, l.display(d.file)
				}
			}
		case d.name == "real_ip_header" && len(d.args) > 0:
			header = d.args[0]
		case d.name == "set_real_ip_from":
			httpList = true
			if trust == "" && l.anyLoopback(d.args) {
				trust = l.display(d.file)
			}
		}
	}
	p := Probe{Stack: StackNginx, Source: trust, ng: &nginxVerdict{httpList: httpList}}
	if header != "" && !edgeHeaders[strings.ToLower(header)] {
		p.ng.httpBadHeader = header
	}

	serverIncludes := l.fs(l.cpanelNginxServerIncludes)
	headers := map[string]bool{}
	ownOK, proxyUntrusted, inherit, ownNoLoop, internal := 0, 0, 0, 0, 0
	badHeaders := map[string]bool{}
	for i, srv := range servers {
		o := per[i]
		hdr := o.header
		if hdr == "" {
			hdr = header
		}
		loop := trust != ""
		if o.list {
			loop = o.loopback
		}
		edgeHdr := hdr == "" || edgeHeaders[strings.ToLower(hdr)]
		if !srv.edgeFacing() {
			// Listens only where the edge never proxies to (a status page on
			// 127.0.0.1:8090, a unix socket): no visitor reaches it through the edge.
			internal++
			continue
		}
		if panel == PanelCPanel && cpanelProxyServer(srv.names) {
			if !loop || !edgeHdr {
				proxyUntrusted++
			}
			continue
		}
		p.Servers++
		shown := hdr
		if shown == "" {
			shown = "X-Real-IP (default)"
		}
		headers[shown] = true
		if loop && edgeHdr {
			if o.list {
				ownOK++
				if p.Source == "" {
					p.Source = o.src
				}
			}
			continue
		}
		u := nginxSite{names: srv.names, ownList: o.list}
		switch {
		case !edgeHdr:
			// The header has to be fixed by hand first, loopback or not.
			u.badHeader = hdr
			badHeaders[hdr] = true
		case o.list:
			ownNoLoop++
		default:
			inherit++
		}
		for _, d := range srv.includeDirs {
			if d == serverIncludes {
				u.serverIncludes = true
			}
		}
		p.ng.untrusted = append(p.ng.untrusted, u)
	}
	p.UntrustedServers = len(p.ng.untrusted)

	if p.Servers == 0 {
		// No site server{} to read: the http-level settings stand for the host.
		p.Servers, p.UntrustedServers, p.ng.untrusted = 0, 0, nil
		p.Header = header
		if p.Header == "" {
			p.Header = "X-Real-IP (default)"
		}
		switch {
		case trust == "":
			p.Note = "no http-level set_real_ip_from 127.0.0.1 in the nginx config"
		case p.ng.httpBadHeader != "":
			p.Note = "real_ip_header " + header + " is not a header the edge sets (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)"
		default:
			p.Trusted, p.Directive = true, "set_real_ip_from 127.0.0.1"
		}
	} else {
		p.Header = joinSorted(headers)
		if len(p.ng.untrusted) == 0 {
			p.Trusted = true
			if ownOK == 0 {
				p.Directive = "set_real_ip_from 127.0.0.1"
			} else {
				p.Directive = "set_real_ip_from 127.0.0.1 in every server{} (" + strconv.Itoa(ownOK) + " through their own list)"
			}
		} else {
			p.Note = strconv.Itoa(len(p.ng.untrusted)) + " of " + strconv.Itoa(p.Servers) + " server{} block(s) do not trust 127.0.0.1 (e.g. " + siteExamples(p.ng.untrusted) + ")"
			if inherit > 0 {
				p.Note += "; " + strconv.Itoa(inherit) + " inherit the http-level list, which has no 127.0.0.1"
			}
			if ownNoLoop > 0 {
				p.Note += "; " + strconv.Itoa(ownNoLoop) + " keep their own set_real_ip_from list without 127.0.0.1, which replaces the http-level one"
			}
			if len(badHeaders) > 0 {
				p.Note += "; real_ip_header " + joinSorted(badHeaders) + " is not a header the edge sets"
			}
		}
	}
	if proxyUntrusted > 0 {
		p.Note = joinNote(p.Note, strconv.Itoa(proxyUntrusted)+" cPanel proxy-subdomain server{} block(s) (cpanel./webmail./whm./...) "+
			"do not trust 127.0.0.1: they proxy to cpsrvd and only ea-nginx's own log reads 127.0.0.1 for them (not counted)")
	}
	if internal > 0 {
		p.Note = joinNote(p.Note, strconv.Itoa(internal)+" server{} block(s) listening only off :80/:443, where the edge never proxies (not counted)")
	}
	if inLocation > 0 {
		p.Note = joinNote(p.Note, strconv.Itoa(inLocation)+" set_real_ip_from line(s) inside location{} blocks: they apply to those locations only, "+
			"so the verdict reads the server{} level")
	}
	if truncated {
		p.Note = joinNote(p.Note, truncatedNote)
	}
	return p
}

// truncatedNote: a walk limit stopped the read, so the verdict is partial.
const truncatedNote = "the configuration walk stopped at a limit (include depth, files or inclusions), so the verdict reads part of it only"

// nginxVerdict is what the plan needs from an nginx probe.
type nginxVerdict struct {
	httpBadHeader string // an http-level real_ip_header the edge does not set
	httpList      bool   // http{} has its own set_real_ip_from list (a server-level list replaces it)
	untrusted     []nginxSite
}

// nginxSite is a server{} block that does not trust the edge.
type nginxSite struct {
	names          []string
	ownList        bool   // it has its own set_real_ip_from list (an http-level trust does not reach it)
	badHeader      string // it trusts the loopback but reads a header the edge does not set
	serverIncludes bool   // it includes cPanel's conf.d/server-includes/
}

// cpanelProxyPrefixes are the service subdomains ea-nginx proxies to cpsrvd.
var cpanelProxyPrefixes = []string{"autoconfig.", "autodiscover.", "cpanel.", "cpcalendars.", "cpcontacts.", "webdisk.", "webmail.", "whm."}

// cpanelProxyServer reports whether every name of a server{} is a cPanel
// service subdomain (cpanel.example.gr, a wildcard cpanel.*, or a regex
// ~^cpanel\.).
func cpanelProxyServer(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		for _, c := range nameCandidates(n) {
			hit := false
			for _, pre := range cpanelProxyPrefixes {
				if strings.HasPrefix(c, pre) {
					hit = true
					break
				}
			}
			if !hit {
				return false
			}
		}
	}
	return true
}

// nameCandidates is what a server_name can start with: the name itself, or
// for a regex (~^...) each option of a leading group, `~^(cpanel|webmail)\.`
// or `~^(?<sub>cpanel|whm)\.` included.
func nameCandidates(n string) []string {
	n = strings.ToLower(n)
	if !strings.HasPrefix(n, "~") {
		return []string{n}
	}
	n = strings.ReplaceAll(strings.TrimLeft(n, "~^"), `\.`, ".")
	if !strings.HasPrefix(n, "(") {
		return []string{n}
	}
	j := strings.Index(n, ")")
	if j < 0 {
		return []string{n}
	}
	inner, rest := n[1:j], n[j+1:]
	switch {
	case strings.HasPrefix(inner, "?:"):
		inner = inner[2:]
	case strings.HasPrefix(inner, "?<") || strings.HasPrefix(inner, "?p<"):
		if k := strings.Index(inner, ">"); k >= 0 {
			inner = inner[k+1:]
		}
	}
	var out []string
	for _, opt := range strings.Split(inner, "|") {
		out = append(out, opt+rest)
	}
	return out
}

func siteExamples(us []nginxSite) string {
	var ex []string
	for _, u := range us {
		name := "(no server_name)"
		if len(u.names) > 0 {
			name = u.names[0]
		}
		ex = append(ex, name)
		if len(ex) == 3 {
			break
		}
	}
	return strings.Join(ex, ", ")
}

func joinSorted(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, " / ")
}

// anyLoopback is anyLoopback4, or anyLoopback6 on the ::1 pass.
func (l layout) anyLoopback(args []string) bool {
	if l.loopIP == "::1" {
		return anyLoopback6(args)
	}
	return anyLoopback(args)
}

// loopNote rewrites a note for the address this pass checks (the notes name
// 127.0.0.1, the first pass).
func (l layout) loopNote(n string) string {
	if l.loopIP == "::1" {
		n = strings.ReplaceAll(n, "127.0.0.1T", "::1T")
		n = strings.ReplaceAll(n, "127.0.0.1", "::1")
	}
	return n
}

// anyLoopback6 reports whether one of a trust directive's arguments covers
// ::1, the source of an IPv6 hop: ::1 or ::1/128 (a wider IPv6 network is not
// a loopback trust).
func anyLoopback6(args []string) bool {
	one := net.ParseIP("::1")
	for _, a := range args {
		if ip := net.ParseIP(a); ip != nil {
			if ip.Equal(one) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if ones, bits := n.Mask.Size(); bits == 128 && ones == 128 && n.IP.Equal(one) {
			return true
		}
	}
	return false
}

// anyLoopback reports whether one of a trust directive's arguments covers the
// edge's address: 127.0.0.1, alone or as a loopback-only network (127.0.0.0/8
// .. /32). The edge proxies from 127.0.0.1 (proxy_bind), so ::1 alone does not
// trust it: a list holding only ::1 still logs 127.0.0.1. 127.0.0.1/1 covers
// half the internet and is not a loopback trust. An origin hop to an IPv6
// destination binds ::1 instead ($cfm_pass_bind / $cfm_origin_bind in the
// edge confs): when the edge listens on IPv6, probe() runs a second pass with
// anyLoopback6.
func anyLoopback(args []string) bool {
	for _, a := range args {
		if ip := net.ParseIP(a); ip != nil {
			if ip.Equal(net.ParseIP("127.0.0.1")) {
				return true
			}
			continue
		}
		_, n, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		if ones, bits := n.Mask.Size(); bits == 32 && ones >= 8 && n.IP.IsLoopback() && n.Contains(net.ParseIP("127.0.0.1")) {
			return true
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
// any peer), or 2 (trusted peers only) with the edge's address (127.0.0.1, or
// ::1 on the IPv6 pass) marked trusted.
func (l layout) lsNativeMatch(b []byte) bool {
	b = xmlCommentRe.ReplaceAll(b, nil)
	m := lsNativeRealIPRe.FindSubmatch(b)
	if m == nil {
		return false
	}
	if string(m[1]) == "1" {
		return true
	}
	if l.loopIP == "::1" {
		return lsTrustedLoopback6Re.Match(b)
	}
	return lsTrustedLoopbackRe.Match(b)
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

// edgeV6ListenFiles: each edge engine's generated IPv6 listen files
// (edgeengine.Profiles, file-precedence order).
func edgeV6ListenFiles() []string {
	var out []string
	for _, p := range edgeengine.InFileOrder() {
		out = append(out, p.ConfPath("cfm-listen-v6-http.conf"), p.ConfPath("cfm-listen-v6-https.conf"))
	}
	return out
}
