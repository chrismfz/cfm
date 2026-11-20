package originrealip

import (
	"path/filepath"
	"sort"
	"strings"
)

// OpenLiteSpeed keeps its server config as plain text, not LiteSpeed
// Enterprise's httpd_config.xml: /usr/local/lsws/conf/httpd_config.conf,
// which `include`s the rest. On DirectAdmin (CustomBuild webserver=
// openlitespeed) it is a symlink to /etc/openlitespeed/httpd_config.conf and
// the settings live in included files (server3, 2026-11-20):
//
//	/etc/openlitespeed/httpd-defaults.conf:      useIpInProxyHeader  2
//	/etc/openlitespeed/httpd-accesscontrol.conf: accessControl{
//	                                                 allow  ALL, 173.245.48.0/20T, ...
//	                                                 deny
//	                                             }
//
// The trust is the same as LiteSpeed's: useIpInProxyHeader 1 takes the client
// from the header of any peer, 2 ("Trusted IP Only") only from an address the
// server-level accessControl allow list marks trusted with a trailing T
// (127.0.0.1T, and ::1T for the edge's IPv6 hop). Only server-level settings
// count: a virtualhost{} block's own accessControl does not trust a proxy for
// the server, so the reader tracks the brace depth across includes.

// olsVerdict is what the OpenLiteSpeed reading found, for the probe's note and
// the plan's wording.
type olsVerdict struct {
	mode       string // the last server-level useIpInProxyHeader value, "" if none
	modeSource string // the file it came from
	aclSource  string // the file of the last server-level accessControl block, "" if none
	allow      []string

	// Every server-level value and list. Which one OpenLiteSpeed keeps when
	// a setting appears twice is not measured, so the verdict asks all of
	// them: a wrong "trusted" would let the edge listen on IPv6 while the
	// origin sees ::1 for every IPv6 visitor.
	modes  []string
	allows [][]string
}

// olsMaxFiles bounds the include walk (a glob loop, a huge vhost tree).
const olsMaxFiles = 512

// olsServerRoot is what $SERVER_ROOT and a relative include path resolve
// against.
const olsServerRoot = "/usr/local/lsws"

func (l layout) readOLS() olsVerdict {
	var v olsVerdict
	seen := map[string]bool{}
	depth := 0
	inACL := -1 // the depth of the server-level accessControl block being read, -1 outside
	var curAllow []string
	var walk func(logical string)
	walk = func(logical string) {
		if len(seen) >= olsMaxFiles || seen[logical] {
			return
		}
		seen[logical] = true
		cf := readConfFile(l.fs(logical))
		if !cf.ok {
			return
		}
		heredoc := "" // the end marker of a multi-line value (rules <<<END_rules)
		for _, raw := range strings.Split(string(cf.b), "\n") {
			if heredoc != "" {
				if strings.TrimSpace(raw) == heredoc {
					heredoc = ""
				}
				continue // rewrite rules and the like: never a brace or a setting
			}
			line := olsStripComment(raw)
			if line == "" {
				continue
			}
			if i := strings.Index(line, "<<<"); i >= 0 {
				heredoc = strings.TrimSpace(line[i+3:])
				continue
			}
			key, val := olsSplit(line)
			switch {
			case strings.HasSuffix(line, "{"):
				name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(line, "{")))
				if depth == 0 && name == "accesscontrol" {
					inACL, curAllow = depth+1, nil
				}
				depth++
				continue
			case line == "}":
				if depth > 0 {
					depth--
				}
				if inACL >= 0 && depth < inACL {
					// A server-level list closed.
					v.aclSource, v.allow, inACL = logical, curAllow, -1
					v.allows = append(v.allows, curAllow)
				}
				continue
			}
			switch strings.ToLower(key) {
			case "include":
				for _, inc := range l.olsInclude(val) {
					walk(inc)
				}
			case "useipinproxyheader":
				if depth == 0 {
					v.mode, v.modeSource = val, logical
					v.modes = append(v.modes, val)
				}
			case "allow":
				if inACL >= 0 && depth == inACL {
					curAllow = append(curAllow, olsList(val)...)
				}
			}
		}
	}
	walk(l.olsConfig)
	return v
}

// olsInclude expands an include argument to logical paths: $SERVER_ROOT and a
// relative path resolve against olsServerRoot; a glob matches on disk, sorted.
func (l layout) olsInclude(arg string) []string {
	arg = strings.Trim(arg, `"'`)
	arg = strings.ReplaceAll(arg, "$SERVER_ROOT", olsServerRoot)
	if arg == "" || strings.Contains(arg, "$") {
		return nil // $VH_ROOT and the like: per-vhost, not server level
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(olsServerRoot, arg)
	}
	if !strings.ContainsAny(arg, "*?[") {
		return []string{arg}
	}
	matches, err := filepath.Glob(l.fs(arg))
	if err != nil {
		return nil
	}
	sort.Strings(matches)
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, l.display(m))
	}
	return out
}

// olsStripComment drops a # comment (at the start, or after whitespace) and
// trims the line.
func olsStripComment(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "#") {
		return ""
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '#' && (s[i-1] == ' ' || s[i-1] == '\t') {
			s = s[:i]
			break
		}
	}
	return strings.TrimSpace(s)
}

// olsSplit splits "key   value" at the first run of whitespace.
func olsSplit(line string) (string, string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, ""
	}
	return line[:i], strings.TrimSpace(line[i:])
}

// olsList splits an allow value: comma and/or whitespace separated entries.
func olsList(val string) []string {
	return strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

// trusted reports whether the reading takes the client from the edge's header
// for the address this pass checks (127.0.0.1, or ::1 on the IPv6 pass):
// every server-level useIpInProxyHeader is 1, or each is 1 or 2 and every
// server-level allow list marks the address trusted.
func (v olsVerdict) trusted(l layout) bool {
	if len(v.modes) == 0 {
		return false
	}
	needACL := false
	for _, m := range v.modes {
		switch m {
		case "1":
		case "2":
			needACL = true
		default:
			return false
		}
	}
	if !needACL {
		return true
	}
	if len(v.allows) == 0 {
		return false
	}
	for _, allow := range v.allows {
		var t []string
		for _, a := range allow {
			if strings.HasSuffix(a, "T") {
				t = append(t, strings.TrimSuffix(a, "T"))
			}
		}
		if !l.anyLoopback(t) {
			return false
		}
	}
	return true
}

func (l layout) probeOLS() Probe {
	v := l.readOLS()
	p := Probe{Stack: StackLiteSpeed, ols: &v}
	if v.trusted(l) {
		p.Trusted, p.Directive = true, "useIpInProxyHeader "+v.mode+" (OpenLiteSpeed)"
		p.Source = v.modeSource
		if v.mode == "2" {
			p.Source = v.aclSource
		}
		return p
	}
	switch v.mode {
	case "":
		p.Note = "OpenLiteSpeed: no server-level useIpInProxyHeader in " + l.olsConfig + " or the files it includes"
	case "1", "2":
		where := "no server-level accessControl block"
		if v.aclSource != "" {
			where = "the server-level accessControl allow list in " + v.aclSource
		}
		p.Note = "OpenLiteSpeed: useIpInProxyHeader 2 (" + v.modeSource + ") but 127.0.0.1T is not in " + where
	default:
		p.Note = "OpenLiteSpeed: useIpInProxyHeader " + v.mode + " (" + v.modeSource + ") does not take the client from the edge's header (1, or 2 with 127.0.0.1T)"
	}
	return p
}

// olsReason is the manual step for OpenLiteSpeed: CFM does not edit its config.
func olsReason(p Probe) string {
	trusted := "127.0.0.1T"
	if p.EdgeIPv6 {
		trusted = "127.0.0.1T, ::1T"
	}
	mode, acl := "/usr/local/lsws/conf/httpd_config.conf", "/usr/local/lsws/conf/httpd_config.conf"
	if p.Panel == PanelDirectAdmin {
		mode, acl = "/etc/openlitespeed/httpd-defaults.conf", "/etc/openlitespeed/httpd-accesscontrol.conf"
	}
	if p.ols != nil {
		if p.ols.modeSource != "" {
			mode = p.ols.modeSource
		}
		if p.ols.aclSource != "" {
			acl = p.ols.aclSource
		}
	}
	r := "OpenLiteSpeed: set the server-level useIpInProxyHeader 2 (\"Trusted IP Only\"; " + mode + ") and add " +
		trusted + " to the server-level accessControl allow list (" + acl + "), then restart it " +
		"(/usr/local/lsws/bin/lswsctrl restart); in WebAdmin (:7080): Server Configuration > General > Use Client IP in Header, " +
		"and Security > Access Control > Allowed List. CFM does not edit the OpenLiteSpeed config"
	if p.Panel == PanelDirectAdmin {
		r += "; DirectAdmin's CustomBuild can rewrite those files on a rebuild, so run `cfm realip` again after one"
	}
	return r
}
