package originrealip

import (
	"path/filepath"
	"sort"
	"strconv"
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
	modes       []string
	modeSources []string
	allows      [][]string

	files []string // every file read, in order
}

// olsMaxFiles bounds the include walk (a glob loop, a huge vhost tree).
const olsMaxFiles = 512

// olsServerRoot is what $SERVER_ROOT and a relative include path resolve
// against.
const olsServerRoot = "/usr/local/lsws"

func (l layout) readOLS() olsVerdict { return l.readOLSWith(nil) }

// readOLSWith reads the config with some files' content replaced (overlay,
// by logical path; nil = the disk as it is): what CustomBuild would install.
func (l layout) readOLSWith(overlay func(logical string) ([]byte, bool)) olsVerdict {
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
		if overlay != nil {
			if b, ok := overlay(logical); ok {
				cf = confFile{b: b, ok: true}
			}
		}
		if !cf.ok {
			return
		}
		v.files = append(v.files, logical)
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
					v.modes, v.modeSources = append(v.modes, val), append(v.modeSources, logical)
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
	return v.modeOK() && (!v.needACL() || v.aclOK(l))
}

// modeOK: there is a server-level useIpInProxyHeader and every one is 1 or 2.
func (v olsVerdict) modeOK() bool {
	return len(v.modes) > 0 && v.badMode() < 0
}

// badMode: the index of the first server-level value that is neither 1 nor
// 2, or -1.
func (v olsVerdict) badMode() int {
	for i, m := range v.modes {
		if m != "1" && m != "2" {
			return i
		}
	}
	return -1
}

// needACL: a value is 2 ("Trusted IP Only"), so the allow list decides.
func (v olsVerdict) needACL() bool {
	for _, m := range v.modes {
		if m == "2" {
			return true
		}
	}
	return false
}

// aclOK: there is a server-level allow list and every one marks the address
// this pass checks trusted.
func (v olsVerdict) aclOK(l layout) bool {
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
		if v.needACL() {
			p.Directive = "useIpInProxyHeader 2 (OpenLiteSpeed)"
			p.Source = v.aclSource
		}
		p.Warning = l.olsRewriteWarning()
		return p
	}
	switch {
	case len(v.modes) == 0:
		p.Note = "OpenLiteSpeed: no server-level useIpInProxyHeader in " + l.olsConfig + " or the files it includes"
	case v.badMode() >= 0:
		i := v.badMode()
		p.Note = "OpenLiteSpeed: useIpInProxyHeader " + v.modes[i] + " (" + v.modeSources[i] + ") does not take the client from the edge's header (1, or 2 with 127.0.0.1T)"
		if len(v.modes) > 1 {
			p.Note += "; the server-level values disagree (" + strings.Join(v.modes, ", ") + "), and every one must be 1 or 2"
		}
	default:
		where := "no server-level accessControl block"
		if v.aclSource != "" {
			where = "the server-level accessControl allow list in " + v.aclSource
		}
		if len(v.allows) > 1 {
			where = "every one of the " + strconv.Itoa(len(v.allows)) + " server-level accessControl allow lists (the last in " + v.aclSource + ")"
		}
		p.Note = "OpenLiteSpeed: useIpInProxyHeader 2 but 127.0.0.1T is not in " + where
	}
	return p
}

// olsRewriteWarning: on DirectAdmin, whether the trust survives `da build
// rewrite_confs`. The config is read again with each DirectAdmin-managed file
// replaced by what CustomBuild would install (its custom copy, else its
// template); if that reading is not trusted, the warning names the live
// files that differ from what would be installed.
func (l layout) olsRewriteWarning() string {
	if !l.anyExists(l.daMarkers) {
		return ""
	}
	installed := func(logical string) ([]byte, bool) {
		src, ok := l.olsDAInstalled(logical)
		if !ok {
			return nil, false
		}
		cf := readConfFile(l.fs(src))
		return cf.b, cf.ok
	}
	after := l.readOLSWith(installed)
	ok := after.trusted(l)
	if ok && l.loopIP == "" && l.edgeIPv6() {
		l6 := l
		l6.loopIP = "::1"
		ok = after.trusted(l6)
	}
	if ok {
		return ""
	}
	var changed []string
	for _, f := range l.readOLS().files {
		b, ok := installed(f)
		if !ok {
			continue
		}
		if live := readConfFile(l.fs(f)); !live.ok || string(live.b) != string(b) {
			changed = append(changed, f+" (keep it in "+filepath.Join(olsDACustomDir, filepath.Base(f))+")")
		}
	}
	w := "trusted now, but not after `da build rewrite_confs`, which rewrites the files under " + olsDALiveDir + " from CustomBuild's templates"
	if len(changed) > 0 {
		w += ": " + strings.Join(changed, ", ")
	}
	return w
}

// olsDACustomDir: DirectAdmin's CustomBuild rewrites every global
// OpenLiteSpeed file under /etc/openlitespeed from its template
// (custombuild/configure/openlitespeed/conf) on `da build rewrite_confs`,
// except httpd-includes.conf, and always uses a copy under this directory
// instead (DirectAdmin FAQ, "templating system for
// nginx/openlitespeed/apache configurations").
const (
	olsDALiveDir     = "/etc/openlitespeed"
	olsDACustomDir   = "/usr/local/directadmin/custombuild/custom/openlitespeed/conf"
	olsDATemplateDir = "/usr/local/directadmin/custombuild/configure/openlitespeed/conf"
)

// olsDAInstalled: for a DirectAdmin-managed file (directly under
// /etc/openlitespeed, not httpd-includes.conf, or the main config that links
// there), the file `da build rewrite_confs` would install in its place: the
// custom copy when there is one, else CustomBuild's template. false when
// CustomBuild does not rewrite the file or has no template for it.
func (l layout) olsDAInstalled(logical string) (string, bool) {
	if logical == l.olsConfig {
		logical = filepath.Join(olsDALiveDir, "httpd_config.conf")
	}
	if filepath.Dir(logical) != olsDALiveDir || filepath.Base(logical) == "httpd-includes.conf" {
		return "", false
	}
	for _, dir := range []string{olsDACustomDir, olsDATemplateDir} {
		p := filepath.Join(dir, filepath.Base(logical))
		if isFile(l.fs(p)) {
			return p, true
		}
	}
	return "", false
}

// olsReason is the manual step for OpenLiteSpeed: CFM does not edit its config.
func (l layout) olsReason(p Probe) string {
	trusted := "127.0.0.1T"
	if p.EdgeIPv6 {
		trusted = "127.0.0.1T, ::1T"
	}
	// What is missing: the mode, the allow list entries, or both.
	needMode, needACL := true, true
	if p.ols != nil {
		needMode = !p.ols.modeOK()
		l4, l6 := l, l
		l4.loopIP, l6.loopIP = "", "::1"
		needACL = !p.ols.aclOK(l4) || (p.EdgeIPv6 && !p.ols.aclOK(l6))
		if !needMode && !needACL {
			needMode, needACL = true, true // the step as a whole (a disagreement the parts do not show)
		}
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
	if p.Panel == PanelDirectAdmin && filepath.Dir(acl) == olsDALiveDir && filepath.Dir(mode) == olsDALiveDir {
		// The DirectAdmin way: a custom copy CustomBuild installs and keeps.
		var steps []string
		if needACL {
			steps = append(steps, "copy "+acl+" to "+filepath.Join(olsDACustomDir, filepath.Base(acl))+" and add "+trusted+" to its allow line there")
		}
		if needMode {
			steps = append(steps, "copy "+mode+" to "+filepath.Join(olsDACustomDir, filepath.Base(mode))+" and set useIpInProxyHeader 2 there (every server-level one)")
		}
		return "OpenLiteSpeed on DirectAdmin: " + strings.Join(steps, "; ") + "; then run `da build rewrite_confs` and restart OpenLiteSpeed " +
			"(/usr/local/lsws/bin/lswsctrl restart). An edit of the live file alone is lost on the next rewrite_confs. " +
			"CFM does not edit the OpenLiteSpeed config"
	}
	return "OpenLiteSpeed: set the server-level useIpInProxyHeader 2 (\"Trusted IP Only\"; " + mode + ") and add " +
		trusted + " to the server-level accessControl allow list (" + acl + "), then restart it " +
		"(/usr/local/lsws/bin/lswsctrl restart); in WebAdmin (:7080): Server Configuration > General > Use Client IP in Header, " +
		"and Security > Access Control > Allowed List. CFM does not edit the OpenLiteSpeed config"
}
