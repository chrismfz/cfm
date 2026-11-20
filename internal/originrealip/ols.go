package originrealip

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
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
	modes        []string
	modeSources  []string
	allows       [][]string
	allowSources []string

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
					v.allows, v.allowSources = append(v.allows, curAllow), append(v.allowSources, logical)
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

// OpenLiteSpeed's useIpInProxyHeader values (its WebAdmin, Ols/DTblDefBase.php
// on server3): 0 No, 1 Yes, 2 Trusted IP Only, 3 Keep Header from Trusted IP
// (2, with the backend's X-Forwarded-For left as it came), 4 Use Last IP (for
// AWS ELB: the last X-Forwarded-For entry, the one the edge appends). 1 and 4
// take the header from any peer, 2 and 3 only from a trusted one.
var (
	olsModeAnyPeer = map[string]bool{"1": true, "4": true}
	olsModeTrusted = map[string]bool{"2": true, "3": true}
)

// badMode: the index of the first server-level value that does not take the
// client from the edge's header (0, or anything unknown), or -1.
func (v olsVerdict) badMode() int {
	for i, m := range v.modes {
		if !olsModeAnyPeer[m] && !olsModeTrusted[m] {
			return i
		}
	}
	return -1
}

// needACL: a value is 2 or 3 (trusted peers only), so the allow list decides.
func (v olsVerdict) needACL() bool {
	for _, m := range v.modes {
		if olsModeTrusted[m] {
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
			for _, m := range v.modes {
				if olsModeTrusted[m] {
					p.Directive = "useIpInProxyHeader " + m + " (OpenLiteSpeed)"
					break
				}
			}
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
		p.Note = "OpenLiteSpeed: useIpInProxyHeader " + v.modes[i] + " (" + v.modeSources[i] + ") does not take the client from the edge's header (1 or 4, or 2 / 3 with 127.0.0.1T)"
		if len(v.modes) > 1 {
			p.Note += "; the server-level values disagree (" + strings.Join(v.modes, ", ") + "), and every one must be 1-4"
		}
	default:
		where := "no server-level accessControl block"
		if v.aclSource != "" {
			where = "the server-level accessControl allow list in " + v.aclSource
		}
		if len(v.allows) > 1 {
			where = "every one of the " + strconv.Itoa(len(v.allows)) + " server-level accessControl allow lists (the last in " + v.aclSource + ")"
		}
		p.Note = "OpenLiteSpeed: useIpInProxyHeader 2 / 3 (trusted IP only) but 127.0.0.1T is not in " + where
	}
	return p
}

// olsRewriteCulprits: the live files whose rewrite alone breaks the trust
// (olsRewriteWarning's reading), for the fix to keep.
func (l layout) olsRewriteCulprits() []string {
	var out []string
	l.culpritsOut = &out
	l.olsRewriteWarning()
	return out
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
	// Each address the edge proxies from that the live config trusts: a ::1
	// the live config does not trust already is not rewrite_confs' doing.
	live := l.readOLS()
	passes := []layout{l}
	if l.loopIP == "" && l.edgeIPv6() {
		l6 := l
		l6.loopIP = "::1"
		if live.trusted(l6) {
			passes = append(passes, l6)
		}
	}
	survives := func(v olsVerdict) bool {
		for _, lp := range passes {
			if !v.trusted(lp) {
				return false
			}
		}
		return true
	}
	if survives(l.readOLSWith(installed)) {
		return ""
	}
	// Name the files whose rewrite alone breaks the trust; a file that only
	// differs from its template (a tuned httpd-tuning.conf) is not one.
	var changed, culprits, culpritFiles []string
	for _, f := range live.files {
		b, ok := installed(f)
		if !ok {
			continue
		}
		if lf := readConfFile(l.fs(f)); lf.ok && string(lf.b) == string(b) {
			continue
		}
		entry := f + " (keep it in " + filepath.Join(olsDACustomDir, filepath.Base(f)) + ")"
		changed = append(changed, entry)
		only := func(logical string) ([]byte, bool) {
			if logical != f {
				return nil, false
			}
			return installed(logical)
		}
		if !survives(l.readOLSWith(only)) {
			culprits = append(culprits, entry)
			culpritFiles = append(culpritFiles, f)
		}
	}
	if len(culprits) > 0 {
		changed = culprits
	}
	if l.culpritsOut != nil {
		*l.culpritsOut = culpritFiles
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

// ── cfm realip fix on DirectAdmin ──────────────────────────────────────────

// olsCtl is OpenLiteSpeed's control script; `restart` is graceful (SIGUSR1,
// "zero down time" by its own help). It has no config test. A var for tests.
var olsCtl = "/usr/local/lsws/bin/lswsctrl"

// olsFixTokens are what the fix adds to the allow list: the edge's two
// source addresses, marked trusted (both always, as the Apache and nginx
// files trust both).
var olsFixTokens = []string{"127.0.0.1T", "::1T"}

// planOLS: on DirectAdmin, the fix edits the one file holding the server-level
// allow list (and, if needed, the one holding useIpInProxyHeader) and writes
// the same content to its custom copy, so the live file is already what
// `da build rewrite_confs` would install; Apply then restarts OpenLiteSpeed
// gracefully. Anything less clear-cut (several lists or values, a custom copy
// that differs from the live file, a file outside /etc/openlitespeed) is the
// manual step.
func (l layout) planOLS(pl *Plan) {
	p := pl.Probe
	pl.Reason = l.olsReason(p)
	v := p.ols
	if p.Panel != PanelDirectAdmin || v == nil {
		return
	}
	edits := map[string][]byte{} // logical path -> new content
	if !v.modeOK() || v.needACL() {
		// Trust through the allow list: one server-level list, in a DA file.
		if len(v.allows) != 1 || filepath.Dir(v.allowSources[0]) != olsDALiveDir {
			return
		}
		src := v.allowSources[0]
		cf := readConfFile(l.fs(src))
		if !cf.ok {
			return
		}
		nb, ok := olsAddTrust(cf.b)
		if !ok {
			return
		}
		if string(nb) != string(cf.b) {
			edits[src] = nb
		}
	}
	if !v.modeOK() {
		if len(v.modes) != 1 || filepath.Dir(v.modeSources[0]) != olsDALiveDir {
			return
		}
		src := v.modeSources[0]
		b := edits[src]
		if b == nil {
			cf := readConfFile(l.fs(src))
			if !cf.ok {
				return
			}
			b = cf.b
		}
		nb, ok := olsSetMode(b, "2")
		if !ok {
			return
		}
		edits[src] = nb
	}
	if len(edits) == 0 {
		return
	}
	// The result must read trusted for both addresses, as written.
	overlay := func(logical string) ([]byte, bool) { b, ok := edits[logical]; return b, ok }
	after := l.readOLSWith(overlay)
	l4, l6 := l, l
	l4.loopIP, l6.loopIP = "", "::1"
	if !after.trusted(l4) || !after.trusted(l6) {
		return
	}
	var writes []FileWrite
	paths := make([]string, 0, len(edits))
	for src := range edits {
		paths = append(paths, src)
	}
	sort.Strings(paths)
	for _, src := range paths {
		custom := filepath.Join(olsDACustomDir, filepath.Base(src))
		// A custom copy that differs from the live file holds edits the live
		// file does not show: which one is meant is the operator's call.
		if c := readConfFile(l.fs(custom)); c.ok {
			if live := readConfFile(l.fs(src)); !live.ok || string(live.b) != string(c.b) {
				pl.Reason = custom + " differs from " + src + "; reconcile them by hand, then: " + pl.Reason
				return
			}
		} else if isFile(l.fs(custom)) || isDir(l.fs(custom)) {
			return
		}
		base, cbase := readConfFile(l.fs(src)), readConfFile(l.fs(custom))
		writes = append(writes,
			FileWrite{Path: l.fs(src), Content: string(edits[src]), Live: true, base: string(base.b), baseExists: base.ok, checkBase: true},
			FileWrite{Path: l.fs(custom), Content: string(edits[src]), base: string(cbase.b), baseExists: cbase.ok, checkBase: true})
	}
	// And after the next rewrite_confs: the edited files are what it installs
	// (their custom copies), every other file what CustomBuild has for it.
	rewritten := func(logical string) ([]byte, bool) {
		if b, ok := edits[logical]; ok {
			return b, true
		}
		if inst, ok := l.olsDAInstalled(logical); ok {
			cf := readConfFile(l.fs(inst))
			return cf.b, cf.ok
		}
		return nil, false
	}
	if ar := l.readOLSWith(rewritten); !ar.trusted(l4) || !ar.trusted(l6) {
		pl.Reason = "the trust would not survive `da build rewrite_confs`: a custom copy or template under " +
			olsDACustomDir + " / " + olsDATemplateDir + " sets it otherwise; reconcile them by hand, then: " + pl.Reason
		return
	}
	pl.Action, pl.Reason, pl.Writes = ActionWrite, "", writes
	pl.Path = writes[0].Path
}

// planOLSKeep: trusted now, but not after `da build rewrite_confs` (the
// warning): write the custom copies of the files whose rewrite breaks the
// trust, with their live content, so a rebuild installs what runs. Nothing
// live changes, so nothing restarts.
func (l layout) planOLSKeep(pl *Plan) {
	culprits := l.olsRewriteCulprits()
	if len(culprits) == 0 {
		return
	}
	var writes []FileWrite
	for _, f := range culprits {
		live := readConfFile(l.fs(f))
		if !live.ok {
			return
		}
		custom := filepath.Join(olsDACustomDir, filepath.Base(f))
		prev := readConfFile(l.fs(custom))
		if prev.ok && string(prev.b) != string(live.b) {
			// The custom copy may hold what the operator means a rebuild to
			// install: as planOLS, the operator's call.
			pl.Reason += "; " + custom + " differs from " + f + ": reconcile them by hand (a rebuild installs the custom copy)"
			return
		}
		writes = append(writes, FileWrite{Path: l.fs(custom), Content: string(live.b), base: string(prev.b), baseExists: prev.ok, checkBase: true})
	}
	pl.Action, pl.Reason, pl.Writes, pl.Path = ActionWrite, "", writes, writes[0].Path
}

// olsAddTrust appends the missing olsFixTokens to the last allow line of the
// file's one top-level accessControl block. false when the file has no such
// block, more than one, or the block has no allow line.
func olsAddTrust(b []byte) ([]byte, bool) {
	lines := strings.Split(string(b), "\n")
	depth, inACL, blocks, last := 0, false, 0, -1
	var have []string
	for i, raw := range lines {
		line := olsStripComment(raw)
		switch {
		case line == "":
		case strings.HasSuffix(line, "{"):
			if depth == 0 && strings.EqualFold(strings.TrimSpace(strings.TrimSuffix(line, "{")), "accesscontrol") {
				inACL, blocks = true, blocks+1
			}
			depth++
		case line == "}":
			if depth > 0 {
				depth--
			}
			if depth == 0 {
				inACL = false
			}
		default:
			if key, val := olsSplit(line); inACL && depth == 1 && strings.EqualFold(key, "allow") {
				last = i
				have = append(have, olsList(val)...)
			}
		}
	}
	if blocks != 1 || last < 0 {
		return nil, false
	}
	var add []string
	for _, tok := range olsFixTokens {
		addr := strings.TrimSuffix(tok, "T")
		var t []string
		for _, h := range have {
			if strings.HasSuffix(h, "T") {
				t = append(t, strings.TrimSuffix(h, "T"))
			}
		}
		covered := anyLoopback(t)
		if addr == "::1" {
			covered = anyLoopback6(t)
		}
		if !covered {
			add = append(add, tok)
		}
	}
	if len(add) == 0 {
		return b, true
	}
	// Before an inline comment, if there is one.
	raw := lines[last]
	body, comment := raw, ""
	if i := olsCommentIndex(raw); i >= 0 {
		body, comment = raw[:i], raw[i:]
	}
	body = strings.TrimRight(body, " \t")
	sep := ", "
	if _, val := olsSplit(strings.TrimSpace(body)); val == "" {
		sep = " "
	}
	lines[last] = body + sep + strings.Join(add, ", ")
	if comment != "" {
		lines[last] += " " + comment
	}
	return []byte(strings.Join(lines, "\n")), true
}

// olsSetMode sets the value of the file's one top-level useIpInProxyHeader.
func olsSetMode(b []byte, val string) ([]byte, bool) {
	lines := strings.Split(string(b), "\n")
	depth, at := 0, -1
	for i, raw := range lines {
		line := olsStripComment(raw)
		switch {
		case line == "":
		case strings.HasSuffix(line, "{"):
			depth++
		case line == "}":
			if depth > 0 {
				depth--
			}
		default:
			if key, _ := olsSplit(line); depth == 0 && strings.EqualFold(key, "useIpInProxyHeader") {
				if at >= 0 {
					return nil, false
				}
				at = i
			}
		}
	}
	if at < 0 {
		return nil, false
	}
	raw := lines[at]
	indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
	lines[at] = indent + "useIpInProxyHeader " + val
	return []byte(strings.Join(lines, "\n")), true
}

// olsCommentIndex: where a # comment starts on a raw line (as
// olsStripComment reads it), or -1.
func olsCommentIndex(s string) int {
	t := strings.TrimLeft(s, " \t")
	off := len(s) - len(t)
	if strings.HasPrefix(t, "#") {
		return off
	}
	for i := 1; i < len(t); i++ {
		if t[i] == '#' && (t[i-1] == ' ' || t[i-1] == '\t') {
			return off + i
		}
	}
	return -1
}

// applyOLS writes every file of the plan, restarts OpenLiteSpeed gracefully
// and checks it runs; on any failure it restores the files and restarts
// again. OpenLiteSpeed has no config test, so the check is that it comes back.
func applyOLS(pl Plan, w io.Writer) error {
	type saved struct {
		path    string
		prev    []byte
		existed bool
	}
	var done []saved
	rollback := func() {
		for i := len(done) - 1; i >= 0; i-- {
			restore(done[i].path, done[i].prev, done[i].existed)
		}
	}
	// The master's PID, "" when it does not run: a graceful restart (SIGUSR1)
	// that took the new config starts a new master; the old one still
	// running is the config NOT taken (review).
	pid := func() string {
		out, err := runCmd(fixTimeout, olsCtl, "status")
		if err != nil || !strings.Contains(out, "is running") {
			return ""
		}
		if m := olsPIDRe.FindStringSubmatch(out); m != nil {
			return m[1]
		}
		return "?"
	}
	before := pid()
	live := false
	for _, fw := range pl.Writes {
		path := fw.Path
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
		prev, existed, err := readIfExists(path)
		if err != nil {
			rollback()
			return err
		}
		if existed && string(prev) == fw.Content {
			continue
		}
		// Planned from the file as it was: one changed since (a rebuild, a
		// hand edit) is not overwritten (review).
		if fw.checkBase && (existed != fw.baseExists || (existed && string(prev) != fw.base)) {
			rollback()
			return fmt.Errorf("%s changed since the plan; nothing written, run the fix again", path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			rollback()
			return err
		}
		if err := writeFile(path, []byte(fw.Content)); err != nil {
			rollback()
			return err
		}
		done = append(done, saved{path, prev, existed})
		live = live || fw.Live
		fmt.Fprintf(w, "  wrote %s\n", path)
	}
	switch {
	case len(done) == 0:
		fmt.Fprintln(w, "  the files already hold the trust; nothing changed")
		return nil
	case !live:
		fmt.Fprintln(w, "  only CustomBuild's custom copies changed: OpenLiteSpeed is not restarted (rewrite_confs installs them as they are)")
		return nil
	case before == "":
		fmt.Fprintln(w, "  OpenLiteSpeed is not running: the change applies when it starts")
		return nil
	}
	out, err := runCmd(fixTimeout, olsCtl, "restart")
	after := pid()
	// lswsctrl waits ~15 s for a new master and returns either way: give a
	// slow one a bounded while longer before reading it as not taken.
	for i := 0; err == nil && after != "" && after == before && before != "?" && i < olsRestartPolls; i++ {
		olsSleep(time.Second)
		after = pid()
	}
	if err == nil && after != "" && (after != before || before == "?") {
		fmt.Fprintln(w, "  OpenLiteSpeed restarted gracefully (pid "+before+" -> "+after+")")
		return nil
	}
	why := "it is not running"
	if after != "" {
		why = "its master still runs as pid " + after + ", so the new config was not taken"
	}
	rollback()
	_, rerr := runCmd(fixTimeout, olsCtl, "restart")
	state := "it was restarted on the restored files and runs"
	if rerr != nil || pid() == "" {
		state = "and it is NOT running now: start it with " + olsCtl + " start"
	}
	return fmt.Errorf("OpenLiteSpeed did not take the new config (%s; restart: %v); the files were restored, %s\n%s", why, err, state, strings.TrimSpace(out))
}

var olsPIDRe = regexp.MustCompile(`with PID (\d+)`)

// olsRestartPolls / olsSleep: the extra wait for a new master (vars for tests).
var (
	olsRestartPolls = 30
	olsSleep        = time.Sleep
)
