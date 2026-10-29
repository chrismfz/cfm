package originrealip

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Plan is what Apply would do on this host.
type Plan struct {
	Probe   Probe
	Action  string // ActionNone | ActionWrite | ActionManual
	Path    string // the file written (ActionWrite)
	Managed bool   // a marked block inside an existing operator file, not a whole file
	Content string // the directives written
	Reason  string // why nothing is written (ActionNone / ActionManual), or how
}

const (
	ActionNone   = "none"   // already trusted
	ActionWrite  = "write"  // Apply writes Path, tests the config, reloads
	ActionManual = "manual" // CFM does not write this stack/panel; Reason says what to do
)

// The CFM-owned whole files, and the markers of a managed block in an
// operator file (DirectAdmin's include files).
const (
	apacheDropIn = "cfm-remoteip.conf"
	nginxDropIn  = "cfm-realip.conf"
	blockBegin   = "# >>> CFM origin real-IP (managed by `cfm realip fix`; do not edit inside) >>>"
	blockEnd     = "# <<< CFM origin real-IP <<<"
)

const header = "# CFM edge -> origin real client IP (written by `cfm realip fix`).\n" +
	"# The CFM edge proxies every web request from 127.0.0.1 and names the client in\n" +
	"# X-Real-IP / X-Forwarded-For / CF-Connecting-IP. Only the loopback is trusted, so\n" +
	"# a client-supplied header cannot spoof the address.\n"

// runCmd runs a command and returns its combined output; tests replace it.
var runCmd = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- fixed binaries and args
	return string(out), err
}

// lookPath finds a binary; tests replace it.
var lookPath = exec.LookPath

// PlanSystem plans the fix for this host.
func PlanSystem(upstream string) Plan {
	return system.plan(system.probe(upstream))
}

// PlanFor plans the fix for a probe already taken on this host.
func PlanFor(p Probe) Plan {
	return system.plan(p)
}

func (l layout) plan(p Probe) Plan {
	pl := Plan{Probe: p}
	if p.Trusted {
		pl.Action, pl.Reason = ActionNone, "already trusted via "+p.Directive+" ("+p.Source+")"
		return pl
	}
	pl.Action = ActionManual
	switch p.Stack {
	case StackApache:
		l.planApache(&pl)
	case StackNginx:
		l.planNginx(&pl)
	case StackLiteSpeed:
		pl.Reason = "LiteSpeed: in WebAdmin set Server > General > Use Client IP in Header = \"Trusted IP Only\" " +
			"and add 127.0.0.1T to Security > Access Control > Allowed List, then restart LiteSpeed " +
			"(CFM does not edit httpd_config.xml)"
	default:
		pl.Reason = "no apache/litespeed/nginx origin detected; nothing to configure"
	}
	return pl
}

func (l layout) planApache(pl *Plan) {
	p := pl.Probe
	if bad := probeForeignHeaders(p); len(bad) > 0 {
		pl.Reason = "RemoteIPHeader " + strings.Join(bad, ",") + " is not a header the edge sets; change it to X-Forwarded-For by hand " +
			"(CFM does not override an operator's RemoteIPHeader)"
		return
	}
	body := "<IfModule remoteip_module>\n    RemoteIPInternalProxy 127.0.0.1\n    RemoteIPInternalProxy ::1\n"
	if p.Header == "" { // no RemoteIPHeader anywhere: mod_remoteip would read nothing
		body += "    RemoteIPHeader X-Forwarded-For\n"
	}
	body += "</IfModule>\n"
	pl.Content = body
	switch {
	case p.Panel == PanelCPanel && isDir(l.cpanelApacheDir):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.cpanelApacheDir, apacheDropIn)
	case p.Panel == PanelDirectAdmin && isFile(l.daApacheIncludes):
		pl.Action, pl.Path, pl.Managed = ActionWrite, l.daApacheIncludes, true
	case isDir(l.debApacheDir) && includes(l.debApacheMain, "conf-enabled/"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.debApacheDir, apacheDropIn)
	case isDir(l.elApacheDir) && includes(l.elApacheMain, "conf.d/"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.elApacheDir, apacheDropIn)
	default:
		pl.Content = ""
		pl.Reason = "no Apache include directory found to drop the RemoteIP trust into; add to the main config:\n" + body
	}
}

func (l layout) planNginx(pl *Plan) {
	p := pl.Probe
	if p.Panel == PanelNGM {
		pl.Reason = "NGM renders nginx itself: the realip trust has to come from NGM's templates " +
			"(NGM docs/cfm-integration-map.md), not a file CFM drops in (apply would overwrite it)"
		return
	}
	if bad := probeForeignHeaders(p); len(bad) > 0 {
		pl.Reason = "real_ip_header " + strings.Join(bad, ",") + " is not a header the edge sets; change it to X-Forwarded-For " +
			"(or remove it for the X-Real-IP default) by hand"
		return
	}
	pl.Content = "set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\n"
	switch {
	case p.Panel == PanelDirectAdmin && isFile(l.daNginxIncludes):
		pl.Action, pl.Path, pl.Managed = ActionWrite, l.daNginxIncludes, true
	case isDir(l.nginxConfD) && includes(l.nginxMain, "conf.d/*.conf"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.nginxConfD, nginxDropIn)
	default:
		pl.Reason = "no nginx include loaded inside http{} found; add to the http{} block:\n" + pl.Content
		pl.Content = ""
	}
}

// probeForeignHeaders is the probe's client headers the edge does not set.
func probeForeignHeaders(p Probe) []string {
	if p.Header == "" || strings.HasSuffix(p.Header, "(default)") {
		return nil
	}
	return foreignHeaders(strings.Split(p.Header, ","))
}

// Apply carries out a write plan: checks the real-IP module is loaded, writes
// the file (or the managed block), runs the origin's config test and reloads it
// gracefully. A failed test restores the previous file and reloads nothing.
func Apply(pl Plan, w io.Writer) error {
	if pl.Action != ActionWrite {
		return nil
	}
	var test, reload []string // config test and graceful reload commands
	switch pl.Probe.Stack {
	case StackApache:
		bin := firstBinary("apachectl", "apache2ctl", "httpd")
		if bin == "" {
			return errors.New("no apachectl/apache2ctl/httpd binary found")
		}
		if out, err := runCmd(bin, "-M"); err != nil || !strings.Contains(out, "remoteip_module") {
			return fmt.Errorf("mod_remoteip is not loaded in Apache (%s -M); enable it first (Debian: a2enmod remoteip)", bin)
		}
		test, reload = []string{bin, "-t"}, []string{bin, "graceful"}
		if bin == "httpd" {
			reload = []string{bin, "-k", "graceful"}
		}
	case StackNginx:
		if lookPathOK("nginx") == "" {
			return errors.New("no nginx binary found")
		}
		if out, _ := runCmd("nginx", "-V"); !strings.Contains(out, "--with-http_realip_module") {
			return errors.New("nginx is built without http_realip_module; set_real_ip_from would fail the config test")
		}
		test, reload = []string{"nginx", "-t"}, []string{"nginx", "-s", "reload"}
	default:
		return fmt.Errorf("no writer for stack %q", pl.Probe.Stack)
	}

	prev, existed, err := readIfExists(pl.Path)
	if err != nil {
		return err
	}
	next := header + pl.Content
	if pl.Managed {
		next = withBlock(prev, pl.Content)
	}
	if existed && string(prev) == next {
		fmt.Fprintf(w, "  %s already holds the trust; nothing changed\n", pl.Path)
		return nil
	}
	if err := writeFile(pl.Path, []byte(next)); err != nil {
		return err
	}
	if out, err := runCmd(test[0], test[1:]...); err != nil {
		restore(pl.Path, prev, existed)
		return fmt.Errorf("config test failed, %s restored: %v\n%s", pl.Path, err, strings.TrimSpace(out))
	}
	fmt.Fprintf(w, "  wrote %s; config test passed\n", pl.Path)
	if out, err := runCmd(reload[0], reload[1:]...); err != nil {
		return fmt.Errorf("config written but the graceful reload failed: %v\n%s", err, strings.TrimSpace(out))
	}
	fmt.Fprintf(w, "  %s reloaded gracefully\n", pl.Probe.Stack)
	return nil
}

var blockRe = regexp.MustCompile(`(?s)\n?` + regexp.QuoteMeta(blockBegin) + `.*?` + regexp.QuoteMeta(blockEnd) + `\n?`)

// withBlock returns prev with the managed block replaced, or appended when the
// file has none.
func withBlock(prev []byte, content string) string {
	block := blockBegin + "\n" + content + blockEnd + "\n"
	s := blockRe.ReplaceAllString(string(prev), "\n")
	s = strings.TrimRight(s, "\n")
	if s != "" {
		s += "\n\n"
	}
	return s + block
}

func readIfExists(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed system config paths
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return b, true, nil
}

// writeFile replaces path atomically, keeping an existing file's mode (0644 for
// a new one: web-server configs are world-readable).
func writeFile(path string, b []byte) error {
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp := path + ".cfm-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func restore(path string, prev []byte, existed bool) {
	if existed {
		_ = writeFile(path, prev)
		return
	}
	_ = os.Remove(path)
}

// includes reports whether a main config file references an include pattern on
// an uncommented line.
func includes(mainConf, pattern string) bool {
	b, err := os.ReadFile(mainConf) // #nosec G304 -- fixed system config paths
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(t), "include") && strings.Contains(t, pattern) {
			return true
		}
	}
	return false
}

func firstBinary(names ...string) string {
	for _, n := range names {
		if p := lookPathOK(n); p != "" {
			return n
		}
	}
	return ""
}

func lookPathOK(name string) string {
	p, err := lookPath(name)
	if err != nil {
		return ""
	}
	return p
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}
