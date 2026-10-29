package originrealip

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Plan is what Apply would do on this host.
type Plan struct {
	Probe   Probe
	Action  string // ActionNone | ActionWrite | ActionManual
	Path    string // the file written (ActionWrite), as it is on disk
	Managed bool   // a marked block inside an existing operator file, not a whole file
	Content string // the directives written
	Reason  string // why nothing is written (ActionNone / ActionManual)
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

const header = "# CFM edge -> origin real client IP (written by `cfm realip fix`, docs/origin-real-ip.md).\n" +
	"# The CFM edge proxies every web request from 127.0.0.1 and sets X-Real-IP to the\n" +
	"# client. X-Real-IP, not X-Forwarded-For: through the edge a local process cannot\n" +
	"# forge it. Only the loopback is trusted, never the server's public address.\n"

// The Apache and nginx directives Apply writes.
const (
	apacheTrust = "<IfModule remoteip_module>\n    RemoteIPInternalProxy 127.0.0.1\n    RemoteIPInternalProxy ::1\n    RemoteIPHeader X-Real-IP\n</IfModule>\n"
	nginxTrust  = "set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\n"
)

// fixTimeout bounds each command Apply runs (module list, config test, reload).
const fixTimeout = 2 * time.Minute

// runCmd runs a command with a deadline and returns its combined output;
// tests replace it.
var runCmd = func(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed binaries and args
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
	if p.Header != "" && !edgeHeaders[strings.ToLower(p.Header)] {
		pl.Reason = "RemoteIPHeader " + p.Header + " is not a header the edge sets; change it to X-Real-IP by hand " +
			"(CFM does not override an operator's RemoteIPHeader)"
		return
	}
	pl.Content = apacheTrust
	mainConf := ""
	for _, m := range l.apacheMains {
		if isFile(l.fs(m.conf)) {
			mainConf = l.fs(m.conf)
			break
		}
	}
	switch {
	case p.Panel == PanelCPanel && isDir(l.fs(l.cpanelApacheDir)) && includes(mainConf, "conf.d/*.conf"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.fs(l.cpanelApacheDir), apacheDropIn)
	case p.Panel == PanelDirectAdmin && isFile(l.fs(l.daApacheIncludes)) && includes(mainConf, "httpd-includes.conf"):
		pl.Action, pl.Path, pl.Managed = ActionWrite, l.fs(l.daApacheIncludes), true
	case isDir(l.fs(l.debApacheDir)) && includes(mainConf, "conf-enabled/"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.fs(l.debApacheDir), apacheDropIn)
	case isDir(l.fs(l.elApacheDir)) && includes(mainConf, "conf.d/"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.fs(l.elApacheDir), apacheDropIn)
	default:
		pl.Content = ""
		pl.Reason = "no Apache include directory found to drop the RemoteIP trust into; add to the main config:\n" + apacheTrust
	}
}

func (l layout) planNginx(pl *Plan) {
	p := pl.Probe
	if p.Panel == PanelNGM {
		pl.Reason = "NGM renders nginx itself: the realip trust has to come from NGM's templates " +
			"(NGM docs/cfm-integration-map.md), not a file CFM drops in (apply would overwrite it)"
		return
	}
	if h := strings.TrimSuffix(p.Header, " (default)"); h != "" && !edgeHeaders[strings.ToLower(h)] {
		pl.Reason = "real_ip_header " + h + " is not a header the edge sets; change it to X-Real-IP " +
			"(or remove it for the X-Real-IP default) by hand"
		return
	}
	pl.Content = nginxTrust
	mainConf := l.fs(l.nginxMain)
	switch {
	case p.Panel == PanelDirectAdmin && isFile(l.fs(l.daNginxIncludes)) && includes(mainConf, "nginx-includes.conf"):
		pl.Action, pl.Path, pl.Managed = ActionWrite, l.fs(l.daNginxIncludes), true
	case isDir(l.fs(l.nginxConfD)) && includes(mainConf, "conf.d/*.conf"):
		pl.Action, pl.Path = ActionWrite, filepath.Join(l.fs(l.nginxConfD), nginxDropIn)
	default:
		pl.Reason = "no nginx include loaded inside http{} found; add to the http{} block:\n" + pl.Content
		pl.Content = ""
	}
}

// Apply carries out a write plan: checks the real-IP module is loaded, writes
// the file (or the managed block), runs the origin's config test and reloads it
// gracefully. A failed test restores the previous file and reloads nothing.
func Apply(pl Plan, w io.Writer) error {
	if pl.Action != ActionWrite {
		return nil
	}
	var test, reload []string
	switch pl.Probe.Stack {
	case StackApache:
		bin := firstBinary("apachectl", "apache2ctl", "httpd")
		if bin == "" {
			return errors.New("no apachectl/apache2ctl/httpd binary found")
		}
		if out, err := runCmd(fixTimeout, bin, "-M"); err != nil || !strings.Contains(out, "remoteip_module") {
			hint := "Debian/Ubuntu: a2enmod remoteip; EL: it ships with httpd"
			if pl.Probe.Panel == PanelCPanel {
				hint = "cPanel: install ea-apache24-mod_remoteip"
			}
			return fmt.Errorf("mod_remoteip is not loaded in Apache (%s -M); enable it first (%s)", bin, hint)
		}
		test, reload = []string{bin, "-t"}, []string{bin, "graceful"}
		if bin == "httpd" {
			reload = []string{bin, "-k", "graceful"}
		}
	case StackNginx:
		if lookPathOK("nginx") == "" {
			return errors.New("no nginx binary found")
		}
		if out, _ := runCmd(fixTimeout, "nginx", "-V"); !strings.Contains(out, "--with-http_realip_module") {
			return errors.New("nginx is built without http_realip_module; set_real_ip_from would fail the config test")
		}
		test, reload = []string{"nginx", "-t"}, []string{"nginx", "-s", "reload"}
	default:
		return fmt.Errorf("no writer for stack %q", pl.Probe.Stack)
	}

	// Write through a symlink to the file it points at, as an editor would.
	path := pl.Path
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	prev, existed, err := readIfExists(path)
	if err != nil {
		return err
	}
	next := header + pl.Content
	if pl.Managed {
		if next, err = withBlock(prev, pl.Content); err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
	}
	if existed && string(prev) == next {
		fmt.Fprintf(w, "  %s already holds the trust; nothing changed\n", path)
		return nil
	}
	if err := writeFile(path, []byte(next)); err != nil {
		return err
	}
	if out, err := runCmd(fixTimeout, test[0], test[1:]...); err != nil {
		restore(path, prev, existed)
		return fmt.Errorf("config test failed, %s restored: %v\n%s", path, err, strings.TrimSpace(out))
	}
	fmt.Fprintf(w, "  wrote %s; config test passed\n", path)
	if out, err := runCmd(fixTimeout, reload[0], reload[1:]...); err != nil {
		return fmt.Errorf("config written but the graceful reload failed: %v\n%s", err, strings.TrimSpace(out))
	}
	fmt.Fprintf(w, "  %s reloaded gracefully\n", pl.Probe.Stack)
	return nil
}

// withBlock returns prev with the managed block replaced, or appended when the
// file has none. A file whose markers do not pair up (an operator deleted one)
// is refused: replacing from a lone BEGIN to a later END would delete the
// operator lines between them.
func withBlock(prev []byte, content string) (string, error) {
	s := string(prev)
	nb, ne := strings.Count(s, blockBegin), strings.Count(s, blockEnd)
	block := blockBegin + "\n" + content + blockEnd + "\n"
	switch {
	case nb == 0 && ne == 0:
		s = strings.TrimRight(s, "\n")
		if s != "" {
			s += "\n\n"
		}
		return s + block, nil
	case nb == 1 && ne == 1 && strings.Index(s, blockBegin) < strings.Index(s, blockEnd):
		i := strings.Index(s, blockBegin)
		j := strings.Index(s, blockEnd) + len(blockEnd)
		if j < len(s) && s[j] == '\n' {
			j++
		}
		return s[:i] + block + s[j:], nil
	default:
		return "", errors.New("the CFM marker lines do not pair up (one was edited or removed); fix them by hand")
	}
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

// writeFile replaces path atomically, keeping an existing file's mode and owner
// (0644 for a new one: web-server configs are world-readable).
func writeFile(path string, b []byte) error {
	mode := os.FileMode(0o644)
	uid, gid := -1, -1
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(st.Uid), int(st.Gid)
		}
	}
	tmp := path + ".cfm-tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if uid >= 0 {
		_ = os.Chown(tmp, uid, gid) // best effort: only root can, and only root runs fix
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

// includes reports whether a main config file loads an include matching
// pattern on an uncommented line (Apache Include / IncludeOptional, nginx
// include, wherever it sits on the line).
func includes(mainConf, pattern string) bool {
	b, err := os.ReadFile(mainConf) // #nosec G304 -- fixed system config paths
	if err != nil {
		return false
	}
	re := regexp.MustCompile(`(?im)^[^#\n]*\binclude(?:optional)?\s+["']?[^\s;"']*` + regexp.QuoteMeta(pattern))
	return re.Match(b)
}

func firstBinary(names ...string) string {
	for _, n := range names {
		if lookPathOK(n) != "" {
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
