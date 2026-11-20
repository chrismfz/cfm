package originrealip

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// server3 (DirectAdmin, CustomBuild webserver=openlitespeed, 2026-11-20): the
// main config, as it is there, includes the rest from /etc/openlitespeed.
const server3OLSMain = `#######################################################################################
# Main configuration                                                                  #
#######################################################################################
include /etc/openlitespeed/httpd-defaults.conf
include /etc/openlitespeed/httpd-logs.conf
include /etc/openlitespeed/httpd-includes.conf
include /etc/openlitespeed/conf.d/*.conf
include /etc/openlitespeed/httpd-accesscontrol.conf
include /etc/openlitespeed/listeners.conf
# Virtual hosts
include /etc/openlitespeed/httpd-vhosts.conf
# All the DirectAdmin vhosts
include /etc/openlitespeed/directadmin-vhosts.conf
`

const server3OLSDefaults = "httpdWorkers                     2\nuser                             apache\n" +
	"disableWebAdmin                  0\nenableLVE                        0\n" +
	"useIpInProxyHeader\t\t 2\ninclude\t\t\t\t /etc/openlitespeed/httpd-directoryindex.conf\n"

// The CustomBuild file as server3 has it: ALL plus Cloudflare's ranges marked
// trusted, no loopback.
const server3OLSACL = "accessControl{\n\tallow                                   ALL, 173.245.48.0/20T, 103.21.244.0/22T, 2400:cb00::/32T, 2c0f:f248::/32T\n\tdeny\n}\n"

func olsDAHost(t *testing.T) (layout, string) {
	t.Helper()
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/directadmin")
	put(t, r, "usr/local/lsws/conf/httpd_config.conf", server3OLSMain)
	put(t, r, "etc/openlitespeed/httpd-defaults.conf", server3OLSDefaults)
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", server3OLSACL)
	put(t, r, "etc/openlitespeed/directadmin-vhosts.conf", "virtualhost example.gr {\n  vhRoot /home/u/\n}\n")
	l.activeStack = running(StackLiteSpeed, true)
	return l, r
}

func TestOpenLiteSpeedDirectAdminServer3(t *testing.T) {
	l, r := olsDAHost(t)
	p := l.probe("")
	if p.Stack != StackLiteSpeed || p.Panel != PanelDirectAdmin || p.Trusted {
		t.Fatalf("server3 as it is: %+v", p)
	}
	if !strings.Contains(p.Note, "OpenLiteSpeed") || !strings.Contains(p.Note, "/etc/openlitespeed/httpd-accesscontrol.conf") {
		t.Fatalf("note = %q", p.Note)
	}
	// fix: the allow list gets the loopback, in the live file and its custom copy.
	pl := l.plan(p)
	acl6 := strings.Replace(server3OLSACL, "2c0f:f248::/32T\n", "2c0f:f248::/32T, 127.0.0.1T, ::1T\n", 1)
	if pl.Action != ActionWrite || len(pl.Writes) != 2 ||
		pl.Writes[0].Path != filepath.Join(r, "etc/openlitespeed/httpd-accesscontrol.conf") ||
		pl.Writes[1].Path != filepath.Join(r, "usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-accesscontrol.conf") ||
		pl.Writes[0].Content != acl6 || pl.Writes[1].Content != acl6 {
		t.Fatalf("fix plan = %+v", pl)
	}
	// A custom copy that differs from the live file: the operator's call.
	stale := put(t, r, "usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-accesscontrol.conf", "accessControl{\n  allow ALL\n}\n")
	pl = l.plan(l.probe(""))
	if pl.Action != ActionManual || !strings.Contains(pl.Reason, "differs from /etc/openlitespeed/httpd-accesscontrol.conf; reconcile") {
		t.Fatalf("differing custom copy: %+v", pl)
	}
	if err := os.Remove(stale); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(pl.Reason, "httpd-defaults.conf") {
		t.Fatalf("the mode is fine, yet the step names the defaults file: %q", pl.Reason)
	}
	for _, want := range []string{"OpenLiteSpeed", "/etc/openlitespeed/httpd-accesscontrol.conf",
		"/usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-accesscontrol.conf", "da build rewrite_confs", "127.0.0.1T", "lswsctrl restart"} {
		if pl.Action != ActionManual || !strings.Contains(pl.Reason, want) {
			t.Fatalf("plan lacks %q: %+v", want, pl)
		}
	}
	if strings.Contains(pl.Reason, "httpd_config.xml") || strings.Contains(pl.Reason, "::1T") {
		t.Fatalf("plan names LiteSpeed Enterprise's file, or ::1T on an IPv4-only edge: %q", pl.Reason)
	}

	acl := strings.Replace(server3OLSACL, "ALL,", "ALL, 127.0.0.1T,", 1)
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", acl)
	p = l.probe("")
	if !p.Trusted || p.Source != "/etc/openlitespeed/httpd-accesscontrol.conf" || !strings.Contains(p.Directive, "OpenLiteSpeed") {
		t.Fatalf("127.0.0.1T added: %+v", p)
	}
	// No CustomBuild templates on disk: nothing says what rewrite_confs
	// would install, so no warning.
	if p.Warning != "" {
		t.Fatalf("no templates, yet a warning: %q", p.Warning)
	}
	// With server3's templates (the live files as CustomBuild wrote them):
	// rewrite_confs would put the ACL back without the loopback. The
	// defaults file equals its template and is not named (review: it was).
	tmpl := "usr/local/directadmin/custombuild/configure/openlitespeed/conf/"
	put(t, r, tmpl+"httpd-accesscontrol.conf", server3OLSACL)
	put(t, r, tmpl+"httpd-defaults.conf", server3OLSDefaults)
	put(t, r, tmpl+"httpd_config.conf", server3OLSMain)
	p = l.probe("")
	if !p.Trusted || !strings.Contains(p.Warning, "/etc/openlitespeed/httpd-accesscontrol.conf (keep it in /usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-accesscontrol.conf)") ||
		strings.Contains(p.Warning, "httpd-defaults.conf") {
		t.Fatalf("live edit only: %q", p.Warning)
	}
	if ok, text := Verdict(p, true); !ok || !strings.Contains(text, "WARNING") {
		t.Fatalf("verdict = %v %q", ok, text)
	}
	custom := "usr/local/directadmin/custombuild/custom/openlitespeed/conf/"
	put(t, r, custom+"httpd-accesscontrol.conf", server3OLSACL) // a stale custom copy, without the trust
	put(t, r, custom+"httpd-defaults.conf", server3OLSDefaults)
	if p := l.probe(""); !strings.Contains(p.Warning, "custom/openlitespeed/conf/httpd-accesscontrol.conf") || strings.Contains(p.Warning, "conf/httpd-defaults.conf") {
		t.Fatalf("a custom copy that differs from the live file: %q", p.Warning)
	}
	if ok, text := Verdict(l.probe(""), true); !ok || !strings.Contains(text, "rewrite_confs") {
		t.Fatalf("verdict = %v %q", ok, text)
	}
	put(t, r, custom+"httpd-accesscontrol.conf", server3OLSACL) // a stale custom copy, without the trust
	if p := l.probe(""); !strings.Contains(p.Warning, "httpd-accesscontrol.conf") {
		t.Fatalf("a stale custom copy: %q", p.Warning)
	}
	put(t, r, custom+"httpd-accesscontrol.conf", acl)
	p = l.probe("")
	if !p.Trusted || p.Warning != "" {
		t.Fatalf("custom copies kept: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionNone {
		t.Fatalf("plan = %+v", pl)
	}

	// The edge listens on IPv6: ::1T is needed too.
	edgeV6(t, r)
	p = l.probe("")
	if p.Trusted || !p.EdgeIPv6 || !strings.Contains(p.Note, "::1T") {
		t.Fatalf("IPv6 edge, 127.0.0.1T only: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionWrite || !strings.Contains(pl.Writes[0].Content, ", ::1T\n") || strings.Count(pl.Writes[0].Content, "127.0.0.1T") != 1 {
		t.Fatalf("plan = %+v", pl)
	}
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", strings.Replace(server3OLSACL, "ALL,", "ALL, 127.0.0.1T, ::1T,", 1))
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("127.0.0.1T and ::1T: %+v", p)
	}
}

func TestOpenLiteSpeedOnlyServerLevelCounts(t *testing.T) {
	cases := []struct {
		name, defaults, acl, vhosts string
		want                        bool
	}{
		{"trusted", server3OLSDefaults, "accessControl {\n  allow ALL, 127.0.0.1T\n}\n", "", true},
		{"several allow lines", server3OLSDefaults, "accessControl{\n  allow ALL\n  allow 127.0.0.1/32T\n}\n", "", true},
		{"loopback allowed, not trusted", server3OLSDefaults, "accessControl{\n  allow ALL, 127.0.0.1\n}\n", "", false},
		{"mode 0", strings.Replace(server3OLSDefaults, "\t\t 2", " 0", 1), "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", "", false},
		{"mode 1: any peer", strings.Replace(server3OLSDefaults, "\t\t 2", " 1", 1), server3OLSACL, "", true},
		{"mode commented out", strings.Replace(server3OLSDefaults, "useIpInProxyHeader", "#useIpInProxyHeader", 1), "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", "", false},
		{"a trust after an inline comment", server3OLSDefaults, "accessControl{\n  allow ALL # 127.0.0.1T\n}\n", "", false},
		{"an allow in a block inside accessControl", server3OLSDefaults, "accessControl{\n  other {\n    allow 127.0.0.1T\n  }\n  allow ALL\n}\n", "", false},
		{"commented allow", server3OLSDefaults, "accessControl{\n  allow ALL\n  #allow 127.0.0.1T\n}\n", "", false},
		{"a vhost's accessControl", server3OLSDefaults, server3OLSACL,
			"virtualhost example.gr {\n  accessControl {\n    allow ALL, 127.0.0.1T\n  }\n}\n", false},
		{"a vhost's useIpInProxyHeader", strings.Replace(server3OLSDefaults, "\t\t 2", " 0", 1), "accessControl{\n  allow ALL, 127.0.0.1T\n}\n",
			"virtualhost example.gr {\n  useIpInProxyHeader 2\n}\n", false},
		{"only a vhost's accessControl", server3OLSDefaults, "",
			"virtualhost example.gr {\n  accessControl {\n    allow ALL, 127.0.0.1T\n  }\n}\n", false},
		{"only a vhost's useIpInProxyHeader", "httpdWorkers 2\n", "accessControl{\n  allow ALL, 127.0.0.1T\n}\n",
			"virtualhost example.gr {\n  useIpInProxyHeader 1\n}\n", false},
		{"a wide network marked trusted", server3OLSDefaults, "accessControl{\n  allow ALL, 0.0.0.0/1T\n}\n", "", false},
		{"two server-level lists, the second without it", server3OLSDefaults,
			"accessControl{\n  allow ALL, 127.0.0.1T\n}\naccessControl{\n  allow ALL\n}\n", "", false},
		{"two server-level lists, the first without it", server3OLSDefaults,
			"accessControl{\n  allow ALL\n}\naccessControl{\n  allow ALL, 127.0.0.1T\n}\n", "", false},
		{"two server-level lists, both with it", server3OLSDefaults,
			"accessControl{\n  allow ALL, 127.0.0.1T\n}\naccessControl{\n  allow 127.0.0.1T\n}\n", "", true},
		{"a second, later mode 0", server3OLSDefaults + "useIpInProxyHeader 0\n", "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", "", false},
		{"an earlier mode 0", "useIpInProxyHeader 0\n" + server3OLSDefaults, "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", "", false},
		{"mode 2 and no list", server3OLSDefaults, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, r := olsDAHost(t)
			put(t, r, "etc/openlitespeed/httpd-defaults.conf", c.defaults)
			put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", c.acl)
			if c.vhosts != "" {
				put(t, r, "etc/openlitespeed/directadmin-vhosts.conf", c.vhosts)
			}
			if p := l.probe(""); p.Trusted != c.want {
				t.Fatalf("trusted = %v, want %v: %+v", p.Trusted, c.want, p)
			}
		})
	}
}

// A plain OpenLiteSpeed (no panel): the settings inline in httpd_config.conf,
// an include through $SERVER_ROOT and a glob.
func TestOpenLiteSpeedPlain(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "usr/local/lsws/conf/httpd_config.conf",
		"serverName x\nuseIpInProxyHeader 2\ninclude $SERVER_ROOT/conf/extra/*.conf\nvirtualhost Example {\n  vhRoot Example/\n}\n")
	put(t, r, "usr/local/lsws/conf/extra/acl.conf", "accessControl  {\n  allow                   ALL, 127.0.0.1T, ::1T # the CFM edge\n}\n")
	l.activeStack = running(StackLiteSpeed, true)
	p := l.probe("")
	if !p.Trusted || p.Panel != PanelPlain || p.Source != "/usr/local/lsws/conf/extra/acl.conf" {
		t.Fatalf("plain OLS: %+v", p)
	}
	put(t, r, "usr/local/lsws/conf/extra/acl.conf", "accessControl  {\n  allow ALL\n}\n")
	p = l.probe("")
	if pl := l.plan(p); p.Trusted || !strings.Contains(pl.Reason, "/usr/local/lsws/conf/extra/acl.conf") || strings.Contains(pl.Reason, "CustomBuild") {
		t.Fatalf("plain OLS untrusted: %+v / %q", p, pl.Reason)
	}
	// No useIpInProxyHeader anywhere: the note says so, the plan names the main config.
	put(t, r, "usr/local/lsws/conf/httpd_config.conf", "serverName x\ninclude $SERVER_ROOT/conf/extra/*.conf\n")
	p = l.probe("")
	if p.Trusted || !strings.Contains(p.Note, "no server-level useIpInProxyHeader") {
		t.Fatalf("no mode: %+v", p)
	}
	if pl := l.plan(p); !strings.Contains(pl.Reason, "/usr/local/lsws/conf/httpd_config.conf") {
		t.Fatalf("plan = %q", pl.Reason)
	}
}

// LiteSpeed Enterprise keeps httpd_config.xml: when it is there, it is read,
// as before, and a stray httpd_config.conf does not count.
func TestLiteSpeedEnterpriseXMLWinsOverConf(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "usr/local/lsws/conf/httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>0</useIpInProxyHeader></httpServerConfig>")
	put(t, r, "usr/local/lsws/conf/httpd_config.conf", "useIpInProxyHeader 1\n")
	l.activeStack = running(StackLiteSpeed, true)
	p := l.probe("")
	if p.Trusted || p.ols != nil {
		t.Fatalf("Enterprise with a stray .conf: %+v", p)
	}
	if pl := l.plan(p); !strings.Contains(pl.Reason, "httpd_config.xml") {
		t.Fatalf("plan = %q", pl.Reason)
	}
}

// An include loop, or one file included twice, is read once.
func TestOpenLiteSpeedIncludeLoop(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "usr/local/lsws/conf/httpd_config.conf", "include /usr/local/lsws/conf/a.conf\nuseIpInProxyHeader 2\n")
	put(t, r, "usr/local/lsws/conf/a.conf", "include /usr/local/lsws/conf/httpd_config.conf\naccessControl{\n allow ALL, 127.0.0.1T\n}\n")
	l.activeStack = running(StackLiteSpeed, true)
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("loop: %+v", p)
	}
}

// A multi-line value (rules <<<END_rules ... END_rules) is skipped whole: a
// line inside it is neither a brace nor a setting.
func TestOpenLiteSpeedHeredoc(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "usr/local/lsws/conf/httpd_config.conf", "useIpInProxyHeader 2\nrewrite {\n  rules <<<END_rules\n}\naccessControl {\n  allow ALL, 127.0.0.1T\n}\nEND_rules\n}\n")
	l.activeStack = running(StackLiteSpeed, true)
	if p := l.probe(""); p.Trusted {
		t.Fatalf("an allow inside a heredoc counted: %+v", p)
	}
}

// The DirectAdmin step names only what is missing (review): a trusted list
// with useIpInProxyHeader 0 asks for the defaults file, not the ACL.
func TestOpenLiteSpeedDAStepNamesWhatIsMissing(t *testing.T) {
	l, r := olsDAHost(t)
	put(t, r, "etc/openlitespeed/httpd-defaults.conf", strings.Replace(server3OLSDefaults, "\t\t 2", " 0", 1))
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", "accessControl{\n  allow ALL, 127.0.0.1T, ::1T\n}\n")
	p := l.probe("")
	// fix: the mode only, the list is already fine.
	pl := l.plan(p)
	if pl.Action != ActionWrite || len(pl.Writes) != 2 || !strings.HasSuffix(pl.Writes[0].Path, "etc/openlitespeed/httpd-defaults.conf") ||
		!strings.Contains(pl.Writes[0].Content, "\nuseIpInProxyHeader 2\ninclude") {
		t.Fatalf("mode 0 fix: %+v", pl)
	}
	// Manual (a differing custom copy): the step names the defaults file only.
	put(t, r, "usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-defaults.conf", "useIpInProxyHeader 0\n")
	pl = l.plan(p)
	if p.Trusted || !strings.Contains(pl.Reason, "custom/openlitespeed/conf/httpd-defaults.conf and set useIpInProxyHeader 2") ||
		strings.Contains(pl.Reason, "httpd-accesscontrol.conf") {
		t.Fatalf("mode 0, list fine: %+v / %q", p, pl.Reason)
	}
	// An earlier 0 and a later 2: the note names the 0, not the list.
	put(t, r, "etc/openlitespeed/conf.d/late.conf", "useIpInProxyHeader 2\n")
	p = l.probe("")
	if p.Trusted || !strings.Contains(p.Note, "useIpInProxyHeader 0 (/etc/openlitespeed/httpd-defaults.conf)") || !strings.Contains(p.Note, "disagree") {
		t.Fatalf("0 then 2: %q", p.Note)
	}
}

// Re-review: OpenLiteSpeed's 3 (Keep Header from Trusted IP) is trusted-only
// like 2, 4 (Use Last IP, for AWS ELB) takes the header from any peer like 1.
func TestOpenLiteSpeedModes3And4(t *testing.T) {
	for _, c := range []struct {
		mode, acl string
		want      bool
	}{
		{"3", "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", true},
		{"3", "accessControl{\n  allow ALL\n}\n", false},
		{"4", "accessControl{\n  allow ALL\n}\n", true},
		{"5", "accessControl{\n  allow ALL, 127.0.0.1T\n}\n", false},
	} {
		l, r := olsDAHost(t)
		put(t, r, "etc/openlitespeed/httpd-defaults.conf", strings.Replace(server3OLSDefaults, "\t\t 2", " "+c.mode, 1))
		put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", c.acl)
		if p := l.probe(""); p.Trusted != c.want {
			t.Fatalf("mode %s, %q: %+v", c.mode, c.acl, p)
		}
	}
}

// Re-review: the rewrite warning covers only what the live config trusts, and
// names only the files whose rewrite breaks it.
func TestOpenLiteSpeedRewriteWarningScope(t *testing.T) {
	l, r := olsDAHost(t)
	tmpl := "usr/local/directadmin/custombuild/configure/openlitespeed/conf/"
	custom := "usr/local/directadmin/custombuild/custom/openlitespeed/conf/"
	acl4 := "accessControl{\n  allow ALL, 127.0.0.1T\n}\n"
	put(t, r, tmpl+"httpd-accesscontrol.conf", server3OLSACL)
	put(t, r, tmpl+"httpd-defaults.conf", server3OLSDefaults)
	put(t, r, tmpl+"httpd-logs.conf", "errorlog x {\n}\n")
	put(t, r, "etc/openlitespeed/httpd-logs.conf", "errorlog y {\n  logLevel DEBUG\n}\n") // differs, irrelevant
	put(t, r, custom+"httpd-accesscontrol.conf", acl4)
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", acl4)
	edgeV6(t, r)
	// ::1 is untrusted live as after: no rewrite warning, only the ::1 gap.
	if p := l.probe(""); p.Trusted || p.Warning != "" {
		t.Fatalf("::1 missing live: %+v", p)
	}
	// Live edit with ::1T, custom copy without it: the warning names the ACL
	// file only, not the differing log file.
	put(t, r, "etc/openlitespeed/httpd-accesscontrol.conf", "accessControl{\n  allow ALL, 127.0.0.1T, ::1T\n}\n")
	p := l.probe("")
	if !p.Trusted || !strings.Contains(p.Warning, "httpd-accesscontrol.conf") || strings.Contains(p.Warning, "httpd-logs.conf") {
		t.Fatalf("culprit only: %+v", p)
	}
}

func TestOLSAddTrustAndSetMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"accessControl{\n\tallow ALL\n}\n", "accessControl{\n\tallow ALL, 127.0.0.1T, ::1T\n}\n"},
		{"accessControl {\n  allow ALL, 127.0.0.1T # edge\n}\n", "accessControl {\n  allow ALL, 127.0.0.1T, ::1T # edge\n}\n"},
		{"accessControl{\n  allow ALL, 127.0.0.1T, ::1T\n}\n", "accessControl{\n  allow ALL, 127.0.0.1T, ::1T\n}\n"},
		{"accessControl{\n  allow ALL\n  allow 10.0.0.0/8T\n  deny\n}\n", "accessControl{\n  allow ALL\n  allow 10.0.0.0/8T, 127.0.0.1T, ::1T\n  deny\n}\n"},
	}
	for _, c := range cases {
		got, ok := olsAddTrust([]byte(c.in))
		if !ok || string(got) != c.want {
			t.Errorf("olsAddTrust(%q) = %q, %v; want %q", c.in, got, ok, c.want)
		}
	}
	for _, in := range []string{
		"useIpInProxyHeader 2\n",                                         // no block
		"accessControl{\n  deny\n}\n",                                    // no allow line
		"accessControl{\n allow ALL\n}\naccessControl{\n allow ALL\n}\n", // two blocks
		"virtualhost x {\n  accessControl{\n    allow ALL\n  }\n}\n",     // a vhost's only
	} {
		if _, ok := olsAddTrust([]byte(in)); ok {
			t.Errorf("olsAddTrust(%q) should refuse", in)
		}
	}
	if got, ok := olsSetMode([]byte("a 1\n  useIpInProxyHeader\t\t 0\nb 2\n"), "2"); !ok || string(got) != "a 1\n  useIpInProxyHeader 2\nb 2\n" {
		t.Errorf("olsSetMode = %q %v", got, ok)
	}
	for _, in := range []string{"a 1\n", "useIpInProxyHeader 0\nuseIpInProxyHeader 1\n"} {
		if _, ok := olsSetMode([]byte(in), "2"); ok {
			t.Errorf("olsSetMode(%q) should refuse", in)
		}
	}
}

func olsCtlStub(t *testing.T, statusAfter string) *[]string {
	t.Helper()
	var calls []string
	restarted := false
	oldRun := runCmd
	runCmd = func(_ time.Duration, name string, args ...string) (string, error) {
		calls = append(calls, strings.TrimSpace(name+" "+strings.Join(args, " ")))
		if name != olsCtl {
			return "", errors.New("unexpected " + name)
		}
		switch args[0] {
		case "restart":
			restarted = true
			return "[OK] Send SIGUSR1", nil
		case "status":
			if restarted && statusAfter != "" {
				return statusAfter, errors.New("exit status 1")
			}
			return "litespeed is running with PID 42.", nil
		}
		return "", nil
	}
	t.Cleanup(func() { runCmd = oldRun })
	return &calls
}

func TestApplyOLSWritesAndRestarts(t *testing.T) {
	l, r := olsDAHost(t)
	calls := olsCtlStub(t, "")
	pl := l.plan(l.probe(""))
	var out strings.Builder
	if err := Apply(pl, &out); err != nil {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}
	for _, fw := range pl.Writes {
		if read(t, fw.Path) != fw.Content {
			t.Fatalf("%s not written", fw.Path)
		}
	}
	if !strings.Contains(strings.Join(*calls, "|"), olsCtl+" restart") {
		t.Fatalf("no restart: %v", *calls)
	}
	if p := l.probe(""); !p.Trusted || p.Warning != "" {
		t.Fatalf("after the fix: %+v", p)
	}
	// Nothing left to do.
	if pl := l.plan(l.probe("")); pl.Action != ActionNone {
		t.Fatalf("second plan = %+v", pl)
	}
	_ = r
}

func TestApplyOLSRollsBackWhenItDoesNotComeBack(t *testing.T) {
	l, r := olsDAHost(t)
	calls := olsCtlStub(t, "[ERROR] litespeed is not running.")
	pl := l.plan(l.probe(""))
	var out strings.Builder
	if err := Apply(pl, &out); err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("apply should fail and restore: %v", err)
	}
	if got := read(t, filepath.Join(r, "etc/openlitespeed/httpd-accesscontrol.conf")); got != server3OLSACL {
		t.Fatalf("live file not restored: %q", got)
	}
	if _, err := os.Stat(filepath.Join(r, "usr/local/directadmin/custombuild/custom/openlitespeed/conf/httpd-accesscontrol.conf")); !os.IsNotExist(err) {
		t.Fatalf("custom copy not removed: %v", err)
	}
	if n := strings.Count(strings.Join(*calls, "|"), olsCtl+" restart"); n != 2 {
		t.Fatalf("want a restart and a restart back, got %v", *calls)
	}
}
