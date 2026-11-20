package originrealip

import (
	"strings"
	"testing"
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
	pl := l.plan(p)
	for _, want := range []string{"OpenLiteSpeed", "/etc/openlitespeed/httpd-defaults.conf", "/etc/openlitespeed/httpd-accesscontrol.conf",
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
	// Only in the live files: rewrite_confs would put the templates back.
	for _, f := range []string{"httpd-accesscontrol.conf", "httpd-defaults.conf"} {
		if !strings.Contains(p.Warning, "custombuild/custom/openlitespeed/conf/"+f) {
			t.Fatalf("no rewrite_confs warning for %s: %q", f, p.Warning)
		}
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
	if pl := l.plan(p); !strings.Contains(pl.Reason, "127.0.0.1T, ::1T") {
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
