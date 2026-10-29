package originrealip

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testLayout mirrors the system layout under a temp root. The panel and origin
// markers start absent; tests create what their host has.
func testLayout(t *testing.T) (layout, string) {
	t.Helper()
	r := t.TempDir()
	j := func(p string) string { return filepath.Join(r, p) }
	return layout{
		cpanelMarkers: []string{j("usr/local/cpanel")},
		daMarkers:     []string{j("usr/local/directadmin")},
		ngmMarkers:    []string{j("etc/ngm")},
		lsMarkers:     []string{j("usr/local/lsws")},
		apMarkers:     []string{j("etc/apache2"), j("etc/httpd")},
		ngMarkers:     []string{j("etc/nginx")},
		apacheGlobs: []string{
			j("etc/apache2/conf.d/*.conf"), j("etc/apache2/conf.d/includes/*.conf"), j("etc/apache2/conf/httpd.conf"),
			j("etc/apache2/apache2.conf"), j("etc/apache2/conf-enabled/*.conf"),
			j("etc/httpd/conf/httpd.conf"), j("etc/httpd/conf.d/*.conf"), j("etc/httpd/conf/extra/*.conf"),
		},
		nginxGlobs: []string{
			j("etc/nginx/nginx.conf"), j("etc/nginx/*.conf"), j("etc/nginx/conf.d/*.conf"),
			j("etc/nginx/conf/sites/*.conf"),
		},
		lsPaths:          []string{j("usr/local/lsws/conf/httpd_config.xml")},
		cpanelApacheDir:  j("etc/apache2/conf.d"),
		debApacheMain:    j("etc/apache2/apache2.conf"),
		debApacheDir:     j("etc/apache2/conf-enabled"),
		elApacheMain:     j("etc/httpd/conf/httpd.conf"),
		elApacheDir:      j("etc/httpd/conf.d"),
		daApacheIncludes: j("etc/httpd/conf/extra/httpd-includes.conf"),
		nginxMain:        j("etc/nginx/nginx.conf"),
		nginxConfD:       j("etc/nginx/conf.d"),
		daNginxIncludes:  j("etc/nginx/nginx-includes.conf"),
	}, r
}

func put(t *testing.T, root, rel, body string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkdir(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
		t.Fatal(err)
	}
}

// fakeCmds stubs runCmd/lookPath. out maps "name arg..." to output; fail lists
// commands that exit non-zero. calls records every command run.
type fakeCmds struct {
	out   map[string]string
	fail  map[string]bool
	calls []string
}

func (f *fakeCmds) install(t *testing.T) {
	t.Helper()
	oldRun, oldLook := runCmd, lookPath
	runCmd = func(name string, args ...string) (string, error) {
		k := strings.TrimSpace(name + " " + strings.Join(args, " "))
		f.calls = append(f.calls, k)
		if f.fail[k] {
			return f.out[k], errors.New("exit status 1")
		}
		return f.out[k], nil
	}
	lookPath = func(name string) (string, error) {
		switch name {
		case "apachectl", "nginx":
			return "/usr/sbin/" + name, nil
		}
		return "", errors.New("not found")
	}
	t.Cleanup(func() { runCmd, lookPath = oldRun, oldLook })
}

// qualityweb, 2026-10-29: cPanel Apache, no Imunify360, only cPanel's
// cloudflare.conf. The edge's loopback is not trusted, so every site logged
// 127.0.0.1.
const cloudflareConf = "<IfModule remoteip_module>\n    RemoteIPHeader CF-Connecting-IP\n    RemoteIPTrustedProxy 173.245.48.0/20\n    RemoteIPTrustedProxy 2400:cb00::/32\n</IfModule>\n"

func TestQualitywebCPanelWithoutImunify(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	mkdir(t, r, "etc/apache2/conf.d")
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", cloudflareConf)

	p := l.probe("httpd")
	if p.Panel != PanelCPanel || p.Stack != StackApache || p.Trusted {
		t.Fatalf("probe = %+v, want cpanel/apache untrusted", p)
	}
	pl := l.plan(p)
	want := filepath.Join(r, "etc/apache2/conf.d/cfm-remoteip.conf")
	if pl.Action != ActionWrite || pl.Path != want || pl.Managed {
		t.Fatalf("plan = %+v, want a whole-file write to %s", pl, want)
	}
	// CF-Connecting-IP is already the header (the edge sets it), so the drop-in
	// adds the loopback trust only and does not fight over RemoteIPHeader.
	if !strings.Contains(pl.Content, "RemoteIPInternalProxy 127.0.0.1") || strings.Contains(pl.Content, "RemoteIPHeader") {
		t.Fatalf("content = %q", pl.Content)
	}

	f := &fakeCmds{out: map[string]string{"apachectl -M": " remoteip_module (shared)\n"}}
	f.install(t)
	var out bytes.Buffer
	if err := Apply(pl, &out); err != nil {
		t.Fatalf("Apply: %v\n%s", err, out.String())
	}
	if got := strings.Join(f.calls, "|"); got != "apachectl -M|apachectl -t|apachectl graceful" {
		t.Errorf("commands = %s", got)
	}
	after := l.probe("httpd")
	if !after.Trusted || after.Source != want || after.Header != "CF-Connecting-IP" {
		t.Fatalf("after fix = %+v", after)
	}
	// A second fix is a no-op.
	if pl2 := l.plan(after); pl2.Action != ActionNone {
		t.Errorf("second plan = %+v, want none", pl2)
	}
}

// mars/titan: Imunify360's i360.remoteip.conf lives in conf.d/*.conf, which the
// probe did not read before (it reported those nodes untrusted).
func TestImunifyRemoteIPConfIsSeen(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", cloudflareConf)
	i360 := put(t, r, "etc/apache2/conf.d/i360.remoteip.conf",
		"<IfModule remoteip_module>\n    RemoteIPInternalProxy 127.0.0.1\n    RemoteIPInternalProxy ::1\n    RemoteIPHeader X-Forwarded-For\n</IfModule>\n")
	p := l.probe("httpd")
	if !p.Trusted || p.Source != i360 || p.Header != "CF-Connecting-IP,X-Forwarded-For" {
		t.Fatalf("probe = %+v", p)
	}
}

func TestApacheNeedsAnEdgeHeader(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "etc/httpd/conf.d")
	put(t, r, "etc/httpd/conf/httpd.conf", "ServerRoot /etc/httpd\nIncludeOptional conf.d/*.conf\n")

	// Loopback trusted but no RemoteIPHeader: mod_remoteip reads nothing.
	put(t, r, "etc/httpd/conf.d/a.conf", "RemoteIPInternalProxy 127.0.0.1\n")
	p := l.probe("httpd")
	if p.Trusted || !strings.Contains(p.Note, "no RemoteIPHeader") {
		t.Fatalf("no header: %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/httpd/conf.d/cfm-remoteip.conf") || !strings.Contains(pl.Content, "RemoteIPHeader X-Forwarded-For") {
		t.Fatalf("EL plan = %+v", pl)
	}

	// A header the edge does not set: reported, never overridden.
	put(t, r, "etc/httpd/conf.d/a.conf", "RemoteIPInternalProxy 127.0.0.1\nRemoteIPHeader X-Client-IP\n")
	p = l.probe("httpd")
	if p.Trusted || !strings.Contains(p.Note, "X-Client-IP") {
		t.Fatalf("foreign header: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual {
		t.Fatalf("foreign header plan = %+v, want manual", pl)
	}

	// The same foreign header without the loopback trust: still manual, since
	// adding the trust alone would leave Apache reading X-Client-IP.
	put(t, r, "etc/httpd/conf.d/a.conf", "RemoteIPHeader X-Client-IP\n")
	if pl := l.plan(l.probe("httpd")); pl.Action != ActionManual || !strings.Contains(pl.Reason, "X-Client-IP") {
		t.Fatalf("foreign header, no trust: plan = %+v", pl)
	}

	// A commented-out directive does not count.
	put(t, r, "etc/httpd/conf.d/a.conf", "# RemoteIPInternalProxy 127.0.0.1\nRemoteIPHeader X-Forwarded-For\n")
	if p := l.probe("httpd"); p.Trusted {
		t.Fatalf("commented trust read as trusted: %+v", p)
	}
}

func TestDebianApacheTarget(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "etc/apache2/conf-enabled")
	put(t, r, "etc/apache2/apache2.conf", "IncludeOptional conf-enabled/*.conf\n")
	pl := l.plan(l.probe("apache2"))
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/apache2/conf-enabled/cfm-remoteip.conf") {
		t.Fatalf("plan = %+v", pl)
	}
}

func TestDirectAdminApacheManagedBlock(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/directadmin")
	inc := put(t, r, "etc/httpd/conf/extra/httpd-includes.conf", "# operator lines\nServerTokens Prod\n")
	put(t, r, "etc/httpd/conf/httpd.conf", "Include conf/extra/httpd-includes.conf\n")
	pl := l.plan(l.probe("httpd"))
	if pl.Action != ActionWrite || pl.Path != inc || !pl.Managed {
		t.Fatalf("plan = %+v", pl)
	}
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module (shared)"}}
	f.install(t)
	var out bytes.Buffer
	if err := Apply(pl, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(inc)
	if !strings.HasPrefix(string(b), "# operator lines\nServerTokens Prod\n\n"+blockBegin) || !strings.HasSuffix(string(b), blockEnd+"\n") {
		t.Fatalf("include file = %q", b)
	}
	if p := l.probe("httpd"); !p.Trusted {
		t.Fatalf("after: %+v", p)
	}
	// Re-applying replaces the block in place, never stacks a second one.
	if err := Apply(pl, &out); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(inc)
	if strings.Count(string(b2), blockBegin) != 1 || string(b2) != string(b) {
		t.Fatalf("re-apply changed the file:\n%s", b2)
	}
}

// avgerinos: DirectAdmin nginx, nginx-cloudflare.conf sets real_ip_header
// X-Forwarded-For (an edge header), nginx-includes.conf is loaded in http{}.
// DirectAdmin leaves /etc/httpd behind (httpd-cloudflare.conf with a
// RemoteIPHeader); the running nginx decides the stack, not that leftover.
func TestDirectAdminNginx(t *testing.T) {
	l, r := testLayout(t)
	l.activeStack = func() string { return StackNginx }
	mkdir(t, r, "usr/local/directadmin")
	put(t, r, "etc/httpd/conf/extra/httpd-cloudflare.conf", "RemoteIPHeader X-Forwarded-For\n")
	put(t, r, "etc/httpd/conf/extra/httpd-includes.conf", "")
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/nginx-includes.conf;\n    include /etc/nginx/nginx-cloudflare.conf;\n}\n")
	put(t, r, "etc/nginx/nginx-cloudflare.conf", "real_ip_header X-Forwarded-For;\nset_real_ip_from 103.21.244.0/22;\n")
	inc := put(t, r, "etc/nginx/nginx-includes.conf", "log_format combined_myip '$remote_addr';\n")

	// No hint (cfm realip passes none): the running service decides.
	p := l.probe("")
	if p.Panel != PanelDirectAdmin || p.Stack != StackNginx || p.Trusted || p.Header != "X-Forwarded-For" {
		t.Fatalf("probe = %+v", p)
	}
	// Without the running-service read the leftover Apache tree would win.
	l2 := l
	l2.activeStack = nil
	if p := l2.probe(""); p.Stack != StackApache {
		t.Fatalf("control: the disk alone reads %q", p.Stack)
	}
	// No edge in front (avgerinos today): fine, not a warning.
	if line := StatusLine(p, false); !strings.HasPrefix(line, "OK") || !strings.Contains(line, "no CFM edge") {
		t.Errorf("status without edge = %q", line)
	}
	if line := StatusLine(p, true); !strings.HasPrefix(line, "WARN") {
		t.Errorf("status with edge = %q", line)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != inc || !pl.Managed || pl.Content != "set_real_ip_from 127.0.0.1;\nset_real_ip_from ::1;\n" {
		t.Fatalf("plan = %+v", pl)
	}
	f := &fakeCmds{out: map[string]string{"nginx -V": "configure arguments: --with-http_realip_module"}}
	f.install(t)
	var out bytes.Buffer
	if err := Apply(pl, &out); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, "|"); got != "nginx -V|nginx -t|nginx -s reload" {
		t.Errorf("commands = %s", got)
	}
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("after: %+v", p)
	}
}

func TestPlainNginxConfD(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "etc/nginx/conf.d")
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	pl := l.plan(l.probe("nginx"))
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/nginx/conf.d/cfm-realip.conf") || pl.Managed {
		t.Fatalf("plan = %+v", pl)
	}
	// real_ip_header proxy_protocol is not an edge header: manual.
	put(t, r, "etc/nginx/conf.d/x.conf", "real_ip_header proxy_protocol;\nset_real_ip_from 127.0.0.1;\n")
	p := l.probe("nginx")
	if p.Trusted || l.plan(p).Action != ActionManual {
		t.Fatalf("proxy_protocol: %+v", p)
	}
}

// ngm.myip.gr: NGM owns nginx.conf and includes only conf/sites/*.conf. CFM
// reports, never writes (NGM docs/cfm-integration-map.md).
func TestNGMIsManual(t *testing.T) {
	l, r := testLayout(t)
	l.activeStack = func() string { return StackNginx }
	mkdir(t, r, "etc/ngm")
	put(t, r, "etc/httpd/conf.d/php83-php.conf", "<Files \".user.ini\">\n</Files>\n") // ngm.myip.gr carries these
	mkdir(t, r, "etc/nginx/conf.d")
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf/sites/*.conf;\n}\n")
	p := l.probe("")
	if p.Panel != PanelNGM || p.Trusted || !strings.Contains(p.Note, "NGM renders nginx") {
		t.Fatalf("probe = %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "NGM") {
		t.Fatalf("plan = %+v", pl)
	}
	// Trust rendered by NGM into a site file is seen.
	put(t, r, "etc/nginx/conf/sites/_ngm-edge.conf", "set_real_ip_from 127.0.0.1;\n")
	if p := l.probe("nginx"); !p.Trusted {
		t.Fatalf("NGM-rendered trust: %+v", p)
	}
}

func TestLiteSpeed(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	mkdir(t, r, "etc/apache2/conf.d")
	xml := put(t, r, "usr/local/lsws/conf/httpd_config.xml", "<httpServerConfig>\n <!-- <useIpInProxyHeader>2</useIpInProxyHeader> -->\n <useIpInProxyHeader>0</useIpInProxyHeader>\n</httpServerConfig>\n")
	// LiteSpeed on disk beats a bogus nginx hint (the edge is nginx-based).
	p := l.probe("nginx")
	if p.Stack != StackLiteSpeed || p.Trusted {
		t.Fatalf("commented/zero: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "Use Client IP in Header") {
		t.Fatalf("plan = %+v", pl)
	}
	// 2 = "Trusted IP Only": needs 127.0.0.1T in the allow list (mars).
	put(t, r, "usr/local/lsws/conf/httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl><allow>ALL</allow></accessControl></security></httpServerConfig>")
	if p := l.probe(""); p.Trusted {
		t.Fatalf("2 without a trusted loopback: %+v", p)
	}
	put(t, r, "usr/local/lsws/conf/httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl>\n      <allow>ALL,127.0.0.1T</allow>\n</accessControl></security></httpServerConfig>")
	if p := l.probe(""); !p.Trusted || p.Source != xml {
		t.Fatalf("native 2 + 127.0.0.1T: %+v", p)
	}
	put(t, r, "usr/local/lsws/conf/httpd_config.xml", "<httpServerConfig><useIpInProxyHeader>1</useIpInProxyHeader></httpServerConfig>")
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("native 1: %+v", p)
	}
}

func TestApplyRollsBackOnFailedConfigTest(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	mkdir(t, r, "etc/apache2/conf.d")
	pl := l.plan(l.probe("httpd"))
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module", "apachectl -t": "AH00526: Syntax error"}, fail: map[string]bool{"apachectl -t": true}}
	f.install(t)
	var out bytes.Buffer
	err := Apply(pl, &out)
	if err == nil || !strings.Contains(err.Error(), "restored") {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(pl.Path); !os.IsNotExist(statErr) {
		t.Fatalf("a new file must be removed after a failed config test")
	}
	for _, c := range f.calls {
		if strings.Contains(c, "graceful") {
			t.Fatalf("reloaded after a failed config test: %v", f.calls)
		}
	}

	// A managed block in an existing operator file: the file goes back byte for byte.
	l2, r2 := testLayout(t)
	mkdir(t, r2, "usr/local/directadmin")
	orig := "Header set X 1\n"
	inc := put(t, r2, "etc/httpd/conf/extra/httpd-includes.conf", orig)
	pl2 := l2.plan(l2.probe("httpd"))
	if err := Apply(pl2, &out); err == nil {
		t.Fatal("want failure")
	}
	if b, _ := os.ReadFile(inc); string(b) != orig {
		t.Fatalf("operator file not restored: %q", b)
	}
}

func TestApplyRefusesWithoutModule(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	mkdir(t, r, "etc/apache2/conf.d")
	pl := l.plan(l.probe("httpd"))
	f := &fakeCmds{out: map[string]string{"apachectl -M": "core_module (static)"}}
	f.install(t)
	if err := Apply(pl, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "mod_remoteip") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(pl.Path); !os.IsNotExist(err) {
		t.Fatal("wrote a drop-in Apache cannot load")
	}

	l2, r2 := testLayout(t)
	mkdir(t, r2, "etc/nginx/conf.d")
	put(t, r2, "etc/nginx/nginx.conf", "include /etc/nginx/conf.d/*.conf;\n")
	f2 := &fakeCmds{out: map[string]string{"nginx -V": "configure arguments: --without-http_realip_module"}}
	f2.install(t)
	if err := Apply(l2.plan(l2.probe("nginx")), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "realip") {
		// "--without-http_realip_module" contains the module name: the check must
		// not be fooled by it.
		t.Fatalf("err = %v", err)
	}
}

func TestLoopbackForms(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "etc/nginx/conf.d")
	for _, ok := range []string{"set_real_ip_from 127.0.0.1/32;\n", "set_real_ip_from 127.0.0.0/8;\n", "set_real_ip_from ::1;\n"} {
		put(t, r, "etc/nginx/conf.d/x.conf", ok)
		if p := l.probe("nginx"); !p.Trusted {
			t.Errorf("expected trusted for %q, got %+v", ok, p)
		}
	}
	put(t, r, "etc/nginx/conf.d/x.conf", "set_real_ip_from 127.0.0.100;\n")
	if p := l.probe("nginx"); p.Trusted {
		t.Errorf("127.0.0.100 must not be loopback trust: %+v", p)
	}
	// The server's public IP is not the loopback either.
	put(t, r, "etc/nginx/conf.d/x.conf", "set_real_ip_from 84.54.49.83;\n")
	if p := l.probe("nginx"); p.Trusted {
		t.Errorf("a public IP must not count: %+v", p)
	}
}

func TestGrepSizeCap(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "etc/nginx/conf.d")
	put(t, r, "etc/nginx/conf.d/big.conf", "set_real_ip_from 127.0.0.1;\n")
	saved := grepMaxBytes
	grepMaxBytes = 4
	defer func() { grepMaxBytes = saved }()
	if p := l.probe("nginx"); p.Trusted {
		t.Errorf("a file over the size cap must be skipped: %+v", p)
	}
}

func TestResolveOriginStack(t *testing.T) {
	none := []string{"/nonexistent/cfm-test-marker"}
	ls, ap, ng := []string{t.TempDir()}, []string{t.TempDir()}, []string{t.TempDir()}
	cases := []struct {
		name, upstream string
		lsM, apM, ngM  []string
		want           string
	}{
		{"litespeed present beats nginx hint", "nginx", ls, none, ng, StackLiteSpeed},
		{"litespeed hint trusted w/o marker", "lshttpd", none, none, none, StackLiteSpeed},
		{"apache hint + apache present", "httpd", none, ap, none, StackApache},
		{"nginx hint + nginx present", "nginx", none, none, ng, StackNginx},
		{"nginx hint but only apache on disk", "nginx", none, ap, none, StackApache},
		{"unknown + nothing present", "", none, none, none, StackUnknown},
	}
	for _, c := range cases {
		if got := resolveOriginStack(c.upstream, c.lsM, c.apM, c.ngM); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCLI(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	mkdir(t, r, "etc/apache2/conf.d")
	var out bytes.Buffer
	if rc := runCLI(nil, &out, l, func() bool { return false }); rc != 0 || !strings.Contains(out.String(), "no CFM edge") {
		t.Fatalf("status without edge: rc=%d %s", rc, out.String())
	}
	out.Reset()
	if rc := runCLI([]string{"status"}, &out, l, func() bool { return true }); rc != 1 || !strings.Contains(out.String(), "cfm realip fix") {
		t.Fatalf("status with edge: rc=%d %s", rc, out.String())
	}
	out.Reset()
	if rc := runCLI([]string{"fix", "--dry-run"}, &out, l, func() bool { return true }); rc != 0 || !strings.Contains(out.String(), "would write") {
		t.Fatalf("dry-run: rc=%d %s", rc, out.String())
	}
	if _, err := os.Stat(filepath.Join(r, "etc/apache2/conf.d/cfm-remoteip.conf")); !os.IsNotExist(err) {
		t.Fatal("dry-run wrote a file")
	}
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module"}}
	f.install(t)
	out.Reset()
	if rc := runCLI([]string{"fix"}, &out, l, func() bool { return true }); rc != 0 || !strings.Contains(out.String(), "OK   Origin real-IP") {
		t.Fatalf("fix: rc=%d %s", rc, out.String())
	}
	out.Reset()
	if rc := runCLI([]string{"status", "--json"}, &out, l, func() bool { return true }); rc != 0 || !strings.Contains(out.String(), `"trusted":true`) {
		t.Fatalf("json: rc=%d %s", rc, out.String())
	}
	if rc := runCLI([]string{"bogus"}, &bytes.Buffer{}, l, func() bool { return true }); rc != 2 {
		t.Fatalf("unknown subcommand rc=%d", rc)
	}
}
