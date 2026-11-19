package originrealip

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testLayout is the real system layout rooted in a temp dir. Fixtures are
// written at their real paths under it, Include lines included, so the probe
// walks them exactly as on a host. Nothing is detected as running unless the
// test says so.
func testLayout(t *testing.T) (layout, string) {
	t.Helper()
	l := system
	l.root = t.TempDir()
	l.activeStack = nil
	return l, l.root
}

func running(stack string, fromListener bool) func() (string, bool) {
	return func() (string, bool) { return stack, fromListener }
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

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
	runCmd = func(_ time.Duration, name string, args ...string) (string, error) {
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

// The cPanel httpd.conf include order, as on qualityweb and mars:
// cloudflare.conf first, then conf.d/*.conf.
const cpanelHTTPD = `ServerRoot "/etc/apache2"
Include "/etc/apache2/conf.modules.d/*.conf"
Include "/etc/apache2/conf.d/includes/pre_main_global.conf"
Include /etc/apache2/conf.d/includes/cloudflare.conf
Include "/etc/apache2/conf.d/*.conf"
<VirtualHost 84.54.49.83:80>
  ServerName shop.gr
  Include "/etc/apache2/conf.d/userdata/std/2_4/shop/shop.gr/*.conf"
</VirtualHost>
`

const cloudflareConf = "<IfModule remoteip_module>\n    RemoteIPHeader CF-Connecting-IP\n    RemoteIPTrustedProxy 173.245.48.0/20\n    RemoteIPTrustedProxy 2400:cb00::/32\n</IfModule>\n"

func cpanelHost(t *testing.T) (layout, string) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/cpanel")
	put(t, r, "etc/apache2/conf/httpd.conf", cpanelHTTPD)
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", cloudflareConf)
	put(t, r, "etc/apache2/conf.d/php.conf", "AddHandler x .php\n")
	return l, r
}

// qualityweb, 2026-10-29: cPanel Apache, no Imunify360, only cPanel's
// cloudflare.conf. The edge's loopback is not trusted, so every site logged
// 127.0.0.1.
func TestQualitywebCPanelWithoutImunify(t *testing.T) {
	l, r := cpanelHost(t)
	p := l.probe("httpd")
	if p.Panel != PanelCPanel || p.Stack != StackApache || p.Trusted || p.Header != "CF-Connecting-IP" {
		t.Fatalf("probe = %+v, want cpanel/apache untrusted reading CF-Connecting-IP", p)
	}
	pl := l.plan(p)
	want := filepath.Join(r, "etc/apache2/conf.d/cfm-remoteip.conf")
	if pl.Action != ActionWrite || pl.Path != want || pl.Managed || pl.Content != apacheTrust {
		t.Fatalf("plan = %+v, want the drop-in at %s", pl, want)
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
	// conf.d loads after cloudflare.conf, so the drop-in's X-Real-IP is the
	// RemoteIPHeader in effect.
	after := l.probe("httpd")
	if !after.Trusted || after.Source != "/etc/apache2/conf.d/cfm-remoteip.conf" || after.Header != "X-Real-IP" {
		t.Fatalf("after fix = %+v", after)
	}
	if pl2 := l.plan(after); pl2.Action != ActionNone {
		t.Errorf("second plan = %+v, want none", pl2)
	}
}

// mars/titan: Imunify360's i360.remoteip.conf in conf.d/*.conf, which the old
// probe did not read. Its X-Forwarded-For is the header in effect (loaded after
// cloudflare.conf's CF-Connecting-IP).
func TestImunifyRemoteIPConfIsSeen(t *testing.T) {
	l, r := cpanelHost(t)
	put(t, r, "etc/apache2/conf.d/i360.remoteip.conf",
		"<IfModule remoteip_module>\n    RemoteIPInternalProxy 127.0.0.1\n    RemoteIPInternalProxy ::1\n    RemoteIPHeader X-Forwarded-For\n</IfModule>\n")
	p := l.probe("httpd")
	if !p.Trusted || p.Source != "/etc/apache2/conf.d/i360.remoteip.conf" || p.Header != "X-Forwarded-For" {
		t.Fatalf("probe = %+v", p)
	}
}

// A <VirtualHost>'s own RemoteIPHeader, or a file Apache never loads, does not
// stand for the server (review finding: `fix` used to re-probe "trusted" while
// every other site still logged 127.0.0.1).
func TestApacheOnlyServerLevelLoadedConfigCounts(t *testing.T) {
	l, r := cpanelHost(t)
	put(t, r, "etc/apache2/conf/httpd.conf", strings.Replace(cpanelHTTPD,
		"  ServerName shop.gr\n", "  ServerName shop.gr\n  RemoteIPHeader X-Real-IP\n  RemoteIPInternalProxy 127.0.0.1\n", 1))
	// pre_main_1.conf exists on cPanel but httpd.conf never includes it.
	put(t, r, "etc/apache2/conf.d/includes/pre_main_1.conf", "RemoteIPInternalProxy 127.0.0.1\nRemoteIPHeader X-Real-IP\n")
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", "")

	p := l.probe("httpd")
	if p.Trusted || p.Header != "" || !strings.Contains(p.Note, "<VirtualHost>") {
		t.Fatalf("probe = %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || !strings.Contains(pl.Content, "RemoteIPHeader X-Real-IP") {
		t.Fatalf("plan = %+v", pl)
	}
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module"}}
	f.install(t)
	if err := Apply(pl, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if after := l.probe("httpd"); !after.Trusted || after.Header != "X-Real-IP" {
		t.Fatalf("after = %+v", after)
	}
}

// Apache's LAST RemoteIPHeader wins, in load order.
func TestApacheLastHeaderWins(t *testing.T) {
	l, r := cpanelHost(t)
	put(t, r, "etc/apache2/conf.d/a.conf", "RemoteIPInternalProxy 10.0.0.1 127.0.0.1\n") // loopback not first
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", "RemoteIPHeader X-Client-IP\n")
	put(t, r, "etc/apache2/conf.d/z.conf", "RemoteIPHeader X-Forwarded-For\n")
	if p := l.probe("httpd"); !p.Trusted || p.Header != "X-Forwarded-For" {
		t.Fatalf("edge header last: %+v", p)
	}
	put(t, r, "etc/apache2/conf.d/includes/cloudflare.conf", "RemoteIPHeader X-Forwarded-For\n")
	put(t, r, "etc/apache2/conf.d/z.conf", "RemoteIPHeader X-Client-IP\n")
	p := l.probe("httpd")
	if p.Trusted || !strings.Contains(p.Note, "X-Client-IP") {
		t.Fatalf("foreign header last: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "X-Client-IP") {
		t.Fatalf("foreign header plan = %+v, want manual", pl)
	}
}

func TestELApacheRelativeIncludes(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/httpd/conf/httpd.conf", "ServerRoot \"/etc/httpd\"\nInclude conf.modules.d/*.conf\nIncludeOptional conf.d/*.conf\n")
	put(t, r, "etc/httpd/conf.d/a.conf", "RemoteIPInternalProxy 127.0.0.1\n# RemoteIPHeader X-Forwarded-For\n")
	p := l.probe("httpd")
	if p.Trusted || !strings.Contains(p.Note, "no server-level RemoteIPHeader") {
		t.Fatalf("no header (the commented one does not count): %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/httpd/conf.d/cfm-remoteip.conf") {
		t.Fatalf("EL plan = %+v", pl)
	}
}

func TestDebianApacheTarget(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/apache2/apache2.conf", "IncludeOptional mods-enabled/*.load\nIncludeOptional conf-enabled/*.conf\n")
	mkdir(t, r, "etc/apache2/conf-enabled")
	pl := l.plan(l.probe("apache2"))
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/apache2/conf-enabled/cfm-remoteip.conf") {
		t.Fatalf("plan = %+v", pl)
	}
}

func TestDirectAdminApacheManagedBlock(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/directadmin")
	put(t, r, "etc/httpd/conf/httpd.conf", "ServerRoot \"/etc/httpd\"\nInclude conf/extra/httpd-includes.conf\nInclude conf/extra/httpd-cloudflare.conf\n")
	put(t, r, "etc/httpd/conf/extra/httpd-cloudflare.conf", "RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 173.245.48.0/20\n")
	inc := put(t, r, "etc/httpd/conf/extra/httpd-includes.conf", "# operator lines\nServerTokens Prod\n")
	p := l.probe("httpd")
	if p.Trusted || p.Header != "X-Forwarded-For" {
		t.Fatalf("probe = %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != inc || !pl.Managed {
		t.Fatalf("plan = %+v", pl)
	}
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module (shared)"}}
	f.install(t)
	var out bytes.Buffer
	if err := Apply(pl, &out); err != nil {
		t.Fatal(err)
	}
	b := read(t, inc)
	if !strings.HasPrefix(b, "# operator lines\nServerTokens Prod\n\n"+blockBegin) || !strings.HasSuffix(b, blockEnd+"\n") {
		t.Fatalf("include file = %q", b)
	}
	// httpd-includes.conf loads BEFORE httpd-cloudflare.conf, so the header in
	// effect stays DirectAdmin's X-Forwarded-For (an edge header): trusted.
	if p := l.probe("httpd"); !p.Trusted || p.Header != "X-Forwarded-For" {
		t.Fatalf("after: %+v", p)
	}
	// Re-applying replaces the block in place, never stacks a second one.
	if err := Apply(pl, &out); err != nil {
		t.Fatal(err)
	}
	if b2 := read(t, inc); b2 != b {
		t.Fatalf("re-apply changed the file:\n%s", b2)
	}
}

// A managed block whose END marker an operator removed is refused (review
// finding: the next run used to delete every operator line in between).
func TestManagedBlockUnpairedMarkersRefused(t *testing.T) {
	prev := "Include important.conf\n" + blockBegin + "\nset_real_ip_from 127.0.0.1;\nInclude also-important.conf\n"
	if _, err := withBlock([]byte(prev), nginxTrust); err == nil {
		t.Fatal("a lone BEGIN marker must be refused")
	}
	if _, err := withBlock([]byte(blockEnd+"\n"+blockBegin+"\n"), nginxTrust); err == nil {
		t.Fatal("markers in the wrong order must be refused")
	}
	got, err := withBlock([]byte("a\n"+blockBegin+"\nold\n"+blockEnd+"\nb\n"), nginxTrust)
	if err != nil || got != "a\n"+blockBegin+"\n"+nginxTrust+blockEnd+"\nb\n" {
		t.Fatalf("replace in place: %q %v", got, err)
	}
}

// avgerinos: DirectAdmin nginx. nginx-cloudflare.conf sets real_ip_header
// X-Forwarded-For (an edge header), nginx-includes.conf is loaded in http{},
// and DirectAdmin leaves /etc/httpd behind. The :80 listener decides the stack.
const daNginxConf = `user nginx;
events { worker_connections 1024; }
http {
    include       /etc/nginx/mime.types;
    include /etc/nginx/nginx-includes.conf;
    include /etc/nginx/nginx-cloudflare.conf;
    include /etc/nginx/directadmin-vhosts.conf;
}
`

func TestDirectAdminNginx(t *testing.T) {
	l, r := testLayout(t)
	l.activeStack = running(StackNginx, true)
	mkdir(t, r, "usr/local/directadmin")
	put(t, r, "etc/httpd/conf/httpd.conf", "Include conf/extra/httpd-cloudflare.conf\n")
	put(t, r, "etc/httpd/conf/extra/httpd-cloudflare.conf", "RemoteIPHeader X-Forwarded-For\n")
	put(t, r, "etc/nginx/nginx.conf", daNginxConf)
	put(t, r, "etc/nginx/mime.types", "types { text/html html; }\n")
	put(t, r, "etc/nginx/nginx-cloudflare.conf", "real_ip_header X-Forwarded-For;\nset_real_ip_from 103.21.244.0/22;\n")
	inc := put(t, r, "etc/nginx/nginx-includes.conf", "log_format combined_myip '$remote_addr';\n")
	put(t, r, "etc/nginx/directadmin-vhosts.conf", "include /usr/local/directadmin/data/users/avgerinos/nginx.conf;\n")
	put(t, r, "usr/local/directadmin/data/users/avgerinos/nginx.conf",
		"server {\n    listen 80;\n    server_name avgerinos.gr;\n    location / { root /home/x; }\n}\n")

	p := l.probe("")
	if p.Panel != PanelDirectAdmin || p.Stack != StackNginx || p.Trusted || p.Header != "X-Forwarded-For" {
		t.Fatalf("probe = %+v", p)
	}
	// No edge in front (avgerinos today): fine, not a warning.
	if line := StatusLine(p, false); !strings.HasPrefix(line, "OK") || !strings.Contains(line, "no CFM edge") {
		t.Errorf("status without edge = %q", line)
	}
	if line := StatusLine(p, true); !strings.HasPrefix(line, "WARN") {
		t.Errorf("status with edge = %q", line)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != inc || !pl.Managed || pl.Content != nginxTrust {
		t.Fatalf("plan = %+v", pl)
	}
	f := &fakeCmds{out: map[string]string{"nginx -V": "configure arguments: --with-http_realip_module"}}
	f.install(t)
	if err := Apply(pl, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.calls, "|"); got != "nginx -V|nginx -t|nginx -s reload" {
		t.Errorf("commands = %s", got)
	}
	after := l.probe("")
	if !after.Trusted || after.Servers != 1 {
		t.Fatalf("after: %+v", after)
	}
	// Without the listener the leftover Apache tree would win.
	l.activeStack = nil
	if p := l.probe(""); p.Stack != StackApache {
		t.Fatalf("control: the disk alone reads %q", p.Stack)
	}
}

// nginx resolves the client per server{}: a block's own set_real_ip_from list
// replaces the http-level one. A block that trusts the loopback itself is
// trusted; one that inherits an http-level list without it is not. stream{} is
// not the HTTP origin.
func TestNginxServerLevelTrust(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "stream {\n    set_real_ip_from 127.0.0.1;\n    server { listen 3306; }\n}\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}\n")
	mkdir(t, r, "etc/nginx/conf.d")
	put(t, r, "etc/nginx/sites-enabled/shop", "server {\n  server_name shop.gr;\n  set_real_ip_from 127.0.0.1;\n  location /x { set_real_ip_from 10.0.0.1; }\n}\n")
	p := l.probe("nginx")
	if !p.Trusted || p.Servers != 1 || !strings.Contains(p.Directive, "own list") || !strings.Contains(p.Note, "location{}") {
		t.Fatalf("own loopback list: %+v", p)
	}
	put(t, r, "etc/nginx/sites-enabled/blog", "server {\n  server_name blog.gr www.blog.gr;\n}\n")
	p = l.probe("nginx")
	if p.Trusted || p.Servers != 2 || p.UntrustedServers != 1 || !strings.Contains(p.Note, "blog.gr") || !strings.Contains(p.Note, "inherit") {
		t.Fatalf("one block inherits nothing: %+v", p)
	}
	if line := StatusLine(p, true); !strings.Contains(line, "those sites log 127.0.0.1") {
		t.Errorf("partial verdict = %q", line)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/nginx/conf.d/cfm-realip.conf") || pl.Managed {
		t.Fatalf("plan = %+v", pl)
	}
	if err := os.WriteFile(pl.Path, []byte(nginxTrust), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := l.probe("nginx"); !p.Trusted || p.Servers != 2 {
		t.Fatalf("after the http-level trust: %+v", p)
	}
	// real_ip_header proxy_protocol is not an edge header: manual.
	put(t, r, "etc/nginx/conf.d/x.conf", "real_ip_header proxy_protocol;\n")
	p = l.probe("nginx")
	if p.Trusted || l.plan(p).Action != ActionManual {
		t.Fatalf("proxy_protocol: %+v", p)
	}
}

// A block whose own list lacks the loopback is out of reach of an http-level
// trust: the plan says so instead of writing a file that changes nothing.
func TestNginxOwnListIsManual(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	put(t, r, "etc/nginx/conf.d/site.conf", "server {\n  server_name shop.gr;\n  set_real_ip_from 10.1.1.1;\n}\n")
	p := l.probe("nginx")
	if p.Trusted || !strings.Contains(p.Note, "replaces the http-level one") {
		t.Fatalf("probe = %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "shop.gr") || !strings.Contains(pl.Reason, nginxTrust) {
		t.Fatalf("plan = %+v", pl)
	}
	// A bad real_ip_header inside the block is manual too.
	put(t, r, "etc/nginx/conf.d/site.conf", "server {\n  server_name shop.gr;\n  set_real_ip_from 127.0.0.1;\n  real_ip_header X-Client-IP;\n}\n")
	p = l.probe("nginx")
	if pl := l.plan(p); p.Trusted || pl.Action != ActionManual || !strings.Contains(pl.Reason, "X-Client-IP") {
		t.Fatalf("bad header: %+v / %+v", p, pl)
	}
	// An inherited http-level header the edge does not set, on a block that
	// trusts nothing yet: writing the trust alone would not fix it.
	put(t, r, "etc/nginx/nginx.conf", "http {\n    real_ip_header X-Client-IP;\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	put(t, r, "etc/nginx/conf.d/site.conf", "server {\n  server_name shop.gr;\n}\n")
	p = l.probe("nginx")
	if pl := l.plan(p); p.Trusted || pl.Action != ActionManual || !strings.Contains(pl.Reason, "X-Client-IP") || !strings.Contains(pl.Reason, "shop.gr") {
		t.Fatalf("inherited bad header: %+v / %+v", p, pl)
	}
}

// cPanel: an include of server-includes/ inside a location{} does not reach the
// block's realip settings, so it does not make the block reachable.
func TestCPanelServerIncludesInLocationDoesNotCount(t *testing.T) {
	l, r := eaNginxHost(t)
	put(t, r, "etc/nginx/conf.d/users/grgr.conf", "server {\n    server_name 24gr.gr www.24gr.gr;\n    include conf.d/includes-optional/cloudflare.conf;\n"+
		"    location / { include conf.d/server-includes/*.conf; }\n}\n")
	put(t, r, "etc/nginx/conf.d/users/koreanbe.conf", "")
	put(t, r, "etc/nginx/conf.d/default.conf", "")
	p := l.probe("")
	if p.Trusted || p.Servers != 1 {
		t.Fatalf("probe = %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual {
		t.Fatalf("plan = %+v (the block keeps its own list and does not include server-includes at server level)", pl)
	}
}

// earth, 2026-11-17: cPanel ea-nginx on :80 in front of Apache. Every server{}
// includes cloudflare.conf (its own list, real_ip_header CF-Connecting-IP), so
// an http-level trust reaches none of them; the site blocks also include
// server-includes/*.conf, where Imunify360's webshield file trusts 127.0.0.1.
// The proxy-subdomain blocks (cpanel./webmail./...) include only cloudflare.conf.
func eaNginxHost(t *testing.T) (layout, string) {
	l, r := testLayout(t)
	l.activeStack = running(StackNginx, true)
	mkdir(t, r, "usr/local/cpanel")
	put(t, r, "etc/apache2/conf/httpd.conf", cpanelHTTPD)
	put(t, r, "etc/nginx/nginx.conf", "include /etc/nginx/conf.d/modules/*.conf;\nevents {}\nhttp {\n    include /etc/nginx/mime.types;\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	put(t, r, "etc/nginx/mime.types", "types { text/html html; }\n")
	put(t, r, "etc/nginx/conf.d/includes-optional/cloudflare.conf",
		"set_real_ip_from 173.245.48.0/20;\nset_real_ip_from 2400:cb00::/32;\nreal_ip_header CF-Connecting-IP;\n")
	put(t, r, "etc/nginx/conf.d/includes-optional/cpanel-proxy.conf", "proxy_set_header X-Real-IP $remote_addr;\n")
	put(t, r, "etc/nginx/conf.d/default.conf", "server {\n    listen 80 reuseport;\n    server_name 127.0.0.1 localhost $hostname;\n    location / { include conf.d/includes-optional/cpanel-proxy.conf; }\n    include conf.d/server-includes/*.conf;\n}\n")
	put(t, r, "etc/nginx/conf.d/cpanel-proxy-non-ssl.conf", "server {\n    server_name cpanel.*;\n    listen 80;\n}\nserver {\n    server_name ~^webmail\\.;\n    listen 80;\n}\n")
	put(t, r, "etc/nginx/conf.d/users.conf", "include conf.d/users/*.conf;\n")
	site := func(user, domain string) string {
		return "server {\n    server_name " + domain + " www." + domain + ";\n    listen 80;\n    include conf.d/includes-optional/cloudflare.conf;\n" +
			"    location / { include conf.d/includes-optional/cpanel-proxy.conf; }\n    include conf.d/server-includes/*.conf;\n    include conf.d/users/" + user + "/*.conf;\n}\n" +
			"server {\n    listen 80;\n    server_name autoconfig." + domain + " cpanel." + domain + " webmail." + domain + " whm." + domain + ";\n" +
			"    include conf.d/includes-optional/cloudflare.conf;\n    location / { include conf.d/includes-optional/cpanel-proxy.conf; }\n}\n"
	}
	put(t, r, "etc/nginx/conf.d/users/grgr.conf", site("grgr", "24gr.gr"))
	put(t, r, "etc/nginx/conf.d/users/koreanbe.conf", site("koreanbe", "koreanbeauty.gr"))
	mkdir(t, r, "etc/nginx/conf.d/server-includes")
	return l, r
}

func TestCPanelEaNginxWithoutImunify(t *testing.T) {
	l, r := eaNginxHost(t)
	p := l.probe("")
	// default + two sites; the two proxy-subdomain blocks per user and the
	// cpanel.* / webmail regex blocks are reported, not counted.
	if p.Panel != PanelCPanel || p.Stack != StackNginx || p.Trusted || p.Servers != 3 || p.UntrustedServers != 3 {
		t.Fatalf("probe = %+v", p)
	}
	if !strings.Contains(p.Note, "replaces the http-level one") || !strings.Contains(p.Note, "4 cPanel proxy-subdomain") {
		t.Fatalf("note = %q", p.Note)
	}
	pl := l.plan(p)
	want := filepath.Join(r, "etc/nginx/conf.d/server-includes/cfm-realip.conf")
	if pl.Action != ActionWrite || pl.Path != want || pl.Managed || pl.Content != nginxTrust {
		t.Fatalf("plan = %+v (an http-level conf.d file would reach no block)", pl)
	}
	f := &fakeCmds{out: map[string]string{"nginx -V": "configure arguments: --with-http_realip_module"}}
	f.install(t)
	if err := Apply(pl, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	after := l.probe("")
	if !after.Trusted || after.Servers != 3 || after.Header != "CF-Connecting-IP / X-Real-IP (default)" ||
		!strings.Contains(after.Note, "proxy-subdomain") {
		t.Fatalf("after: %+v", after)
	}
	if pl := l.plan(after); pl.Action != ActionNone {
		t.Fatalf("second run plans %+v", pl)
	}
}

func TestCPanelEaNginxImunifyWebshieldIsSeen(t *testing.T) {
	l, r := eaNginxHost(t)
	put(t, r, "etc/nginx/conf.d/server-includes/imunify360-webshield.conf", "set_real_ip_from 127.0.0.1;\n")
	p := l.probe("")
	if !p.Trusted || p.Servers != 3 || !strings.Contains(p.Source, "imunify360-webshield.conf") || !strings.Contains(p.Directive, "3 through their own list") {
		t.Fatalf("probe = %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionNone {
		t.Fatalf("plan = %+v", pl)
	}
}

func TestCPanelProxyServer(t *testing.T) {
	cases := map[string]bool{
		"cpanel.x.gr webmail.x.gr whm.x.gr": true,
		"cpanel.*":                          true,
		`~^(cpanel|webmail|whm)\.`:          true,
		`~^(?<sub>cpanel|whm)\..+$`:         true,
		`~^(?:www|cpanel)\.`:                false,
		`~^webmail\.`:                       true,
		"autodiscover.x.gr x.gr":            false,
		"webmailer.gr":                      false,
		"":                                  false,
	}
	for names, want := range cases {
		if got := cpanelProxyServer(strings.Fields(names)); got != want {
			t.Errorf("%q: got %v, want %v", names, got, want)
		}
	}
}

// ngm.myip.gr: NGM owns nginx.conf and includes only conf/sites/*.conf. CFM
// reports, never writes (NGM docs/cfm-integration-map.md).
func TestNGMIsManual(t *testing.T) {
	l, r := testLayout(t)
	l.activeStack = running(StackNginx, true)
	mkdir(t, r, "etc/ngm")
	mkdir(t, r, "etc/nginx/conf.d")
	put(t, r, "etc/httpd/conf.d/php83-php.conf", "<Files \".user.ini\">\n</Files>\n") // ngm.myip.gr carries these
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include mime.types;\n    include /etc/nginx/conf/sites/*.conf;\n}\n")
	p := l.probe("")
	if p.Panel != PanelNGM || p.Stack != StackNginx || p.Trusted || !strings.Contains(p.Note, "NGM renders nginx") {
		t.Fatalf("probe = %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "NGM") {
		t.Fatalf("plan = %+v", pl)
	}
	// Trust NGM renders at http level (top of an included site file) is seen.
	put(t, r, "etc/nginx/conf/sites/_ngm-edge.conf", "set_real_ip_from 127.0.0.1;\n")
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("NGM-rendered trust: %+v", p)
	}
}

func TestLiteSpeed(t *testing.T) {
	l, r := cpanelHost(t)
	xml := "usr/local/lsws/conf/httpd_config.xml"
	put(t, r, xml, "<httpServerConfig>\n <!-- <useIpInProxyHeader>2</useIpInProxyHeader> -->\n <useIpInProxyHeader>0</useIpInProxyHeader>\n</httpServerConfig>\n")
	// LiteSpeed on disk beats a bogus nginx hint (the edge is nginx-based).
	p := l.probe("nginx")
	if p.Stack != StackLiteSpeed || p.Trusted {
		t.Fatalf("commented/zero: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "Use Client IP in Header") {
		t.Fatalf("plan = %+v", pl)
	}
	// 2 = "Trusted IP Only": needs 127.0.0.1T in the allow list (mars).
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl><allow>ALL</allow></accessControl></security></httpServerConfig>")
	if p := l.probe(""); p.Trusted {
		t.Fatalf("2 without a trusted loopback: %+v", p)
	}
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl>\n      <allow>ALL,127.0.0.1T</allow>\n</accessControl></security></httpServerConfig>")
	if p := l.probe(""); !p.Trusted || p.Source != "/"+xml {
		t.Fatalf("native 2 + 127.0.0.1T: %+v", p)
	}
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>1</useIpInProxyHeader></httpServerConfig>")
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("native 1: %+v", p)
	}
	// A leftover /usr/local/lsws while Apache owns :80 is Apache.
	l.activeStack = running(StackApache, true)
	if p := l.probe(""); p.Stack != StackApache {
		t.Fatalf("leftover LiteSpeed with Apache listening: %+v", p)
	}
}

func TestActiveOriginStackPrefersTheListener(t *testing.T) {
	f := &fakeCmds{out: map[string]string{
		"ss -Hltnp sport = :80": `LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=4645,fd=25),("nginx",pid=4643,fd=25))`,
	}}
	f.install(t)
	// httpd is also "active" (DirectAdmin nginx_apache): the listener decides.
	if s, fromListener := activeOriginStack(); s != StackNginx || !fromListener {
		t.Fatalf("got %q %v", s, fromListener)
	}
	f.out["ss -Hltnp sport = :80"] = ""
	f.fail = map[string]bool{"systemctl is-active --quiet lsws": true, "systemctl is-active --quiet lshttpd": true}
	if s, fromListener := activeOriginStack(); s != StackApache || fromListener {
		t.Fatalf("fallback: got %q %v", s, fromListener)
	}
}

func TestApplyRollsBackOnFailedConfigTest(t *testing.T) {
	l, _ := cpanelHost(t)
	pl := l.plan(l.probe("httpd"))
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module", "apachectl -t": "AH00526: Syntax error"}, fail: map[string]bool{"apachectl -t": true}}
	f.install(t)
	err := Apply(pl, &bytes.Buffer{})
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

	// A managed block in an existing operator file: back byte for byte.
	l2, r2 := testLayout(t)
	mkdir(t, r2, "usr/local/directadmin")
	put(t, r2, "etc/httpd/conf/httpd.conf", "Include conf/extra/httpd-includes.conf\n")
	orig := "Header set X 1\n"
	inc := put(t, r2, "etc/httpd/conf/extra/httpd-includes.conf", orig)
	if err := Apply(l2.plan(l2.probe("httpd")), &bytes.Buffer{}); err == nil {
		t.Fatal("want failure")
	}
	if got := read(t, inc); got != orig {
		t.Fatalf("operator file not restored: %q", got)
	}
}

func TestApplyRefusesWithoutModule(t *testing.T) {
	l, _ := cpanelHost(t)
	pl := l.plan(l.probe("httpd"))
	f := &fakeCmds{out: map[string]string{"apachectl -M": "core_module (static)"}}
	f.install(t)
	err := Apply(pl, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "ea-apache24-mod_remoteip") {
		t.Fatalf("err = %v (cPanel needs the EA4 package hint)", err)
	}
	if _, err := os.Stat(pl.Path); !os.IsNotExist(err) {
		t.Fatal("wrote a drop-in Apache cannot load")
	}

	l2, r2 := testLayout(t)
	mkdir(t, r2, "etc/nginx/conf.d")
	put(t, r2, "etc/nginx/nginx.conf", "http { include /etc/nginx/conf.d/*.conf; }\n")
	f2 := &fakeCmds{out: map[string]string{"nginx -V": "configure arguments: --without-http_realip_module"}}
	f2.install(t)
	// "--without-http_realip_module" contains the module name; not fooled by it.
	if err := Apply(l2.plan(l2.probe("nginx")), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "realip") {
		t.Fatalf("err = %v", err)
	}
}

// A symlinked target is written through, not replaced by a regular file.
func TestApplyWritesThroughSymlink(t *testing.T) {
	l, r := testLayout(t)
	mkdir(t, r, "usr/local/directadmin")
	put(t, r, "etc/httpd/conf/httpd.conf", "Include conf/extra/httpd-includes.conf\n")
	real := put(t, r, "srv/conf/httpd-includes.conf", "ServerTokens Prod\n")
	link := filepath.Join(r, "etc/httpd/conf/extra/httpd-includes.conf")
	mkdir(t, r, "etc/httpd/conf/extra")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f := &fakeCmds{out: map[string]string{"apachectl -M": "remoteip_module"}}
	f.install(t)
	if err := Apply(l.plan(l.probe("httpd")), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced by a regular file")
	}
	if !strings.Contains(read(t, real), blockBegin) {
		t.Fatal("the link target was not updated")
	}
}

func TestAnyLoopback(t *testing.T) {
	// The edge proxies from 127.0.0.1: ::1 alone does not trust it.
	for _, ok := range [][]string{{"127.0.0.1"}, {"127.0.0.1/32"}, {"127.0.0.0/8"}, {"::1", "127.0.0.1"}, {"10.0.0.1", "127.0.0.1"}} {
		if !anyLoopback(ok) {
			t.Errorf("%v must be loopback trust", ok)
		}
	}
	for _, bad := range [][]string{{"127.0.0.100"}, {"127.0.0.1/1"}, {"127.0.0.0/1"}, {"0.0.0.0/0"}, {"::/0"}, {"84.54.49.83"}, {"127.0.0.2"}, {"::1"}, {"::1/128"}} {
		if anyLoopback(bad) {
			t.Errorf("%v must not be loopback trust", bad)
		}
	}
}

func TestGrepSizeCap(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http { include /etc/nginx/conf.d/*.conf; }\n")
	put(t, r, "etc/nginx/conf.d/big.conf", "# padding padding padding padding padding\nset_real_ip_from 127.0.0.1;\n")
	saved := grepMaxBytes
	grepMaxBytes = 64 // fits nginx.conf, not big.conf
	defer func() { grepMaxBytes = saved }()
	if p := l.probe("nginx"); p.Trusted {
		t.Errorf("a file over the size cap must be skipped: %+v", p)
	}
}

func TestIncludeLoopIsBounded(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http { include /etc/nginx/a.conf; }\n")
	put(t, r, "etc/nginx/a.conf", "include /etc/nginx/b.conf;\n")
	put(t, r, "etc/nginx/b.conf", "include /etc/nginx/a.conf;\nset_real_ip_from 127.0.0.1;\n")
	if p := l.probe("nginx"); !p.Trusted {
		t.Fatalf("probe = %+v", p)
	}
}

func TestResolveOriginStack(t *testing.T) {
	cases := []struct {
		name, upstream string
		dirs           []string
		want           string
	}{
		{"litespeed present beats nginx hint", "nginx", []string{"usr/local/lsws", "etc/nginx"}, StackLiteSpeed},
		{"litespeed hint trusted w/o marker", "lshttpd", nil, StackLiteSpeed},
		{"apache hint + apache present", "httpd", []string{"etc/httpd"}, StackApache},
		{"nginx hint + nginx present", "nginx", []string{"etc/nginx"}, StackNginx},
		{"nginx hint but only apache on disk", "nginx", []string{"etc/apache2"}, StackApache},
		{"unknown + nothing present", "", nil, StackUnknown},
	}
	for _, c := range cases {
		l, r := testLayout(t)
		for _, d := range c.dirs {
			mkdir(t, r, d)
		}
		if got := l.resolveOriginStack(c.upstream); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCLI(t *testing.T) {
	l, r := cpanelHost(t)
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

// nginx's tokenizer: nothing inside quotes is syntax, `${var}` is part of its
// token, and `#` comments only at a token's start. A quoted regex quantifier
// used to open and close blocks, and the server{} the next directives were
// credited to drifted.
func TestNginxTokenizerQuotesAndVarBraces(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	put(t, r, "etc/nginx/conf.d/a.conf", `server {
    server_name shop.gr;
    add_header X-Brace "}";
    set_real_ip_from 127.0.0.1;
    location ~ "^/(\d{4})/{2}" { return 301 https://${host}/x#frag; }
    add_header X-A 'a;b}{c # not a comment';
}
server {
    server_name blog.gr;
}
`)
	p := l.probe("nginx")
	// blog.gr has no list and http{} none: untrusted. The old tokenizer
	// closed shop.gr at the quoted "}", took its trust for http-level, and
	// blog.gr inherited it.
	if p.Trusted || p.Servers != 2 || p.UntrustedServers != 1 || !strings.Contains(p.Note, "blog.gr") || strings.Contains(p.Note, "shop.gr") {
		t.Fatalf("probe = %+v", p)
	}
	_, servers, _ := l.nginxDirectives(l.nginxMain, l.nginxPrefix, "set_real_ip_from")
	if len(servers) != 2 || strings.Join(servers[0].names, ",") != "shop.gr" || strings.Join(servers[1].names, ",") != "blog.gr" {
		t.Fatalf("servers = %+v", servers)
	}
}

// cPanel with an http-level set_real_ip_from list: a server-includes trust
// would replace it for every block that inherits it, so the plan is manual.
func TestCPanelEaNginxHTTPListIsManual(t *testing.T) {
	l, r := eaNginxHost(t)
	put(t, r, "etc/nginx/conf.d/lb.conf", "set_real_ip_from 10.0.0.5;\n")
	p := l.probe("")
	if p.Trusted {
		t.Fatalf("probe = %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionManual || !strings.Contains(pl.Reason, "http{} has its own set_real_ip_from list") || !strings.Contains(pl.Reason, nginxTrust) {
		t.Fatalf("plan = %+v", pl)
	}
}

// Only server{} blocks the edge proxies to count: a status page on
// 127.0.0.1:8090 or a unix socket is no visitor's site.
func TestNginxOnlyEdgeFacingServersCount(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n}\n")
	put(t, r, "etc/nginx/conf.d/a.conf", `server { server_name shop.gr; listen 443 ssl; listen [::]:443 ssl; set_real_ip_from 127.0.0.1; }
server { listen 127.0.0.1:8090; location /nginx_status { stub_status; } }
server { listen unix:/run/x.sock; }
server { server_name plain.gr; set_real_ip_from 127.0.0.1; }
`)
	p := l.probe("nginx")
	if !p.Trusted || p.Servers != 2 || !strings.Contains(p.Note, "2 server{} block(s) listening only off :80/:443") {
		t.Fatalf("probe = %+v", p)
	}
	for l, want := range map[string]string{"80": "80", "*:443": "443", "[::]:80": "80", "127.0.0.1:8090": "8090", "localhost": "80", "[::1]": "80", "10.0.0.1": "80"} {
		if got := listenPort(l); got != want {
			t.Errorf("listenPort(%q) = %q, want %q", l, got, want)
		}
	}
}

// A walk limit is said, not silently judged on part of the configuration.
func TestNginxTruncatedWalkIsNoted(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/d0.conf;\n}\n")
	for i := 0; i <= walkMaxDepth+1; i++ {
		put(t, r, "etc/nginx/d"+strconv.Itoa(i)+".conf", "include /etc/nginx/d"+strconv.Itoa(i+1)+".conf;\n")
	}
	if p := l.probe("nginx"); !strings.Contains(p.Note, "walk stopped at a limit") {
		t.Fatalf("probe = %+v", p)
	}
}

// edgeV6 marks the edge as listening on IPv6, as scripts/cfm-edge-listen-v6.sh
// does (one of its listen files present).
func edgeV6(t *testing.T, r string) {
	t.Helper()
	put(t, r, "usr/local/openresty/nginx/conf/cfm-listen-v6-http.conf", "listen [::]:9080;\n")
}

// When the edge listens on IPv6, an IPv6 visitor's hop reaches the origin from
// ::1: a trust of 127.0.0.1 alone is no longer enough (Apache).
func TestEdgeIPv6RequiresLoopback6Apache(t *testing.T) {
	l, r := cpanelHost(t)
	put(t, r, "etc/apache2/conf.d/i360.remoteip.conf",
		"<IfModule remoteip_module>\n    RemoteIPInternalProxy 127.0.0.1\n    RemoteIPHeader X-Forwarded-For\n</IfModule>\n")
	if p := l.probe("httpd"); !p.Trusted || p.EdgeIPv6 {
		t.Fatalf("IPv4-only edge, 127.0.0.1 trusted: %+v", p)
	}
	edgeV6(t, r)
	p := l.probe("httpd")
	if p.Trusted || !p.EdgeIPv6 || !strings.Contains(p.Note, "::1") || strings.Contains(p.Note, "127.0.0.1 in the Apache") {
		t.Fatalf("IPv6 edge, ::1 untrusted: %+v", p)
	}
	if line := StatusLine(p, true); !strings.Contains(line, "logs ::1 for every IPv6 visitor") {
		t.Errorf("verdict = %q", line)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Content != apacheTrust || !strings.Contains(pl.Content, "::1") {
		t.Fatalf("plan = %+v", pl)
	}
	if err := os.WriteFile(pl.Path, []byte(pl.Content), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := l.probe("httpd"); !p.Trusted || !p.EdgeIPv6 {
		t.Fatalf("after the fix (both loopbacks): %+v", p)
	}
	// ::1 alone (no 127.0.0.1) is still untrusted on an IPv6 edge: both hops occur.
	l2, r2 := cpanelHost(t)
	put(t, r2, "etc/apache2/conf.d/x.conf", "RemoteIPInternalProxy ::1\nRemoteIPHeader X-Real-IP\n")
	edgeV6(t, r2)
	if p := l2.probe("httpd"); p.Trusted {
		t.Fatalf("::1 only: %+v", p)
	}
}

func TestEdgeIPv6RequiresLoopback6LiteSpeed(t *testing.T) {
	l, r := cpanelHost(t)
	xml := "usr/local/lsws/conf/httpd_config.xml"
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl><allow>ALL,127.0.0.1T</allow></accessControl></security></httpServerConfig>")
	edgeV6(t, r)
	p := l.probe("")
	if p.Trusted || !p.EdgeIPv6 || !strings.Contains(p.Note, "::1T") {
		t.Fatalf("127.0.0.1T only: %+v", p)
	}
	if pl := l.plan(p); pl.Action != ActionManual || !strings.Contains(pl.Reason, "127.0.0.1T and ::1T") {
		t.Fatalf("plan = %+v", pl)
	}
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl><allow>ALL, 127.0.0.1T, ::1T</allow></accessControl></security></httpServerConfig>")
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("127.0.0.1T + ::1T: %+v", p)
	}
	// ::1 without T is allowed, not trusted; a longer address ending in ::1 is not ::1.
	for _, allow := range []string{"ALL,127.0.0.1T,::1", "ALL,127.0.0.1T,2001:db8::1T"} {
		put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>2</useIpInProxyHeader>\n<security><accessControl><allow>"+allow+"</allow></accessControl></security></httpServerConfig>")
		if p := l.probe(""); p.Trusted {
			t.Fatalf("%s: %+v", allow, p)
		}
	}
	put(t, r, xml, "<httpServerConfig><useIpInProxyHeader>1</useIpInProxyHeader></httpServerConfig>")
	if p := l.probe(""); !p.Trusted {
		t.Fatalf("native 1 (any peer): %+v", p)
	}
}

func TestEdgeIPv6RequiresLoopback6Nginx(t *testing.T) {
	l, r := testLayout(t)
	put(t, r, "etc/nginx/nginx.conf", "http {\n    include /etc/nginx/conf.d/*.conf;\n    include /etc/nginx/sites-enabled/*;\n}\n")
	put(t, r, "etc/nginx/conf.d/a.conf", "set_real_ip_from 127.0.0.1;\n")
	put(t, r, "etc/nginx/sites-enabled/shop", "server {\n  server_name shop.gr;\n}\n")
	if p := l.probe("nginx"); !p.Trusted {
		t.Fatalf("IPv4-only edge: %+v", p)
	}
	edgeV6(t, r)
	p := l.probe("nginx")
	if p.Trusted || !p.EdgeIPv6 || !strings.Contains(p.Note, "::1") {
		t.Fatalf("IPv6 edge, http-level 127.0.0.1 only: %+v", p)
	}
	pl := l.plan(p)
	if pl.Action != ActionWrite || pl.Path != filepath.Join(r, "etc/nginx/conf.d/cfm-realip.conf") {
		t.Fatalf("plan = %+v", pl)
	}
	if err := os.WriteFile(pl.Path, []byte(pl.Content), 0o644); err != nil {
		t.Fatal(err)
	}
	if p := l.probe("nginx"); !p.Trusted {
		t.Fatalf("after the fix: %+v", p)
	}
}

func TestAnyLoopback6(t *testing.T) {
	for _, ok := range [][]string{{"::1"}, {"::1/128"}, {"127.0.0.1", "::1"}, {"0:0:0:0:0:0:0:1"}} {
		if !anyLoopback6(ok) {
			t.Errorf("%v must be ::1 trust", ok)
		}
	}
	for _, bad := range [][]string{{"127.0.0.1"}, {"::/0"}, {"::/127"}, {"::2"}, {"2001:db8::1"}, {"::ffff:127.0.0.1"}, {"x"}} {
		if anyLoopback6(bad) {
			t.Errorf("%v must not be ::1 trust", bad)
		}
	}
}
