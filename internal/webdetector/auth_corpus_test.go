package webdetector

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"unsafe"
)

const authBase = "1000.5\t1.2.3.4\tShop.GR\tPOST\t/wp-login.php\tHTTP/1.1\t302\t0\t0.1\t0.1\t-\tMozilla/5.0\tcfm_apache"

func TestParseSocketTSVAuthColumn(t *testing.T) {
	rec, ok := parseSocketTSV(authBase + "\t0\tWP_LOGIN;li=1;l=/wp-admin/;c=wordpress_logged_in_ab")
	if !ok || rec.Auth != "WP_LOGIN;li=1;l=/wp-admin/;c=wordpress_logged_in_ab" || rec.Bypass || rec.UpstreamName != "cfm_apache" {
		t.Fatalf("15 columns: %+v ok=%v", rec, ok)
	}
	if rec.UA != "mozilla/5.0" {
		t.Fatalf("ua = %q", rec.UA)
	}
	// The bypass flag still reads with the 15th column after it.
	if rec, _ = parseSocketTSV(authBase + "\t1\tWP_LOGIN;li=0;l=;c="); !rec.Bypass || rec.Auth == "" {
		t.Fatalf("bypass beside auth: %+v", rec)
	}
	// 14 columns (every non-login line, every older module): no Auth.
	if rec, _ = parseSocketTSV(authBase + "\t2"); !rec.Bypass || rec.Auth != "" {
		t.Fatalf("14 columns: %+v", rec)
	}
	// File tailers never read past column 11.
	if rec, _ = parseTSV(authBase + "\t0\tWP_LOGIN;li=1;l=;c="); rec.Auth != "" {
		t.Fatalf("file TSV read an auth column: %+v", rec)
	}
	// A 16th TAB (cannot come from log-cfm, which cleans the field) stays inside Auth.
	if rec, _ = parseSocketTSV(authBase + "\t0\tWP_LOGIN;li=0;l=;c=\textra"); rec.Auth != "WP_LOGIN;li=0;l=;c=\textra" {
		t.Fatalf("16th column: %q", rec.Auth)
	}
	// A field past maxAuthField is cut to it.
	if rec, _ = parseSocketTSV(authBase + "\t0\t" + strings.Repeat("x", 800)); len(rec.Auth) != maxAuthField {
		t.Fatalf("auth not capped: %d", len(rec.Auth))
	}
}

// Version skew: an older daemon split socket lines into at most 14 columns.
// Every line but a login POST's keeps 14, so the old reading of its bypass
// flag and upstream name is unchanged; only a login POST's bypass bit folds.
func TestAuthColumnOldParserSkew(t *testing.T) {
	oldParse := func(line string) (up string, bypass bool) {
		f := strings.SplitN(line, "\t", 14)
		return f[12], len(f) == 14 && (f[13] == "1" || f[13] == "2")
	}
	plain := authBase + "\t1"
	if up, bp := oldParse(plain); up != "cfm_apache" || !bp {
		t.Fatalf("old parser on a 14-column line: %q %v", up, bp)
	}
	rec, _ := parseSocketTSV(plain)
	if rec.UpstreamName != "cfm_apache" || !rec.Bypass || rec.Auth != "" {
		t.Fatalf("new parser on a 14-column line: %+v", rec)
	}
	if up, bp := oldParse(plain + "\tWP_LOGIN;li=0;l=;c="); up != "cfm_apache" || bp {
		t.Fatalf("old parser on a login line (bypass is expected to fold): %q %v", up, bp)
	}
}

func TestParseAuthField(t *testing.T) {
	af, ok := parseAuthField("WP_LOGIN;li=1;l=/wp-login.php;c=a,b;a=lostpassword")
	if !ok || af.Tag != "WP_LOGIN" || !af.LoggedIn || af.Loc != "/wp-login.php" ||
		len(af.Cookies) != 2 || af.Action != "lostpassword" {
		t.Fatalf("%+v %v", af, ok)
	}
	for _, bad := range []string{"", "-", "WP_LOGIN", ";li=0", "WP_LOGIN;l=;c=", "WP_LOGIN:ok;li=1", strings.Repeat("x", 300)} {
		if _, ok := parseAuthField(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if af, ok := parseAuthField("JOOMLA_ADMIN;li=0;c=;l="); !ok || af.Cookies != nil || af.LoggedIn {
		t.Errorf("empty lists: %+v", af)
	}
}

func TestAuthOutcome(t *testing.T) {
	origin := func(st int) LogRec { return LogRec{Status: st, UpstreamName: "cfm_apache_ssl", Upstream: true} }
	cases := []struct {
		name string
		rec  LogRec
		af   authField
		want string
	}{
		{"cookie set", origin(302), authField{Tag: "WP_LOGIN", LoggedIn: true, Loc: "/wp-admin/"}, "ok"},
		{"form again", origin(200), authField{Tag: "WP_LOGIN"}, "fail"},
		{"302 back to login (glaveris)", origin(302), authField{Tag: "WP_LOGIN", Loc: "/wp-login.php"}, "fail"},
		{"hide-login slug", origin(302), authField{Tag: "WP_LOGIN", Loc: "/My-Login/"}, "fail"},
		{"303 back to login", origin(303), authField{Tag: "WP_LOGIN", Loc: "/wp-login.php"}, "fail"},
		{"301 canonical redirect to the login page (lelaki.gr)", origin(301), authField{Tag: "WP_LOGIN", Loc: "/wp-login.php"}, "?"},
		{"308 canonical redirect", origin(308), authField{Tag: "WP_LOGIN", Loc: "/wp-login.php"}, "?"},
		{"307 to the login page", origin(307), authField{Tag: "WP_LOGIN", Loc: "/wp-login.php"}, "?"},
		{"302 elsewhere without cookie (2FA)", origin(302), authField{Tag: "WP_LOGIN", Loc: "/2fa/"}, "?"},
		{"lostpassword", origin(302), authField{Tag: "WP_LOGIN", Action: "lostpassword", Loc: "/wp-login.php"}, "na"},
		{"query action cannot hide a success", origin(302), authField{Tag: "WP_LOGIN", LoggedIn: true, Action: "lostpassword"}, "ok"},
		{"action=login is the login", origin(200), authField{Tag: "WP_LOGIN", Action: "login"}, "fail"},
		{"an unknown action runs the login", origin(200), authField{Tag: "WP_LOGIN", Action: "zz"}, "fail"},
		{"register", origin(200), authField{Tag: "WP_LOGIN", Action: "register"}, "na"},
		{"cfm_apache preset, but no upstream answered", LogRec{Status: 200, UpstreamName: "cfm_apache"}, authField{Tag: "WP_LOGIN"}, "?"},
		{"the challenge server answered", LogRec{Status: 200, UpstreamName: "cfm_challenge"}, authField{Tag: "WP_LOGIN"}, "?"},
		{"edge block", LogRec{Status: 403, UpstreamName: "cfm_block"}, authField{Tag: "WP_LOGIN", LoggedIn: true}, "?"},
		{"no upstream name", LogRec{Status: 200, UpstreamName: "-"}, authField{Tag: "WP_LOGIN"}, "?"},
		{"other CMS", origin(200), authField{Tag: "JOOMLA_ADMIN"}, "?"},
		{"5xx", origin(500), authField{Tag: "WP_LOGIN"}, "?"},
	}
	for _, c := range cases {
		if got := authOutcome(c.rec, c.af); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func authRec(ip, host, uri string, status int, auth string) LogRec {
	return LogRec{TS: 1000, IP: ip, Host: host, Method: "post", URI: uri, Status: status, Auth: auth, UpstreamName: "cfm_apache", Upstream: true}
}

func TestAuthCorpusShapes(t *testing.T) {
	c := newAuthCorpus(0)
	// Two Joomla sites: md5 cookie names and per-site digits fold into one shape.
	c.add(authRec("1.1.1.1", "a.gr", "/administrator/index.php?task=login&option=com_login&x=1&return=aHR0cA", 303,
		"JOOMLA_ADMIN;li=0;l=/administrator/index.php;c=0123456789abcdef0123456789abcdef,joomla_user_state"), "a.gr")
	c.add(authRec("2.2.2.2", "b.gr", "/administrator/index.php?option=com_login&task=login", 303,
		"JOOMLA_ADMIN;li=0;l=/administrator/index.php;c=joomla_user_state,fedcba9876543210fedcba9876543210"), "b.gr")
	c.add(authRec("2.2.2.2", "b.gr", "/administrator/index.php?option=com_login&task=login#x", 303,
		"JOOMLA_ADMIN;li=0;l=/administrator/index.php;c=joomla_user_state,fedcba9876543210fedcba9876543210"), "b.gr")
	c.add(authRec("3.3.3.3", "c.gr", "/wp-login.php", 200, "WP_LOGIN;li=0;l=;c="), "c.gr")
	c.add(LogRec{Host: "c.gr", Auth: "garbage"}, "c.gr")

	s := c.snapshot("", "", 0)
	if s.Shapes != 2 || len(s.Entries) != 2 {
		t.Fatalf("shapes = %d: %+v", s.Shapes, s.Entries)
	}
	j := s.Entries[0]
	if j.Tag != "JOOMLA_ADMIN" || j.Count != 3 || j.IPs != 2 || j.Hosts != 2 ||
		j.Cookies != "<h>,joomla_user_state" || j.Path != "/administrator/index.php?option=com_login&task=login" || j.Status != 303 {
		t.Fatalf("joomla shape: %+v", j)
	}
	if strings.Join(j.Examples, ",") != "a.gr,b.gr" {
		t.Fatalf("examples: %v", j.Examples)
	}
	if s.Totals["JOOMLA_ADMIN"]["?"] != 3 || s.Totals["WP_LOGIN"]["fail"] != 1 {
		t.Fatalf("totals: %v", s.Totals)
	}
	if f := c.snapshot("wp_login", "fail", 0); len(f.Entries) != 1 || len(f.Totals) != 1 {
		t.Fatalf("filter: %+v", f)
	}
	if f := c.snapshot("", "ok", 0); len(f.Entries) != 0 {
		t.Fatalf("outcome filter: %+v", f)
	}
}

func TestAuthPathShape(t *testing.T) {
	for in, want := range map[string]string{
		"/administrator/index.php?option=com_content&task=article.save&id=42": "/administrator/index.php?option=com_content&task=article.save",
		"/admin/index.php?route=common/login&user_token=0123456789abcdef0123": "/admin/index.php?route=common/login",
		"/admin123/index.php?controller=adminlogin&token=x&redirect=y":        "/admin<n>/index.php?controller=adminlogin",
		"/wp-login.php?action=lostpassword&wp_lang=el":                        "/wp-login.php?action=lostpassword",
		"/login?username=bob&next=/x":                                         "/login",
		"/x.php?task=" + strings.Repeat("z", 50):                              "/x.php?task=" + strings.Repeat("z", 32),
	} {
		if got := authPathShape(in); got != want {
			t.Errorf("%s → %q, want %q", in, got, want)
		}
	}
}

func TestAuthLocShape(t *testing.T) {
	for in, want := range map[string]string{
		"":                                    "",
		"/wp-admin/":                          "/wp-admin/",
		"/wp-login.php":                       "/wp-login.php",
		"/members/john/":                      "/members/<user>/",
		"/user/Maria/profile/edit":            "/user/<user>/…",
		"/admin123/admin/index/index/key/ab/": "/admin<n>/admin/…",
		"/administrator/index.php":            "/administrator/index.php",
	} {
		if got := authLocShape(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

// The corpus must not pin the socket line its fields were cut from.
func TestAuthCorpusClonesStrings(t *testing.T) {
	line := authBase + "\t0\tWP_LOGIN;li=0;l=/wp-login.php;c=x" + strings.Repeat(" ", 4096)
	rec, _ := parseSocketTSV(line)
	c := newAuthCorpus(0)
	host := rec.Host
	c.add(rec, host)
	lo, hi := uintptr(unsafe.Pointer(unsafe.StringData(line))), uintptr(unsafe.Pointer(unsafe.StringData(line)))+uintptr(len(line))
	in := func(s string) bool {
		if s == "" {
			return false
		}
		p := uintptr(unsafe.Pointer(unsafe.StringData(s)))
		return p >= lo && p < hi
	}
	for _, e := range c.entries {
		for _, f := range []string{e.Tag, e.Upstream, e.Method, e.Path, e.Location, e.Cookies, e.Action, e.key} {
			if in(f) {
				t.Errorf("entry field %q points into the line", f)
			}
		}
		if in(e.net) {
			t.Errorf("net %q points into the line", e.net)
		}
		for _, h := range e.Examples {
			if in(h) {
				t.Errorf("example %q points into the line", h)
			}
		}
	}
	for k := range c.byNet {
		if in(k) {
			t.Errorf("byNet key %q points into the line", k)
		}
	}
	for k := range c.totals {
		if in(k) {
			t.Errorf("totals key %q points into the line", k)
		}
	}
}

func TestAuthCorpusPerNetAndEviction(t *testing.T) {
	c := newAuthCorpus(0)
	for i := 0; i < 40; i++ {
		ip := "6.6.6." + strconv.Itoa(i) // one /24
		c.add(authRec(ip, "a.gr", "/"+strings.Repeat("q", i+1)+"/login", 200, "LOGIN_POST;li=0;l=;c="), "a.gr")
	}
	s := c.snapshot("", "", 0)
	if s.Shapes != authCorpusPerNet || s.DroppedByTag["LOGIN_POST"] != int64(40-authCorpusPerNet) {
		t.Fatalf("per-/24 share: shapes=%d dropped=%v", s.Shapes, s.DroppedByTag)
	}
	c = newAuthCorpus(0)
	for i := 0; i < 40; i++ {
		ip := "2001:db8::" + strconv.FormatInt(int64(i+1), 16) // one /64
		c.add(authRec(ip, "a.gr", "/"+strings.Repeat("r", i+1)+"/login", 200, "LOGIN_POST;li=0;l=;c="), "a.gr")
	}
	if s = c.snapshot("", "", 0); s.Shapes != authCorpusPerNet {
		t.Fatalf("per-/64 share: shapes=%d", s.Shapes)
	}

	// The third review's lock: 125 networks x 16 shapes x 2 lines filled the
	// corpus with count-2 shapes and every later real shape was dropped. The
	// least-used shape is evicted now, and a real one that keeps coming stays.
	c = newAuthCorpus(0)
	for n := 0; n < 125; n++ {
		for k := 0; k < authCorpusPerNet; k++ {
			r := authRec("10."+strconv.Itoa(n)+".0.1", "a.gr", "/"+letters(n)+"-"+strings.Repeat("z", k+1)+"/login", 200, "LOGIN_POST;li=0;l=;c=")
			r.TS = float64(100 + n)
			c.add(r, "a.gr")
			c.add(r, "a.gr")
		}
	}
	if s = c.snapshot("", "", 0); s.Shapes != authCorpusCap {
		t.Fatalf("not full: %d", s.Shapes)
	}
	for i := 0; i < 1000; i++ {
		c.add(authRec("203.0.113."+strconv.Itoa(i%250), "w.gr", "/wp-login.php", 200, "WP_LOGIN;li=0;l=;c="), "w.gr")
	}
	s = c.snapshot("WP_LOGIN", "", 0)
	if len(s.Entries) != 1 || s.Entries[0].Count != 1000 || s.Dropped != 0 {
		t.Fatalf("real shape after the junk: %+v", s)
	}
	if len(c.byNet) > authCorpusCap {
		t.Fatalf("net bookkeeping outgrew the corpus: %d", len(c.byNet))
	}
	// The evicted shape released its network's slot.
	total := 0
	for _, n := range c.byNet {
		total += n
	}
	if total != len(c.entries) {
		t.Fatalf("net slots %d != live shapes %d", total, len(c.entries))
	}
	if e := newAuthCorpus(0).snapshot("", "", 0); e.Entries == nil {
		t.Fatal("entries must be [] not null")
	}
}

// letters spells n without digits or hex letters (both fold in a shape).
func letters(n int) string {
	out := ""
	for {
		out = string(rune('g'+n%20)) + out
		n /= 20
		if n == 0 {
			return out
		}
	}
}

func TestAuthNet(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4": "1.2.3.0/24", "2001:db8::1": "2001:db8::/64", "::ffff:1.2.3.4": "1.2.3.0/24", "junk": "junk",
	} {
		if got := authNet(in); got != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
}

func TestAuthCorpusBounds(t *testing.T) {
	c := newAuthCorpus(3)
	for i := 0; i < 5; i++ {
		c.add(authRec("1.1.1.1", "a.gr", "/login", 302, "LOGIN_POST;li=0;l=/p"+string(rune('a'+i))+";c="), "a.gr")
	}
	s := c.snapshot("", "", 0)
	if s.Shapes != 3 || s.Evicted != 2 || s.Dropped != 0 || s.Totals["LOGIN_POST"]["?"] != 5 {
		t.Fatalf("cap: shapes=%d evicted=%d dropped=%d totals=%v", s.Shapes, s.Evicted, s.Dropped, s.Totals)
	}
	c = newAuthCorpus(0)
	for i := 0; i < 100; i++ {
		ip := "10.0." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10))
		c.add(authRec(ip, ip+".gr", "/wp-login.php", 200, "WP_LOGIN;li=0;l=;c="), ip+".gr")
	}
	e := c.snapshot("", "", 0).Entries[0]
	if e.Count != 100 || e.IPs != authCorpusSetCap || e.Hosts != authCorpusSetCap || !e.Capped || len(e.Examples) != authCorpusHosts {
		t.Fatalf("set caps: %+v", e)
	}
	if got := len(c.snapshot("", "", 5000).Entries); got != 1 {
		t.Fatalf("limit clamp: %d", got)
	}
}

func TestAuthCorpusIngestAndAPI(t *testing.T) {
	e := NewEngine(Config{})
	rec, _ := parseSocketTSV(authBase + "\t0\tWP_LOGIN;li=0;l=/wp-login.php;c=")
	e.ingest(rec, "")
	other, _ := parseSocketTSV(strings.Replace(authBase, "/wp-login.php", "/", 1) + "\t0")
	e.ingest(other, "")
	s := e.authCorpus.snapshot("", "", 0)
	if len(s.Entries) != 1 || s.Entries[0].Examples[0] != "shop.gr" || s.Entries[0].Location != "/wp-login.php" {
		t.Fatalf("ingest: %+v", s)
	}

	// Admin-only.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/webdet/auth-corpus", nil)
	req = req.WithContext(scopedCtx("shop.gr"))
	w := httptest.NewRecorder()
	e.handleAuthCorpus(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("scoped caller: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/v1/webdet/auth-corpus?tag=WP_LOGIN", nil)
	e.handleAuthCorpus(w, req.WithContext(adminCtx()))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"webdet.auth_corpus.v1"`) || !strings.Contains(w.Body.String(), `"fail"`) {
		t.Fatalf("admin: %d %s", w.Code, w.Body.String())
	}
}
