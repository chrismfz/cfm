package webdetector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const authBase = "1000.5\t1.2.3.4\tShop.GR\tPOST\t/wp-login.php\tHTTP/1.1\t302\t0\t0.1\t0.1\t-\tMozilla/5.0\tcfm_apache"

func TestParseSocketTSVAuthColumn(t *testing.T) {
	rec, ok := parseSocketTSV(authBase + "\t0\tWP_LOGIN:ok;l=/wp-admin/;c=wordpress_logged_in_ab")
	if !ok || rec.Auth != "WP_LOGIN:ok;l=/wp-admin/;c=wordpress_logged_in_ab" || rec.Bypass || rec.UpstreamName != "cfm_apache" {
		t.Fatalf("15 columns: %+v ok=%v", rec, ok)
	}
	if rec.UA != "mozilla/5.0" {
		t.Fatalf("ua = %q", rec.UA)
	}
	// The bypass flag still reads with the 15th column after it.
	if rec, _ = parseSocketTSV(authBase + "\t1\tWP_LOGIN:fail;l=;c="); !rec.Bypass || rec.Auth == "" {
		t.Fatalf("bypass beside auth: %+v", rec)
	}
	// 14 columns (every non-login line, every older module): no Auth.
	if rec, _ = parseSocketTSV(authBase + "\t2"); !rec.Bypass || rec.Auth != "" {
		t.Fatalf("14 columns: %+v", rec)
	}
	// File tailers never read past column 11.
	if rec, _ = parseTSV(authBase + "\t0\tWP_LOGIN:ok;l=;c="); rec.Auth != "" {
		t.Fatalf("file TSV read an auth column: %+v", rec)
	}
	// A 16th TAB (cannot come from log-cfm, which cleans the field) stays inside Auth, capped.
	rec, _ = parseSocketTSV(authBase + "\t0\t" + strings.Repeat("x", 400))
	if len(rec.Auth) != maxAuthField {
		t.Fatalf("auth not capped: %d", len(rec.Auth))
	}
}

func TestParseAuthField(t *testing.T) {
	af, ok := parseAuthField("WP_LOGIN:na;l=/wp-login.php;c=a,b;a=lostpassword")
	if !ok || af.Tag != "WP_LOGIN" || af.Outcome != "na" || af.Loc != "/wp-login.php" ||
		len(af.Cookies) != 2 || af.Action != "lostpassword" {
		t.Fatalf("%+v %v", af, ok)
	}
	for _, bad := range []string{"", "-", "WP_LOGIN", ":ok", "WP_LOGIN:", "WP_LOGIN:maybe;l=", strings.Repeat("x", 300)} {
		if _, ok := parseAuthField(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if af, ok := parseAuthField("JOOMLA_ADMIN:?;c=;l="); !ok || af.Cookies != nil {
		t.Errorf("empty lists: %+v", af)
	}
}

func authRec(ip, host, uri string, status int, auth string) LogRec {
	return LogRec{TS: 1000, IP: ip, Host: host, Method: "post", URI: uri, Status: status, Auth: auth}
}

func TestAuthCorpusShapes(t *testing.T) {
	c := newAuthCorpus(0)
	// Two Joomla sites: md5 cookie names and per-site digits fold into one shape.
	c.add(authRec("1.1.1.1", "a.gr", "/administrator/index.php?task=login&option=com_login&x=1&return=aHR0cA", 303,
		"JOOMLA_ADMIN:?;l=/administrator/index.php;c=0123456789abcdef0123456789abcdef,joomla_user_state"), "a.gr")
	c.add(authRec("2.2.2.2", "b.gr", "/administrator/index.php?option=com_login&task=login", 303,
		"JOOMLA_ADMIN:?;l=/administrator/index.php;c=joomla_user_state,fedcba9876543210fedcba9876543210"), "b.gr")
	c.add(authRec("2.2.2.2", "b.gr", "/administrator/index.php?option=com_login&task=login#x", 303,
		"JOOMLA_ADMIN:?;l=/administrator/index.php;c=joomla_user_state,fedcba9876543210fedcba9876543210"), "b.gr")
	c.add(authRec("3.3.3.3", "c.gr", "/wp-login.php", 200, "WP_LOGIN:fail;l=;c="), "c.gr")
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

func TestAuthCorpusBounds(t *testing.T) {
	c := newAuthCorpus(3)
	for i := 0; i < 5; i++ {
		c.add(authRec("1.1.1.1", "a.gr", "/login", 302, "LOGIN_POST:?;l=/p"+string(rune('a'+i))+";c="), "a.gr")
	}
	s := c.snapshot("", "", 0)
	if s.Shapes != 3 || s.Dropped != 2 || s.Totals["LOGIN_POST"]["?"] != 5 {
		t.Fatalf("cap: shapes=%d dropped=%d totals=%v", s.Shapes, s.Dropped, s.Totals)
	}
	c = newAuthCorpus(0)
	for i := 0; i < 100; i++ {
		ip := "10.0." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10))
		c.add(authRec(ip, ip+".gr", "/wp-login.php", 200, "WP_LOGIN:fail;l=;c="), ip+".gr")
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
	rec, _ := parseSocketTSV(authBase + "\t0\tWP_LOGIN:fail;l=/wp-login.php;c=")
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
