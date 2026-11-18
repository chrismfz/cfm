package apiserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	webdet "cfm/internal/webdetector"
)

// prefixTestServer builds the :6060 shape that matters here: TokenMiddleware
// in front of a mux whose catch-all is the UI shell, with the real /cfm-admin/
// re-dispatcher and sentinel handlers on the API, pprof, login and MCP routes.
// The sentinels' bodies say which handler a request reached.
func prefixTestServer() http.Handler {
	m := http.NewServeMux()
	sentinel := func(name string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("reached:" + name))
		})
	}
	m.Handle("/", sentinel("shell"))
	m.Handle("/cfm-admin/", cfmAdminPrefixHandler(m))
	m.Handle("/api/v1/webdet/rules/export", sentinel("api"))
	m.Handle("/api/v1/webdet/", sentinel("api"))
	m.Handle("/debug/pprof/", sentinel("debug"))
	m.Handle("/debug/", sentinel("shell"))
	m.Handle("/login", sentinel("login"))
	m.Handle("/mcp", sentinel("mcp"))
	m.Handle("/search", sentinel("search"))
	m.Handle("/me/security/", sentinel("me"))
	return TokenMiddleware("secret", NewTokenStore())(m)
}

func iframeGet(target string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.Header.Set("Accept", "text/html,application/xhtml+xml")
	r.Header.Set("Sec-Fetch-Dest", "iframe")
	return r
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

// A token-less iframe page load must never reach a non-page handler, however
// many /cfm-admin prefixes the path carries.
func TestNestedCfmAdminPrefixNeverReachesNonPageHandlers(t *testing.T) {
	h := prefixTestServer()
	prefixes := []string{"", "/cfm-admin", "/cfm-admin/cfm-admin", "/cfm-admin/cfm-admin/cfm-admin"}
	targets := map[string]string{
		"/api/v1/webdet/rules/export": "api",
		"/api/v1/webdet/top":          "api",
		"/debug/pprof/":               "debug",
		"/mcp":                        "mcp",
		"/login":                      "login",
		"/search":                     "search",
		"/me/security/factors":        "me",
	}
	for _, pre := range prefixes {
		nested := strings.Count(pre, "/cfm-admin") >= 2
		for path, name := range targets {
			for _, withOrigin := range []bool{false, true} {
				target := pre + path
				if withOrigin {
					target += "?cfmExpectedOrigin=https%3A%2F%2Fexample.com%3A2083"
				}
				rec := serve(h, iframeGet(target))
				body := rec.Body.String()
				// /login and /mcp are public (the MCP surface authenticates
				// itself), so a single or no prefix legitimately reaches them.
				public := name == "login" || name == "mcp"
				if public && !nested {
					continue
				}
				if strings.Contains(body, "reached:"+name) {
					t.Fatalf("GET %s without credentials reached the %s handler (status %d)", target, name, rec.Code)
				}
				switch rec.Code {
				case http.StatusUnauthorized, http.StatusSeeOther, http.StatusNotFound:
				default:
					t.Fatalf("GET %s: status %d, want 401/303/404 (body %q)", target, rec.Code, body)
				}
			}
		}
	}
}

// Path forms a client controls (empty segments, dot segments, encoded slashes,
// case) must never carry an unauthenticated request to the API. A redirect to
// the clean path is fine: the follow-up request is checked afresh.
func TestCfmAdminPathTricksNeverReachAPIUnauthenticated(t *testing.T) {
	h := prefixTestServer()
	targets := []string{
		"//api/v1/webdet/rules/export",
		"/cfm-admin//api/v1/webdet/rules/export",
		"/cfm-admin/./api/v1/webdet/rules/export",
		"/cfm-admin/x/../api/v1/webdet/rules/export",
		"/cfm-admin/cfm-admin/../api/v1/webdet/rules/export",
		"/x/../api/v1/webdet/rules/export",
		"/login/../api/v1/webdet/rules/export",
		"/cfm-admin/login/../api/v1/webdet/rules/export",
		"/cfm-admin%2Fapi/v1/webdet/rules/export",
		"/cfm-admin/%2Fapi/v1/webdet/rules/export",
		"/cfm-admin/api%2Fv1/webdet/rules/export",
		"/cfm-admin/%2e/api/v1/webdet/rules/export",
		"/cfm-admin/%2e%2e/api/v1/webdet/rules/export",
		"/cfm-admin/cfm-admin%2Fapi/v1/webdet/rules/export",
		"/cfm-admin/cfm-admin/%2e%2e/cfm-admin/api/v1/webdet/rules/export",
		"/CFM-ADMIN/api/v1/webdet/rules/export",
		"/cfm-admin/API/v1/webdet/rules/export",
		"/cfm-admin/api/v1/webdet/rules/export/",
		"/cfm-admin/api/v1/webdet/rules/export/.",
		"/cfm-admin/assets/../api/v1/webdet/rules/export",
		// Public-path prefixes followed by dot segments.
		"/login/../api/v1/webdet/rules/export",
		"/mcp/../api/v1/webdet/rules/export",
		"/cfm-admin/mcp/../api/v1/webdet/rules/export",
		"/assets/x/../../api/v1/webdet/rules/export",
		"/.well-known/oauth-authorization-server/../../api/v1/webdet/rules/export",
		"/api/v1/embed/bootstrap/../../webdet/rules/export",
		"/cfm-admin/api/v1/embed/bootstrap/../../v1/webdet/rules/export",
	}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodConnect, http.MethodPost}
	for _, target := range targets {
		for _, method := range methods {
			r := iframeGet(target)
			r.Method = method
			rec := serve(h, r)
			if strings.Contains(rec.Body.String(), "reached:api") {
				t.Fatalf("%s %s without credentials reached the API handler (status %d)", method, target, rec.Code)
			}
		}
	}
}

// The legitimate cPanel iframe shell and normal page/API paths keep working.
func TestCfmAdminPrefixLegitimatePathsStillWork(t *testing.T) {
	h := prefixTestServer()

	for _, target := range []string{
		"/cfm-admin/",
		"/cfm-admin/webdetector/",
		"/cfm-admin/webdetector/rules/index.html",
		"/cfm-admin/debug/",
		"/cfm-admin/?cfmExpectedOrigin=https%3A%2F%2Fexample.com%3A2083",
		"/",
		"/webdetector/",
	} {
		rec := serve(h, iframeGet(target))
		if rec.Code != http.StatusOK || rec.Body.String() != "reached:shell" {
			t.Fatalf("iframe shell GET %s: status %d body %q, want the shell", target, rec.Code, rec.Body.String())
		}
	}

	// The exemption needs an iframe page load: a plain token-less browser
	// request is sent to the login page.
	r := httptest.NewRequest(http.MethodGet, "/cfm-admin/webdetector/", nil)
	r.Header.Set("Accept", "text/html")
	if rec := serve(h, r); rec.Code != http.StatusSeeOther {
		t.Fatalf("plain browser GET without credentials: status %d, want 303", rec.Code)
	}

	// Authenticated API calls, with and without the prefix.
	for _, target := range []string{"/cfm-admin/api/v1/webdet/rules/export", "/api/v1/webdet/rules/export"} {
		r := httptest.NewRequest(http.MethodGet, target, nil)
		r.Header.Set("Authorization", "Bearer secret")
		rec := serve(h, r)
		if rec.Code != http.StatusOK || rec.Body.String() != "reached:api" {
			t.Fatalf("authenticated GET %s: status %d body %q", target, rec.Code, rec.Body.String())
		}
	}

	// Login stays public through one prefix.
	if rec := serve(h, iframeGet("/cfm-admin/login")); rec.Body.String() != "reached:login" {
		t.Fatalf("GET /cfm-admin/login: status %d body %q", rec.Code, rec.Body.String())
	}

	// A nested prefix is refused even with valid credentials: no client sends it.
	r = httptest.NewRequest(http.MethodGet, "/cfm-admin/cfm-admin/api/v1/webdet/rules/export", nil)
	r.Header.Set("Authorization", "Bearer secret")
	if rec := serve(h, r); rec.Code != http.StatusNotFound {
		t.Fatalf("authenticated nested-prefix GET: status %d, want 404", rec.Code)
	}
}

func TestStripCfmAdminPrefixes(t *testing.T) {
	cases := map[string]string{
		"":                               "",
		"/":                              "/",
		"/cfm-admin":                     "/",
		"/cfm-admin/":                    "/",
		"/cfm-admin/api/v1/x":            "/api/v1/x",
		"/cfm-admin/cfm-admin/api/v1/x":  "/api/v1/x",
		"/cfm-admin/cfm-admin/cfm-admin": "/",
		"/cfm-adminx/api":                "/cfm-adminx/api",
		"/api/cfm-admin/x":               "/api/cfm-admin/x",
	}
	for in, want := range cases {
		if got := stripCfmAdminPrefixes(in); got != want {
			t.Errorf("stripCfmAdminPrefixes(%q) = %q, want %q", in, got, want)
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.URL.Path = in
		if got := authMiddlewarePath(r); got != want {
			t.Errorf("authMiddlewarePath(%q) = %q, want %q", in, got, want)
		}
	}
}

var registeredPatternRe = regexp.MustCompile(`\.(?:Handle|HandleFunc)\(\s*"((?:[A-Z]+ )?/[^"]*)"`)

// TestEmbedShellRefusesEveryRegisteredNonPageRoute keeps
// embedShellNonPageRoots in step with the routes the :6060 mux carries: every
// route this package (and the MCP mount) registers, and every prefix the web
// detector proxies onto it, must be refused by the token-less iframe
// exemption. Only the UI catch-all and the /cfm-admin/ re-dispatcher serve the
// shell.
func TestEmbedShellRefusesEveryRegisteredNonPageRoute(t *testing.T) {
	var patterns []string
	for _, dir := range []string{".", "../mcpserver"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range registeredPatternRe.FindAllStringSubmatch(string(src), -1) {
				p := m[1]
				if i := strings.IndexByte(p, ' '); i >= 0 {
					p = p[i+1:] // "GET /x" method patterns
				}
				patterns = append(patterns, p)
			}
		}
	}
	patterns = append(patterns, webdet.SharedAPIPrefixes()...)
	if len(patterns) < 50 {
		t.Fatalf("found only %d registered patterns; the source scan is broken", len(patterns))
	}
	for _, p := range patterns {
		if p == "/" || p == "/cfm-admin/" {
			continue
		}
		for _, pre := range []string{"", "/cfm-admin"} {
			path := pre + p
			if isEmbedShellPagePath(path) {
				t.Errorf("registered route %q (as %q) passes the token-less iframe exemption; add its first segment to embedShellNonPageRoots", p, path)
			}
		}
	}
}

// Public paths are exact: the routes themselves are public, a path beneath
// one of them is not.
func TestPublicPathsAreExact(t *testing.T) {
	pub := func(p string) bool {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.URL.Path = p
		return isPublicPath(r)
	}
	for _, p := range []string{
		"/login", "/login/verify", "/login/webauthn/begin", "/login/webauthn/finish", "/logout",
		"/api/v1/embed/bootstrap", "/api/v1/embed/admin-bootstrap",
		"/mcp", "/mcp/oauth/token", "/.well-known/openid-configuration",
		"/cfm-admin/login", "/cfm-admin/mcp",
	} {
		if !pub(p) {
			t.Errorf("%s: not public, want public", p)
		}
	}
	for _, p := range []string{
		"/login/x", "/logout/x", "/mcp/x", "/mcp/oauth", "/api/v1/embed/bootstrap/x",
		"/api/v1/embed/code", "/cfm-admin/mcp/x",
	} {
		if pub(p) {
			t.Errorf("%s: public, want auth required", p)
		}
	}
}
