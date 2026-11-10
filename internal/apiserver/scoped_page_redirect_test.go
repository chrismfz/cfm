package apiserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	webdet "cfm/internal/webdetector"
)

// The server-side list mirrors the nav's ADMIN_ONLY_NAV_PATHS. Read the JS
// list and compare, so the two can never drift (CLAUDE.md §5).
func TestScopedAdminOnlyPagesMatchNav(t *testing.T) {
	b, err := os.ReadFile("../webui/static/assets/shared/controller-bootstrap.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "const ADMIN_ONLY_NAV_PATHS = new Set([")
	if start < 0 {
		t.Fatal("ADMIN_ONLY_NAV_PATHS not found in controller-bootstrap.js")
	}
	end := strings.Index(src[start:], "]);")
	if end < 0 {
		t.Fatal("end of ADMIN_ONLY_NAV_PATHS not found")
	}
	var js []string
	for _, m := range regexp.MustCompile(`'(/cfm-admin[^']*)'`).FindAllStringSubmatch(src[start:start+end], -1) {
		p := strings.TrimPrefix(m[1], "/cfm-admin")
		if p == "" {
			p = "/"
		}
		js = append(js, p)
	}
	var goList []string
	for p := range scopedAdminOnlyPages {
		goList = append(goList, p)
	}
	sort.Strings(js)
	sort.Strings(goList)
	if strings.Join(js, " ") != strings.Join(goList, " ") {
		t.Fatalf("scopedAdminOnlyPages != ADMIN_ONLY_NAV_PATHS\n go: %v\n js: %v", goList, js)
	}
}

// uiChain is the request path a cfm-admin page load takes in the daemon: the
// token middleware, then the /cfm-admin/ prefix rewriter, then the embedded UI.
func uiChain(store *TokenStore) http.Handler {
	m := http.NewServeMux()
	m.Handle("/", webUIHandler())
	m.HandleFunc("/cfm-admin/", func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/cfm-admin")
		if r2.URL.Path == "" || r2.URL.Path[0] != '/' {
			r2.URL.Path = "/" + r2.URL.Path
		}
		m.ServeHTTP(w, r2)
	})
	return TokenMiddleware("admin-secret", store)(m)
}

func TestScopedUserRedirectedFromAdminOnlyPages(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	useTestEmbedAdminCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"trimel.gr", "www.trimel.gr"}, nil, nil, "viewer", "cpanel:trimel", time.Hour)
	h := uiChain(store)

	const ua = "Mozilla/5.0 (test)"
	scopedCookie := func(req *http.Request) {
		v, err := encodeEmbedCookie(req, st.ID, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: v})
	}
	adminSSOCookie := func(req *http.Request) {
		v, err := encodeEmbedAdminCookie(req, embedBootstrapNow().Add(embedAdminBootstrapTTL))
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: embedAdminCookieName, Value: v})
	}
	proxied := func(req *http.Request) { // edge topology: prefix stripped, base in a trusted header
		req.RemoteAddr = "127.0.0.1:50000"
		req.Header.Set("X-CFM-Base", "/cfm-admin")
	}

	for _, c := range []struct {
		name     string
		url      string
		auth     func(*http.Request)
		redirect bool
	}{
		// cPanel user (embed cookie): admin-only pages bounce to the landing page.
		{"scoped cookie, dashboard", "https://host/cfm-admin/", scopedCookie, true},
		{"scoped cookie, dashboard index.html", "https://host/cfm-admin/index.html", scopedCookie, true},
		{"scoped cookie, alerts", "https://host/cfm-admin/alerts/", scopedCookie, true},
		{"scoped cookie, web bots", "https://host/cfm-admin/webdetector/bots/", scopedCookie, true},
		{"scoped cookie, unknown path (served as dashboard)", "https://host/cfm-admin/nope/", scopedCookie, true},
		{"scoped cookie via edge, alerts", "https://host/alerts/", func(r *http.Request) { proxied(r); scopedCookie(r) }, true},
		{"scoped bearer, health", "https://host/cfm-admin/health/", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+st.Token) }, true},
		// ...and keep everything a scoped user is meant to see.
		{"scoped cookie, controls", "https://host/cfm-admin/webdetector/controls/", scopedCookie, false},
		{"scoped cookie, forensics", "https://host/cfm-admin/webdetector/forensics/", scopedCookie, false},
		{"scoped cookie, asset", "https://host/cfm-admin/assets/style.css", scopedCookie, false},
		{"scoped cookie, unknown API path", "https://host/cfm-admin/api/v1/no-such-endpoint", scopedCookie, false},
		// Admin, by every route: never redirected.
		{"admin bearer, dashboard", "https://host/cfm-admin/", func(r *http.Request) { r.Header.Set("Authorization", "Bearer admin-secret") }, false},
		{"admin bearer via edge, alerts", "https://host/alerts/", func(r *http.Request) { proxied(r); r.Header.Set("Authorization", "Bearer admin-secret") }, false},
		{"admin bearer, direct port, no prefix", "http://127.0.0.1:6060/", func(r *http.Request) { r.Header.Set("Authorization", "Bearer admin-secret") }, false},
		{"admin WHM SSO cookie, dashboard", "https://host/cfm-admin/", adminSSOCookie, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, c.url, nil)
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Accept", "text/html")
			c.auth(req)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if c.redirect {
				if rr.Code != http.StatusSeeOther || rr.Header().Get("Location") != scopedLandingPage {
					t.Fatalf("want 303 -> %s, got %d Location=%q", scopedLandingPage, rr.Code, rr.Header().Get("Location"))
				}
				return
			}
			if rr.Code == http.StatusSeeOther && rr.Header().Get("Location") == scopedLandingPage {
				t.Fatalf("redirected to the scoped landing page, must not be")
			}
			if rr.Code != http.StatusOK {
				t.Fatalf("want 200, got %d (Location=%q)", rr.Code, rr.Header().Get("Location"))
			}
		})
	}
}

// An admin who logged in normally can also carry a customer's scoped embed
// cookie: staff open the customer's cPanel (WHM "log in as user"), and the
// plugin sets it on the same host, for every port. The admin login must win,
// on the hostname and on the direct port, or the admin browses as that
// customer and is bounced off the dashboard. A cPanel iframe call (embedded)
// keeps its scoped identity.
func TestAdminSessionBeatsLingeringScopedEmbedCookie(t *testing.T) {
	useTestEmbedCookieSigningKey(t)
	store := NewTokenStore()
	st := store.Issue([]string{"trimel.gr"}, nil, nil, "viewer", "cpanel:trimel", time.Hour)
	old := sessionAllowedRequest
	sessionAllowedRequest = func(*http.Request) bool { return true }
	t.Cleanup(func() { sessionAllowedRequest = old })

	var role string
	m := http.NewServeMux()
	m.HandleFunc("/cfm-admin/api/v1/__role__", func(w http.ResponseWriter, r *http.Request) {
		role, _ = r.Context().Value(webdet.CtxRoleKey{}).(string)
	})
	probe := TokenMiddleware("admin-secret", store)(m)
	page := uiChain(store)

	for _, host := range []string{"https://node.example", "https://node.example:6061"} {
		withScoped := func(path string) *http.Request {
			req := httptest.NewRequest(http.MethodGet, host+path, nil)
			req.Header.Set("Accept", "text/html")
			v, err := encodeEmbedCookie(req, st.ID, time.Now().Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(&http.Cookie{Name: embedBootstrapCookieName, Value: v})
			return req
		}

		rr := httptest.NewRecorder()
		page.ServeHTTP(rr, withScoped("/cfm-admin/"))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: admin session + scoped cookie on the dashboard: want 200, got %d Location=%q",
				host, rr.Code, rr.Header().Get("Location"))
		}

		role = ""
		probe.ServeHTTP(httptest.NewRecorder(), withScoped("/cfm-admin/api/v1/__role__"))
		if role != webdet.CtxRoleAdmin {
			t.Fatalf("%s: admin session + scoped cookie: role=%q, want admin", host, role)
		}

		role = ""
		req := withScoped("/cfm-admin/api/v1/__role__")
		req.Header.Set("X-CFM-Embedded", "cpanel")
		probe.ServeHTTP(httptest.NewRecorder(), req)
		if role != webdet.CtxRoleScoped {
			t.Fatalf("%s: embedded request with both cookies: role=%q, want scoped", host, role)
		}
	}
}
