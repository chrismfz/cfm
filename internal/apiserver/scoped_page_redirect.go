package apiserver

import (
	"io/fs"
	"net/http"
	"strings"

	webdet "cfm/internal/webdetector"
	"cfm/internal/webui"
)

// scopedLandingPage is where a scoped (cPanel) user lands: the page the
// cPanel plugin's embed bootstrap opens first.
const scopedLandingPage = "/cfm-admin/webdetector/controls/"

// scopedAdminOnlyPages are the cfm-admin pages a scoped user must not open:
// they show box-wide data, so every API call they make answers a scoped
// caller 403 "admin token required". The nav hides their links
// (ADMIN_ONLY_NAV_PATHS in assets/shared/controller-bootstrap.js, the list
// this one mirrors, pinned by TestScopedAdminOnlyPagesMatchNav), but a
// scoped page can still reach one: by a link, by typing the URL, or before
// the page has learnt it is scoped. A cPanel user did on qualityweb
// (2026-11-09, ticket 324850) and got a dashboard of empty cards asking for
// an admin token. Paths are relative to the /cfm-admin base, without the
// trailing slash; "/" is the dashboard.
var scopedAdminOnlyPages = map[string]struct{}{
	"/":                   {},
	"/health":             {},
	"/alerts":             {},
	"/mail":               {},
	"/firewall":           {},
	"/webdetector/bots":   {},
	"/webdetector/tokens": {},
	"/notifier":           {},
	"/detectors":          {},
	"/settings":           {},
	"/debug":              {},
}

// scopedAdminPageRedirect sends a scoped user who asks for an admin-only
// cfm-admin page to the scoped landing page instead (303). Only the page's
// HTML is redirected (GET/HEAD); assets and the API are untouched, and so is
// every admin request, whatever the route (hostname, port, proxy, WHM SSO):
// they carry the admin role, never the scoped one.
func scopedAdminPageRedirect(static fs.FS, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			webdet.IsScopedRequest(r) && isScopedAdminOnlyPage(static, r.URL.Path) {
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, scopedLandingPage, http.StatusSeeOther)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isScopedAdminOnlyPage reports whether path (relative to the /cfm-admin base,
// as webui.Handler sees it) serves an admin-only page's HTML. A path the
// embedded UI does not have also counts: webui.Handler answers it with the
// root index.html, which is the dashboard.
func isScopedAdminOnlyPage(static fs.FS, path string) bool {
	p := strings.TrimSuffix(path, "index.html")
	p = strings.TrimRight(p, "/")
	if p == "" {
		p = "/"
	}
	if strings.HasPrefix(p, "/assets/") || p == "/assets" {
		return false
	}
	// A file (has an extension in its last segment) is not a page.
	if last := p[strings.LastIndexByte(p, '/')+1:]; strings.Contains(last, ".") {
		return false
	}
	if _, ok := scopedAdminOnlyPages[p]; ok {
		return true
	}
	if static == nil {
		return false
	}
	if f, err := static.Open(strings.TrimPrefix(p, "/")); err == nil {
		_ = f.Close()
		return false
	}
	return true // unknown path → webui.Handler falls back to the dashboard
}

// webUIHandler is the embedded UI with the scoped admin-page redirect in front.
func webUIHandler() http.Handler {
	return scopedAdminPageRedirect(webui.FS(), webui.Handler())
}
