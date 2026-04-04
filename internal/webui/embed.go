// internal/webui/embed.go
//
// Embeds the cfm-admin static UI files into the binary.
//
// Files are copied into internal/webui/static/ by `make ui` before build:
//   make ui && make build
//
// Serving strategy:
//   - Files that exist in the embedded FS are served directly.
//   - Assets under /assets/ get long-lived cache headers (filenames are stable).
//   - Everything else falls back to index.html (SPA navigation via HTML5 history).
//
// Prefix handling:
//   The UI uses hardcoded /cfm-admin/... paths throughout (API calls, navigation,
//   asset references). Two scenarios work without any JS/HTML changes:
//
//   OpenResty proxy (/cfm-admin/ → Go /):
//     OpenResty rewrites /cfm-admin/foo → /foo before forwarding. Go just serves /foo.
//
//   Direct port (:6061 → /cfm-admin/...):
//     Go's /cfm-admin/ handler strips the prefix and re-dispatches on the same mux.
//     /cfm-admin/api/v1/... → strips → /api/v1/... → API handler ✓
//     /cfm-admin/assets/app.js → strips → /assets/app.js → this handler ✓
//     /cfm-admin/login → strips → /login → login handler ✓

package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:static
var staticFS embed.FS

// FS returns the embedded static filesystem rooted at static/.
func FS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("webui: static/ not embedded — run `make ui` before `make build`")
	}
	return sub
}

// Handler returns an http.Handler that serves the embedded SPA.
// Register at "/" in the mux.
func Handler() http.Handler {
	static := FS()
	fileServer := http.FileServer(http.FS(static))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check whether the requested file actually exists.
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath != "" {
			if f, err := static.Open(cleanPath); err == nil {
				f.Close()
				// Vite/static assets with stable names → cache forever.
				if strings.HasPrefix(r.URL.Path, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				} else {
					w.Header().Set("Cache-Control", "no-store")
				}
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		// File not found → serve index.html for SPA client-side routing.
		w.Header().Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}
