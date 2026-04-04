// internal/webui/embed.go
//
// Embeds the cfm-admin static UI files into the binary.
// Files live in internal/webui/static/ (committed directly, no build step).
//
// Serving strategy:
//   - Files that exist in the embedded FS are served directly.
//   - Directories trigger index.html lookup (e.g. /webdetector/ → webdetector/index.html).
//   - Unknown paths fall back to root index.html (SPA navigation).
//   - All responses use no-store (stable filenames, management UI — always fresh).
//
// Prefix handling:
//   The UI uses hardcoded /cfm-admin/... paths throughout.
//
//   OpenResty proxy:  /cfm-admin/foo → OpenResty rewrites → /foo → Go serves directly.
//   Direct port 6061: /cfm-admin/foo → Go's /cfm-admin/ handler strips → /foo → re-dispatch.

package webui

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"strings"
)

// Register MIME types explicitly — Go's FileServer relies on the OS MIME
// database which may map .js/.css to text/plain on minimal Linux installs,
// causing browsers to block them with nosniff.
func init() {
	mime.AddExtensionType(".js",    "application/javascript; charset=utf-8")
	mime.AddExtensionType(".mjs",   "application/javascript; charset=utf-8")
	mime.AddExtensionType(".css",   "text/css; charset=utf-8")
	mime.AddExtensionType(".html",  "text/html; charset=utf-8")
	mime.AddExtensionType(".json",  "application/json")
	mime.AddExtensionType(".svg",   "image/svg+xml")
	mime.AddExtensionType(".ico",   "image/x-icon")
	mime.AddExtensionType(".woff2", "font/woff2")
	mime.AddExtensionType(".woff",  "font/woff")
	mime.AddExtensionType(".ttf",   "font/ttf")
	mime.AddExtensionType(".png",   "image/png")
	mime.AddExtensionType(".webp",  "image/webp")
}

//go:embed all:static
var staticFS embed.FS

// FS returns the embedded static filesystem rooted at static/.
func FS() fs.FS {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic("webui: static/ not embedded — files must be in internal/webui/static/")
	}
	return sub
}

// Handler returns an http.Handler that serves the embedded SPA.
// Register at "/" in the mux.
func Handler() http.Handler {
	static := FS()
	fileServer := http.FileServer(http.FS(static))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")

		if cleanPath != "" {
			f, err := static.Open(cleanPath)
			if err == nil {
				_, statErr := f.Stat()
				f.Close()

				if statErr == nil {
					// File or directory exists — serve it directly.
					// FileServer handles directories by looking for index.html inside.
					w.Header().Set("Cache-Control", "no-store")
					fileServer.ServeHTTP(w, r)
					return
				}
			}
		}

		// Path not found → root index.html (SPA client-side routing).
		w.Header().Set("Cache-Control", "no-store")
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}
