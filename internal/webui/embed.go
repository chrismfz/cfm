// internal/webui/embed.go
//
// Embeds the cfm-admin static UI files into the binary.
// Files live in internal/webui/static/ (committed directly, no build step).
//
// Page routing (multi-page app, not SPA):
//   /                        → static/index.html          (dashboard)
//   /webdetector/            → static/webdetector/index.html
//   /webdetector/vhost/      → static/webdetector/vhost/index.html
//   /webdetector/forensics/  → static/webdetector/forensics/index.html
//   /webdetector/waf/        → static/webdetector/waf/index.html
//   /governor/               → static/governor/index.html
//   /assets/                → static/assets/  (JS, CSS)
//   unknown path             → static/index.html  (fallback)
//
// Prefix handling:
//   OpenResty proxy:  /cfm-admin/foo → OpenResty rewrites → /foo → Go serves.
//   Direct port 6061: /cfm-admin/foo → Go's /cfm-admin/ handler strips → /foo.

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

// Handler returns an http.Handler that serves the embedded multi-page UI.
// Register at "/" in the mux.
//
// fs.FS paths must NOT end with a slash (fs.ValidPath rule), so directory
// requests like "/webdetector/" must have the trailing slash stripped before
// the existence check. The original path (with slash) is passed to FileServer
// so it correctly serves the directory's index.html.
func Handler() http.Handler {
	static := FS()
	fileServer := http.FileServer(http.FS(static))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		// Strip leading slash. Empty = root request → serve via FileServer directly.
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath == "" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// fs.FS does not allow trailing slashes — strip before Open().
		// The original r.URL.Path (with slash) is passed to FileServer so
		// it can find and serve the directory's index.html correctly.
		lookupPath := strings.TrimRight(cleanPath, "/")

		f, err := static.Open(lookupPath)
		if err == nil {
			f.Close()
			// Path exists (file or directory) — FileServer handles it.
			// For directories it serves index.html; for files it serves directly.
			fileServer.ServeHTTP(w, r)
			return
		}

		// Path not found → fall back to root index.html.
		// Handles genuinely unknown paths gracefully.
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}
