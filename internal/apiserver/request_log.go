// internal/apiserver/request_log.go
//
// Request logging + panic recovery middleware for the cfm apiserver.
//
// Logs to cfm.api.log (via logging.LogfAPI):
//   - All requests with status >= 400
//   - Panics (logged as 500 with the panic value)
//
// Format:
//   2026-01-01 12:00:00 [apiserver] GET /api/v1/webdet/top-short 200 1.2ms ip=1.2.3.4
//   2026-01-01 12:00:00 [apiserver] PANIC GET /api/v1/foo: runtime error: ...

package apiserver

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"cfm/internal/logging"
)

// statusRecorder wraps http.ResponseWriter to capture the status code.
type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

// realIPFromRequest extracts the client IP for logging.
// Mirrors the middleware's isLoopbackDirect logic — if direct peer is loopback,
// trust X-Forwarded-For for the real client IP.
func realIPFromRequest(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return xff
		}
	}
	return host
}

// RequestLogMiddleware logs all requests with status >= 400 and recovers panics.
// Wire it as the outermost layer (after LoadAndSave, before serving).
func RequestLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ip := realIPFromRequest(r)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		// Panic recovery — log and return 500.
		defer func() {
			if p := recover(); p != nil {
				rec.status = http.StatusInternalServerError
				logging.LogfAPI("[apiserver] PANIC %s %s ip=%s: %v",
					r.Method, r.URL.RequestURI(), ip, p)
				if !rec.wrote {
					http.Error(w, `{"error":"internal server error"}`,
						http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(rec, r)

		elapsed := time.Since(start)
		ms := fmt.Sprintf("%.1fms", float64(elapsed.Microseconds())/1000.0)

		// Log errors and slow requests; skip noisy successful asset/static requests.
		path := r.URL.Path
		isAsset := len(path) > 8 && path[:8] == "/assets/"
		if rec.status >= 400 || (rec.status >= 500) {
			logging.LogfAPI("[apiserver] %s %s %d %s ip=%s",
				r.Method, r.URL.RequestURI(), rec.status, ms, ip)
		} else if !isAsset && logging.DebugEnabled() {
			// Full request log only in debug mode to avoid noise.
			logging.LogfAPI("[apiserver] %s %s %d %s ip=%s",
				r.Method, r.URL.RequestURI(), rec.status, ms, ip)
		}
	})
}
