// internal/apiserver/apiserver_debug.go
//
// This file exists solely to keep the blank import of net/http/pprof isolated.
// Its init() registers handlers on http.DefaultServeMux; we immediately
// re-register the same handlers on our own private mux so DefaultServeMux is
// never reachable from outside.
package apiserver

import (
	"net/http"
	"net/http/pprof" // side-effect: registers on DefaultServeMux (we ignore that)
)

// registerPprofHandlers wires the standard pprof suite onto the given mux, each
// behind adminOnlyHandler so only an admin-authenticated request reaches a
// profiler.
//
// Why the explicit gate: the shared mux-wide auth middleware (TokenMiddleware)
// authenticates BOTH admin tokens (role=admin) AND valid scoped, per-vhost
// cPanel/DA tokens (role=scoped) and passes both through. pprof exposes
// host-global process state — heap/goroutine dumps, the daemon command line,
// CPU/trace captures — that is meaningless and unsafe for a scoped tenant, so
// "valid token" is not enough; the handler must prove admin. Without this gate
// a scoped viewer token could pull a full heap dump of the daemon. This mirrors
// the pattern already used for /api/v1/debug/* (see RegisterDebugEndpoints) and
// /unblock, /search.
//
// Effective policy (anonymous/invalid rejected earlier by TokenMiddleware):
//
//	anonymous -> 401
//	invalid   -> 401
//	scoped    -> 403
//	admin     -> 200
//
// Called only from Start() in apiserver.go.
func registerPprofHandlers(m *http.ServeMux) {
	// Index also handles /debug/pprof/allocs, /debug/pprof/block, etc.
	// via its internal dispatch, so registering the root is sufficient —
	// but we also register the named endpoints explicitly so go tool pprof
	// can drive them directly with a URL.
	m.Handle("/debug/pprof/", adminOnlyHandler(http.HandlerFunc(pprof.Index)))
	m.Handle("/debug/pprof/cmdline", adminOnlyHandler(http.HandlerFunc(pprof.Cmdline)))
	m.Handle("/debug/pprof/profile", adminOnlyHandler(http.HandlerFunc(pprof.Profile)))
	m.Handle("/debug/pprof/symbol", adminOnlyHandler(http.HandlerFunc(pprof.Symbol)))
	m.Handle("/debug/pprof/trace", adminOnlyHandler(http.HandlerFunc(pprof.Trace)))
}
