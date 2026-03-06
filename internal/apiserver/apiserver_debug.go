// internal/apiserver/apiserver_pprof.go
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

// registerPprofHandlers wires the standard pprof suite onto the given mux.
// Called only from RegisterPprof() in apiserver.go.
func registerPprofHandlers(m *http.ServeMux) {
	// Index also handles /debug/pprof/allocs, /debug/pprof/block, etc.
	// via its internal dispatch, so registering the root is sufficient —
	// but we also register the named endpoints explicitly so go tool pprof
	// can drive them directly with a URL.
	m.HandleFunc("/debug/pprof/", pprof.Index)
	m.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	m.HandleFunc("/debug/pprof/profile", pprof.Profile)
	m.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	m.HandleFunc("/debug/pprof/trace", pprof.Trace)
}
