// internal/webdetector/http_api.go
package webdetector

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
	"strconv"
	"cfm/internal/logging"
)

// ServeHTTP starts a small HTTP server for webdetector API.
// It should be called from the detector register (in a goroutine).
func (e *Engine) ServeHTTP(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/webdet/top-short", e.handleTopShort)
	mux.HandleFunc("/api/v1/webdet/suspicious", e.handleSuspicious)
	mux.HandleFunc("/api/v1/webdet/drilldown", e.handleDrilldown)
	mux.HandleFunc("/api/v1/webdet/hot-ips", e.handleHotIPs)
        mux.HandleFunc("/api/v1/webdet/long-top", e.handleLongTop)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	// If addr looks like "unix:/path", listen on unix socket instead.
	if len(addr) > 5 && addr[:5] == "unix:" {
		path := addr[5:]
		l, err := net.Listen("unix", path)
		if err != nil {
			logging.Logf("[webdetector] HTTP listen (unix %s) failed: %v", path, err)
			return
		}
		logging.Logf("[webdetector] HTTP API listening on unix:%s", path)
		_ = srv.Serve(l)
		return
	}

	logging.Logf("[webdetector] HTTP API listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Logf("[webdetector] HTTP server error: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// topShortResponse τυλίγει τα rows μαζί με config-based μεταδεδομένα
// για να μπορεί το CLI να δείχνει short window + long horizon.
type topShortResponse struct {
    WindowSec      float64    `json:"window_sec"`
    LongHorizonSec float64    `json:"long_horizon_sec"`
    Rows           []ShortRow `json:"rows"`

}


func (e *Engine) handleTopShort(w http.ResponseWriter, r *http.Request) {
    rows := e.TopShort(0)

    resp := topShortResponse{
        WindowSec:      e.cfg.Window.Seconds(),
        LongHorizonSec: e.cfg.LongHorizon().Seconds(),
        Rows:           rows,
    }



    writeJSON(w, http.StatusOK, resp)
}



// handleDrilldown, handleSuspicious κτλ μένουν όπως ήταν.


func (e *Engine) handleSuspicious(w http.ResponseWriter, r *http.Request) {
	limit := 50
	minScore := e.cfg.MinScore
	rows := e.longwin.SuspiciousTop(limit, minScore)
	writeJSON(w, http.StatusOK, rows)
}

// longTopResponse: scored long-window rows χωρίς minScore threshold.
type longTopResponse struct {
        LongHorizonSec float64        `json:"long_horizon_sec"`
        Rows           []SuspiciousRow `json:"rows"`
}

// handleLongTop επιστρέφει ΟΛΑ τα hosts από το long window, scored,
// ταξινομημένα by score desc, χωρίς minScore filter.
func (e *Engine) handleLongTop(w http.ResponseWriter, r *http.Request) {
        // optional ?limit=N (default 50)
        limit := 50
        if v := r.URL.Query().Get("limit"); v != "" {
                if n, err := strconv.Atoi(v); err == nil && n > 0 {
                        limit = n
                }
        }

        rows := e.longwin.SuspiciousTop(limit, 0) // minScore=0 → όλα με score

        resp := longTopResponse{
                LongHorizonSec: e.cfg.LongHorizon().Seconds(),
                Rows:           rows,
        }
        writeJSON(w, http.StatusOK, resp)
}


func (e *Engine) handleDrilldown(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}
	d := e.HostDetail(host, 10)
	// Attach long-window summary as a nested field for convenience.
	if lr, ok := e.longwin.One(host); ok {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"short": d,
			"long":  lr,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"short": d,
	})
}





func (e *Engine) handleHotIPs(w http.ResponseWriter, r *http.Request) {
    // προαιρετικό ?limit=N
    limit := 20
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        }
    }

    rows := e.HotIPs(limit)
    writeJSON(w, http.StatusOK, rows)
}
