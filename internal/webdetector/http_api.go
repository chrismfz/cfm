// internal/webdetector/http_api.go
package webdetector

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
	"strconv"
	"cfm/internal/logging"
	"os"
	"context"

)

// ServeHTTPWithContext starts a small HTTP server for webdetector API.
// When ctx is canceled, the server is gracefully shut down.
func (e *Engine) ServeHTTPWithContext(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/webdet/top-short", e.handleTopShort)
	// aliases (compat)
	mux.HandleFunc("/api/v1/webdet/top", e.handleTopShort)
	mux.HandleFunc("/api/v1/webdet/suspicious", e.handleSuspicious)
	mux.HandleFunc("/api/v1/webdet/drilldown", e.handleDrilldown)
	mux.HandleFunc("/api/v1/webdet/hot-ips", e.handleHotIPs)
        mux.HandleFunc("/api/v1/webdet/long-top", e.handleLongTop)
        mux.HandleFunc("/api/v1/webdet/ip-short", e.handleIPShort)
        mux.HandleFunc("/api/v1/webdet/ip-drilldown", e.handleIPDrilldown)
	mux.HandleFunc("/api/v1/webdet/analyze-ip", e.handleAnalyzeIP)
	mux.HandleFunc("/api/v1/webdet/analyze-host", e.handleAnalyzeHost)

	// summary (new)
	mux.HandleFunc("/api/v1/webdet/summary", e.handleWebdetSummary)

    // Challenge JSON API
    mux.HandleFunc("/api/v1/challenge/summary", e.handleChallengeSummary)
    mux.HandleFunc("/api/v1/challenge/vhosts", e.handleChallengeVhosts)
    mux.HandleFunc("/api/v1/challenge/vhost",  e.handleChallengeVhost)  // ?host=
    mux.HandleFunc("/api/v1/challenge/ips",    e.handleChallengeIPs)
    mux.HandleFunc("/api/v1/challenge/ip",     e.handleChallengeIP)     // ?ip=
    mux.HandleFunc("/api/v1/challenge/events", e.handleChallengeEvents)
    mux.HandleFunc("/api/v1/challenge/vhost/add",    e.handleChallengeVhostAdd)
    mux.HandleFunc("/api/v1/challenge/vhost/remove", e.handleChallengeVhostRemove)
    mux.HandleFunc("/api/v1/challenge/vhost/status", e.handleChallengeVhostStatus)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

    // Shutdown on ctx cancel.
    go func() {
        <-ctx.Done()
        ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
        defer cancel()
        _ = srv.Shutdown(ctx2)
    }()


	// If addr looks like "unix:/path", listen on unix socket instead.
	if len(addr) > 5 && addr[:5] == "unix:" {
		path := addr[5:]
	        _ = os.Remove(path)
		l, err := net.Listen("unix", path)
		if err != nil {
			logging.Logf("[webdetector] HTTP listen (unix %s) failed: %v", path, err)
			return err
		}
        defer func() {
            _ = l.Close()
            _ = os.Remove(path)
        }()
		logging.Logf("[webdetector] HTTP API listening on unix:%s", path)
        if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
            logging.Logf("[webdetector] HTTP server error: %v", err)
            return err
        }
        return nil
	}

	logging.Logf("[webdetector] HTTP API listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Logf("[webdetector] HTTP server error: %v", err)
		return err
	}
    return nil
}

// ServeHTTP starts the webdetector API server without a cancelable context.
// Prefer ServeHTTPWithContext when running under a manager that supports reload.
func (e *Engine) ServeHTTP(addr string) {
    _ = e.ServeHTTPWithContext(context.Background(), addr)
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}


type webdetSummary struct {
	Now            time.Time `json:"now"`
	WindowSec      float64   `json:"window_sec"`
	LongHorizonSec float64   `json:"long_horizon_sec"`
}

func (e *Engine) handleWebdetSummary(w http.ResponseWriter, r *http.Request) {
	resp := webdetSummary{
		Now:            time.Now(),
		WindowSec:      e.cfg.Window.Seconds(),
		LongHorizonSec: e.cfg.LongHorizon().Seconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}



// topShortResponse τυλίγει τα rows μαζί με config-based μεταδεδομένα
// για να μπορεί το CLI να δείχνει short window + long horizon.
type topShortResponse struct {
    WindowSec      float64    `json:"window_sec"`
    LongHorizonSec float64    `json:"long_horizon_sec"`
    Rows           []ShortRow `json:"rows"`

}

// ipShortResponse: IP-level short window (δεν έχει long horizon ακόμη).

type ipShortResponse struct {
    WindowSec      float64     `json:"window_sec"`
    LongHorizonSec float64     `json:"long_horizon_sec"`
    Short          []IPSignals `json:"short"`
    Long           []IPSignals `json:"long,omitempty"`
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


// handleIPShort: επιστρέφει IPSignals από το short window με optional ?limit=
func (e *Engine) handleIPShort(w http.ResponseWriter, r *http.Request) {
    limit := 0
    if v := r.URL.Query().Get("limit"); v != "" {
        if n, err := strconv.Atoi(v); err == nil && n > 0 {
            limit = n
        }
    }

rowsShort := e.IPShort(limit)
rowsLong  := e.IPLong(limit)

resp := ipShortResponse{
    WindowSec:      e.cfg.Window.Seconds(),
    LongHorizonSec: e.cfg.LongHorizon().Seconds(),
    Short:          rowsShort,
    Long:           rowsLong,
}

    writeJSON(w, http.StatusOK, resp)
}



// handleDrilldown, handleSuspicious κτλ μένουν όπως ήταν.


func (e *Engine) handleSuspicious(w http.ResponseWriter, r *http.Request) {
	limit := 50
	minScore := e.cfg.MinScore
    if minScore <= 0 {
        minScore = 0.50
    }
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


// internal/webdetector/http_api.go
// Replace the handleDrilldown function with this version that honours ?top=N

func (e *Engine) handleDrilldown(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
		return
	}

	// ?top=N lets callers (e.g. the live dashboard) request more than the default 10
	topN := 10
	if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			topN = n
		}
	}

	d := e.HostDetail(host, topN)
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


// handleIPDrilldown: short-window drilldown per IP.
func (e *Engine) handleIPDrilldown(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    if ip == "" {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ip"})
        return
    }

    d := e.IPDetail(ip)
    writeJSON(w, http.StatusOK, d)
}

// handleAnalyzeIP: offline log scan για μία IP.
func (e *Engine) handleAnalyzeIP(w http.ResponseWriter, r *http.Request) {
    ip := r.URL.Query().Get("ip")
    if ip == "" {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ip"})
        return
    }

    // προαιρετικό ?max_lines=N (debug / safety)
    var maxLines int64
    if v := r.URL.Query().Get("max_lines"); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
            maxLines = n
        }
    }

    res, err := e.AnalyzeIP(ip, maxLines)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
        return
    }

    writeJSON(w, http.StatusOK, res)
}

// handleAnalyzeHost: offline log scan για ένα vhost.
func (e *Engine) handleAnalyzeHost(w http.ResponseWriter, r *http.Request) {
    host := r.URL.Query().Get("host")
    if host == "" {
        writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing host"})
        return
    }

    // προαιρετικό ?max_lines=N (debug / safety)
    var maxLines int64
    if v := r.URL.Query().Get("max_lines"); v != "" {
        if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
            maxLines = n
        }
    }

    res, err := e.AnalyzeHost(host, maxLines)
    if err != nil {
        writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
        return
    }

    writeJSON(w, http.StatusOK, res)
}
