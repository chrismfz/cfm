// internal/webdetector/http_api.go
package webdetector

import (
	"cfm/internal/logging"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
	"strings"
)

// RegisterHTTP wires all webdetector + challenge endpoints onto the provided mux.
func (e *Engine) RegisterHTTP(mux *http.ServeMux) {
	if mux == nil {
		return
	}

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
	mux.HandleFunc("/api/v1/webdet/summary", e.handleWebdetSummary)
	mux.HandleFunc("/api/v1/webdet/vhosts", e.handleWebdetVhosts)
	mux.HandleFunc("/api/v1/webdet/rules", e.handleWebdetRulesList)
	mux.HandleFunc("/api/v1/webdet/rules/get", e.handleWebdetRulesGet)
	mux.HandleFunc("/api/v1/webdet/rules/add", e.handleWebdetRulesAdd)
	mux.HandleFunc("/api/v1/webdet/rules/update", e.handleWebdetRulesUpdate)
	mux.HandleFunc("/api/v1/webdet/rules/remove", e.handleWebdetRulesRemove)
	mux.HandleFunc("/api/v1/webdet/rules/simulate", e.handleWebdetRulesSimulate)

	// History API
	mux.HandleFunc("/api/v1/webdet/history/events", e.handleHistoryEvents)
	mux.HandleFunc("/api/v1/webdet/history/summary", e.handleHistorySummary)
	mux.HandleFunc("/api/v1/webdet/history/stats", e.handleHistoryStats)
	mux.HandleFunc("/api/v1/webdet/history/challenge-outcomes", e.handleHistoryChallengeOutcomes)
	mux.HandleFunc("/api/v1/webdet/history/prune", e.handleHistoryPrune)
	mux.HandleFunc("/api/v1/webdet/history/truncate", e.handleHistoryTruncate)

	// Challenge JSON API
	mux.HandleFunc("/api/v1/challenge/summary", e.handleChallengeSummary)
	mux.HandleFunc("/api/v1/challenge/vhosts", e.handleChallengeVhosts)
	mux.HandleFunc("/api/v1/challenge/vhost", e.handleChallengeVhost) // ?host=
	mux.HandleFunc("/api/v1/challenge/ips", e.handleChallengeIPs)
	mux.HandleFunc("/api/v1/challenge/ip", e.handleChallengeIP) // ?ip=
	mux.HandleFunc("/api/v1/challenge/events", e.handleChallengeEvents)
	mux.HandleFunc("/api/v1/challenge/vhost/add", e.handleChallengeVhostAdd)
	mux.HandleFunc("/api/v1/challenge/vhost/remove", e.handleChallengeVhostRemove)
	mux.HandleFunc("/api/v1/challenge/vhost/status", e.handleChallengeVhostStatus)
	mux.HandleFunc("/api/v1/challenge/exclude/list", e.handleChallengeExcludeList)
	mux.HandleFunc("/api/v1/challenge/exclude/add", e.handleChallengeExcludeAdd)
	mux.HandleFunc("/api/v1/challenge/exclude/remove", e.handleChallengeExcludeRemove)
	mux.HandleFunc("/api/v1/waf/exclude/list", e.handleWAFExcludeList)
	mux.HandleFunc("/api/v1/waf/exclude/add", e.handleWAFExcludeAdd)
	mux.HandleFunc("/api/v1/waf/exclude/remove", e.handleWAFExcludeRemove)
	mux.HandleFunc("/api/v1/waf/engine/summary", e.handleWAFEngineSummary)
}

// ServeHTTPWithContext starts a small standalone HTTP server for webdetector API.
// Prefer RegisterHTTP when running under the shared apiserver.
func (e *Engine) ServeHTTPWithContext(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	e.RegisterHTTP(mux)

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
	// honour optional ?limit=N; keep backward compatibility with ?top=N
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	} else if v := r.URL.Query().Get("top"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	rows := applyShortFilter(e.TopShort(limit), parseVhostFilter(r))

	resp := topShortResponse{
		WindowSec:      e.cfg.Window.Seconds(),
		LongHorizonSec: e.cfg.LongHorizon().Seconds(),
		Rows:           rows,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleIPShort: επιστρέφει IPSignals από το short window με optional ?limit=
func (e *Engine) handleIPShort(w http.ResponseWriter, r *http.Request) {
	if vhostScopeFromContext(r.Context()) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	rowsShort := e.IPShort(limit)
	rowsLong := e.IPLong(limit)
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
	rows := applySuspiciousFilter(e.longwin.SuspiciousTop(limit, minScore), parseVhostFilter(r))
	writeJSON(w, http.StatusOK, rows)
}

// longTopResponse: scored long-window rows χωρίς minScore threshold.
type longTopResponse struct {
	LongHorizonSec float64         `json:"long_horizon_sec"`
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

	rows := applySuspiciousFilter(e.longwin.SuspiciousTop(limit, 0), parseVhostFilter(r))
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

	if !vhostAllowed(host, parseVhostFilter(r)) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
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
	if vhostScopeFromContext(r.Context()) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return
	}
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
	if vhostScopeFromContext(r.Context()) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return
	}
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
	if vhostScopeFromContext(r.Context()) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin token required"})
		return
	}
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing ip"})
		return
	}
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
	// Guard 2: scoped tokens may only analyze their own vhosts.
	if !vhostAllowed(strings.ToLower(host), vhostScopeFromContext(r.Context())) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}
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
