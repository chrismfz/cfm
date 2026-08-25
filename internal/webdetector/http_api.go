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
	"strings"
	"time"
)

// SharedAPIPrefixes is the canonical list of top-level /api/v1/<group>/
// prefixes the shared apiserver must proxy to the engine mux
// (internal/detectors/webdetector_register.go mounts exactly these behind
// webdetRoutesProxy). The engine's routes and this list MUST move together:
// a route under a prefix missing here is registered on the engine mux but
// unreachable through the shared apiserver — the request falls through to
// the webui catch-all and callers get the dashboard HTML instead of JSON
// (how the /api/v1/clam/ group shipped broken).
// TestRegisterHTTP_SharedPrefixCoverage enforces the pairing.
func SharedAPIPrefixes() []string {
	return []string{
		"/api/v1/webdet/",
		"/api/v1/challenge/",
		"/api/v1/waf/",
		"/api/v1/cpanel/",
		"/api/v1/http3/",
		"/api/v1/clam/",
	}
}

type apiRoute struct {
	path    string
	handler http.HandlerFunc
}

// apiRoutes is the single source of truth for the engine's HTTP surface —
// RegisterHTTP registers exactly this table, and the prefix-coverage test
// walks it. Add new endpoints here, never with a bare mux.HandleFunc.
func (e *Engine) apiRoutes() []apiRoute {
	return []apiRoute{
		{"/api/v1/webdet/top-short", e.handleTopShort},
		// aliases (compat)
		{"/api/v1/webdet/top", e.handleTopShort},
		{"/api/v1/webdet/suspicious", e.handleSuspicious},
		{"/api/v1/webdet/drilldown", e.handleDrilldown},
		{"/api/v1/webdet/hot-ips", e.handleHotIPs},
		{"/api/v1/webdet/long-top", e.handleLongTop},
		{"/api/v1/webdet/ip-short", e.handleIPShort},
		{"/api/v1/webdet/ip-drilldown", e.handleIPDrilldown},
		{"/api/v1/webdet/access-recent", e.handleAccessRecent},
		{"/api/v1/webdet/analyze-ip", e.handleAnalyzeIP},
		{"/api/v1/webdet/force-unblock-ip", e.handleForceUnblockIP},
		{"/api/v1/webdet/analyze-host", e.handleAnalyzeHost},
		{"/api/v1/webdet/host-access-history", e.handleHostAccessHistory},
		{"/api/v1/webdet/summary", e.handleWebdetSummary},
		{"/api/v1/webdet/ingest-source", e.handleIngestSource},
		{"/api/v1/webdet/vhosts", e.handleWebdetVhosts},
		{"/api/v1/webdet/rules", e.handleWebdetRulesList},
		{"/api/v1/webdet/rules/get", e.handleWebdetRulesGet},
		{"/api/v1/webdet/rules/add", e.handleWebdetRulesAdd},
		{"/api/v1/webdet/rules/update", e.handleWebdetRulesUpdate},
		{"/api/v1/webdet/rules/remove", e.handleWebdetRulesRemove},
		{"/api/v1/webdet/rules/simulate", e.handleWebdetRulesSimulate},

		// Bot-top control surface (box-wide, UA-keyed).
		{"/api/v1/webdet/ua-top", e.handleUATop},
		{"/api/v1/webdet/ua-drill", e.handleUADrill},
		{"/api/v1/webdet/ua-emergency", e.handleUAEmergency},

		// History API
		{"/api/v1/webdet/history/events", e.handleHistoryEvents},
		{"/api/v1/webdet/history/summary", e.handleHistorySummary},
		{"/api/v1/webdet/history/stats", e.handleHistoryStats},
		{"/api/v1/webdet/history/challenge-outcomes", e.handleHistoryChallengeOutcomes},
		{"/api/v1/webdet/history/waf-by-rule", e.handleHistoryWAFByRule},
		{"/api/v1/webdet/history/vhost-overview", e.handleHistoryVhostOverview},
		{"/api/v1/webdet/history/prune", e.handleHistoryPrune},
		{"/api/v1/webdet/history/truncate", e.handleHistoryTruncate},

		// Challenge JSON API
		{"/api/v1/challenge/summary", e.handleChallengeSummary},
		{"/api/v1/challenge/vhosts", e.handleChallengeVhosts},
		{"/api/v1/challenge/vhost", e.handleChallengeVhost}, // ?host=
		{"/api/v1/challenge/ips", e.handleChallengeIPs},
		{"/api/v1/challenge/ip", e.handleChallengeIP}, // ?ip=
		{"/api/v1/challenge/events", e.handleChallengeEvents},
		{"/api/v1/challenge/vhost/add", requirePOST(e.handleChallengeVhostAdd)},
		{"/api/v1/challenge/vhost/remove", requirePOST(e.handleChallengeVhostRemove)},
		{"/api/v1/challenge/vhost/status", e.handleChallengeVhostStatus},
		{"/api/v1/challenge/vhost/attack", requirePOST(e.handleChallengeVhostAttack)}, // ?host=&on=1|0 (under-attack override)
		{"/api/v1/challenge/exclude/list", e.handleChallengeExcludeList},
		{"/api/v1/challenge/exclude/add", requirePOST(e.handleChallengeExcludeAdd)},
		{"/api/v1/challenge/exclude/remove", requirePOST(e.handleChallengeExcludeRemove)},
		{"/api/v1/waf/exclude/list", e.handleWAFExcludeList},
		{"/api/v1/waf/exclude/add", requirePOST(e.handleWAFExcludeAdd)},
		{"/api/v1/waf/exclude/remove", requirePOST(e.handleWAFExcludeRemove)},
		{"/api/v1/clam/override/list", e.handleClamOverrideList},
		{"/api/v1/clam/override/add", requirePOST(e.handleClamOverrideAdd)},
		{"/api/v1/clam/override/remove", requirePOST(e.handleClamOverrideRemove)},
		{"/api/v1/clam/mode/list", e.handleClamModeList},
		{"/api/v1/clam/mode/add", requirePOST(e.handleClamModeAdd)},
		{"/api/v1/clam/mode/remove", requirePOST(e.handleClamModeRemove)},
		{"/api/v1/clam/sigignore/list", e.handleClamSigIgnoreList},
		{"/api/v1/clam/sigignore/add", requirePOST(e.handleClamSigIgnoreAdd)},
		{"/api/v1/clam/sigignore/remove", requirePOST(e.handleClamSigIgnoreRemove)},
		{"/api/v1/clam/health", e.handleClamHealth},
		{"/api/v1/http3/list", e.handleHTTP3List},
		{"/api/v1/http3/enable", e.handleHTTP3Enable},
		{"/api/v1/http3/disable", e.handleHTTP3Disable},
		{"/api/v1/waf/engine/summary", e.handleWAFEngineSummary},
		{"/api/v1/waf/rules", e.handleWAFRules},
		{"/api/v1/waf/hit-rates", e.handleWAFHitRates},
		{"/api/v1/cpanel/user-info", e.handleCpanelUserInfo},
	}
}

// RegisterHTTP wires all webdetector + challenge endpoints onto the provided mux.
func (e *Engine) RegisterHTTP(mux *http.ServeMux) {
	if mux == nil {
		return
	}
	for _, rt := range e.apiRoutes() {
		mux.HandleFunc(rt.path, rt.handler)
	}
}

// requirePOST wraps a state-changing handler so only POST reaches it. A non-POST
// request is rejected with 405 + Allow: POST before the handler parses params or
// touches state (authentication is still applied mux-wide by the apiserver
// first). Mutating control-plane endpoints must be POST so the session-CSRF
// boundary (which correctly treats GET/HEAD as safe) actually covers them — a GET
// mutator would change state outside that boundary. Applied in the apiRoutes table
// so the method policy lives with the route (audit R03). Read endpoints stay
// unwrapped.
//
// This is the canonical place to declare a mutator's method. A few older mutators
// keep a handler-local method check instead — force-unblock checks auth before
// method, and ua-emergency serves BOTH GET (list) and POST (mutate) — so hoisting
// them here would change their auth/response ordering; they are intentionally left
// as-is. New mutators should use requirePOST in the table.
func requirePOST(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		h(w, r)
	}
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
	if !RequireAdmin(w, r) {
		return
	}
	resp := webdetSummary{
		Now:            time.Now(),
		WindowSec:      e.cfg.Window.Seconds(),
		LongHorizonSec: e.cfg.LongHorizon().Seconds(),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (e *Engine) handleIngestSource(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
		return
	}
	writeJSON(w, http.StatusOK, e.IngestSourceState())
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
	if err := validateScopedVhostQuery(r, "vhosts"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "vhosts not in scope"})
		return
	}

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

	rows := decorateDCFracShort(decorateCostShort(decorateFacetShort(decorateShadowShort(decorateSolverFarmShort(applyShortFilter(e.TopShort(limit), parseVhostFilter(r)))))))

	resp := topShortResponse{
		WindowSec:      e.cfg.Window.Seconds(),
		LongHorizonSec: e.cfg.LongHorizon().Seconds(),
		Rows:           rows,
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleIPShort: επιστρέφει IPSignals από το short window με optional ?limit=
func (e *Engine) handleIPShort(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
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
	if err := validateScopedVhostQuery(r, "vhosts"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "vhosts not in scope"})
		return
	}

	limit := 50
	minScore := e.cfg.MinScore
	if minScore <= 0 {
		minScore = 0.50
	}
	rows := decorateDCFracSuspicious(decorateCostSuspicious(decorateFacetSuspicious(decorateShadowSuspicious(decorateSolverFarmSuspicious(applySuspiciousFilter(e.longwin.SuspiciousTop(limit, minScore), parseVhostFilter(r)))))))
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
	if err := validateScopedVhostQuery(r, "vhosts"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "vhosts not in scope"})
		return
	}

	// optional ?limit=N (default 50)
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	rows := decorateDCFracSuspicious(decorateCostSuspicious(decorateFacetSuspicious(decorateShadowSuspicious(decorateSolverFarmSuspicious(applySuspiciousFilter(e.longwin.SuspiciousTop(limit, 0), parseVhostFilter(r)))))))
	resp := longTopResponse{
		LongHorizonSec: e.cfg.LongHorizon().Seconds(),
		Rows:           rows,
	}
	writeJSON(w, http.StatusOK, resp)
}

// internal/webdetector/http_api.go
// Replace the handleDrilldown function with this version that honours ?top=N

func (e *Engine) handleDrilldown(w http.ResponseWriter, r *http.Request) {
	if err := validateScopedVhostQuery(r, "host"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

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
	now := time.Now()
	resp := map[string]interface{}{"short": d}
	if lr, ok := e.longwin.One(host); ok {
		resp["long"] = lr
	}
	// Under-Attack Mode (I1): carry the escalation state (and, when escalated,
	// the since) so the CLI drilldown and MCP host_drilldown surface it without a
	// second fetch. Single-sourced via deriveVhostState; normalizeHost keeps the
	// attack-tracker lookup in lock-step with how the state helper keys it.
	resp["state"] = e.deriveVhostStateForHost(host, now)
	if on, since, _ := e.VhostAttackState(normalizeHost(host)); on && !since.IsZero() {
		resp["attack_since"] = since
	}
	writeJSON(w, http.StatusOK, resp)
}

func (e *Engine) handleHotIPs(w http.ResponseWriter, r *http.Request) {
	if !RequireAdmin(w, r) {
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
	if !RequireAdmin(w, r) {
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
	if !RequireAdmin(w, r) {
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
	last, err := parseAnalyzeLast(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid last duration"})
		return
	}
	res, err := e.AnalyzeIPWithOptions(ip, AnalyzeOptions{MaxLines: maxLines, Last: last})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func parseAnalyzeLast(r *http.Request) (time.Duration, error) {
	v := strings.TrimSpace(r.URL.Query().Get("last"))
	if v == "" {
		return 0, nil
	}
	return time.ParseDuration(v)
}

// handleAnalyzeHost: offline log scan για ένα vhost.
func (e *Engine) handleAnalyzeHost(w http.ResponseWriter, r *http.Request) {
	if err := validateScopedVhostQuery(r, "host"); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "host not in scope"})
		return
	}

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
	last, err := parseAnalyzeLast(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid last duration"})
		return
	}
	res, err := e.AnalyzeHostWithOptions(host, AnalyzeOptions{MaxLines: maxLines, Last: last})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, res)
}
