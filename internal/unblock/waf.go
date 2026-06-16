// internal/unblock/waf.go
//
// WAFCleaner abstracts the OpenResty/Lua WAF enforcement planes so the unblock
// package can clear them during a "force unblock" without importing the
// webdetector package (which would create an import cycle: webdetector already
// imports unblock).
//
// Two implementations exist:
//
//   - The in-daemon *webdetector.NginxBridge satisfies this interface
//     directly. It clears the Go-side challenge/block state (ClearIP) and
//     calls the local nginx /cfm-admin/purge-ip endpoint to drop the per-IP
//     shared-dict caches. The daemon registers it via SetWAFCleaner at startup.
//
//   - HTTPWAFCleaner (below) is used by short-lived processes that are not the
//     daemon — notably the `cfm unblock` CLI — which reach the running daemon
//     over its admin HTTP API instead.
package unblock

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// WAFFinding describes one WAF plane that held state for the IP and was cleared.
type WAFFinding struct {
	// Plane is a short identifier: "challenge", "block", "throttle",
	// "decision_cache", "geo", "ok_touch", "wafpush".
	Plane string `json:"plane"`
	// Detail is human-readable context, e.g. the reason a challenge/block was
	// active ("403waf_flood") or a count ("2 bucket(s)").
	Detail string `json:"detail,omitempty"`
}

// WAFResult is the outcome of clearing the WAF planes for one IP.
type WAFResult struct {
	// Found is true when at least one plane held per-IP state (i.e. the IP
	// really was being enforced by the WAF layer, even if absent from every
	// blocklist). This is the "was it actually on a list, and why" signal.
	Found bool `json:"found"`
	// Cleared lists each plane that held state and was cleared.
	Cleared []WAFFinding `json:"cleared,omitempty"`
	// Err is non-empty when clearing failed (or partially failed); the planes
	// that did clear are still listed in Cleared.
	Err string `json:"err,omitempty"`
}

// Summary renders the findings as a compact one-liner for logs / step detail /
// Slack, e.g. "challenge (403waf_flood), throttle (2 bucket(s))".
func (r WAFResult) Summary() string {
	if len(r.Cleared) == 0 {
		if r.Err != "" {
			return "waf clear error: " + r.Err
		}
		return "no active WAF state"
	}
	parts := make([]string, 0, len(r.Cleared))
	for _, f := range r.Cleared {
		if f.Detail != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", f.Plane, f.Detail))
		} else {
			parts = append(parts, f.Plane)
		}
	}
	sort.Strings(parts)
	out := strings.Join(parts, ", ")
	if r.Err != "" {
		out += "; partial: " + r.Err
	}
	return out
}

// WAFCleaner clears the per-IP WAF enforcement planes for an IP.
type WAFCleaner interface {
	// ForceUnblock clears every per-IP WAF plane for ip and reports what was
	// found/cleared. It must be best-effort and must not panic; transport or
	// backend errors are returned in WAFResult.Err.
	ForceUnblock(ip string) WAFResult
}

// ── package-level registry ───────────────────────────────────────────────────
//
// A single process has exactly one relevant cleaner: the daemon registers its
// in-process bridge; the CLI registers an HTTP cleaner pointing at the daemon.
// Callers fetch it via WAFCleanerHook() and pass it as Options.WAF, keeping Do
// free of any direct webdetector dependency.

var _wafCleaner atomic.Value // stores WAFCleaner

// SetWAFCleaner registers the process-wide WAF cleaner. Safe for concurrent
// use; in practice called once during startup.
func SetWAFCleaner(c WAFCleaner) {
	if c == nil {
		return
	}
	_wafCleaner.Store(c)
}

// WAFCleanerHook returns the registered WAF cleaner, or nil when none is wired
// (e.g. DNAT mode with no OpenResty layer). A nil return means "skip the WAF
// plane", which Do handles gracefully.
func WAFCleanerHook() WAFCleaner {
	if v := _wafCleaner.Load(); v != nil {
		if c, ok := v.(WAFCleaner); ok {
			return c
		}
	}
	return nil
}

// ── HTTP cleaner (used by the CLI) ───────────────────────────────────────────

// HTTPWAFCleaner reaches a running cfm daemon over its admin HTTP API to force
// a per-IP WAF unblock. Used when there is no in-process bridge.
type HTTPWAFCleaner struct {
	baseURL string
	token   string
	hc      *http.Client
}

// NewHTTPWAFCleaner builds a cleaner targeting baseURL (e.g.
// "http://127.0.0.1:6060") with the given admin bearer token. Returns nil if
// baseURL is empty so callers can pass the result straight through.
func NewHTTPWAFCleaner(baseURL, token string) WAFCleaner {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	return &HTTPWAFCleaner{
		baseURL: baseURL,
		token:   strings.TrimSpace(token),
		hc:      &http.Client{Timeout: 5 * time.Second},
	}
}

// ForceUnblock POSTs to /api/v1/webdet/force-unblock-ip on the daemon.
func (c *HTTPWAFCleaner) ForceUnblock(ip string) WAFResult {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := c.baseURL + "/api/v1/webdet/force-unblock-ip?ip=" + url.QueryEscape(ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return WAFResult{Err: "build request: " + err.Error()}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return WAFResult{Err: "daemon unreachable: " + err.Error()}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return WAFResult{Err: fmt.Sprintf("daemon http %d", resp.StatusCode)}
	}

	var out WAFResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return WAFResult{Err: "decode response: " + err.Error()}
	}
	return out
}
