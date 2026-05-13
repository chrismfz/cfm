package dnat

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"cfm/internal/clihttp"
)

// _apiBase holds the base URL of the cfm apiserver (e.g.
// "http://127.0.0.1:6060"). The CLI status path uses it to fetch the
// daemon's in-memory transition/probe state. Empty when not set yet,
// in which case fetchDaemonState returns (nil, nil) — callers should
// treat that as "no daemon-side state available, render with what we
// have locally".
var _apiBase atomic.Value

// SetAPIBase records the apiserver base URL. Called by cmd/cfm/main.go
// once during dispatch.
func SetAPIBase(base string) {
	_apiBase.Store(strings.TrimRight(strings.TrimSpace(base), "/"))
}

func apiBase() string {
	if v := _apiBase.Load(); v != nil {
		return v.(string)
	}
	return ""
}

// daemonStateResponse mirrors the apiserver's dnatStateResponse JSON.
// Duplicated here to keep this package import-cycle-free.
type daemonStateResponse struct {
	Web    StateSnapshot `json:"web"`
	CPanel StateSnapshot `json:"cpanel"`
}

// fetchDaemonState GETs /api/v1/dnat/state from the local apiserver.
// Returns (snapshot, nil) on success, or (nil, err) on any failure
// (apiserver not running, auth missing, bad status). Failures here are
// non-fatal for the caller — status output falls back to the locally
// observable values.
func fetchDaemonState() (*daemonStateResponse, error) {
	base := apiBase()
	if base == "" {
		return nil, fmt.Errorf("apiserver base URL not configured")
	}
	// Bound the call: this runs inline during `cfm dnat status`, so a
	// stuck daemon must not hang the CLI. The endpoint is local and
	// trivially cheap, so 1.5s is generous.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/dnat/state", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := clihttp.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("apiserver dnat/state status %d", resp.StatusCode)
	}
	var out daemonStateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// daemonSnapshot returns the daemon's snapshot for the given scope, or a
// zero-valued StateSnapshot when the apiserver is unreachable. The
// caller renders the zero value as "(no daemon-side state)" rather than
// silently omitting the lines.
func daemonSnapshot(scope DNATScope) StateSnapshot {
	state, err := fetchDaemonState()
	if err != nil || state == nil {
		return StateSnapshot{Scope: string(scope)}
	}
	if scope == ScopeCPanel {
		return state.CPanel
	}
	return state.Web
}
