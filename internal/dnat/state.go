package dnat

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"cfm/internal/logging"
)

// DNATScope distinguishes the web DNAT pipeline (`inet cfm_redirect`) from the
// cPanel one (`inet cfm_panel_redirect`). It exists so the persistence,
// health-probe and transition-log helpers in this file can be shared across
// both pipelines without leaking copy/paste.
type DNATScope string

const (
	ScopeWeb    DNATScope = "web"
	ScopeCPanel DNATScope = "cpanel"
)

// edgeHealthPath is the only localhost-only endpoint angie/openresty currently
// expose that is suitable for a Lua-aware readiness check. See
// configs/angie.conf and configs/openresty.conf (`location = /__ssl_debug`).
const edgeHealthPath = "/__ssl_debug"

var webDNATIntentPath = "/var/lib/cfm/dnat_enabled"

func intentPath(scope DNATScope) string {
	if scope == ScopeCPanel {
		return panelChallengeEnabledStatePath
	}
	return webDNATIntentPath
}

// IntentPath returns the on-disk path that records the operator's persisted
// DNAT intent for the given scope.
func IntentPath(scope DNATScope) string { return intentPath(scope) }

// PersistIntent writes the operator's ON/OFF intent for the given scope so it
// can survive reboots. The runtime nftables state remains the source of truth
// for "is DNAT live right now"; this file is the source of truth for "should
// DNAT be live". The web file is created 0o600 (root-only) since it controls
// boot behavior; the cpanel file path is shared with legacy code that uses
// 0o644 and is left unchanged here for compatibility.
func PersistIntent(scope DNATScope, enabled bool) error {
	p := intentPath(scope)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	v := "0\n"
	if enabled {
		v = "1\n"
	}
	mode := os.FileMode(0o600)
	if scope == ScopeCPanel {
		mode = 0o644
	}
	return os.WriteFile(p, []byte(v), mode)
}

// LoadIntent returns the persisted intent for the given scope. `present`
// is false when the file does not exist; callers should treat that as
// "no intent recorded yet" and default to OFF.
func LoadIntent(scope DNATScope) (enabled bool, present bool) {
	b, err := os.ReadFile(intentPath(scope))
	if err != nil {
		return false, false
	}
	v := strings.TrimSpace(strings.ToLower(string(b)))
	switch v {
	case "1", "true", "on", "forced":
		return true, true
	default:
		return false, true
	}
}

// LastTransition captures the most recent ON/OFF transition recorded by
// LogTransition. It is exposed so the `cfm dnat` and `cfm dnat cpanel`
// status commands can show what just happened without grepping logs.
type LastTransition struct {
	At     time.Time
	State  string // "ON" or "OFF"
	Action string // manual | startup | startup-timeout | failsafe-off | failsafe-recover
	Reason string
}

var (
	transitionMu sync.RWMutex
	transitions  = map[DNATScope]LastTransition{}
)

// GetLastTransition returns the most recent transition for the given scope.
func GetLastTransition(scope DNATScope) LastTransition {
	transitionMu.RLock()
	defer transitionMu.RUnlock()
	return transitions[scope]
}

// LogTransition records a single state-change line with a discoverable tag.
// Every DNAT state change — manual CLI, startup restore, failsafe off,
// failsafe recover — flows through this helper so a single
// `grep dnat /var/log/cfm/*` reconstructs the full timeline.
func LogTransition(scope DNATScope, state, action, reason string) {
	transitionMu.Lock()
	transitions[scope] = LastTransition{
		At:     time.Now().UTC(),
		State:  state,
		Action: action,
		Reason: reason,
	}
	transitionMu.Unlock()
	if reason == "" {
		logging.Logf("[dnat] scope=%s state=%s action=%s", scope, state, action)
		return
	}
	logging.Logf("[dnat] scope=%s state=%s action=%s reason=%q", scope, state, action, reason)
}

// ProbeResult captures the outcome of the most recent edge-health probe.
type ProbeResult struct {
	At     time.Time
	OK     bool
	Reason string
}

var (
	probeMu     sync.RWMutex
	lastProbes  = map[DNATScope]ProbeResult{}
	probeClient = newProbeHTTPClient()
)

// GetLastProbe returns the most recent probe outcome for the given scope.
func GetLastProbe(scope DNATScope) ProbeResult {
	probeMu.RLock()
	defer probeMu.RUnlock()
	return lastProbes[scope]
}

func recordProbe(scope DNATScope, ok bool, reason string) {
	probeMu.Lock()
	lastProbes[scope] = ProbeResult{At: time.Now().UTC(), OK: ok, Reason: reason}
	probeMu.Unlock()
}

func newProbeHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives:   true,
			DialContext:         (&net.Dialer{Timeout: 300 * time.Millisecond}).DialContext,
			TLSHandshakeTimeout: 800 * time.Millisecond,
		},
		Timeout: 1500 * time.Millisecond,
	}
}

// EdgePort describes one local edge listener to probe.
type EdgePort struct {
	Port    int
	TLS     bool
	Healthz bool // when true, /__ssl_debug is GET-tested on this port in addition to TCP-dial.
}

// WebEdgePorts returns the two edge proxy listener ports that web DNAT
// redirects to: 9080 (HTTP) and 9043 (HTTPS). Both serve /__ssl_debug.
func WebEdgePorts() []EdgePort {
	return []EdgePort{
		{Port: getenvInt("HTTP_PORT", 9080), TLS: false, Healthz: true},
		{Port: getenvInt("HTTPS_PORT", 9043), TLS: true, Healthz: true},
	}
}

// CPanelEdgePorts returns the panel listener ports plus a healthz-probe on the
// canonical /__ssl_debug endpoint. The panel listener configs do not expose
// /__ssl_debug themselves, but they share the same Lua subsystem as the main
// 9080/9043 server — if Lua is broken, the panel paths are broken too. So
// each panel port is TCP-dialed and the canonical health endpoint is
// additionally hit once via 9080/9043.
func CPanelEdgePorts() []EdgePort {
	out := make([]EdgePort, 0, len(panelProbePorts)+2)
	for _, p := range panelProbePorts {
		out = append(out, EdgePort{Port: p, TLS: false, Healthz: false})
	}
	out = append(out,
		EdgePort{Port: getenvInt("HTTP_PORT", 9080), TLS: false, Healthz: true},
		EdgePort{Port: getenvInt("HTTPS_PORT", 9043), TLS: true, Healthz: true},
	)
	return out
}

// probeEdgeHealthy returns ok=true only when every listed port accepts a TCP
// connection AND every port marked Healthz returns HTTP 200 for
// /__ssl_debug. On failure it returns a single human-readable reason
// describing the first failing step (e.g. `tcp:127.0.0.1:9043 err=...`,
// `https:9043 status=502`). The result is also stashed for status output.
//
// This works identically for angie and openresty since both expose
// /__ssl_debug on 127.0.0.1:9080 and :9043.
func probeEdgeHealthy(ctx context.Context, scope DNATScope, ports []EdgePort) (ok bool, reason string) {
	if len(ports) == 0 {
		recordProbe(scope, true, "")
		return true, ""
	}
	dialer := net.Dialer{Timeout: 300 * time.Millisecond}
	for _, p := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", p.Port)
		c, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			r := fmt.Sprintf("tcp:%s err=%v", addr, err)
			recordProbe(scope, false, r)
			return false, r
		}
		_ = c.Close()
	}
	for _, p := range ports {
		if !p.Healthz {
			continue
		}
		scheme := "http"
		if p.TLS {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://127.0.0.1:%d%s", scheme, p.Port, edgeHealthPath)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			r := fmt.Sprintf("%s:%d req-build err=%v", scheme, p.Port, err)
			recordProbe(scope, false, r)
			return false, r
		}
		resp, err := probeClient.Do(req)
		if err != nil {
			r := fmt.Sprintf("%s:%d err=%v", scheme, p.Port, err)
			recordProbe(scope, false, r)
			return false, r
		}
		_, _ = io.CopyN(io.Discard, resp.Body, 256)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			r := fmt.Sprintf("%s:%d status=%d", scheme, p.Port, resp.StatusCode)
			recordProbe(scope, false, r)
			return false, r
		}
	}
	recordProbe(scope, true, "")
	return true, ""
}
