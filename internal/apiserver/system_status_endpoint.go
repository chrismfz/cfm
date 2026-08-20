package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/cfmlog"
	"cfm/internal/cputhrottle"
	"cfm/internal/edgelog"
	"cfm/internal/firewall"
	"cfm/internal/firewall/selfip"
	"cfm/internal/healthmodel"
	"cfm/internal/healthstore"
	"cfm/internal/kmsg"
	"cfm/internal/lvecpu"
	"cfm/internal/maildns"
	"cfm/internal/maillog"
	"cfm/internal/mailmeter"
	"cfm/internal/mailqueue"
	"cfm/internal/mailruntime"
	"cfm/internal/mailtraffic"
	"cfm/internal/mysqllog"
	"cfm/internal/netstat"
	"cfm/internal/panelfp"
	"cfm/internal/procstat"
	"cfm/internal/svcstat"
	webdet "cfm/internal/webdetector"
)

type cmdCacheEntry struct {
	mu         sync.Mutex
	output     []byte
	durationMS int64
	expiresAt  time.Time
}

var cmdCache sync.Map

var runCachedCommandFn = runCachedCommand

const (
	healthSnapshotSchemaV1   = "health.snapshot.v1"
	healthTimeseriesSchemaV1 = "health.timeseries.v1"
	healthAnomaliesSchemaV1  = "health.anomalies.v1"
)

type healthTimeseriesResponse struct {
	SchemaVersion string                    `json:"schema_version"`
	NodeID        string                    `json:"node_id"`
	GeneratedAt   time.Time                 `json:"generated_at"`
	Window        string                    `json:"window"`
	Step          string                    `json:"step"`
	Points        []healthTimeseriesPointV1 `json:"points"`
}

type healthTimeseriesPointV1 struct {
	CollectedAt time.Time `json:"collected_at"`
	Load1       float64   `json:"load1"`
	CPUPct      float64   `json:"cpu_pct"`
	RamUsedPct  float64   `json:"ram_used_pct"`
	SwapUsedPct float64   `json:"swap_used_pct"`
	DiskRootPct float64   `json:"disk_root_pct"`
	DiskTmpPct  float64   `json:"disk_tmp_pct"`
	TempMaxC    float64   `json:"temp_max_c"`
	RxMbps      float64   `json:"rx_mbps"`
	TxMbps      float64   `json:"tx_mbps"`
	SampleCount int       `json:"sample_count"`
}

type healthAnomalyV1 struct {
	When      time.Time `json:"when"`
	Source    string    `json:"source"`
	Reason    string    `json:"reason"`
	Signal    string    `json:"signal"`
	Scope     string    `json:"scope"`
	Count     int       `json:"count"`
	SrcIP     string    `json:"src_ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	UserAgent string    `json:"user_agent"`
}

type healthAnomaliesResponse struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Since         time.Time         `json:"since"`
	Count         int               `json:"count"`
	Anomalies     []healthAnomalyV1 `json:"anomalies"`
}

type healthIngestRequest struct {
	NodeID string             `json:"node_id"`
	Sample healthstore.Sample `json:"sample"`
}

// healthSnapshotCache backs the opt-in `?cache_ttl=` mode of
// /api/v1/health/snapshot. Collection takes ~1-2s (smartctl, systemd,
// listener/socket probes), so the dashboard asks for a cached snapshot
// instead of recollecting on every poll: a fresh-enough snapshot is served
// as-is, a stale one is served immediately while a single background
// refresh recollects (stale-while-revalidate), and only a cold cache
// collects synchronously.
type healthSnapshotCache struct {
	mu         sync.Mutex
	snap       *healthmodel.HealthSnapshotV1
	fetchedAt  time.Time
	refreshing bool
}

var (
	healthSnapCache         = &healthSnapshotCache{}
	collectHealthSnapshotFn = healthmodel.CollectSnapshotNow
)

func (c *healthSnapshotCache) get(nodeID string, backend firewall.Backend, ttl time.Duration) healthmodel.HealthSnapshotV1 {
	if ttl <= 0 {
		return collectHealthSnapshotFn(nodeID, backend)
	}
	c.mu.Lock()
	if c.snap != nil {
		snap := *c.snap
		if time.Since(c.fetchedAt) >= ttl && !c.refreshing {
			c.refreshing = true
			go func() {
				fresh := collectHealthSnapshotFn(nodeID, backend)
				c.mu.Lock()
				c.snap, c.fetchedAt, c.refreshing = &fresh, time.Now(), false
				c.mu.Unlock()
			}()
		}
		c.mu.Unlock()
		return snap
	}
	c.mu.Unlock()
	// Cold cache: collect synchronously. Concurrent cold requests may each
	// collect once (rare — first dashboard load only); last write wins.
	fresh := collectHealthSnapshotFn(nodeID, backend)
	c.mu.Lock()
	c.snap, c.fetchedAt = &fresh, time.Now()
	c.mu.Unlock()
	return fresh
}

type healthAnomalyStore struct {
	mu      sync.RWMutex
	cap     int
	events  []healthAnomalyV1
	nextIdx int
	count   int
}

func newHealthAnomalyStore(capacity int) *healthAnomalyStore {
	if capacity <= 0 {
		capacity = 1000
	}
	return &healthAnomalyStore{cap: capacity, events: make([]healthAnomalyV1, capacity)}
}

func (s *healthAnomalyStore) append(ev healthAnomalyV1) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[s.nextIdx] = ev
	s.nextIdx = (s.nextIdx + 1) % s.cap
	if s.count < s.cap {
		s.count++
	}
}

func (s *healthAnomalyStore) since(since time.Time) []healthAnomalyV1 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.count == 0 {
		return nil
	}
	out := make([]healthAnomalyV1, 0, s.count)
	start := s.nextIdx - s.count
	if start < 0 {
		start += s.cap
	}
	for i := 0; i < s.count; i++ {
		idx := (start + i) % s.cap
		ev := s.events[idx]
		if !since.IsZero() && ev.When.Before(since) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

var (
	healthAnomalies      = newHealthAnomalyStore(1000)
	healthAnomalySubOnce sync.Once
)

// RegisterSystemStatus wires read-only system/status style helpers for web UI.
func RegisterSystemStatus(m *http.ServeMux, backend firewall.Backend) {
	if m == nil {
		return
	}
	healthAnomalySubOnce.Do(func() {
		SubscribeAPIAnomalyEvents(func(ev APIAnomalyEvent) {
			healthAnomalies.append(healthAnomalyV1{
				When:      ev.When.UTC(),
				Source:    ev.Source,
				Reason:    ev.Reason,
				Signal:    ev.Signal,
				Scope:     ev.Scope,
				Count:     ev.Count,
				SrcIP:     ev.SrcIP,
				Method:    ev.Method,
				Path:      ev.Path,
				Status:    ev.Status,
				UserAgent: ev.UserAgent,
			})
		})
	})

	m.HandleFunc("/api/v1/system/processes", handleSystemProcesses)
	m.HandleFunc("/api/v1/system/listeners", handleSystemListeners)
	m.HandleFunc("/api/v1/system/dmesg", handleSystemDmesg)
	m.HandleFunc("/api/v1/system/services", handleSystemServices)
	m.HandleFunc("/api/v1/system/ip-forensics", handleSystemIPForensics)
	m.HandleFunc("/api/v1/system/edge-error-log", handleSystemEdgeErrorLog)
	m.HandleFunc("/api/v1/system/waf-fp-hunt", handleSystemWAFFPHunt)
	m.HandleFunc("/api/v1/system/lve-cpu", handleSystemLVECPU)
	m.HandleFunc("/api/v1/system/cpu-throttle", handleSystemCPUThrottle)
	m.HandleFunc("/api/v1/system/mysql-log", handleSystemMySQLLog)
	m.HandleFunc("/api/v1/system/cfm-log", handleSystemCFMLog)
	m.HandleFunc("/api/v1/system/journal", handleSystemJournal)
	m.HandleFunc("/api/v1/system/mail-log", handleSystemMailLog)
	m.HandleFunc("/api/v1/system/mail-queue", handleSystemMailQueue)
	m.HandleFunc("/api/v1/mail/traffic", handleMailTraffic)
	m.HandleFunc("/api/v1/mail/dns", handleMailDNS)
	m.HandleFunc("/api/v1/mail/runtime", handleMailRuntime)
	m.HandleFunc("/api/v1/system/dnat", handleSystemDNAT)
	m.HandleFunc("/api/v1/system/ssl/stats", handleSystemSSLStats)
	m.HandleFunc("/api/v1/system/ssl/refresh", handleSystemSSLRefresh)
	m.HandleFunc("/api/v1/health/snapshot", handleHealthSnapshot(backend))
	m.HandleFunc("/api/v1/health/timeseries", handleHealthTimeseries)
	m.HandleFunc("/api/v1/health/anomalies", handleHealthAnomalies)
	m.HandleFunc("/api/v1/health/ingest", handleHealthIngest)
}

func requireHealthAccess(w http.ResponseWriter, r *http.Request) bool {
	if webdet.RequireAdmin(w, r) {
		return true
	}
	// Hook: add scoped health authorization rules here when product requirements
	// permit non-admin access to selected health slices.
	return false
}

// handleSystemProcesses serves the historical top-like process snapshot plus
// optional filtered inspection (GET /api/v1/system/processes?top=N&match=COMM&
// pid=PID&details=1). With no new options it preserves the original behaviour:
// all processes are ranked by CPU, then RSS, and truncated to top. PPID is an
// additive base field. `details=1` opts into direct child PIDs and bounded,
// best-effort sanitized argv; raw /proc/<pid>/cmdline is never returned.
func handleSystemProcesses(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	top := 15
	if v := strings.TrimSpace(r.URL.Query().Get("top")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	match := strings.TrimSpace(r.URL.Query().Get("match"))
	pid := 0
	if v := strings.TrimSpace(r.URL.Query().Get("pid")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "pid must be a positive integer"})
			return
		}
		pid = n
	}
	detailRaw := strings.TrimSpace(r.URL.Query().Get("details"))
	details := detailRaw == "1" || strings.EqualFold(detailRaw, "true")

	procs, err := procstat.List(procstat.Options{
		Limit: top, Match: match, PID: pid, Details: details,
	})
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	resp := map[string]any{
		"ok":        true,
		"schema":    "system.processes.v1",
		"top":       top,
		"count":     len(procs),
		"processes": procs,
	}
	if match != "" {
		resp["match"] = match
	}
	if pid > 0 {
		resp["pid"] = pid
	}
	if details {
		resp["details"] = true
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// handleSystemListeners serves the listening TCP/UDP sockets and their owning
// process (GET /api/v1/system/listeners). Read-only, admin-only. Backs the MCP
// listening_ports tool — "is the edge/daemon/panel actually listening, who owns
// :443?". Returns owning COMM/pid + a bounded bind-address sample per group (no
// connections/peers); results are grouped by (proto, port, process) so a host
// binding a service on hundreds of IP aliases stays compact — see netstat.PortGroup.
func handleSystemListeners(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	listeners, err := netstat.Listeners(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"schema": "system.listeners.v1",
		"count":  len(listeners),
		"groups": listeners,
	})
}

// handleSystemDmesg tails the kernel ring buffer (GET /api/v1/system/dmesg?
// lines=N&grep=SUBSTR). Read-only, admin-only. Backs the MCP dmesg_tail tool —
// the "why did it OOM/crash/reset?" view (OOM kills, I/O errors, segfaults, nft
// drops) that the structured health snapshot can't surface.
func handleSystemDmesg(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	lines := kmsg.DefaultLines
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))
	out, truncated, err := kmsg.Tail(r.Context(), lines, grep)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"schema":    "system.dmesg.v1",
		"count":     len(out),
		"truncated": truncated,
		"grep":      grep,
		"lines":     out,
	})
}

// handleSystemServices serves systemd unit status for the CFM / hosting-stack
// units — or an explicit comma-separated `units=` list (GET /api/v1/system/
// services?units=cfm,mariadb). Read-only, admin-only. Backs the MCP
// service_status tool — "is cfm/the edge/mysql/mail running, and is anything
// flapping (restart count)?". With no units the curated default set is returned
// and not-installed units are elided; an explicit list keeps not-found units so
// the operator learns a named unit isn't present.
func handleSystemServices(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var units []string
	if v := strings.TrimSpace(r.URL.Query().Get("units")); v != "" {
		for _, u := range strings.Split(v, ",") {
			if u = strings.TrimSpace(u); u != "" {
				units = append(units, u)
			}
		}
	}
	svcs, err := svcstat.Status(r.Context(), units)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":       true,
		"schema":   "system.services.v1",
		"explicit": len(units) > 0,
		"count":    len(svcs),
		"services": svcs,
	})
}

// handleSystemIPForensics does an on-demand, bounded lookup of one source IP in
// the edge access log (GET /api/v1/system/ip-forensics?ip=1.2.3.4). Read-only,
// admin-only. Backs the MCP ip_forensics tool — the raw request lines for an IP
// (the correlation ip_drilldown's aggregate view and the short-window
// edge_access_tail ring can't give for an OLDER WAF hit). Bounded by design:
// reads only the last `lines` of the log via tail (default 300k, max 2M), with a
// timeout and a capped match set; no continuous cost.
func handleSystemIPForensics(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "missing ip"})
		return
	}
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))
	includeRotated := r.URL.Query().Get("include_rotated") == "1"
	maxFiles := 0
	if v := strings.TrimSpace(r.URL.Query().Get("max_files")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxFiles = n
		}
	}

	res, err := edgelog.GrepIP(r.Context(), ip, edgelog.Opts{
		Source:         source,
		TailLines:      lines,
		Limit:          limit,
		IncludeRotated: includeRotated,
		MaxFiles:       maxFiles,
	})
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error": err.Error(), "available_logs": edgelog.AvailableLogs(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":             true,
		"schema":         "system.ip_forensics.v1",
		"result":         res,
		"available_logs": edgelog.AvailableLogs(),
	})
}

// handleSystemEdgeErrorLog tails the edge (OpenResty/Angie) ERROR log
// (GET /api/v1/system/edge-error-log?grep=SUBSTR&lines=N&limit=M&source=). Read-only,
// admin-only. Backs the MCP edge_error_tail tool: this is where the edge Lua
// writes ngx.log() — panel decision logonly verdicts
// ([cfm_panel_decision] logonly=would_enforce …), module-load failures, and Lua
// runtime errors — none of which the access-log ring (edge_access_tail) carries.
// Bounded by design: reads only the last `lines` via tail (default 5000, max
// 200k) with a timeout, returns the NEWEST `limit` matches; no continuous cost.
func handleSystemEdgeErrorLog(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))
	source := strings.TrimSpace(r.URL.Query().Get("source"))

	res, err := edgelog.TailError(r.Context(), grep, source, lines, limit)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error": err.Error(), "available_logs": edgelog.AvailableErrorLogs(),
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":             true,
		"schema":         "system.edge_error_log.v1",
		"result":         res,
		"available_logs": edgelog.AvailableErrorLogs(),
	})
}

// handleSystemWAFFPHunt aggregates the panel LOGONLY burn-in signal from the
// edge ERROR log (GET /api/v1/system/waf-fp-hunt?lines=N&source=). Read-only,
// admin-only. Backs the MCP waf_fp_hunt tool: it scans the edge error log for
// the `[cfm_panel_waf]` would-be WAF actions (Phase 2e) and `[cfm_panel_decision]`
// would-enforce verdicts (Phase 2d) and returns aggregates that answer "is it
// safe to turn panel enforcement on?" — separating expected internet-scanner
// noise from the non-scanner residue (panel_waf.nonscanner_would_block) and any
// bridge ip-block (panel_decision.ip_block_count). Host-wide (all panel vhosts
// share one error log), so admin-only by construction. Bounded like the sibling
// edge-error-log read (tail window + timeout); the collected panel-marker lines
// are capped so a huge window can't blow memory.
func handleSystemWAFFPHunt(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}
	source := strings.TrimSpace(r.URL.Query().Get("source"))

	// Collect the panel-marker lines (bounded), then aggregate. Each marker line
	// is short (~300 B); the cap keeps worst-case memory small even on a 200k
	// tail window that is mostly panel traffic.
	const maxCollect = 50000
	collected := make([]string, 0, 1024)
	truncated := false
	logFile, scanned, err := edgelog.ScanError(r.Context(),
		[]string{"[cfm_panel_waf]", "[cfm_panel_decision]"}, source, lines,
		func(line string) {
			if len(collected) < maxCollect {
				collected = append(collected, line)
			} else {
				truncated = true
			}
		})
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false, "error": err.Error(), "available_logs": edgelog.AvailableErrorLogs(),
		})
		return
	}

	summary := panelfp.Summarize(collected)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":             true,
		"schema":         "system.waf_fp_hunt.v1",
		"log_file":       logFile,
		"lines_scanned":  scanned,
		"collected":      len(collected),
		"truncated":      truncated,
		"summary":        summary,
		"available_logs": edgelog.AvailableErrorLogs(),
	})
}

// handleSystemLVECPU returns the per-tenant CPU pressure ranking on CloudLinux
// (GET /api/v1/system/lve-cpu?top=N). Read-only, admin-only. Backs the MCP
// lve_cpu tool. The data comes from the in-memory lvecpu collector, which
// samples /proc/lve/list every ~15s and computes each LVE's CPU cores + %-of-
// limit (lvestat.Diff), hottest-first. `available:false` on a non-CloudLinux
// host; `ready:false` while the collector is warming up (needs two samples).
// Host-wide (all tenants), so admin-only by construction.
func handleSystemLVECPU(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	top := 25
	if v := strings.TrimSpace(r.URL.Query().Get("top")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			top = n
		}
	}
	if top > 500 {
		top = 500
	}

	if !lvecpu.Available() {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "schema": "system.lve_cpu.v1", "available": false,
		})
		return
	}
	samples, at, ready := lvecpu.Latest()
	if !ready {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "schema": "system.lve_cpu.v1", "available": true,
			"ready": false, "interval_sec": lvecpu.IntervalSeconds(),
		})
		return
	}
	total := len(samples)
	if len(samples) > top {
		samples = samples[:top]
	}
	// Resolve uid→login for the returned rows only (bounded, cached). samples is
	// the collector's copy, so filling Username here is safe.
	now := time.Now()
	for i := range samples {
		samples[i].Username = resolveLVEUsername(samples[i].UID, now)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "schema": "system.lve_cpu.v1", "available": true, "ready": true,
		"sampled_at": at.UTC(), "interval_sec": lvecpu.IntervalSeconds(),
		"tenants": total, "top": samples,
	})
}

// handleSystemCPUThrottle answers "the box load is high — is the CPU being
// throttled or is this genuine demand?" (GET /api/v1/system/cpu-throttle).
// Read-only, admin-only. It reads the instantaneous cpufreq/thermal/load signals
// from sysfs/proc and classifies the root cause (thermal_throttling /
// frequency_capped / genuine_demand / low_load / no_cpufreq_data — the last on
// VMs where cpufreq isn't exposed). Cheap synchronous read (a handful of small
// sysfs files); no collector, no external command.
func handleSystemCPUThrottle(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":         true,
		"schema":     "system.cpu_throttle.v1",
		"assessment": cputhrottle.ReadAndClassify(cputhrottle.Params{}),
	})
}

// handleSystemMySQLLog tails the MySQL error or slow-query log
// (GET /api/v1/system/mysql-log?which=error|slow&lines=N&grep=SUBSTR). Read-only,
// admin-only. Backs the MCP mysql_log_tail (error) and mysql_slow_queries (slow)
// tools — the "MySQL pressure is high, what's erroring / what's slow?" companion
// to mysql_pressure. Bounded (tail window + timeout + capped output); needs no DB
// connection, just the log files. A missing slow log is reported as found=false
// (likely disabled), not an error.
func handleSystemMySQLLog(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	which := strings.TrimSpace(r.URL.Query().Get("which"))
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))

	res, err := mysqllog.Tail(r.Context(), which, lines, limit, grep)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"schema": "system.mysql_log.v1",
		"result": res,
	})
}

// handleSystemCFMLog tails one of CFM's own logs (GET /api/v1/system/cfm-log?
// which=main|error|api|detector|challenges|smtp|mysql|waf|clam|socket|lsm|service
// &lines=N&limit=M&grep=SUBSTR). Read-only, admin-only. Backs the MCP
// cfm_log_tail tool — "what did the daemon/detector/WAF/challenge subsystem log?"
// without shelling into the box. Bounded tail (window + timeout + capped output);
// a missing log path is found=false, not an error (feature off / relocated).
func handleSystemCFMLog(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	which := strings.TrimSpace(r.URL.Query().Get("which"))
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))

	res, err := cfmlog.TailFile(r.Context(), which, lines, limit, grep)
	if err != nil {
		status := http.StatusBadGateway // stream/exec failure (timeout, unreadable) → server error
		if errors.Is(err, cfmlog.ErrUnknownSource) {
			status = http.StatusBadRequest // bad `which` → client error
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "sources": cfmlog.FileSources()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "schema": "system.cfm_log.v1", "result": res, "sources": cfmlog.FileSources(),
	})
}

// handleSystemJournal tails an allow-listed systemd unit's journal
// (GET /api/v1/system/journal?unit=<unit>&lines=N&limit=M&grep=SUBSTR). Read-only,
// admin-only. Backs the MCP journal_tail tool. The unit MUST be in the allow-list
// (cfm + hosting-stack units) — an arbitrary unit is rejected 400, so the read
// surface stays bounded. A non-systemd host returns available=false, not an error.
func handleSystemJournal(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	unit := strings.TrimSpace(r.URL.Query().Get("unit"))
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))

	res, err := cfmlog.TailJournal(r.Context(), unit, lines, limit, grep)
	if err != nil {
		// TailJournal only errors on a bad/blocked unit (a caller fault); a
		// journalctl runtime failure is surfaced in res.Note, not as an error.
		status := http.StatusBadGateway
		if errors.Is(err, cfmlog.ErrUnitNotAllowed) {
			status = http.StatusBadRequest
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "units": cfmlog.JournalUnits()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "schema": "system.journal.v1", "result": res, "units": cfmlog.JournalUnits(),
	})
}

// handleSystemMailLog serves a bounded tail of a mail log (exim/dovecot/postfix)
// — GET /api/v1/system/mail-log?which=exim|dovecot|postfix&lines=&limit=&grep=.
// Read-only, admin-only. Backs the MCP mail_log_tail tool: the raw exim mainlog
// is where authenticated senders (A=dovecot_login:) and injecting scripts (cwd=)
// live, for outbound-abuse investigations. `found:false` when the service isn't
// logging at a known path (not installed / logs elsewhere), not an error.
func handleSystemMailLog(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	which := strings.TrimSpace(r.URL.Query().Get("which"))
	lines := 0
	if v := strings.TrimSpace(r.URL.Query().Get("lines")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			lines = n
		}
	}
	limit := 0
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	grep := strings.TrimSpace(r.URL.Query().Get("grep"))

	res, err := maillog.Tail(r.Context(), which, lines, limit, grep)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":     true,
		"schema": "system.mail_log.v1",
		"result": res,
	})
}

// handleSystemMailQueue serves the MTA-agnostic mail-queue report
// (GET /api/v1/system/mail-queue). Read-only, admin-only. Backs the MCP
// mail_queue_summary tool — the "why is mail backing up / who's flooding the
// queue / why are messages frozen?" breakdown (age distribution + top sender/
// recipient domains + oldest + top defer/freeze reasons). It reads the report
// the active queue detector (exim_queues / postfix_queues) publishes each poll,
// so there is NO per-request MTA probe. `available:false` when no queue detector
// is enabled or the first poll hasn't run yet.
func handleSystemMailQueue(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	rep, ok := mailqueue.Latest()
	if !ok {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "schema": "system.mail_queue.v1", "available": false,
			"note": "no mail-queue report yet (exim_queues/postfix_queues detector not enabled, or first poll pending)",
		})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"schema":    "system.mail_queue.v1",
		"available": true,
		"report":    rep,
	})
}

// mailTrafficScope resolves the caller's mail-traffic view. It returns
// (scope, ok): scope==nil means admin (whole server, no domain filter); a
// non-nil (possibly empty) set is a scoped caller limited to exactly those mail
// domains — an empty set therefore sees nothing (fail closed). ok=false denies
// (unauthenticated / unknown role → the handler 403s). Unlike MySQL scope,
// mail domains ARE the token's vhost allowlist, so no /etc/userdomains mapping
// is needed.
func mailTrafficScope(r *http.Request) (map[string]struct{}, bool) {
	if webdet.IsAdminRequest(r) {
		return nil, true // admin: whole server
	}
	role, _ := r.Context().Value(webdet.CtxRoleKey{}).(string)
	authn, _ := r.Context().Value(webdet.CtxAuthnKey{}).(bool)
	if !authn || role != webdet.CtxRoleScoped {
		return nil, false // unauthenticated / unknown role → deny
	}
	// Scoped: copy the vhost allowlist, lowercased. A nil/empty allowlist yields
	// a non-nil empty set (owns nothing) so the store filters to nothing rather
	// than mistaking it for the admin nil sentinel. Defensively drop the
	// host-wide sentinel "*": it is the store's key for host-wide and local-user
	// rows, so were it ever to appear in a scoped token's allowlist it would
	// otherwise match all of them — a scoped caller must never reach those.
	raw, _ := r.Context().Value(webdet.CtxScopeKey{}).(map[string]struct{})
	scope := make(map[string]struct{}, len(raw))
	for h := range raw {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || h == mailmeter.HostWide {
			continue
		}
		scope[h] = struct{}{}
	}
	return scope, true
}

// handleMailTraffic serves the Mail Monitor traffic report
// (GET /api/v1/mail/traffic). Read-only, scope-aware: admins see the whole
// server; a scoped cPanel viewer sees only its own domains (host-wide and
// local-unix-user rows are admin-only by construction). It reads the per-hour
// counters the mailtraffic collector persists, so there is NO per-request MTA
// probe. `available:false` when the collector isn't enabled. Query params:
// hours (window, default 24, max 720) and limit (rows per list, default 20).
func handleMailTraffic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	scope, ok := mailTrafficScope(r)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "not authorized"})
		return
	}
	st := mailtraffic.SharedStore()
	if st == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "schema": "system.mail_traffic.v1", "available": false,
			"note": "mail-traffic collector not enabled (or store unavailable)",
		})
		return
	}
	hours := clampInt(r.URL.Query().Get("hours"), 24, 1, 24*30)
	limit := clampInt(r.URL.Query().Get("limit"), 20, 1, 200)
	sum, err := st.TrafficSummary(hours, scope, limit)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "schema": "system.mail_traffic.v1", "available": true, "traffic": sum,
	})
}

// mailSelfIP caches the host's bound IPs (enumerated once) for the DNS check.
var mailSelfIP = selfip.New()

// publicSendingIPs keeps only the globally-routable addresses — the ones that
// would appear in an SPF record or carry a PTR. Loopback/link-local/private are
// dropped (they'd never be a sending IP and only add noise).
func publicSendingIPs(ips []string) []string {
	out := make([]string, 0, len(ips))
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() || !ip.IsGlobalUnicast() {
			continue
		}
		out = append(out, s)
	}
	return out
}

// domainInScope reports whether a scoped caller may query domain: it must equal,
// or be a subdomain of, one of the caller's vhosts.
func domainInScope(domain string, scope map[string]struct{}) bool {
	for v := range scope {
		if domain == v || strings.HasSuffix(domain, "."+v) {
			return true
		}
	}
	return false
}

// handleMailDNS serves the DNS mail-auth check (GET /api/v1/mail/dns?domain=).
// Read-only, scope-aware: admins may check any domain; a scoped cPanel viewer
// only its own domains (or their subdomains). Reports SPF/DMARC/DKIM/PTR/MX with
// human findings — the DNS half of a deliverability diagnosis (why Gmail says
// "SPF did not pass"). Optional dkim_selector (comma-separated) overrides the
// default selector probed.
func handleMailDNS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	// Normalize an FQDN root dot before the scope check so a scoped owner querying
	// "example.com." isn't wrongly denied (maildns.Check normalizes again anyway).
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("domain"))), ".")
	if domain == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "domain required"})
		return
	}
	scope, ok := mailTrafficScope(r)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "not authorized"})
		return
	}
	if scope != nil && !domainInScope(domain, scope) { // scoped caller, out-of-scope domain
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "domain not in scope"})
		return
	}

	// Cap the DKIM selectors so a caller can't turn one request into an
	// unbounded burst of DNS lookups at the target's nameservers.
	const maxSelectors = 10
	var selectors []string
	if sel := strings.TrimSpace(r.URL.Query().Get("dkim_selector")); sel != "" {
		for _, s := range strings.Split(sel, ",") {
			if s = strings.TrimSpace(s); s != "" {
				selectors = append(selectors, s)
				if len(selectors) >= maxSelectors {
					break
				}
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	rep := maildns.Check(ctx, net.DefaultResolver, domain, publicSendingIPs(mailSelfIP.LocalIPs()), selectors)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok": true, "schema": "system.mail_dns.v1", "report": rep,
	})
}

// handleMailRuntime serves the SMTP/spamd runtime SATURATION snapshot
// (GET /api/v1/mail/runtime). Host-level, admin-only, read-only: current inbound
// SMTP sessions vs Exim's smtp_accept_max and active spamd children vs
// --max-children, each as current/max → utilisation% → a saturation class
// (ok/warn/critical), plus the worst of the two. A cap that can't be resolved
// from config classifies "unknown", never "ok" (docs/whats-wrong-rootcause.md
// §3). This is the "mail is up but wedged" signal the queue summary can't see.
// Backs the mail_runtime MCP tool. exim_conf reports which config the SMTP cap
// came from ("" when smtp_accept_max wasn't found).
//
// The `signals` block is the 1a-sig collector (v1): a bounded tail of the Exim
// mainlog tallied into saturation-event counts (spamd_error, inbound_conn_refused)
// over the observed window_seconds. It's the LOG-driven half of the geometry —
// events the instantaneous gauge can't see. Burn-in only: exposed for rate
// observation, no whats_wrong finding fires on it yet. Degrades to a zeroed
// block (never an error) when the mainlog is missing/empty/unreadable.
func handleMailRuntime(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	eximMax, eximPath := mailruntime.DiscoverEximMaxima()
	spamdN, spamdOK := mailruntime.DiscoverSpamdMaxChildren()
	snap := mailruntime.Live(nil, eximMax.EximMax(), mailruntime.SpamdMax(spamdN, spamdOK))

	// 1a-sig collector (v1): tally saturation-event signatures over a bounded
	// tail of the Exim mainlog. This is the LOG-driven half of the geometry —
	// spamd read-timeouts and inbound-cap rejections that the instantaneous
	// current/max gauge can't see. Burn-in only for now: the counts are exposed
	// so their real rates can be observed; no whats_wrong finding fires on them
	// yet (docs/whats-wrong-rootcause.md §5a). A missing/empty mainlog yields a
	// zeroed block with lines_scanned=0, never an error — the gauge above still
	// stands on its own.
	const sigTailLines = 20000
	var counts mailruntime.SigCounts
	var win mailruntime.EximWindow
	sigLog, scanned, sigErr := maillog.ScanTail(r.Context(), "exim", sigTailLines, func(line string) {
		counts.AddEximLine(line)
		win.Observe(line)
	})
	signals := map[string]any{
		"spamd_error":          counts.SpamdError,
		"inbound_conn_refused": counts.InboundConnRefused,
		"window_seconds":       win.Seconds(),
		"lines_scanned":        scanned,
		"log_file":             sigLog,
	}
	if sigErr != nil {
		// A tail failure (timeout/unreadable) degrades the signals block only; the
		// geometry snapshot is still returned. Surface the reason for observability.
		signals["error"] = sigErr.Error()
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"schema":    "system.mail_runtime.v1",
		"snapshot":  snap,
		"exim_conf": eximPath,
		"signals":   signals,
	})
}

func handleSystemDNAT(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 5*time.Second)
	out, ms, err := runCachedCommandFn("system_dnat", cacheTTL, "cfm", "dnat")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "duration_ms": ms, "output": string(out)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "duration_ms": ms, "output": string(out)})
}

func handleSystemSSLStats(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 10*time.Second)
	out, ms, err := runCachedCommandFn("system_ssl_stats", cacheTTL, "cfm", "ssl", "stats", "--json")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "duration_ms": ms, "output": string(out)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "duration_ms": ms, "stats": parseCLIJSONOutput(out)})
}

// parseCLIJSONOutput decodes the JSON body of a CLI command's combined
// output. `cfm ssl ... --json` can emit log lines before the JSON (the CLI
// process's logging.Logf goes to stdout, and we capture CombinedOutput), so
// on a whole-output parse failure it retries from the first '{'. Falls back
// to the trimmed raw string — a string, not []byte: encoding/json would
// base64 a byte slice and the UI would render gibberish.
func parseCLIJSONOutput(out []byte) any {
	var parsed any
	if json.Unmarshal(out, &parsed) == nil {
		return parsed
	}
	if idx := bytes.IndexByte(out, '{'); idx >= 0 {
		if json.NewDecoder(bytes.NewReader(out[idx:])).Decode(&parsed) == nil {
			return parsed
		}
	}
	return string(bytes.TrimSpace(out))
}

// handleHealthSnapshot serves the canonical health snapshot (admin-only).
// Default is a fresh collection (what `cfm health` expects); `?cache_ttl=60s`
// (clamped to 1s..1m, same as the other system endpoints) opts into the
// stale-while-revalidate cache the dashboard uses, so it recollects at most
// once per TTL. `collected_at` in the payload tells the caller the real age.
// runSSLRefreshFn is a test seam for the `cfm ssl refresh` invocation.
var runSSLRefreshFn = func(ctx context.Context) ([]byte, error) {
	return exec.CommandContext(ctx, "cfm", "ssl", "refresh", "--json").CombinedOutput()
}

// handleSystemSSLRefresh forces a certificate rescan + collector refresh
// (`cfm ssl refresh --json` — the WebUI "Rescan certs" button). Admin-only,
// POST-only, bounded to 90s: the refresh walks the cert source directories,
// which can take a while on boxes with thousands of vhosts.
func handleSystemSSLRefresh(w http.ResponseWriter, r *http.Request) {
	if !webdet.RequireAdmin(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	start := time.Now()
	out, err := runSSLRefreshFn(ctx)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "duration_ms": ms, "output": string(bytes.TrimSpace(out))})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "duration_ms": ms, "stats": parseCLIJSONOutput(out)})
}

func handleHealthSnapshot(backend firewall.Backend) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireHealthAccess(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		nodeID := localNodeID()
		cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 0)
		_ = json.NewEncoder(w).Encode(healthSnapCache.get(nodeID, backend, cacheTTL))
	}
}

func handleHealthTimeseries(w http.ResponseWriter, r *http.Request) {
	if !requireHealthAccess(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	window, err := parseDurationBounded(r.URL.Query().Get("window"), time.Hour, time.Minute, 7*24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"invalid window"}`, http.StatusBadRequest)
		return
	}
	step, err := parseDurationBounded(r.URL.Query().Get("step"), 5*time.Minute, time.Second, 24*time.Hour)
	if err != nil {
		http.Error(w, `{"error":"invalid step"}`, http.StatusBadRequest)
		return
	}
	if step > window {
		http.Error(w, `{"error":"step cannot exceed window"}`, http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	nodeID := localNodeID()
	samples := healthstore.Global().LastWindow(nodeID, now, window)
	points := aggregateHealthSamples(samples, step)
	resp := healthTimeseriesResponse{
		SchemaVersion: healthTimeseriesSchemaV1,
		NodeID:        nodeID,
		GeneratedAt:   now,
		Window:        window.String(),
		Step:          step.String(),
		Points:        points,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func aggregateHealthSamples(samples []healthstore.Sample, step time.Duration) []healthTimeseriesPointV1 {
	if len(samples) == 0 {
		return nil
	}
	if step <= 0 {
		step = time.Minute
	}
	buckets := make(map[int64][]healthstore.Sample)
	keys := make([]int64, 0, len(samples))
	for _, sm := range samples {
		ts := sm.CollectedAt.UTC().Unix()
		bucket := ts / int64(step.Seconds())
		if _, exists := buckets[bucket]; !exists {
			keys = append(keys, bucket)
		}
		buckets[bucket] = append(buckets[bucket], sm)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]healthTimeseriesPointV1, 0, len(keys))
	for _, bucket := range keys {
		sms := buckets[bucket]
		var sumLoad, sumCPU, sumRAM, sumSwap, sumRoot, sumTmp, sumTemp, sumRx, sumTx float64
		for _, sm := range sms {
			sumLoad += sm.Load1
			sumCPU += sm.CPUPct
			sumRAM += sm.RamUsedPct
			sumSwap += sm.SwapUsedPct
			sumRoot += sm.DiskRootPct
			sumTmp += sm.DiskTmpPct
			sumTemp += sm.TempMaxC
			sumRx += sm.RxMbps
			sumTx += sm.TxMbps
		}
		n := float64(len(sms))
		out = append(out, healthTimeseriesPointV1{
			CollectedAt: time.Unix(bucket*int64(step.Seconds()), 0).UTC(),
			Load1:       sumLoad / n,
			CPUPct:      sumCPU / n,
			RamUsedPct:  sumRAM / n,
			SwapUsedPct: sumSwap / n,
			DiskRootPct: sumRoot / n,
			DiskTmpPct:  sumTmp / n,
			TempMaxC:    sumTemp / n,
			RxMbps:      sumRx / n,
			TxMbps:      sumTx / n,
			SampleCount: len(sms),
		})
	}
	return out
}

func handleHealthAnomalies(w http.ResponseWriter, r *http.Request) {
	if !requireHealthAccess(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	since, err := parseSince(r.URL.Query().Get("since"))
	if err != nil {
		http.Error(w, `{"error":"invalid since"}`, http.StatusBadRequest)
		return
	}
	items := healthAnomalies.since(since)
	resp := healthAnomaliesResponse{
		SchemaVersion: healthAnomaliesSchemaV1,
		GeneratedAt:   time.Now().UTC(),
		Since:         since,
		Count:         len(items),
		Anomalies:     items,
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func handleHealthIngest(w http.ResponseWriter, r *http.Request) {
	if !requireHealthAccess(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	var req healthIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(req.Sample.NodeID)
	}
	if nodeID == "" {
		http.Error(w, `{"error":"node_id required"}`, http.StatusBadRequest)
		return
	}
	if req.Sample.CollectedAt.IsZero() {
		req.Sample.CollectedAt = time.Now().UTC()
	}
	req.Sample.NodeID = nodeID
	healthstore.Global().Append(nodeID, req.Sample)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"schema_version": "health.ingest_ack.v1",
		"ok":             true,
		"node_id":        nodeID,
		"collected_at":   req.Sample.CollectedAt.UTC(),
	})
}

func localNodeID() string {
	host, err := os.Hostname()
	if err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return "local"
}

func parseDurationBounded(raw string, fallback, min, max time.Duration) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, err
	}
	if d < min || d > max {
		return 0, strconv.ErrSyntax
	}
	return d, nil
}

func parseSince(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Now().UTC().Add(-24 * time.Hour), nil
	}
	if d, err := time.ParseDuration(raw); err == nil {
		if d < 0 {
			return time.Time{}, strconv.ErrSyntax
		}
		return time.Now().UTC().Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

func parseCacheTTL(raw string, fallback time.Duration) time.Duration {
	if strings.TrimSpace(raw) == "" {
		return fallback
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	if d <= 0 {
		return 0
	}
	if d < time.Second {
		return time.Second
	}
	if d > time.Minute {
		return time.Minute
	}
	return d
}

func runCachedCommand(key string, ttl time.Duration, name string, args ...string) ([]byte, int64, error) {
	if ttl <= 0 {
		start := time.Now()
		out, err := exec.Command(name, args...).CombinedOutput()
		return out, time.Since(start).Milliseconds(), err
	}
	now := time.Now()
	raw, _ := cmdCache.LoadOrStore(key, &cmdCacheEntry{})
	entry := raw.(*cmdCacheEntry)

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if now.Before(entry.expiresAt) && entry.output != nil {
		return append([]byte(nil), entry.output...), entry.durationMS, nil
	}

	start := time.Now()
	out, err := exec.Command(name, args...).CombinedOutput()
	ms := time.Since(start).Milliseconds()
	if err != nil {
		return out, ms, err
	}

	entry.output = append([]byte(nil), out...)
	entry.durationMS = ms
	entry.expiresAt = time.Now().Add(ttl)

	return append([]byte(nil), out...), ms, nil
}
