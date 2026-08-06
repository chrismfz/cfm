package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/edgelog"
	"cfm/internal/firewall"
	"cfm/internal/healthmodel"
	"cfm/internal/healthstore"
	"cfm/internal/kmsg"
	"cfm/internal/mysqllog"
	"cfm/internal/netstat"
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
	m.HandleFunc("/api/v1/system/mysql-log", handleSystemMySQLLog)
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

// handleSystemProcesses serves a top-like snapshot of the busiest processes
// (GET /api/v1/system/processes?top=N). Read-only, admin-only. Returns process
// COMM only — never the cmdline (which can carry secrets). Backs the MCP
// process_list tool; the "load is high, who's eating it?" companion to
// system_health's aggregate CPU.
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
	procs, err := procstat.Top(top)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":        true,
		"schema":    "system.processes.v1",
		"top":       top,
		"count":     len(procs),
		"processes": procs,
	})
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

	res, err := edgelog.GrepIP(r.Context(), ip, source, lines, limit)
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
