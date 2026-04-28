package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/healthstore"
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

type healthSnapshotResponse struct {
	SchemaVersion string             `json:"schema_version"`
	NodeID        string             `json:"node_id"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Snapshot      healthstore.Sample `json:"snapshot"`
}

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
	RamUsedPct  float64   `json:"ram_used_pct"`
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
func RegisterSystemStatus(m *http.ServeMux) {
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

	m.HandleFunc("/api/v1/system/dnat", handleSystemDNAT)
	m.HandleFunc("/api/v1/system/ssl/stats", handleSystemSSLStats)
	m.HandleFunc("/api/v1/health/snapshot", handleHealthSnapshot)
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
	var parsed any
	if json.Unmarshal(out, &parsed) != nil {
		parsed = bytes.TrimSpace(out)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "duration_ms": ms, "stats": parsed})
}

func handleHealthSnapshot(w http.ResponseWriter, r *http.Request) {
	if !requireHealthAccess(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	nodeID := localNodeID()
	snapshot, ok := healthstore.Global().Latest(nodeID)
	if !ok {
		http.Error(w, `{"error":"no snapshot available"}`, http.StatusNotFound)
		return
	}
	if snapshot.NodeID == "" {
		snapshot.NodeID = nodeID
	}
	resp := healthSnapshotResponse{
		SchemaVersion: healthSnapshotSchemaV1,
		NodeID:        nodeID,
		GeneratedAt:   time.Now().UTC(),
		Snapshot:      snapshot,
	}
	_ = json.NewEncoder(w).Encode(resp)
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
		var sumLoad, sumRAM, sumRoot, sumTmp, sumTemp, sumRx, sumTx float64
		for _, sm := range sms {
			sumLoad += sm.Load1
			sumRAM += sm.RamUsedPct
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
			RamUsedPct:  sumRAM / n,
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
