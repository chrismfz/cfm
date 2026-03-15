package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cmdCacheEntry struct {
	mu         sync.Mutex
	output     []byte
	durationMS int64
	expiresAt  time.Time
}

var cmdCache sync.Map

// RegisterSystemStatus wires read-only system/status style helpers for web UI.
func RegisterSystemStatus(m *http.ServeMux) {
	if m == nil {
		return
	}
	m.HandleFunc("/api/v1/system/status", handleSystemStatus)
	m.HandleFunc("/api/v1/system/dnat", handleSystemDNAT)
	m.HandleFunc("/api/v1/system/ssl/stats", handleSystemSSLStats)
}

func handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}

	args := []string{"status", "--no-ttl", "--cache-ttl", "10s"}
	if isTrue(r.URL.Query().Get("timings")) {
		args = append(args, "--timings")
	}
	if ct := strings.TrimSpace(r.URL.Query().Get("cache_ttl")); ct != "" {
		args = []string{"status", "--no-ttl", "--cache-ttl", ct}
		if isTrue(r.URL.Query().Get("timings")) {
			args = append(args, "--timings")
		}
	}

	cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 10*time.Second)
	cacheKey := "system_status:" + strings.Join(args, " ")
	out, ms, err := runCachedCommand(cacheKey, cacheTTL, "cfm", args...)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":          false,
			"error":       err.Error(),
			"duration_ms": ms,
			"output":      string(out),
		})
		return
	}

	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":          true,
		"duration_ms": ms,
		"output":      string(out),
		"timings":     parseTimingBlock(string(out)),
	})
}

func handleSystemDNAT(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 5*time.Second)
	out, ms, err := runCachedCommand("system_dnat", cacheTTL, "cfm", "dnat")
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error(), "duration_ms": ms, "output": string(out)})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "duration_ms": ms, "output": string(out)})
}

func handleSystemSSLStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	cacheTTL := parseCacheTTL(r.URL.Query().Get("cache_ttl"), 10*time.Second)
	out, ms, err := runCachedCommand("system_ssl_stats", cacheTTL, "cfm", "ssl", "stats", "--json")
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

func parseTimingBlock(out string) map[string]int64 {
	m := map[string]int64{}
	idx := strings.Index(out, "Timing (ms):")
	if idx < 0 {
		return m
	}
	for _, ln := range strings.Split(out[idx+len("Timing (ms):"):], "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || !strings.Contains(ln, ":") {
			continue
		}
		parts := strings.SplitN(ln, ":", 2)
		k := strings.TrimSpace(parts[0])
		vtxt := strings.TrimSpace(parts[1])
		if vtxt == "" {
			continue
		}
		v, err := strconv.ParseInt(vtxt, 10, 64)
		if err == nil {
			m[k] = v
		}
	}
	return m
}

func isTrue(v string) bool {
	s := strings.TrimSpace(strings.ToLower(v))
	return s == "1" || s == "true" || s == "yes" || s == "on"
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
