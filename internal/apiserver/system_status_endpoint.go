package apiserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

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

// RegisterSystemStatus wires read-only system/status style helpers for web UI.
func RegisterSystemStatus(m *http.ServeMux) {
	if m == nil {
		return
	}
	m.HandleFunc("/api/v1/system/dnat", handleSystemDNAT)
	m.HandleFunc("/api/v1/system/ssl/stats", handleSystemSSLStats)
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
