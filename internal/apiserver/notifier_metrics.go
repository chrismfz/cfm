package apiserver

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"cfm/internal/notify"
)

type notifierWindowSpec struct {
	Name   string
	Dur    time.Duration
	Bucket time.Duration
}

var notifierWindowSpecs = map[string]notifierWindowSpec{
	"1h":  {Name: "1h", Dur: time.Hour, Bucket: 5 * time.Minute},
	"6h":  {Name: "6h", Dur: 6 * time.Hour, Bucket: 15 * time.Minute},
	"24h": {Name: "24h", Dur: 24 * time.Hour, Bucket: time.Hour},
	"7d":  {Name: "7d", Dur: 7 * 24 * time.Hour, Bucket: 6 * time.Hour},
}

const notifierMetricsCacheTTL = 15 * time.Second

type notifierMetricsCacheEntry struct {
	ExpiresAt time.Time
	Path      string
	Size      int64
	ModUnix   int64
	Window    string
	Payload   notifierMetricsResponse
}

type notifierMetricsCache struct {
	mu    sync.RWMutex
	entry notifierMetricsCacheEntry
}

func (c *notifierMetricsCache) get(path string, stat os.FileInfo, window string, now time.Time) (notifierMetricsResponse, bool) {
	if c == nil {
		return notifierMetricsResponse{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if now.After(c.entry.ExpiresAt) {
		return notifierMetricsResponse{}, false
	}
	if c.entry.Path != path || c.entry.Window != window {
		return notifierMetricsResponse{}, false
	}
	if stat != nil && (c.entry.Size != stat.Size() || c.entry.ModUnix != stat.ModTime().UnixNano()) {
		return notifierMetricsResponse{}, false
	}
	return c.entry.Payload, true
}

func (c *notifierMetricsCache) set(path string, stat os.FileInfo, window string, now time.Time, payload notifierMetricsResponse) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry = notifierMetricsCacheEntry{
		ExpiresAt: now.Add(notifierMetricsCacheTTL),
		Path:      path,
		Window:    window,
		Payload:   payload,
	}
	if stat != nil {
		c.entry.Size = stat.Size()
		c.entry.ModUnix = stat.ModTime().UnixNano()
	}
}

var notifierMetricsAggCache notifierMetricsCache

type notifierMetricsBucket struct {
	Start    string `json:"start"`
	Attempts int    `json:"attempts"`
	Success  int    `json:"success"`
	Errors   int    `json:"errors"`
}

type notifierMetricsResponse struct {
	Window     string                  `json:"window"`
	From       string                  `json:"from"`
	To         string                  `json:"to"`
	Total      int                     `json:"total_attempts"`
	Success    int                     `json:"success_count"`
	Errors     int                     `json:"error_count"`
	PerChannel map[string]int          `json:"per_channel"`
	PerKind    map[string]int          `json:"per_kind"`
	Series     []notifierMetricsBucket `json:"series"`
	Cached     bool                    `json:"cached"`
}

func handleNotifierMetrics(w http.ResponseWriter, r *http.Request, cfgDir string) {
	if r.Method != http.MethodGet {
		writeNotifierJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
		return
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = "1h"
	}
	spec, ok := notifierWindowSpecs[window]
	if !ok {
		writeNotifierJSON(w, http.StatusBadRequest, map[string]any{"error": "window must be one of 1h, 6h, 24h, 7d"})
		return
	}
	adminCfg, _, err := notify.LoadAdminConfig(cfgDir)
	if err != nil {
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	path := strings.TrimSpace(adminCfg.Notifier.JSONLPath)
	if path == "" {
		path = "/var/lib/cfm/notify.log.jsonl"
	}

	now := time.Now().UTC()
	stat, statErr := os.Stat(path)
	if statErr == nil {
		if cached, hit := notifierMetricsAggCache.get(path, stat, window, now); hit {
			cached.Cached = true
			writeNotifierJSON(w, http.StatusOK, cached)
			return
		}
	}

	payload, err := aggregateNotifierMetrics(path, spec, now)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			payload = emptyNotifierMetrics(spec, now)
			writeNotifierJSON(w, http.StatusOK, payload)
			return
		}
		writeNotifierJSON(w, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("failed to aggregate notifier metrics: %v", err)})
		return
	}
	if statErr == nil {
		notifierMetricsAggCache.set(path, stat, window, now, payload)
	}
	writeNotifierJSON(w, http.StatusOK, payload)
}

func emptyNotifierMetrics(spec notifierWindowSpec, now time.Time) notifierMetricsResponse {
	from := now.Add(-spec.Dur)
	series := buildNotifierSeries(from, now, spec.Bucket)
	return notifierMetricsResponse{
		Window:     spec.Name,
		From:       from.Format(time.RFC3339),
		To:         now.Format(time.RFC3339),
		PerChannel: map[string]int{},
		PerKind:    map[string]int{},
		Series:     series,
	}
}

func aggregateNotifierMetrics(path string, spec notifierWindowSpec, now time.Time) (notifierMetricsResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return notifierMetricsResponse{}, err
	}
	defer f.Close()

	from := now.Add(-spec.Dur)
	series := buildNotifierSeries(from, now, spec.Bucket)
	index := make(map[int64]int, len(series))
	for i := range series {
		ts, _ := time.Parse(time.RFC3339, series[i].Start)
		index[ts.Unix()] = i
	}

	out := notifierMetricsResponse{
		Window:     spec.Name,
		From:       from.Format(time.RFC3339),
		To:         now.Format(time.RFC3339),
		PerChannel: map[string]int{},
		PerKind:    map[string]int{},
		Series:     series,
	}

	s := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, 2*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		ts := notifierRecordTime(row)
		if ts.IsZero() || ts.Before(from) || ts.After(now) {
			continue
		}

		out.Total++
		if notifierRecordIsError(row) {
			out.Errors++
		} else {
			out.Success++
		}
		kind := strings.TrimSpace(toString(row["kind"]))
		if kind == "" {
			kind = strings.TrimSpace(toString(row["Kind"]))
		}
		if kind != "" {
			out.PerKind[kind]++
		}
		for _, ch := range notifierRecordChannels(row) {
			out.PerChannel[ch]++
		}

		bucketStart := ts.UTC().Truncate(spec.Bucket)
		if i, ok := index[bucketStart.Unix()]; ok {
			out.Series[i].Attempts++
			if notifierRecordIsError(row) {
				out.Series[i].Errors++
			} else {
				out.Series[i].Success++
			}
		}
	}
	if err := s.Err(); err != nil {
		return notifierMetricsResponse{}, err
	}

	return out, nil
}

func buildNotifierSeries(from, to time.Time, step time.Duration) []notifierMetricsBucket {
	if step <= 0 {
		step = time.Hour
	}
	start := from.UTC().Truncate(step)
	if start.Before(from.UTC()) {
		start = start.Add(step)
	}
	if start.After(to.UTC()) {
		start = from.UTC().Truncate(step)
	}
	out := make([]notifierMetricsBucket, 0, int(to.Sub(from)/step)+2)
	for ts := start; !ts.After(to.UTC()); ts = ts.Add(step) {
		out = append(out, notifierMetricsBucket{Start: ts.Format(time.RFC3339)})
	}
	return out
}

func notifierRecordTime(row map[string]any) time.Time {
	if s := strings.TrimSpace(toString(row["time"])); s != "" {
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts.UTC()
		}
		if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return ts.UTC()
		}
	}
	if ev, ok := row["event"].(map[string]any); ok {
		if s := strings.TrimSpace(toString(ev["When"])); s != "" {
			if ts, err := time.Parse(time.RFC3339Nano, s); err == nil {
				return ts.UTC()
			}
		}
	}
	return time.Time{}
}

func notifierRecordIsError(row map[string]any) bool {
	if dropped, ok := row["dropped"].(bool); ok && dropped {
		return true
	}
	errVal := strings.TrimSpace(toString(row["err"]))
	if errVal != "" {
		return true
	}
	return false
}

func notifierRecordChannels(row map[string]any) []string {
	out := make([]string, 0, 2)
	seen := map[string]struct{}{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if ch := toString(row["channel"]); ch != "" {
		add(ch)
	}
	if raw, ok := row["channels"].([]any); ok {
		for _, v := range raw {
			add(toString(v))
		}
	}
	if len(out) > 0 {
		sort.Strings(out)
	}
	return out
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	default:
		return ""
	}
}
