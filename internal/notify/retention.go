package notify

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	jsonlRetentionMu    sync.Mutex
	retentionPrunerOnce sync.Once
	// retentionPrunerOn: the 5 minute pruner runs in this process (the
	// daemon's Load). Without it (a one-shot CLI) every append prunes, as
	// before.
	retentionPrunerOn atomic.Bool
	// jsonlAppendsSincePrune counts rows appended per history file since its
	// last prune (under jsonlRetentionMu).
	jsonlAppendsSincePrune = map[string]int{}
)

// pruneEveryAppends: appendJSONL prunes after this many rows when the 5
// minute pruner has not run since (an alert storm).
const pruneEveryAppends = 1000

type RetentionUsage struct {
	Path            string `json:"path"`
	Entries         int    `json:"entries"`
	ApproxSizeBytes int64  `json:"approx_size_bytes"`
	Oldest          string `json:"oldest,omitempty"`
	Newest          string `json:"newest,omitempty"`
}

func parseRetentionAge(raw string) (time.Duration, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return 0, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d, nil
	}
	if strings.HasSuffix(v, "d") {
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(v, "d")))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid max_age")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return 0, fmt.Errorf("invalid max_age")
}

func activeRetentionLimits() (int, time.Duration) {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if cfg == nil {
		return 0, 0
	}
	return cfg.MaxEntries, cfg.MaxAge
}

func ensureRetentionPruner() {
	retentionPrunerOnce.Do(func() {
		retentionPrunerOn.Store(true)
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				if err := runRetentionPrune(); err != nil {
					continue
				}
			}
		}()
	})
}

func runRetentionPrune() error {
	cfgMu.RLock()
	current := cfg
	cfgMu.RUnlock()
	if current == nil || strings.TrimSpace(current.JSONLPath) == "" {
		return nil
	}
	maxEntries, maxAge := activeRetentionLimits()
	if maxEntries <= 0 && maxAge <= 0 {
		return nil
	}
	jsonlRetentionMu.Lock()
	defer jsonlRetentionMu.Unlock()
	jsonlAppendsSincePrune[current.JSONLPath] = 0
	return pruneJSONLWithLimits(current.JSONLPath, maxEntries, maxAge, time.Now().UTC())
}

func pruneJSONLWithLimits(path string, maxEntries int, maxAge time.Duration, now time.Time) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	type row struct {
		line string
		ts   time.Time
	}
	rows := make([]row, 0, 256)
	read := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		read++
		ts := parseJSONLTime(line)
		if maxAge > 0 && !ts.IsZero() && ts.Before(now.Add(-maxAge)) {
			continue
		}
		rows = append(rows, row{line: line, ts: ts})
	}
	if err := s.Err(); err != nil {
		return err
	}
	if maxEntries > 0 && len(rows) > maxEntries {
		rows = rows[len(rows)-maxEntries:]
	}
	if len(rows) == read {
		// Nothing to drop: leave the file as it is. Rewriting and fsyncing
		// a 40 MB history every 5 minutes for nothing is ~12 GB a day.
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".retention-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	for _, r := range rows {
		if _, err := tmp.WriteString(r.line + "\n"); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func parseJSONLTime(line string) time.Time {
	// Only the three time keys, not a map of every field: a prune of 100 000
	// rows went from 565 ms and 4.7 M allocations to 342 ms and 1.0 M
	// (BenchmarkPruneJSONL). The keys match case-insensitively now (Go's
	// struct decoding); the rows CFM writes use the lowercase ones.
	var raw struct {
		Time      any `json:"time"`
		TS        any `json:"ts"`
		Timestamp any `json:"timestamp"`
	}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return time.Time{}
	}
	for _, v := range []any{raw.Time, raw.TS, raw.Timestamp} {
		if v := strings.TrimSpace(toString(v)); v != "" {
			if ts, err := time.Parse(time.RFC3339Nano, v); err == nil {
				return ts.UTC()
			}
			if ts, err := time.Parse(time.RFC3339, v); err == nil {
				return ts.UTC()
			}
		}
	}
	return time.Time{}
}

func JSONLUsage(path string) (RetentionUsage, error) {
	usage := RetentionUsage{Path: path}
	if strings.TrimSpace(path) == "" {
		return usage, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return usage, nil
		}
		return usage, err
	}
	usage.ApproxSizeBytes = st.Size()

	f, err := os.Open(path)
	if err != nil {
		return usage, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var oldest, newest time.Time
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		usage.Entries++
		ts := parseJSONLTime(line)
		if ts.IsZero() {
			continue
		}
		if oldest.IsZero() || ts.Before(oldest) {
			oldest = ts
		}
		if newest.IsZero() || ts.After(newest) {
			newest = ts
		}
	}
	if err := s.Err(); err != nil {
		return usage, err
	}
	if !oldest.IsZero() {
		usage.Oldest = oldest.Format(time.RFC3339Nano)
	}
	if !newest.IsZero() {
		usage.Newest = newest.Format(time.RFC3339Nano)
	}
	return usage, nil
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}
