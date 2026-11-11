package notify

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		n++
	}
	return n
}

// An append does not rewrite the history: the 5 minute pruner keeps it in
// bounds, and a storm prunes every pruneEveryAppends rows.
func TestAppendJSONLPrunesInBatches(t *testing.T) {
	prev := retentionPrunerOn.Load()
	retentionPrunerOn.Store(true)
	t.Cleanup(func() { retentionPrunerOn.Store(prev) })
	path := filepath.Join(t.TempDir(), "notify.log.jsonl")
	installTestConfig(t, &config{JSONLPath: path, MaxEntries: 10})
	jsonlRetentionMu.Lock()
	delete(jsonlAppendsSincePrune, path)
	jsonlRetentionMu.Unlock()

	now := time.Now().UTC()
	for i := 0; i < 50; i++ {
		if err := appendJSONL(path, map[string]any{"time": now.Format(time.RFC3339Nano), "i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if got := countLines(t, path); got != 50 {
		t.Fatalf("pruned on append: %d rows, want all 50 until a prune runs", got)
	}
	// The periodic pruner trims it to MAX_ENTRIES and resets the count.
	if err := runRetentionPrune(); err != nil {
		t.Fatal(err)
	}
	if got := countLines(t, path); got != 10 {
		t.Fatalf("after the periodic prune: %d rows, want 10", got)
	}
	// A storm: the pruneEveryAppends-th append prunes.
	for i := 0; i < pruneEveryAppends; i++ {
		if err := appendJSONL(path, map[string]any{"time": now.Format(time.RFC3339Nano), "s": i}); err != nil {
			t.Fatal(err)
		}
	}
	if got := countLines(t, path); got != 10 {
		t.Fatalf("after %d appends: %d rows, want the storm prune to keep 10", pruneEveryAppends, got)
	}
}

// Without the periodic pruner (a one-shot CLI) every append prunes, as
// before; MAX_AGE alone drops expired rows, and a prune that drops nothing
// leaves the file untouched.
func TestAppendJSONLWithoutPrunerAndMaxAge(t *testing.T) {
	prev := retentionPrunerOn.Load()
	retentionPrunerOn.Store(false)
	t.Cleanup(func() { retentionPrunerOn.Store(prev) })
	path := filepath.Join(t.TempDir(), "notify.log.jsonl")
	installTestConfig(t, &config{JSONLPath: path, MaxAge: time.Hour})
	old := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	if err := os.WriteFile(path, []byte(`{"ts":"`+old+`","i":"old"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendJSONL(path, map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	if got := countLines(t, path); got != 1 {
		t.Fatalf("MAX_AGE without the pruner: %d rows, want the expired one dropped", got)
	}
	st, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if err := pruneJSONLWithLimits(path, 0, time.Hour, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if st2, _ := os.Stat(path); !os.SameFile(st, st2) {
		t.Fatal("a prune that dropped nothing rewrote the file")
	}
}

// parseJSONLTime reads the same keys, in the same order, as before.
func TestParseJSONLTime(t *testing.T) {
	ts := "2026-11-11T12:00:00.5Z"
	want, _ := time.Parse(time.RFC3339Nano, ts)
	for line, w := range map[string]time.Time{
		`{"time":"` + ts + `","host":"a"}`:               want,
		`{"ts":"` + ts + `"}`:                            want,
		`{"timestamp":"2026-11-11T12:00:00Z"}`:           want.Truncate(time.Second),
		`{"time":"","ts":"` + ts + `"}`:                  want,
		`{"time":"not a time","ts":"` + ts + `"}`:        want,
		`{"dropped":true,"event":{"time":"` + ts + `"}}`: {},
		`not json`:       {},
		`{"time":12345}`: {},
	} {
		if got := parseJSONLTime(line); !got.Equal(w) {
			t.Errorf("%s: %v, want %v", line, got, w)
		}
	}
}

// BenchmarkPruneJSONL: one prune of a 100 000-row history (MAX_ENTRIES'
// default), the cost every alert used to pay.
func BenchmarkPruneJSONL(b *testing.B) {
	dir := b.TempDir()
	src := filepath.Join(dir, "src.jsonl")
	f, _ := os.Create(src)
	w := bufio.NewWriter(f)
	now := time.Now().UTC()
	for i := 0; i < 100000; i++ {
		row, _ := json.Marshal(map[string]any{
			"time": now.Add(-time.Duration(i) * time.Second).Format(time.RFC3339Nano), "host": "mars.example",
			"event_id": fmt.Sprintf("ev-%d", i), "kind": "WEB/LOGIN_BRUTEFORCE", "srcip": "203.0.113.9",
			"reason": strings.Repeat("r", 120), "channel": "smtp", "status": "success", "count": 4,
		})
		w.Write(row)
		w.WriteByte('\n')
	}
	w.Flush()
	f.Close()
	raw, _ := os.ReadFile(src)
	path := filepath.Join(dir, "notify.log.jsonl")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		_ = os.WriteFile(path, raw, 0o600)
		b.StartTimer()
		if err := pruneJSONLWithLimits(path, 100000, 30*24*time.Hour, now); err != nil {
			b.Fatal(err)
		}
	}
}
