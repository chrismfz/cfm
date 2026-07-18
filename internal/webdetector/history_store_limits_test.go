package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

// TestHistoryPrune_RowCap asserts the pruner's hard row cap: with maxRows
// set, prune keeps exactly the newest maxRows rows regardless of the time
// retention window.
func TestHistoryPrune_RowCap(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.db"), 30, time.Hour, 5)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	defer hs.Close()

	now := time.Now().Unix()
	for i := 0; i < 12; i++ {
		hs.Append(HistoryEvent{TsUnix: now - int64(12-i), Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Reason: "WAF_SQLI:42"})
	}

	trimmed, err := hs.Prune(30)
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if trimmed != 7 {
		t.Fatalf("trimmed=%d want=7 (12 rows, cap 5)", trimmed)
	}

	st, err := hs.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if st.Events != 5 {
		t.Fatalf("events=%d want=5 after row cap", st.Events)
	}
	if st.MaxRows != 5 {
		t.Fatalf("stats max_rows=%d want=5", st.MaxRows)
	}

	// The newest rows survive: the remaining events are the last five.
	hs.mu.Lock()
	got, err := hs.readWAFEventsSinceLocked(0)
	hs.mu.Unlock()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("rows=%d want=5", len(got))
	}
	if got[0].TsUnix != now-1 || got[4].TsUnix != now-5 {
		t.Fatalf("expected newest five rows kept, got ts range %d..%d", got[0].TsUnix, got[4].TsUnix)
	}
}

// TestHistoryPrune_NoCapWhenDisabled: maxRows<=0 keeps the old behavior.
func TestHistoryPrune_NoCapWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	hs, err := NewHistoryStore(filepath.Join(dir, "history.db"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	defer hs.Close()

	now := time.Now().Unix()
	for i := 0; i < 10; i++ {
		hs.Append(HistoryEvent{TsUnix: now - int64(i), Type: "waf_trigger", Host: "a.com", IP: "1.1.1.1", Reason: "WAF_SQLI:42"})
	}
	if _, err := hs.Prune(30); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	st, _ := hs.Stats()
	if st.Events != 10 {
		t.Fatalf("events=%d want=10 (cap disabled)", st.Events)
	}
}
