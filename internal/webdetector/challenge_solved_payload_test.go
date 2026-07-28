package webdetector

import (
	"path/filepath"
	"testing"
	"time"
)

func newSolveTestEngine(t *testing.T) *Engine {
	t.Helper()
	hs, err := NewHistoryStore(filepath.Join(t.TempDir(), "history.jsonl"), 30, time.Hour, 0)
	if err != nil {
		t.Fatalf("NewHistoryStore: %v", err)
	}
	return &Engine{history: hs, chalAPI: NewChallengeAPIStore(1000)}
}

func latestSolveEvent(t *testing.T, e *Engine) HistoryEvent {
	t.Helper()
	rows, err := e.history.QueryEvents("", "", "challenge_solved", 10)
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d challenge_solved rows, want 1", len(rows))
	}
	return rows[0]
}

// A solve must persist the UA and the real solve latency. Without the UA there
// is nothing to cluster a solver farm on (the forensics UI renders payload.ua,
// which is why challenge_solved rows used to show an empty UA column).
func TestRecordChallengeSolved_PersistsUAAndSolveLatency(t *testing.T) {
	e := newSolveTestEngine(t)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"

	e.RecordChallengeSolved(ChallengeSolve{
		IP:       "203.0.113.9",
		Host:     "shop.example.com",
		URI:      "/product-category/lamps/page/5",
		Diff:     16,
		UA:       ua,
		VerifyMS: 0,
		SolveMS:  1342,
	})

	ev := latestSolveEvent(t, e)
	if ev.IP != "203.0.113.9" || ev.Host != "shop.example.com" {
		t.Errorf("ip/host = %q/%q", ev.IP, ev.Host)
	}
	if got, _ := ev.Payload["ua"].(string); got != ua {
		t.Errorf("payload.ua = %q, want %q", got, ua)
	}
	if got := toF(ev.Payload["solve_ms"]); got != 1342 {
		t.Errorf("payload.solve_ms = %v, want 1342", ev.Payload["solve_ms"])
	}
	// The legacy server-side timing keeps its old key and meaning.
	if got := toF(ev.Payload["ms"]); got != 0 {
		t.Errorf("payload.ms = %v, want 0 (server-side verify time)", ev.Payload["ms"])
	}
}

// An unknown solve latency (-1) must be omitted rather than persisted, so a
// consumer never mistakes the sentinel for an impossibly fast solve.
func TestRecordChallengeSolved_OmitsUnknownSolveLatency(t *testing.T) {
	e := newSolveTestEngine(t)

	e.RecordChallengeSolved(ChallengeSolve{
		IP:      "203.0.113.10",
		Host:    "shop.example.com",
		Diff:    16,
		SolveMS: -1,
	})

	ev := latestSolveEvent(t, e)
	if v, ok := ev.Payload["solve_ms"]; ok {
		t.Errorf("payload.solve_ms = %v, want the key to be absent", v)
	}
	if v, ok := ev.Payload["ua"]; ok {
		t.Errorf("payload.ua = %v, want the key to be absent for an empty UA", v)
	}
}

func toF(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	}
	return -1e9
}
