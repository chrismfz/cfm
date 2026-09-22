package webdetector

import (
	"net/http"
	"net/http/httptest"
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

// The Rung-1 facts must reach durable history, not just the log line: an
// operator asking "is my armed challenge_v2 covering traffic?" from MCP gets
// nothing if hs/v2 live only in cfm.challenges.log. The rung-disabled
// sentinel (-1) must NOT be persisted, and hs=- (nothing reported) must stay
// distinguishable from a scored-clean hs=0 — D5d.
func TestRecordChallengeSolved_PersistsHumanityAndV2Grain(t *testing.T) {
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{
		IP: "203.0.113.11", Host: "shop.example.com", URI: "/",
		HumanityScored: true, HumanityScore: 130,
		HumanityTells: "sw_renderer,outer_zero,no_input",
		V2Grain:       v2GrainMark,
	})
	ev := latestSolveEvent(t, e)
	if got := toF(ev.Payload["hs"]); got != 130 {
		t.Errorf("payload.hs = %v, want 130", ev.Payload["hs"])
	}
	if got, _ := ev.Payload["tells"].(string); got != "sw_renderer,outer_zero,no_input" {
		t.Errorf("payload.tells = %q", got)
	}
	if got, _ := ev.Payload["v2"].(string); got != "mark" {
		t.Errorf("payload.v2 = %q, want mark", got)
	}
	if _, ok := ev.Payload["hs_nopayload"]; ok {
		t.Errorf("a scored solve must not carry hs_nopayload")
	}

	// Scored clean AND unarmed: hs present at 0, no v2 key at all.
	e2 := newSolveTestEngine(t)
	e2.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.12", Host: "shop.example.com", URI: "/", HumanityScored: true})
	ev2 := latestSolveEvent(t, e2)
	if got := toF(ev2.Payload["hs"]); got != 0 {
		t.Errorf("clean solve: payload.hs = %v, want 0", ev2.Payload["hs"])
	}
	if _, ok := ev2.Payload["v2"]; ok {
		t.Errorf("unarmed solve must carry no v2 grain, got %v", ev2.Payload["v2"])
	}

	// Nothing reported: hs=0 plus the marker that says why.
	e3 := newSolveTestEngine(t)
	e3.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.13", Host: "shop.example.com", URI: "/", HumanityScored: true, HumanityNoPayload: true})
	ev3 := latestSolveEvent(t, e3)
	if ok, _ := ev3.Payload["hs_nopayload"].(bool); !ok {
		t.Errorf("no-payload solve must be distinguishable from scored-clean, payload=%v", ev3.Payload)
	}

	// Never scored (rung off, or a literal that never went through verify):
	// nothing humanity-shaped may be persisted. hs 0 is a REAL score meaning
	// "scored clean, passed", so the zero value must not be able to assert it.
	e4 := newSolveTestEngine(t)
	e4.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.14", Host: "shop.example.com", URI: "/", V2Grain: v2GrainMark})
	ev4 := latestSolveEvent(t, e4)
	for _, k := range []string{"hs", "tells", "v2", "sig", "hs_nopayload"} {
		if _, ok := ev4.Payload[k]; ok {
			t.Errorf("unscored solve persisted %q = %v", k, ev4.Payload[k])
		}
	}
}

// The raw report must also reach durable history as payload.sig, with the same
// numbers the log line shows, so a corpus pass can aggregate across the fleet
// instead of parsing a log field on every node.
func TestRecordChallengeSolved_PersistsRawSignals(t *testing.T) {
	e := newSolveTestEngine(t)
	e.RecordChallengeSolved(ChallengeSolve{
		IP: "203.0.113.20", Host: "shop.example.com", URI: "/",
		HumanityScored: true,
		humanity: &humanitySignals{
			PTR: iptr(0), TCH: iptr(0), KEY: iptr(0), MV: fptr(0),
			HC: iptr(8), DPR: fptr(1.5), RAF: fptr(16.666666666666668),
		},
	})
	sig, ok := latestSolveEvent(t, e).Payload["sig"].(map[string]any)
	if !ok {
		t.Fatalf("payload.sig missing or not an object")
	}
	// Reported zeros are present AS zeros — that is the whole point: "the
	// client never moved the mouse" must be readable, not inferred.
	for k, want := range map[string]float64{"ptr": 0, "tch": 0, "key": 0, "mv": 0, "hc": 8, "dpr": 1.5} {
		got, present := sig[k]
		if !present {
			t.Errorf("sig.%s missing", k)
			continue
		}
		if toF(got) != want {
			t.Errorf("sig.%s = %v, want %v", k, got, want)
		}
	}
	// Same rounding as the log line, so the two surfaces cannot disagree.
	if toF(sig["raf"]) != 16.7 {
		t.Errorf("sig.raf = %v, want 16.7 (log-line rounding)", sig["raf"])
	}
	// An unreported signal is an ABSENT key, never a zero.
	if _, present := sig["dm"]; present {
		t.Errorf("unreported deviceMemory must not be persisted, got %v", sig["dm"])
	}

	// No payload at all → no sig key, matching the log's missing sig= field.
	e2 := newSolveTestEngine(t)
	e2.RecordChallengeSolved(ChallengeSolve{IP: "203.0.113.21", Host: "shop.example.com", URI: "/", HumanityScored: true})
	if _, present := latestSolveEvent(t, e2).Payload["sig"]; present {
		t.Errorf("a solve with no retained report must carry no sig key")
	}
}

// payload.sig is per-visitor device-fingerprint material CFM's own challenge
// page collected. Scoped-vs-admin is a hard boundary and this is a NEW
// category of data on that surface, so it must not reach a scoped (cPanel)
// caller — while everything the scoped surface already carried stays.
func TestHistoryEventsRedactsSigForScopedCallers(t *testing.T) {
	rows := []HistoryEvent{{
		Type: "challenge_solved", Host: "shop.example.com", IP: "203.0.113.30",
		Payload: map[string]interface{}{
			"ua": "Mozilla/5.0", "hs": 0, "v2": "mark",
			"sig": map[string]any{"hc": 8.0, "dpr": 1.5},
		},
	}}

	scoped := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(scopedCtx("shop.example.com"))
	redactScopedHistoryRows(scoped, rows)
	if _, present := rows[0].Payload["sig"]; present {
		t.Errorf("sig must not cross the scoped boundary, got %v", rows[0].Payload["sig"])
	}
	for _, k := range []string{"ua", "hs", "v2"} {
		if _, present := rows[0].Payload[k]; !present {
			t.Errorf("scoped caller lost %q, which it always had", k)
		}
	}

	// Admin sees the row untouched — the burn-in readout is admin/MCP.
	adminRows := []HistoryEvent{{Payload: map[string]interface{}{"sig": map[string]any{"hc": 8.0}}}}
	redactScopedHistoryRows(httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(adminCtx()), adminRows)
	if _, present := adminRows[0].Payload["sig"]; !present {
		t.Errorf("admin must still receive sig")
	}
}
