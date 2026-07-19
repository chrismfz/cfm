package webdetector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func has40xComboReason(reasons []string) bool {
	for _, reason := range reasons {
		if strings.HasPrefix(reason, "40x_combo") {
			return true
		}
	}
	return false
}

func ipHas40xComboReason(rows []IPSignals, ip string) bool {
	for _, r := range rows {
		if r.IP == ip {
			return has40xComboReason(r.Reasons)
		}
	}
	return false
}

func TestIP40xCombo_Static404403Ignored(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 1,
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 3; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.1",
			Host:   "example.com",
			Method: "get",
			URI:    "/assets/missing.css?ver=1",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}
	for i := 0; i < 3; i++ {
		e.ingest(LogRec{
			TS:     now + float64(10+i),
			IP:     "10.0.0.1",
			Host:   "example.com",
			Method: "get",
			URI:    "/assets/forbidden.js",
			Status: 403,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if ipHas40xComboReason(rows, "10.0.0.1") {
		t.Fatalf("did not expect 40x_combo for repeated static assets; rows=%+v", rows)
	}
}

func TestIP40xCombo_NonStatic403404Counts(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 2,
	})

	now := float64(time.Now().Unix())
	uris := []struct {
		uri    string
		status int
	}{
		{"/admin", 403},
		{"/private", 403},
		{"/missing-a", 404},
		{"/missing-b", 404},
	}
	for i, u := range uris {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.2",
			Host:   "example.com",
			Method: "get",
			URI:    u.uri,
			Status: u.status,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if !ipHas40xComboReason(rows, "10.0.0.2") {
		t.Fatalf("expected 40x_combo for non-static 403/404 mix; rows=%+v", rows)
	}
}

func TestIP40xCombo_IgnorePrefixesStillApplied(t *testing.T) {
	e := NewEngine(Config{
		Every:                 1 * time.Second,
		Window:                2 * time.Minute,
		IP40xComboCount:       4,
		IP40xComboUniquePaths: 1,
		Ignore40xPrefixes:     []string{"/ignored"},
	})

	now := float64(time.Now().Unix())
	for i := 0; i < 5; i++ {
		e.ingest(LogRec{
			TS:     now + float64(i),
			IP:     "10.0.0.3",
			Host:   "example.com",
			Method: "get",
			URI:    "/ignored/secret",
			Status: 404,
			UA:     "ua",
		}, "raw")
	}

	rows := e.IPShort(0)
	if ipHas40xComboReason(rows, "10.0.0.3") {
		t.Fatalf("did not expect 40x_combo for ignored prefix paths; rows=%+v", rows)
	}
}

// TestIP40xCombo_SuccessShareGate covers the success-share gate: the 40x_combo
// hard-ban must fire only when 40x is a meaningful SHARE of the IP's traffic, so
// a legit heavy client (content migration probing REST post IDs, headless
// frontend, dashboard) that does bulk 2xx with incidental 404s is spared, while a
// path scanner (almost all 40x) is still banned. Reproduces the production FP: a
// Greek user's migration tool read /wp-json/wp/v2/posts/<id> across a range,
// 404ing the gaps, and got a WEB/40X ban despite being ~9% 40x.
func TestIP40xCombo_SuccessShareGate(t *testing.T) {
	mk := func(minShare int) *Engine {
		return NewEngine(Config{
			Every:                 1 * time.Second,
			Window:                5 * time.Minute,
			IP40xComboCount:       20,
			IP40xComboUniquePaths: 10,
			IP40xComboMinSharePct: minShare, // 0 → FillDefaults sets 25
		})
	}
	feed := func(e *Engine, ip string, ok, notFound int) {
		now := float64(time.Now().Unix())
		ts := now
		for i := 0; i < ok; i++ {
			e.ingest(LogRec{TS: ts, IP: ip, Host: "h", Method: "get",
				URI: fmt.Sprintf("/wp-json/wp/v2/posts/%d", 1000+i), Status: 200, UA: "ua"}, "raw")
			ts += 0.05
		}
		for i := 0; i < notFound; i++ {
			e.ingest(LogRec{TS: ts, IP: ip, Host: "h", Method: "get",
				URI: fmt.Sprintf("/wp-json/wp/v2/posts/%d", 5000+i), Status: 404, UA: "ua"}, "raw")
			ts += 0.05
		}
	}

	// Legit heavy client: 300 × 2xx + 30 unique 404s → 40x share ≈ 9% < 25% → NO ban.
	e := mk(0)
	feed(e, "10.0.0.9", 300, 30)
	if ipHas40xComboReason(e.IPShort(0), "10.0.0.9") {
		t.Fatalf("legit heavy client (~9%% 40x) must NOT get a 40x_combo ban")
	}

	// Scanner: the SAME 30 unique 404s, but essentially no successes → ~100% 40x
	// share → still banned (the gate does not weaken real enumeration detection).
	e2 := mk(0)
	feed(e2, "10.0.0.10", 0, 30)
	if !ipHas40xComboReason(e2.IPShort(0), "10.0.0.10") {
		t.Fatalf("scanner (~100%% 40x) must still get a 40x_combo ban")
	}

	// Disable knob: a negative pct restores the pre-gate behaviour, so the same
	// heavy client IS banned again — proving the gate is what spared it.
	e3 := mk(-1)
	feed(e3, "10.0.0.11", 300, 30)
	if !ipHas40xComboReason(e3.IPShort(0), "10.0.0.11") {
		t.Fatalf("negative IP40xComboMinSharePct must disable the gate (client banned again)")
	}
}
