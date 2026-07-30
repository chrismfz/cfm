package cookiediscard

import (
	"testing"
	"time"
)

// The apex↔www canonical redirect makes a single real visitor solve twice — once
// on the host it landed on, once on the sibling the origin 301'd it to — for the
// same gate. Counting that as two solves is what banned a CGNAT address on
// 2026-07-29. A handful of such visitors behind one address must stay below
// MIN_SOLVES, because each contributes ONE journey, not two.
func TestApexWWWDoubleSolveCollapses(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 8})

	// Seven real visitors behind one CGNAT address, each solving apex then www
	// for the register gate: 14 raw solves. Collapsed it is 7 journeys — below 8.
	const ip, path = "100.64.12.9", "/forum/ucp.php?mode=register"
	for i := 0; i < 7; i++ {
		h.solve(ip, "example.gr", path, chromeUA)
		h.clock = h.clock.Add(3 * time.Second)
		h.solve(ip, "www.example.gr", path, chromeUA)
		h.clock = h.clock.Add(3 * time.Second)
	}

	if alerts := h.run(t); len(alerts) != 0 {
		t.Fatalf("got %d alerts for 14 raw solves that collapse to 7 apex↔www journeys, want 0", len(alerts))
	}
}

// The collapse must not let the real target escape: a cookie-less pipeline that
// re-solves the same gate climbs both host spellings together, so max(apex, www)
// is still the full journey count and the finding fires. It also reports the raw
// total so the inflation is visible.
func TestCollapseStillCatchesTheRepeatSolver(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 8})

	const ip, path = "198.51.100.7", "/forum/ucp.php?mode=register"
	for i := 0; i < 20; i++ { // 20 apex + 20 www = 40 raw, collapses to 20
		h.solve(ip, "example.gr", path, chromeUA)
		h.clock = h.clock.Add(2 * time.Second)
		h.solve(ip, "www.example.gr", path, chromeUA)
		h.clock = h.clock.Add(2 * time.Second)
	}

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (20 journeys is far above MIN_SOLVES=8)", len(alerts))
	}
	a := alerts[0]
	if a.Count != 20 {
		t.Errorf("Count = %d, want 20 collapsed journeys", a.Count)
	}
	if a.Extra["solves"] != "20" || a.Extra["raw_solves"] != "40" {
		t.Errorf("Extra solves=%q raw_solves=%q, want 20 / 40", a.Extra["solves"], a.Extra["raw_solves"])
	}
}

// Collapse is per (apex-normalised host, PATH): two different force-challenged
// gates are two journeys even on the same host pair — the redirect preserves the
// path, so a shared path is the signature of the canonical double, and distinct
// paths are distinct gates that must not be merged away.
func TestCollapseIsPerPath(t *testing.T) {
	h := newHarness(t, Config{MinSolves: 8})
	const ip = "203.0.113.5"

	// Eight distinct paths, each solved once on apex and once on www: 16 raw,
	// but 8 journeys — exactly the threshold, so it fires (not collapsed to 1).
	for i := 0; i < 8; i++ {
		p := "/gate/" + string(rune('a'+i))
		h.solve(ip, "example.gr", p, chromeUA)
		h.solve(ip, "www.example.gr", p, chromeUA)
	}

	alerts := h.run(t)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1 (8 distinct gates = 8 journeys = MIN_SOLVES)", len(alerts))
	}
	if a := alerts[0]; a.Count != 8 || a.Extra["raw_solves"] != "16" {
		t.Errorf("Count=%d raw_solves=%q, want 8 / 16", a.Count, a.Extra["raw_solves"])
	}
}

// A panel/mail host must never be collapsed into an apex. webmail.example.gr is a
// different surface with different auth; if the collapse stripped arbitrary
// leading labels it would merge unrelated hosts and hide a real repeat-solver
// hammering the panel. splitWWW adds/strips only "www.".
func TestPanelHostsAreNotCollapsed(t *testing.T) {
	if got, isWWW := splitWWW("webmail.example.gr"); got != "webmail.example.gr" || isWWW {
		t.Errorf("splitWWW(webmail.example.gr) = (%q, %v), must be unchanged", got, isWWW)
	}
	if got, isWWW := splitWWW("www.example.gr"); got != "example.gr" || !isWWW {
		t.Errorf("splitWWW(www.example.gr) = (%q, %v), want (example.gr, true)", got, isWWW)
	}
	if got, isWWW := splitWWW("example.gr"); got != "example.gr" || isWWW {
		t.Errorf("splitWWW(example.gr) = (%q, %v), want (example.gr, false)", got, isWWW)
	}
	// A bare label has no registrable www pair; stripping would leave nothing
	// meaningful, so it stays put and never merges.
	if got, isWWW := splitWWW("www.localhost"); got != "www.localhost" || isWWW {
		t.Errorf("splitWWW(www.localhost) = (%q, %v), want unchanged", got, isWWW)
	}

	// End to end: 8 solves on webmail. must still fire — the collapse leaves a
	// single-surface repeat-solver untouched.
	h := newHarness(t, Config{MinSolves: 8})
	for i := 0; i < 8; i++ {
		h.solve("192.0.2.44", "webmail.example.gr", "/", chromeUA)
	}
	if alerts := h.run(t); len(alerts) != 1 {
		t.Fatalf("got %d alerts for 8 webmail solves, want 1 (panel hosts are never collapsed)", len(alerts))
	}
}

// effectiveSolves never exceeds the raw count — the safety property that makes
// this change unable to create a new false positive or ban.
func TestEffectiveSolvesNeverExceedsRaw(t *testing.T) {
	cases := [][]solveRec{
		{},
		{{host: "example.gr", path: "/"}},
		{{host: "example.gr", path: "/"}, {host: "www.example.gr", path: "/"}},
		{{host: "www.example.gr", path: "/a"}, {host: "www.example.gr", path: "/a"}, {host: "example.gr", path: "/a"}},
		{{host: "a.example.gr", path: "/"}, {host: "b.example.gr", path: "/"}},
	}
	for i, recs := range cases {
		raw := len(recs)
		if eff := effectiveSolves(recs, 0); eff > raw {
			t.Errorf("case %d: effectiveSolves=%d > raw=%d", i, eff, raw)
		}
	}
	// truncated records are added back verbatim.
	if eff := effectiveSolves(nil, 5); eff != 5 {
		t.Errorf("effectiveSolves(nil, 5) = %d, want 5", eff)
	}
}
