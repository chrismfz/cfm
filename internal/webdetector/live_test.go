package webdetector

import (
	"strings"
	"testing"
)

// sigLetters is a fixed-slot presence cell: f/c/d/s when active, '·' otherwise,
// so the SIG column scans vertically (each signal keeps its column position).
func TestSigLetters(t *testing.T) {
	cases := []struct {
		facet, cost, dc, shadow int
		want                    string
	}{
		{0, 0, 0, 0, "····"},
		{5, 0, 0, 0, "f···"},
		{0, 12, 0, 0, "·c··"},
		{0, 0, 90, 0, "··d·"},
		{0, 0, 0, 3, "···s"},
		{5, 12, 90, 3, "fcds"},
		{5, 0, 90, 0, "f·d·"},
	}
	for _, tc := range cases {
		if got := sigLetters(tc.facet, tc.cost, tc.dc, tc.shadow); got != tc.want {
			t.Errorf("sigLetters(%d,%d,%d,%d)=%q, want %q", tc.facet, tc.cost, tc.dc, tc.shadow, got, tc.want)
		}
	}
}

// sigTokens are the bottom-panel REASONS tokens, in a stable order, only for
// active signals, with the % suffix on the ratio signals.
func TestSigTokens(t *testing.T) {
	if got := sigTokens(0, 0, 0, 0, false); len(got) != 0 {
		t.Fatalf("no signals should yield no tokens, got %v", got)
	}
	got := strings.Join(sigTokens(805, 40, 90, 2, true), ",")
	want := "farm,facet=805,cost=40%,dc=90%,shadow=2"
	if got != want {
		t.Fatalf("sigTokens = %q, want %q", got, want)
	}
	// Only the active ones appear, order preserved.
	got2 := strings.Join(sigTokens(0, 0, 90, 0, false), ",")
	if got2 != "dc=90%" {
		t.Fatalf("single-signal tokens = %q, want %q", got2, "dc=90%")
	}
}
