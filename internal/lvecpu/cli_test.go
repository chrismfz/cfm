package lvecpu

import (
	"testing"

	"cfm/internal/lvestat"
)

func TestLimitCPUFormatting(t *testing.T) {
	cases := map[int64]string{
		0:       "∞",
		60000:   "6c",    // 6.0 → "6c" (no trailing zeros)
		155000:  "15.5c", // was "16c" under %.2g (2 sig-figs rounding) — now exact
		1000000: "100c",  // was "1e+02c" under %.2g — now no scientific notation
		5000:    "0.5c",
		12500:   "1.25c",
	}
	for in, want := range cases {
		if got := limitCPU(in); got != want {
			t.Errorf("limitCPU(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestFlagStrThresholds(t *testing.T) {
	mk := func(pct float64, limit int64) lvestat.CPUSample {
		return lvestat.CPUSample{PctOfLimit: pct, LimitCPU: limit}
	}
	if flagStr(mk(95, 60000)) != "🔴" {
		t.Error("≥90% should be 🔴")
	}
	if flagStr(mk(75, 60000)) != "🟡" {
		t.Error("≥70% should be 🟡")
	}
	if flagStr(mk(20, 60000)) != "" {
		t.Error("<70% should be unflagged")
	}
	if flagStr(mk(999, 0)) != "" {
		t.Error("unlimited (lCPU=0) should never flag")
	}
	// pctOfLimit is ASCII-only now (glyph moved to its own column).
	if pctOfLimit(mk(16, 60000)) != "16%" {
		t.Errorf("pctOfLimit should be plain ASCII, got %q", pctOfLimit(mk(16, 60000)))
	}
	if pctOfLimit(mk(50, 0)) != "-" {
		t.Error("unlimited pctOfLimit should be '-'")
	}
}
