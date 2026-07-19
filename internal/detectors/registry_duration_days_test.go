package detectors

import (
	"testing"
	"time"
)

// TestParseCfgDuration_Days locks the "d" (days) extension on top of Go's
// time.ParseDuration, plus composability with the standard units. The stdlib
// parser stops at "h", so without this a "7d" value would fail and silently
// fall back to the caller's default.
func TestParseCfgDuration_Days(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		// day unit
		{"1d", 24 * time.Hour, true},
		{"7d", 7 * 24 * time.Hour, true},
		{"0d", 0, true},
		{"1.5d", 36 * time.Hour, true},
		{"0.5d", 12 * time.Hour, true},
		// composites: day + standard units in one value
		{"1d12h", 36 * time.Hour, true},
		{"2d30m", 2*24*time.Hour + 30*time.Minute, true},
		{"1d1h1m1s", 25*time.Hour + time.Minute + time.Second, true},
		// standard units still work unchanged (fast path)
		{"20s", 20 * time.Second, true},
		{"25m", 25 * time.Minute, true},
		{"6h", 6 * time.Hour, true},
		{"90m", 90 * time.Minute, true},
		// sign is preserved
		{"-1d", -24 * time.Hour, true},
		// malformed -> error (caller keeps its default)
		{"", 0, false},
		{"d", 0, false},
		{"7dd", 0, false},
		{"7days", 0, false},
		{"7D", 0, false}, // only lowercase "d" is a day unit
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, err := parseCfgDuration(c.in)
		if c.ok {
			if err != nil {
				t.Errorf("parseCfgDuration(%q) unexpected error: %v", c.in, err)
				continue
			}
			if got != c.want {
				t.Errorf("parseCfgDuration(%q) = %v, want %v", c.in, got, c.want)
			}
		} else if err == nil {
			t.Errorf("parseCfgDuration(%q) = %v, want error", c.in, got)
		}
	}
}

// TestKVDur_Days confirms the day unit flows through kvDur (the EVERY/WINDOW/
// COOLDOWN/TIMEOUT reader), including alongside an inline comment, and that a
// bad value still falls back to the default rather than parsing wrong.
func TestKVDur_Days(t *testing.T) {
	kv := KV{
		"WINDOW":    "3d",
		"COOLDOWN":  "1d12h ; a day and a half",
		"BOGUS":     "7days",
		"UPPERCASE": "2D",
	}
	if got := kvDur(kv, "WINDOW", time.Minute); got != 3*24*time.Hour {
		t.Errorf("kvDur WINDOW = %v, want 72h", got)
	}
	if got := kvDur(kv, "COOLDOWN", time.Minute); got != 36*time.Hour {
		t.Errorf("kvDur COOLDOWN = %v, want 36h", got)
	}
	// invalid day-ish values must fall back to the default, not misparse
	if got := kvDur(kv, "BOGUS", 5*time.Minute); got != 5*time.Minute {
		t.Errorf("kvDur BOGUS = %v, want 5m (default)", got)
	}
	if got := kvDur(kv, "UPPERCASE", 5*time.Minute); got != 5*time.Minute {
		t.Errorf("kvDur UPPERCASE = %v, want 5m (default; only lowercase d)", got)
	}
}

// TestParseBlockPolicy_Days confirms BLOCK accepts a day-valued TTL so the
// whole detectors.conf duration surface is consistent (BLOCK = "7d").
func TestParseBlockPolicy_Days(t *testing.T) {
	p := parseBlockPolicy(KV{"BLOCK": "7d"})
	if p.Mode != "ttl" {
		t.Fatalf("parseBlockPolicy BLOCK=7d Mode = %q, want ttl", p.Mode)
	}
	if p.TTL != 7*24*time.Hour {
		t.Errorf("parseBlockPolicy BLOCK=7d TTL = %v, want 168h", p.TTL)
	}
	// composite too
	if p := parseBlockPolicy(KV{"BLOCK": "1d12h"}); p.Mode != "ttl" || p.TTL != 36*time.Hour {
		t.Errorf("parseBlockPolicy BLOCK=1d12h = {%q,%v}, want {ttl,36h}", p.Mode, p.TTL)
	}
}
