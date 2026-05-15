//go:build linux

package lsm

import (
	"strings"
	"testing"
)

// TestResolveWatchedUidFallback covers the four meaningful sentinel
// inputs and the panel-present interaction. Pure function, no fixtures
// needed.
func TestResolveWatchedUidFallback(t *testing.T) {
	cases := []struct {
		name      string
		cfg       int
		panel     bool
		wantThr   uint32
		wantApply bool
	}{
		{"auto-no-panel applies default 1000", -1, false, 1000, true},
		{"auto-with-panel disables fallback", -1, true, 0, false},
		{"explicit-zero always disables", 0, false, 0, false},
		{"explicit-zero overrides panel-absent", 0, false, 0, false},
		{"explicit-500 applies regardless of panel", 500, true, 500, true},
		{"explicit-1000 applies regardless of panel", 1000, true, 1000, true},
		{"negative-other-than-minus-1 treated as auto", -7, false, 1000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			thr, apply := resolveWatchedUidFallback(tc.cfg, tc.panel)
			if thr != tc.wantThr || apply != tc.wantApply {
				t.Errorf("cfg=%d panel=%t → (%d, %t), want (%d, %t)",
					tc.cfg, tc.panel, thr, apply, tc.wantThr, tc.wantApply)
			}
		})
	}
}

// TestParseConf_WatchedUidFallbackMin exercises the top-level parser
// and the sentinel handling.
func TestParseConf_WatchedUidFallbackMin(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{"default sentinel", "enabled = true\n", -1},
		{"explicit auto", "watched_uid_fallback_min = -1\n", -1},
		{"explicit disable", "watched_uid_fallback_min = 0\n", 0},
		{"explicit threshold", "watched_uid_fallback_min = 1000\n", 1000},
		{"explicit non-default threshold", "watched_uid_fallback_min = 500\n", 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseConf(strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if c.WatchedUidFallbackMin != tc.want {
				t.Errorf("got %d, want %d", c.WatchedUidFallbackMin, tc.want)
			}
		})
	}
}

func TestParseConf_WatchedUidFallbackMin_RejectsBelowMinusOne(t *testing.T) {
	if _, err := ParseConf(strings.NewReader("watched_uid_fallback_min = -2\n")); err == nil {
		t.Error("expected parse error for value < -1")
	}
}

func TestParseConf_WatchedUidFallbackMin_RejectsNonNumeric(t *testing.T) {
	if _, err := ParseConf(strings.NewReader("watched_uid_fallback_min = auto\n")); err == nil {
		t.Error("expected parse error for non-numeric value")
	}
}

func TestFormatConf_WatchedUidFallbackMin_RoundTrip(t *testing.T) {
	original := DefaultConf()
	original.WatchedUidFallbackMin = 500

	rendered := FormatConf(original)
	parsed, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	if parsed.WatchedUidFallbackMin != 500 {
		t.Errorf("round-trip lost value: got %d, want 500\n--- rendered ---\n%s",
			parsed.WatchedUidFallbackMin, rendered)
	}
}

// TestWebUserNames_HasNewAdditions guards against accidental deletion
// of the legacy / multi-distro web user names we added after live
// EL9 FP triage.
func TestWebUserNames_HasNewAdditions(t *testing.T) {
	want := []string{"nobody", "tomcat", "lighttpd", "caddy", "httpd"}
	have := map[string]bool{}
	for _, n := range WebUserNames {
		have[n] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("WebUserNames missing %q", w)
		}
	}
}
