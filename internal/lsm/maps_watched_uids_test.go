//go:build linux

package lsm

import (
	"strings"
	"testing"
)

// TestResolveWatchedUidFallback covers the three meaningful inputs.
// Panel-detect was removed — auto-detect was a coverage gap on panel
// hosts (sysadmin accounts at uid >= 1000 silently unwatched).
// Deprecated -1 sentinel is mapped to 1000 with a one-time warning
// emitted by the lifecycle code, not here.
func TestResolveWatchedUidFallback(t *testing.T) {
	cases := []struct {
		name      string
		cfg       int
		wantThr   uint32
		wantApply bool
	}{
		{"deprecated -1 mapped to 1000", -1, 1000, true},
		{"any negative mapped to 1000", -7, 1000, true},
		{"explicit zero disables", 0, 0, false},
		{"explicit 500", 500, 500, true},
		{"explicit 1000 (the shipped default)", 1000, 1000, true},
		{"explicit large threshold", 65535, 65535, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			thr, apply := resolveWatchedUidFallback(tc.cfg)
			if thr != tc.wantThr || apply != tc.wantApply {
				t.Errorf("cfg=%d → (%d, %t), want (%d, %t)",
					tc.cfg, thr, apply, tc.wantThr, tc.wantApply)
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
		{"default when key absent", "enabled = true\n", 1000},
		{"deprecated -1 accepted (mapped at runtime)", "watched_uid_fallback_min = -1\n", -1},
		{"explicit disable", "watched_uid_fallback_min = 0\n", 0},
		{"explicit shipped default", "watched_uid_fallback_min = 1000\n", 1000},
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

// TestParseConf_ExcludeKnobs covers the three opt-out conf keys
// introduced with the watched-uid model cleanup.
func TestParseConf_ExcludeKnobs(t *testing.T) {
	body := `
enabled = true
watched_uid_fallback_min = 1000
exclude_user = chris
exclude_user = devops
exclude_uid  = 1001
exclude_uid  = 1002
exclude_gid  = 10
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := c.ExcludeUsers, []string{"chris", "devops"}; !equalStringSlices(got, want) {
		t.Errorf("ExcludeUsers: got %v, want %v", got, want)
	}
	if got, want := c.ExcludeUIDs, []uint32{1001, 1002}; !equalUint32Slices(got, want) {
		t.Errorf("ExcludeUIDs: got %v, want %v", got, want)
	}
	if got, want := c.ExcludeGIDs, []uint32{10}; !equalUint32Slices(got, want) {
		t.Errorf("ExcludeGIDs: got %v, want %v", got, want)
	}
}

func TestParseConf_ExcludeKnobs_Validation(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty username", "exclude_user =\n"},
		{"empty username with whitespace", "exclude_user =    \n"},
		{"negative uid", "exclude_uid = -5\n"},
		{"non-numeric uid", "exclude_uid = chris\n"},
		{"negative gid", "exclude_gid = -1\n"},
		{"non-numeric gid", "exclude_gid = wheel\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseConf(strings.NewReader(tc.body)); err == nil {
				t.Errorf("expected parse error for %q", tc.body)
			}
		})
	}
}

func TestFormatConf_ExcludeKnobs_RoundTrip(t *testing.T) {
	original := DefaultConf()
	original.ExcludeUsers = []string{"chris", "devops"}
	original.ExcludeUIDs = []uint32{1001, 1002}
	original.ExcludeGIDs = []uint32{10}

	rendered := FormatConf(original)
	parsed, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	if !equalStringSlices(parsed.ExcludeUsers, original.ExcludeUsers) {
		t.Errorf("ExcludeUsers round-trip: got %v, want %v\n%s",
			parsed.ExcludeUsers, original.ExcludeUsers, rendered)
	}
	if !equalUint32Slices(parsed.ExcludeUIDs, original.ExcludeUIDs) {
		t.Errorf("ExcludeUIDs round-trip: got %v, want %v\n%s",
			parsed.ExcludeUIDs, original.ExcludeUIDs, rendered)
	}
	if !equalUint32Slices(parsed.ExcludeGIDs, original.ExcludeGIDs) {
		t.Errorf("ExcludeGIDs round-trip: got %v, want %v\n%s",
			parsed.ExcludeGIDs, original.ExcludeGIDs, rendered)
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalUint32Slices(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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
