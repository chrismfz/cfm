//go:build linux

package lsm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakePasswd dumps a synthetic /etc/passwd to a temp file and
// swaps passwdPath at the package var for the duration of the test.
// The cleanup restores the original passwdPath via t.Cleanup so a
// failed subtest doesn't leak the override.
func writeFakePasswd(t *testing.T, body string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "passwd")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fake passwd: %v", err)
	}
	orig := passwdPath
	passwdPath = path
	t.Cleanup(func() { passwdPath = orig })
}

// TestComputeWatchedUids_Layers exercises the three additive layers
// against a synthetic /etc/passwd. computeWatchedUids is the pure
// core extracted from populateWatchedUids; testing it directly
// avoids needing a real *ebpf.Map.
//
// Fake passwd layout:
//   root            0    0     (excluded by everything by convention; not in any layer)
//   apache         48   48     (Layer 1: in WebUserNames)
//   nobody         99   99     (Layer 1: in WebUserNames)
//   alt-php-N5    700  700     (Layer 1: WebUserNamePrefixes hit)
//   chris        1000 1000     (Layer 3 only — uid >= fallback)
//   devops       1001 10       (Layer 3 + primary gid 10)
//   batch1       1500 1500     (Layer 3 only)
//   ftpaccount   1002 1002     (Layer 3 only)
func TestComputeWatchedUids_Layers(t *testing.T) {
	writeFakePasswd(t, `root:x:0:0::/root:/bin/bash
apache:x:48:48::/var/www:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
alt-php-N5:x:700:700::/:/sbin/nologin
chris:x:1000:1000::/home/chris:/bin/bash
devops:x:1001:10::/home/devops:/bin/bash
batch1:x:1500:1500::/home/batch1:/bin/bash
ftpaccount:x:1002:1002::/home/ftpaccount:/bin/bash
`)

	cases := []struct {
		name string
		opts WatchedUidsOptions
		want []uint32 // sorted ascending
	}{
		{
			name: "layer 1 only when fallback disabled",
			opts: WatchedUidsOptions{FallbackMin: 0},
			want: []uint32{48, 99, 700}, // apache, nobody, alt-php-N5
		},
		{
			name: "fallback 1000 watches all regular users",
			opts: WatchedUidsOptions{FallbackMin: 1000},
			want: []uint32{48, 99, 700, 1000, 1001, 1002, 1500},
		},
		{
			name: "deprecated -1 mapped to 1000",
			opts: WatchedUidsOptions{FallbackMin: -1},
			want: []uint32{48, 99, 700, 1000, 1001, 1002, 1500},
		},
		{
			name: "exclude_user removes only that uid",
			opts: WatchedUidsOptions{FallbackMin: 1000, ExcludeUsers: []string{"chris"}},
			want: []uint32{48, 99, 700, 1001, 1002, 1500},
		},
		{
			name: "exclude_user with unknown name skips silently",
			opts: WatchedUidsOptions{FallbackMin: 1000, ExcludeUsers: []string{"nobody-such-account"}},
			want: []uint32{48, 99, 700, 1000, 1001, 1002, 1500},
		},
		{
			name: "exclude_uid removes by number",
			opts: WatchedUidsOptions{FallbackMin: 1000, ExcludeUIDs: []uint32{1500}},
			want: []uint32{48, 99, 700, 1000, 1001, 1002},
		},
		{
			name: "exclude_gid removes by primary group",
			opts: WatchedUidsOptions{FallbackMin: 1000, ExcludeGIDs: []uint32{10}},
			want: []uint32{48, 99, 700, 1000, 1002, 1500}, // devops (gid 10) dropped
		},
		{
			name: "exclude_user CAN drop a static WebUserNames hit (documented footgun)",
			opts: WatchedUidsOptions{FallbackMin: 0, ExcludeUsers: []string{"apache"}},
			want: []uint32{99, 700},
		},
		{
			name: "exclude_gid can drop Layer 1 too (documented footgun)",
			opts: WatchedUidsOptions{FallbackMin: 0, ExcludeGIDs: []uint32{48}},
			want: []uint32{99, 700}, // apache (gid 48) dropped despite Layer 1
		},
		{
			name: "combined exclusions",
			opts: WatchedUidsOptions{
				FallbackMin:   1000,
				ExcludeUsers:  []string{"chris"},
				ExcludeUIDs:   []uint32{1500},
				ExcludeGIDs:   []uint32{10},
			},
			want: []uint32{48, 99, 700, 1002}, // 1000(chris), 1001(devops gid 10), 1500 all dropped
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := computeWatchedUids(tc.opts)
			if err != nil {
				t.Fatalf("computeWatchedUids: %v", err)
			}
			gotSorted := sortedUids(got)
			if !equalUint32Slices(gotSorted, tc.want) {
				t.Errorf("computeWatchedUids(%+v) = %v, want %v",
					tc.opts, gotSorted, tc.want)
			}
		})
	}
}

func sortedUids(m map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0, len(m))
	for u := range m {
		out = append(out, u)
	}
	// simple insertion sort — small slices, no sort import needed
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

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
