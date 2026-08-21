package webdetector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The status list must carry BOTH halves of a manual challenge's TTL: the
// window the operator granted (TTLSec) and the expiry the remaining time is
// derived from. `cfm webtop challenge` renders them as the TTL/LEFT columns.
func TestChallengeAPIStore_ManualRecordsGrantedTTL(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.RecordVhostManual("e-vafeiadis.gr", true, 6*time.Hour, "manual")

	// Apex AND www, mirroring the bridge's expansion.
	for _, h := range []string{"e-vafeiadis.gr", "www.e-vafeiadis.gr"} {
		v, ok := s.GetVhost(h)
		if !ok {
			t.Fatalf("%s: no status record after manual_on", h)
		}
		if v.TTLSec != int(6*time.Hour/time.Second) {
			t.Errorf("%s: TTLSec = %d, want %d", h, v.TTLSec, int(6*time.Hour/time.Second))
		}
		if rem := time.Until(v.ExpiresAt); rem < 5*time.Hour+59*time.Minute || rem > 6*time.Hour {
			t.Errorf("%s: remaining = %s, want ~6h", h, rem)
		}
	}

	// A refresh re-grants the full window: the total must track the NEW grant,
	// not stretch from the original Since (which is why TTLSec exists at all).
	s.RecordVhostManual("e-vafeiadis.gr", true, 30*time.Minute, "manual")
	if v, _ := s.GetVhost("e-vafeiadis.gr"); v.TTLSec != 1800 {
		t.Errorf("after refresh TTLSec = %d, want 1800", v.TTLSec)
	}

	// manual_off clears the TTL along with the expiry — a lapsed row must not
	// keep advertising a window.
	s.RecordVhostManual("e-vafeiadis.gr", false, 0, "manual_off")
	if v, _ := s.GetVhost("e-vafeiadis.gr"); v.TTLSec != 0 || !v.ExpiresAt.IsZero() {
		t.Errorf("after manual_off: TTLSec = %d, ExpiresAt = %v, want 0/zero", v.TTLSec, v.ExpiresAt)
	}
}

// An auto challenge has no granted window (it lives and dies by the scorer), so
// it must not report one.
func TestChallengeAPIStore_AutoHasNoTTL(t *testing.T) {
	s := NewChallengeAPIStore(100)
	row := SuspiciousRow{Host: "auto.gr", Score: 0.8, UniqueIPs: 40, RPS: 3}
	s.RecordVhostAuto("auto.gr", true, row, 0.7, 0.6, 35*time.Minute)

	v, ok := s.GetVhost("auto.gr")
	if !ok {
		t.Fatal("no status record after auto_on")
	}
	if v.TTLSec != 0 {
		t.Errorf("auto row TTLSec = %d, want 0", v.TTLSec)
	}
	if !v.ExpiresAt.IsZero() {
		t.Errorf("auto row ExpiresAt = %v, want zero", v.ExpiresAt)
	}
}

// When a manual challenge lapses and the host is still hot, the next auto_on
// flips the row to Mode=="auto" — it must not keep advertising the granted TTL
// of the challenge that ended, or an API consumer reading the JSON raw (WebUI,
// MCP) shows a window that no longer exists. ExpiresAt deliberately survives
// the flip (vhostEffectivelyActive keys on it), which is why readers still
// gate the remaining time on the mode.
func TestChallengeAPIStore_AutoFlipClearsLapsedManualTTL(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.RecordVhostManual("hot.gr", true, time.Hour, "manual")

	// Force the manual window to have lapsed, as a real TTL expiry would.
	s.mu.Lock()
	s.vhosts["hot.gr"].ExpiresAt = time.Now().Add(-time.Minute)
	s.vhosts["hot.gr"].manualUntil = s.vhosts["hot.gr"].ExpiresAt
	s.mu.Unlock()

	row := SuspiciousRow{Host: "hot.gr", Score: 0.9, UniqueIPs: 300, RPS: 12}
	s.RecordVhostAuto("hot.gr", true, row, 0.7, 0.6, 35*time.Minute)

	v, _ := s.GetVhost("hot.gr")
	if v.Mode != "auto" || v.Status != "active" {
		t.Fatalf("expected active/auto after the lapsed manual, got %s/%s", v.Status, v.Mode)
	}
	if v.TTLSec != 0 {
		t.Errorf("TTLSec = %d after flipping to auto, want 0 (the manual window is over)", v.TTLSec)
	}
	// The CLI must still render "-" for both columns despite the stale expiry.
	total, left := chalTTLCols(chalVhost{Mode: v.Mode, TTLSec: v.TTLSec, ExpiresAt: v.ExpiresAt})
	if total != "-" || left != "-" {
		t.Errorf("columns = %q/%q, want -/- for a live auto challenge", total, left)
	}
}

// A restart must not shrink the reported total: restoreManualChallenges
// re-records with the REMAINING window, so the granted TTL has to ride along
// separately or a 6h challenge reads as "4h total" after one restart.
func TestChallengeAPIStore_RestoredKeepsGrantedTotal(t *testing.T) {
	s := NewChallengeAPIStore(100)
	s.RecordVhostManualRestored("example.gr", 4*time.Hour, 6*time.Hour, "operator")

	v, ok := s.GetVhost("example.gr")
	if !ok {
		t.Fatal("no status record after restore")
	}
	if v.TTLSec != int(6*time.Hour/time.Second) {
		t.Errorf("TTLSec = %d, want the granted 6h", v.TTLSec)
	}
	if rem := time.Until(v.ExpiresAt); rem < 3*time.Hour+59*time.Minute || rem > 4*time.Hour {
		t.Errorf("remaining = %s, want the surviving ~4h", rem)
	}

	// A snapshot written before TTLs were persisted carries total=0: fall back
	// to the remaining window rather than reporting "-".
	s.RecordVhostManualRestored("legacy.gr", 90*time.Minute, 0, "operator")
	if v, _ := s.GetVhost("legacy.gr"); v.TTLSec != 5400 {
		t.Errorf("legacy TTLSec = %d, want the 5400s fallback", v.TTLSec)
	}
}

// The granted TTL must survive the on-disk round trip, and an older snapshot
// without the key must load cleanly.
func TestManualChalPersist_KeepsGrantedTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manual.json")

	var s1 manualChalState
	s1.init(path)
	s1.set("example.gr", 10*time.Hour, "operator")

	var s2 manualChalState
	s2.init(path)
	ent, ok := s2.snapshot()["example.gr"]
	if !ok {
		t.Fatal("manual challenge not restored after reload")
	}
	if ent.TTL != 10*time.Hour {
		t.Errorf("restored TTL = %s, want 10h", ent.TTL)
	}

	// Pre-TTL snapshot: no ttl_sec key at all.
	legacy := filepath.Join(t.TempDir(), "legacy.json")
	b, _ := json.Marshal([]map[string]any{{
		"host":       "old.gr",
		"expires_at": time.Now().Add(time.Hour).Format(time.RFC3339Nano),
		"reason":     "manual",
	}})
	if err := os.WriteFile(legacy, b, 0o600); err != nil {
		t.Fatalf("write legacy snapshot: %v", err)
	}
	var s3 manualChalState
	s3.init(legacy)
	ent, ok = s3.snapshot()["old.gr"]
	if !ok {
		t.Fatal("legacy entry not restored")
	}
	// The granted window is unrecoverable, so the remaining one is adopted...
	if ent.TTL < 59*time.Minute || ent.TTL > time.Hour {
		t.Errorf("legacy TTL = %s, want the ~1h remaining window", ent.TTL)
	}
	// ...and written back, so a later restart reports the SAME total instead of
	// re-shrinking it to whatever is left then — the shrinking this field exists
	// to stop, which the fallback alone would reintroduce for legacy entries.
	var s4 manualChalState
	s4.init(legacy)
	again, ok := s4.snapshot()["old.gr"]
	if !ok {
		t.Fatal("legacy entry not restored on the second load")
	}
	if again.TTL != ent.TTL {
		t.Errorf("TTL drifted across restarts: %s then %s, want it pinned after the back-fill", ent.TTL, again.TTL)
	}
}

func TestChalTTLCols(t *testing.T) {
	cases := []struct {
		name  string
		in    chalVhost
		total string
		// left is matched exactly when set; leftAbout instead asserts the
		// rendered remaining time parses back to within a second or two of the
		// expected window (the column is rendered from the wall clock, so an
		// exact string would flake on any scheduling stall).
		left      string
		leftAbout time.Duration
	}{
		{
			name:  "manual row shows granted total and remaining",
			in:    chalVhost{Mode: "manual", TTLSec: 1800, ExpiresAt: time.Now().Add(20 * time.Minute)},
			total: "30m", leftAbout: 20 * time.Minute,
		},
		{
			// An auto row can carry the stale expiry of a lapsed manual
			// challenge; printing it would show a live challenge as "expired".
			name:  "auto row ignores a stale expiry",
			in:    chalVhost{Mode: "auto", TTLSec: 1800, ExpiresAt: time.Now().Add(-time.Hour)},
			total: "-", left: "-",
		},
		{
			name:  "manual row with no expiry",
			in:    chalVhost{Mode: "manual"},
			total: "-", left: "-",
		},
		{
			name:  "manual row restored without a known total",
			in:    chalVhost{Mode: "manual", ExpiresAt: time.Now().Add(time.Hour)},
			total: "-", leftAbout: time.Hour,
		},
		{
			name:  "lapsed manual row",
			in:    chalVhost{Mode: "manual", TTLSec: 3600, ExpiresAt: time.Now().Add(-time.Minute)},
			total: "1h", left: "expired",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, left := chalTTLCols(tc.in)
			if total != tc.total {
				t.Errorf("total = %q, want %q", total, tc.total)
			}
			if tc.leftAbout > 0 {
				got, err := time.ParseDuration(left)
				if err != nil {
					t.Fatalf("left = %q, not a duration: %v", left, err)
				}
				if d := tc.leftAbout - got; d < 0 || d > 5*time.Second {
					t.Errorf("left = %q, want ~%s", left, tc.leftAbout)
				}
				return
			}
			if left != tc.left {
				t.Errorf("left = %q, want %q", left, tc.left)
			}
		})
	}
}

func TestShortDur(t *testing.T) {
	cases := map[time.Duration]string{
		30 * time.Minute:                   "30m",
		6 * time.Hour:                      "6h",
		24 * time.Hour:                     "24h",
		90 * time.Minute:                   "1h30m",
		45 * time.Second:                   "45s",
		time.Hour + 30*time.Second:         "1h0m30s",
		0:                                  "0s",
		time.Minute + 500*time.Millisecond: "1m1s",
	}
	for in, want := range cases {
		if got := shortDur(in); got != want {
			t.Errorf("shortDur(%s) = %q, want %q", in, got, want)
		}
	}
}
