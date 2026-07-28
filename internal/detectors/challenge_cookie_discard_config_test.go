package detectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestChallengeCookieDiscardConfigParses reads the real configs/detectors.conf
// and asserts every [challenge_cookie_discard] scalar parses to the value that
// is written there, using an absurd fallback so a silent fall-back to the
// built-in default fails instead of passing.
//
// What it catches, all invisible at runtime precisely because the shipped
// defaults equal the intended config:
//
//   - a key renamed on one side only, or typo'd, which the factory never reads;
//   - a documented value drifting from the number the comments above it justify
//     (MIN_SOLVES = 8 is calibrated; a silent change to it changes what fires);
//   - a BLOCK value appearing in the shipped section, which would start banning
//     residential proxy exits on upgrade with nobody choosing it;
//   - DRY_RUN coming back, which reads like a safety net and is not one.
//
// What it does NOT catch, checked rather than assumed: the inline-comment trap
// from CLAUDE.md §5. `kvInt`/`kvDur` strip a trailing `; note` today, on quoted
// and unquoted values alike — verified by adding one to this section and
// watching the test still pass. Keep comments on their own line anyway.
func TestChallengeCookieDiscardConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("detectors.conf not found at %s: %v", path, err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatalf("ReadSectionsFile: %v", err)
	}
	kv, ok := secs.ByName["challenge_cookie_discard"]
	if !ok {
		t.Fatal("[challenge_cookie_discard] section missing from detectors.conf")
	}

	ints := map[string]int{
		"ENABLED":            1,
		"MIN_SOLVES":         8,
		"SAMPLE_LIMIT":       10,
		"MAX_TRACKED_IPS":    100000,
		"MAX_TRACKED_PER_IP": 2000,
		"MAX_QUEUE":          20000,
	}
	for key, want := range ints {
		if got := kvInt(kv, key, -999); got != want {
			t.Errorf("%s = %d, want %d (a -999 here means the value did not parse and the built-in default would silently apply)", key, got, want)
		}
	}

	durs := map[string]time.Duration{
		"EVERY":    30 * time.Second,
		"WINDOW":   10 * time.Minute,
		"COOLDOWN": 30 * time.Minute,
	}
	for key, want := range durs {
		if got := kvDur(kv, key, time.Hour*999); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}

	// BLOCK must stay unset: the detector ships alert-only so the finding can be
	// burned in, and a value here would start banning real residential proxy
	// exits on upgrade without anyone choosing it.
	if got := kvStrClean(kv, "BLOCK", ""); got != "" {
		t.Errorf("BLOCK = %q in the reference config; it must ship unset (alert-only)", got)
	}

	// There is no generic DRY_RUN in this framework — only detectors that read it
	// themselves have one, and this is not one of them. A DRY_RUN line here would
	// be silently ignored while BLOCK banned for real, which is exactly what an
	// operator reading it would not expect.
	if raw := kvStrClean(kv, "DRY_RUN", ""); raw != "" {
		t.Errorf("DRY_RUN = %q is set but this detector never reads it; use BLOCK = \"dryrun\" instead", raw)
	}
}
