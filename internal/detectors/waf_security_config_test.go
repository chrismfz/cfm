package detectors

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWAFSecurityConfigParses guards against the inline-comment parser trap:
// kvInt/kvBool/kvDur do NOT strip a trailing "; comment" from a scalar value,
// so a line like `SQLI = 1 ; note` parses as the string "1 ; note", fails
// strconv.Atoi, and silently falls back to the register default. Because the
// shipped defaults happen to equal the intended config, such a regression is
// invisible at runtime. This test reads the real configs/detectors.conf and
// asserts every [waf_security] scalar parses to its written value using an
// absurd fallback default — if an inline comment sneaks back onto a value line,
// the parsed result becomes the absurd default and this test fails.
func TestWAFSecurityConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "detectors.conf")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("detectors.conf not found at %s: %v", path, err)
	}
	secs, err := ReadSectionsFile(path)
	if err != nil {
		t.Fatalf("ReadSectionsFile: %v", err)
	}
	kv, ok := secs.ByName["waf_security"]
	if !ok {
		t.Fatal("[waf_security] section missing from detectors.conf")
	}

	// Numeric families: absurd fallback (999) proves the real value parsed.
	ints := map[string]int{
		"SQLI": 1, "RCE": 1, "BACKDOOR": 1, "UPLOAD_EXPLOIT": 1,
		"WEBSHELL": 0, "XXE": 0, "SSRF": 0, "BAD_UA": 0, "IP_HOST": 0,
		"AUTH_BURST": 0, "SUPERGLOBAL": 0, "BAD_UTF8": 0, "SAMPLE_LIMIT": 10,
	}
	for key, want := range ints {
		if got := kvInt(kv, key, 999); got != want {
			t.Errorf("%s parsed as %d, want %d (999 = fell back to default → inline comment on the value line?)", key, got, want)
		}
	}

	// DRY_RUN must parse to false; an inline comment would make kvBool fall
	// back to the `true` default and silently keep it in observe mode.
	if kvBool(kv, "DRY_RUN", true) {
		t.Error("DRY_RUN parsed as true (fell back to default) — expected 0/false")
	}

	// Durations / string policy read via the comment-stripping helpers, but
	// pin them so the shipped intent is asserted.
	if got := kvStrClean(kv, "EVERY", ""); got != "20s" {
		t.Errorf("EVERY = %q, want 20s", got)
	}
	if got := kvStrClean(kv, "BLOCK", ""); got != "6h" {
		t.Errorf("BLOCK = %q, want 6h (soft TTL default)", got)
	}

	// Leniency subsection must exist and be activatable (MATCH_COUNTRY present).
	lenKV, ok := secs.ByName["waf_security.leniency"]
	if !ok {
		t.Fatal("[waf_security.leniency] subsection missing")
	}
	if got := kvStrClean(lenKV, "MATCH_COUNTRY", ""); got != "GR,CY" {
		t.Errorf("leniency MATCH_COUNTRY = %q, want GR,CY", got)
	}
}
