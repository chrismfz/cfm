package detectors

import (
	"testing"
	"time"
)

// TestKVScalarInlineComments locks the fix for the inline-comment parse trap:
// kvInt/kvBool/kvDur must ignore a trailing "; comment"/"# comment" (and the
// embedded quote the section parser leaves on a quoted value) instead of
// silently falling back to the default. See CLAUDE.md §5.
func TestKVScalarInlineComments(t *testing.T) {
	// Values as the section parser actually stores them: TrimSpace + Trim(`"`)
	// on the ends only, so a quoted value with an inline comment keeps a stray
	// interior quote (`"20s" ; note` → `20s" ; note`).
	kv := KV{
		"A_INT":       "60    ; raised from 35",
		"A_INT_HASH":  "85 # percent",
		"A_BOOL":      "no             ; forces dryrun",
		"A_DUR":       "25m   ; raised from 15m",
		"A_DUR_QUOTE": `20s" ; how often`, // quoted value + inline comment, as stored
		"A_PLAIN_INT": "42",
		"A_PLAIN_DUR": "2m",
	}

	if got := kvInt(kv, "A_INT", -1); got != 60 {
		t.Errorf("kvInt A_INT = %d, want 60", got)
	}
	if got := kvInt(kv, "A_INT_HASH", -1); got != 85 {
		t.Errorf("kvInt A_INT_HASH = %d, want 85", got)
	}
	if got := kvBool(kv, "A_BOOL", true); got != false {
		t.Errorf("kvBool A_BOOL = %v, want false", got)
	}
	if got := kvDur(kv, "A_DUR", -1); got != 25*time.Minute {
		t.Errorf("kvDur A_DUR = %v, want 25m", got)
	}
	if got := kvDur(kv, "A_DUR_QUOTE", -1); got != 20*time.Second {
		t.Errorf("kvDur A_DUR_QUOTE = %v, want 20s (embedded-quote case)", got)
	}
	// No-comment values still parse.
	if got := kvInt(kv, "A_PLAIN_INT", -1); got != 42 {
		t.Errorf("kvInt A_PLAIN_INT = %d, want 42", got)
	}
	if got := kvDur(kv, "A_PLAIN_DUR", -1); got != 2*time.Minute {
		t.Errorf("kvDur A_PLAIN_DUR = %v, want 2m", got)
	}
	// Absent key → default; genuinely-garbage value → default.
	if got := kvInt(kv, "MISSING", 7); got != 7 {
		t.Errorf("kvInt MISSING = %d, want 7 (default)", got)
	}
	if got := kvInt(KV{"G": "notanumber ; x"}, "G", 9); got != 9 {
		t.Errorf("kvInt garbage = %d, want 9 (default)", got)
	}
}
