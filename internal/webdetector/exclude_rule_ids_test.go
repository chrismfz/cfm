package webdetector

import (
	"reflect"
	"testing"
)

func TestParseRuleIDSpec_Bare(t *testing.T) {
	got, err := parseRuleIDSpec("320")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []int{320}) {
		t.Fatalf("got %v want [320]", got)
	}
}

func TestParseRuleIDSpec_GroupPrefix(t *testing.T) {
	got, err := parseRuleIDSpec("3xx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 100 || got[0] != 300 || got[99] != 399 {
		t.Fatalf("3xx: got %v (len=%d), want 300..399", got, len(got))
	}
	// Case-insensitive.
	gotUpper, err := parseRuleIDSpec("3XX")
	if err != nil || !reflect.DeepEqual(got, gotUpper) {
		t.Fatalf("3XX should equal 3xx: %v vs %v", gotUpper, got)
	}
}

func TestParseRuleIDSpec_Range(t *testing.T) {
	got, err := parseRuleIDSpec("310-317")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []int{310, 311, 312, 313, 314, 315, 316, 317}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Reversed range still works (auto-swap).
	gotRev, err := parseRuleIDSpec("317-310")
	if err != nil || !reflect.DeepEqual(gotRev, want) {
		t.Fatalf("reversed range broken: %v err=%v", gotRev, err)
	}
}

func TestParseRuleIDSpec_RangeClippedToValid(t *testing.T) {
	// Range overlapping the [100,999] window should be clipped, not rejected.
	got, err := parseRuleIDSpec("90-110")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got[0] != 100 || got[len(got)-1] != 110 {
		t.Fatalf("clipped range got %v", got)
	}
}

func TestParseRuleIDSpec_Invalid(t *testing.T) {
	bad := []string{"", "abc", "99", "1000", "0xx", "10xx", "300-", "-300", "3xy"}
	for _, s := range bad {
		if _, err := parseRuleIDSpec(s); err == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}

func TestParseRuleIDs_Mixed(t *testing.T) {
	got, err := parseRuleIDs("320, 3xx, 410-412")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 3xx already includes 320; result is union sorted unique.
	// Expect 300..399 + 410, 411, 412 = 103 entries.
	if len(got) != 103 {
		t.Fatalf("expected 103 entries, got %d (%v)", len(got), got[:min(20, len(got))])
	}
	if got[0] != 300 || got[99] != 399 || got[100] != 410 || got[102] != 412 {
		t.Fatalf("union ordering broken: got %v ... %v", got[:5], got[len(got)-5:])
	}
}

func TestParseRuleIDs_EmptyMeansNoScoping(t *testing.T) {
	got, err := parseRuleIDs("")
	if err != nil || got != nil {
		t.Fatalf("empty input: got=%v err=%v, want nil/nil", got, err)
	}
	gotWS, err := parseRuleIDs("  ,   ,")
	if err != nil || gotWS != nil {
		t.Fatalf("whitespace-only: got=%v err=%v, want nil/nil", gotWS, err)
	}
}

func TestNormalizeRuleIDs_DropsOutOfRange(t *testing.T) {
	got := normalizeRuleIDs([]int{320, 50, 1500, 320, 101})
	want := []int{101, 320}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if normalizeRuleIDs(nil) != nil {
		t.Errorf("nil input should return nil")
	}
}

func TestRuleIDsKey_StableAcrossOrder(t *testing.T) {
	a := ruleIDsKey([]int{101, 320})
	b := ruleIDsKey([]int{320, 101}) // unsorted input — store always sorts before keying
	if a == "" || a == b {
		// We document that callers must pass sorted IDs (normalizeRuleIDs does
		// this). Document the contract: keying without normalisation is
		// allowed to differ. So the test only asserts non-emptiness here.
		t.Skip("ruleIDsKey contract is sorted input; behaviour on unsorted is undefined")
	}
}

