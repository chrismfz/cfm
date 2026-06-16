package unblock

import (
	"context"
	"net"
	"testing"
)

type fakeWAF struct {
	calledWith string
	ret        WAFResult
}

func (f *fakeWAF) ForceUnblock(ip string) WAFResult {
	f.calledWith = ip
	return f.ret
}

// findWAFStep returns the SrcWAF step from a result, or nil if absent.
func findWAFStep(r *Result) *Step {
	for i := range r.Steps {
		if r.Steps[i].Source == SrcWAF {
			return &r.Steps[i]
		}
	}
	return nil
}

func TestDo_WAFCleared(t *testing.T) {
	f := &fakeWAF{ret: WAFResult{
		Found: true,
		Cleared: []WAFFinding{
			{Plane: "challenge", Detail: "403waf_flood"},
			{Plane: "throttle", Detail: "2 keys"},
		},
	}}

	res, err := Do(context.Background(), net.ParseIP("1.2.3.4"), Options{WAF: f})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if f.calledWith != "1.2.3.4" {
		t.Fatalf("cleaner called with %q, want 1.2.3.4", f.calledWith)
	}
	if res.WAF == nil || !res.WAF.Found {
		t.Fatalf("res.WAF not populated: %+v", res.WAF)
	}
	step := findWAFStep(res)
	if step == nil {
		t.Fatal("expected a SrcWAF step, got none")
	}
	if step.Action != ActionRemoved {
		t.Fatalf("WAF step action = %q, want %q", step.Action, ActionRemoved)
	}
	// Summary is sorted, so order is deterministic regardless of slice order.
	if step.Detail != "challenge (403waf_flood), throttle (2 keys)" {
		t.Fatalf("unexpected WAF step detail: %q", step.Detail)
	}
}

func TestDo_WAFNotFound(t *testing.T) {
	f := &fakeWAF{ret: WAFResult{Found: false}}
	res, err := Do(context.Background(), net.ParseIP("1.2.3.4"), Options{WAF: f})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	step := findWAFStep(res)
	if step == nil || step.Action != ActionNotFound {
		t.Fatalf("expected a not_found WAF step, got %+v", step)
	}
}

func TestDo_WAFError(t *testing.T) {
	f := &fakeWAF{ret: WAFResult{Err: "daemon unreachable"}}
	res, _ := Do(context.Background(), net.ParseIP("1.2.3.4"), Options{WAF: f})
	step := findWAFStep(res)
	if step == nil || step.Action != ActionError || step.Err != "daemon unreachable" {
		t.Fatalf("expected an error WAF step, got %+v", step)
	}
}

func TestDo_NoWAFCleaner(t *testing.T) {
	res, err := Do(context.Background(), net.ParseIP("1.2.3.4"), Options{})
	if err != nil {
		t.Fatalf("Do returned error: %v", err)
	}
	if res.WAF != nil {
		t.Fatalf("res.WAF should be nil with no cleaner, got %+v", res.WAF)
	}
	if findWAFStep(res) != nil {
		t.Fatal("did not expect a SrcWAF step with no cleaner")
	}
}

func TestWAFResultSummary(t *testing.T) {
	cases := []struct {
		name string
		in   WAFResult
		want string
	}{
		{"empty", WAFResult{}, "no active WAF state"},
		{"err only", WAFResult{Err: "boom"}, "waf clear error: boom"},
		{"sorted", WAFResult{Cleared: []WAFFinding{{Plane: "throttle", Detail: "1 key"}, {Plane: "block", Detail: "abuse"}}}, "block (abuse), throttle (1 key)"},
		{"no detail", WAFResult{Cleared: []WAFFinding{{Plane: "geo"}}}, "geo"},
	}
	for _, c := range cases {
		if got := c.in.Summary(); got != c.want {
			t.Errorf("%s: Summary() = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestWAFCleanerHookRoundtrip(t *testing.T) {
	// Save/restore so this test does not leak global state into others.
	prev := WAFCleanerHook()
	t.Cleanup(func() {
		if prev != nil {
			SetWAFCleaner(prev)
		}
	})

	f := &fakeWAF{}
	SetWAFCleaner(f)
	if WAFCleanerHook() != f {
		t.Fatal("WAFCleanerHook did not return the registered cleaner")
	}
	// SetWAFCleaner(nil) must not clobber an existing cleaner.
	SetWAFCleaner(nil)
	if WAFCleanerHook() != f {
		t.Fatal("SetWAFCleaner(nil) clobbered the registered cleaner")
	}
}
