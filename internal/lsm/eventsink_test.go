//go:build linux

package lsm

import (
	"strings"
	"testing"
	"time"
)

// freshSink returns a sink with the given cap that has no recorded
// history — keeps tests independent of package-global state.
func freshSink(cap int) *eventSink {
	return &eventSink{
		cfg:  EventSinkConf{DetectRatePerMin: cap},
		rate: map[PolicyID]*eventRateBucket{},
	}
}

func TestEventSink_AllowsUpToCapAndSuppressesPastIt(t *testing.T) {
	s := freshSink(3)
	base := time.Unix(1_700_000_000, 0)

	// First 3 in the same second pass.
	for i := 0; i < 3; i++ {
		allow, summary := s.rateAllow(PolicyCredEscal, 3, base.Add(time.Duration(i)*time.Millisecond))
		if !allow {
			t.Fatalf("event %d unexpectedly suppressed", i)
		}
		if summary != "" {
			t.Fatalf("event %d produced summary on first window: %q", i, summary)
		}
	}
	// 4th and 5th inside the same window are suppressed and produce
	// no summary yet (summary only fires when the window rolls).
	for i := 3; i < 5; i++ {
		allow, summary := s.rateAllow(PolicyCredEscal, 3, base.Add(time.Duration(i)*time.Millisecond))
		if allow {
			t.Fatalf("event %d should be suppressed (cap=3)", i)
		}
		if summary != "" {
			t.Fatalf("event %d emitted summary before window roll: %q", i, summary)
		}
	}
}

func TestEventSink_EmitsSummaryOnWindowRoll(t *testing.T) {
	s := freshSink(1)
	base := time.Unix(1_700_000_000, 0)

	// Window 1: allow one, suppress one.
	if allow, _ := s.rateAllow(PolicyCredEscal, 1, base); !allow {
		t.Fatal("first event must pass cap=1")
	}
	if allow, _ := s.rateAllow(PolicyCredEscal, 1, base.Add(time.Second)); allow {
		t.Fatal("second event in same window must be suppressed")
	}

	// Roll past 60s; the bucket must emit a summary for the previous
	// window's suppressed events AND allow the new event.
	allow, summary := s.rateAllow(PolicyCredEscal, 1, base.Add(61*time.Second))
	if !allow {
		t.Fatal("event after roll must be allowed")
	}
	if summary == "" {
		t.Fatal("window roll with suppressed>0 must produce a summary")
	}
	if want := "CFML-CRED-002 suppressed=1 in_last=60s"; !strings.Contains(summary, want) {
		t.Errorf("summary %q missing %q", summary, want)
	}
}

func TestEventSink_NoSummaryWhenNothingSuppressed(t *testing.T) {
	s := freshSink(10)
	base := time.Unix(1_700_000_000, 0)

	if _, summary := s.rateAllow(PolicyMemfdExec, 10, base); summary != "" {
		t.Errorf("first event in a window must not produce a summary: %q", summary)
	}
	// Skip past the window without ever exceeding the cap.
	if _, summary := s.rateAllow(PolicyMemfdExec, 10, base.Add(61*time.Second)); summary != "" {
		t.Errorf("roll with zero suppressed must not produce a summary: %q", summary)
	}
}

func TestEventSink_ZeroCapDisablesGating(t *testing.T) {
	s := freshSink(0)
	base := time.Unix(1_700_000_000, 0)

	// Hammer the bucket — every call must pass.
	for i := 0; i < 1000; i++ {
		allow, summary := s.rateAllow(PolicyCredEscal, 0, base.Add(time.Duration(i)*time.Microsecond))
		if !allow {
			t.Fatalf("event %d was suppressed even though rate=0 means uncapped", i)
		}
		if summary != "" {
			t.Fatalf("event %d emitted a summary with rate=0: %q", i, summary)
		}
	}
}

// TestEventSink_NegativeCapTreatedAsUncapped guards against the
// subtle bug where a negative cap would otherwise satisfy
// `emitted >= ratePerMin` on the very first event and suppress
// everything. ParseConf already rejects negatives, but
// ConfigureEventSink is public and a future caller could pass one in.
func TestEventSink_NegativeCapTreatedAsUncapped(t *testing.T) {
	s := freshSink(-5)
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < 50; i++ {
		allow, _ := s.rateAllow(PolicyCredEscal, -5, base.Add(time.Duration(i)*time.Millisecond))
		if !allow {
			t.Fatalf("event %d suppressed with negative cap (must be treated as uncapped)", i)
		}
	}
}

func TestEventSink_BucketsAreIndependentPerPolicy(t *testing.T) {
	s := freshSink(1)
	base := time.Unix(1_700_000_000, 0)

	// Cap=1, one of each policy in the same window — both must pass
	// because the buckets are per-policy.
	if allow, _ := s.rateAllow(PolicyCredEscal, 1, base); !allow {
		t.Fatal("CRED-002 first must pass")
	}
	if allow, _ := s.rateAllow(PolicyMemfdExec, 1, base); !allow {
		t.Fatal("EXEC-001 first must pass (separate bucket)")
	}
	// Second hit on each must be suppressed.
	if allow, _ := s.rateAllow(PolicyCredEscal, 1, base.Add(time.Millisecond)); allow {
		t.Fatal("CRED-002 second must be suppressed")
	}
	if allow, _ := s.rateAllow(PolicyMemfdExec, 1, base.Add(time.Millisecond)); allow {
		t.Fatal("EXEC-001 second must be suppressed")
	}
}

func TestParseConf_EventsSection(t *testing.T) {
	body := `enabled = true
[events]
detect_rate_per_min = 7
`
	c, err := ParseConf(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := c.EventSink.DetectRatePerMin, 7; got != want {
		t.Errorf("EventSink.DetectRatePerMin = %d, want %d", got, want)
	}
}

func TestParseConf_EventsSection_Default(t *testing.T) {
	// No [events] section — must fall back to DefaultEventSinkConf.
	c, err := ParseConf(strings.NewReader("enabled = true\n"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := c.EventSink.DetectRatePerMin, DefaultEventSinkConf().DetectRatePerMin; got != want {
		t.Errorf("EventSink default = %d, want %d", got, want)
	}
}

func TestParseConf_EventsSection_RejectsNegative(t *testing.T) {
	body := `[events]
detect_rate_per_min = -1
`
	_, err := ParseConf(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected parse error for negative detect_rate_per_min")
	}
}

func TestParseConf_EventsSection_RejectsUnknownKey(t *testing.T) {
	body := `[events]
unknown_key = 5
`
	_, err := ParseConf(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected parse error for unknown [events] key")
	}
}

func TestParseConf_EventsSection_RejectsDuplicate(t *testing.T) {
	body := `[events]
detect_rate_per_min = 5
[events]
detect_rate_per_min = 6
`
	_, err := ParseConf(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected parse error for duplicate [events] section")
	}
}

func TestFormatConf_EventsRoundTrip(t *testing.T) {
	original := DefaultConf()
	original.EventSink.DetectRatePerMin = 42

	rendered := FormatConf(original)
	parsed, err := ParseConf(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("ParseConf(FormatConf): %v\n--- rendered ---\n%s", err, rendered)
	}
	if got, want := parsed.EventSink.DetectRatePerMin, 42; got != want {
		t.Errorf("after round-trip: %d, want %d\n--- rendered ---\n%s", got, want, rendered)
	}
}

