package mailq

import (
	"testing"
	"time"
)

func TestPublishLatest_FreshestWins(t *testing.T) {
	TestOnlyReset()
	t.Cleanup(TestOnlyReset)

	if _, ok := Latest(); ok {
		t.Fatalf("empty store must report ok=false")
	}

	now := time.Now()
	Publish(Measurement{MTA: "exim", Total: 12, Frozen: 2, MeasuredAt: now.Add(-time.Minute)})
	Publish(Measurement{MTA: "postfix", Total: 3, MeasuredAt: now})

	m, ok := Latest()
	if !ok || m.MTA != "postfix" || m.Total != 3 {
		t.Fatalf("freshest measurement should win, got %+v ok=%v", m, ok)
	}

	// Newer exim reading takes over again.
	Publish(Measurement{MTA: "exim", Total: 40, Frozen: 5, MeasuredAt: now.Add(time.Second)})
	m, _ = Latest()
	if m.MTA != "exim" || m.Total != 40 || m.Frozen != 5 {
		t.Fatalf("expected newer exim measurement, got %+v", m)
	}
}

func TestPublish_IgnoresEmptyMTAAndDefaultsTime(t *testing.T) {
	TestOnlyReset()
	t.Cleanup(TestOnlyReset)

	Publish(Measurement{Total: 99})
	if _, ok := Latest(); ok {
		t.Fatalf("empty MTA must be ignored")
	}

	Publish(Measurement{MTA: "exim", Total: 1})
	m, ok := Latest()
	if !ok || m.MeasuredAt.IsZero() {
		t.Fatalf("MeasuredAt should default to now, got %+v ok=%v", m, ok)
	}
}
