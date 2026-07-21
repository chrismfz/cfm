package clam

import "testing"

// The settable sink receives published events, a nil sink is a safe no-op, and
// a panicking sink is contained (must never take down a scanner worker).
func TestScanEventSink(t *testing.T) {
	t.Cleanup(func() { SetScanEventSink(nil) })

	var calls int
	var last ScanEvent
	SetScanEventSink(func(ev ScanEvent) { calls++; last = ev })

	publishScanEvent(ScanEvent{EventType: "clam_infected", Host: "a.example.com", Signature: "Eicar-Test"})
	if calls != 1 {
		t.Fatalf("sink calls = %d, want 1", calls)
	}
	if last.Host != "a.example.com" || last.Signature != "Eicar-Test" {
		t.Fatalf("delivered event wrong: %+v", last)
	}

	// Detach: publishing must not call the old sink or panic.
	SetScanEventSink(nil)
	publishScanEvent(ScanEvent{Host: "b.example.com"})
	if calls != 1 {
		t.Fatalf("sink called after detach: calls = %d", calls)
	}

	// A panicking sink is contained (no crash).
	SetScanEventSink(func(ScanEvent) { panic("boom") })
	publishScanEvent(ScanEvent{Host: "c.example.com"})
}
