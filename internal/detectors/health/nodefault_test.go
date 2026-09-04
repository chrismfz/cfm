package health

import (
	"strings"
	"testing"
	"time"
)

// SMART-fail and mdadm-degraded publish a durable fault event once when the
// condition is ENTERED (including at first sight if already faulted), never
// re-firing while it persists — including across a transient/errored SMART probe
// (Health == "") — and re-arm only after a definite recovery.
func TestDetectorSmartMdadmFaultPublish(t *testing.T) {
	var events []NodeFaultEvent
	SetNodeFaultEventSink(func(ev NodeFaultEvent) { events = append(events, ev) })
	defer SetNodeFaultEventSink(nil)

	d := New(Config{SmartAlert: true, MdadmAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	degraded := MdstatSummary{Status: "DEGRADED", Arrays: []MdArrayInfo{{Name: "md0", ExpectedMembers: 2, ActiveMembers: 1, FailedMissing: 1}}}

	// cycle 1: sda already FAIL at first sight + array degraded → 2 events
	d.evaluate(Snapshot{Time: base, Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL", Model: "WD40"}, "/dev/sdb": {Health: "PASS"}},
		Mdadm: degraded})
	// cycle 2: sda probe ERRORED (Health "") — must NOT re-arm the edge
	d.evaluate(Snapshot{Time: base.Add(time.Minute), Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "", Error: "smartctl timeout"}, "/dev/sdb": {Health: "PASS"}},
		Mdadm: degraded})
	// cycle 3: sda reads FAIL again — still no re-fire (edge held through the "")
	d.evaluate(Snapshot{Time: base.Add(2 * time.Minute), Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL"}, "/dev/sdb": {Health: "PASS"}},
		Mdadm: degraded})
	// cycle 4: sdb now FAIL (new), array recovered (no event, re-arms mdadm)
	d.evaluate(Snapshot{Time: base.Add(3 * time.Minute), Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL"}, "/dev/sdb": {Health: "FAIL"}},
		Mdadm: MdstatSummary{Status: "HEALTHY"}})

	smart := map[string]NodeFaultEvent{}
	smartCount := map[string]int{}
	mdadm := 0
	for _, e := range events {
		switch e.Type {
		case "disk_smart_fail":
			smart[e.Key] = e
			smartCount[e.Key]++
		case "disk_mdadm_degraded":
			mdadm++
		}
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 fault events (sda, md0, sdb), got %d: %+v", len(events), events)
	}
	if mdadm != 1 {
		t.Errorf("mdadm should fire once on entry, got %d", mdadm)
	}
	if smartCount["/dev/sda"] != 1 {
		t.Errorf("sda must fire exactly once despite the errored-probe cycle, got %d", smartCount["/dev/sda"])
	}
	if smartCount["/dev/sdb"] != 1 {
		t.Errorf("sdb should fire once when it turns FAIL, got %d", smartCount["/dev/sdb"])
	}
	if e := smart["/dev/sda"]; e.Severity != "critical" || !strings.Contains(e.Message, "FAIL on /dev/sda") || !strings.Contains(e.Message, "WD40") {
		t.Errorf("sda message/severity wrong: %+v", e)
	}

	// cycle 5: array degraded again → re-fires (edge re-armed after recovery)
	d.evaluate(Snapshot{Time: base.Add(4 * time.Minute), Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL"}, "/dev/sdb": {Health: "FAIL"}},
		Mdadm: degraded})
	mdadm2 := 0
	for _, e := range events {
		if e.Type == "disk_mdadm_degraded" {
			mdadm2++
		}
	}
	if mdadm2 != 2 {
		t.Errorf("mdadm should re-fire after recovery, got %d total", mdadm2)
	}
}

// A fault present before the persister has registered its sink is retried, not
// dropped: the edge advances only on a delivered publish.
func TestDetectorFaultRetriedUntilSinkRegistered(t *testing.T) {
	SetNodeFaultEventSink(nil) // no sink yet
	d := New(Config{SmartAlert: true, Cooldown: time.Millisecond})
	base := time.Now()

	d.evaluate(Snapshot{Time: base, Host: "h", Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL"}}})
	if d.lastSmartFailed["/dev/sda"] {
		t.Fatal("edge must NOT advance while the publish had no sink")
	}

	var events []NodeFaultEvent
	SetNodeFaultEventSink(func(ev NodeFaultEvent) { events = append(events, ev) })
	defer SetNodeFaultEventSink(nil)

	d.evaluate(Snapshot{Time: base.Add(time.Minute), Host: "h", Smart: map[string]SmartInfo{"/dev/sda": {Health: "FAIL"}}})
	if len(events) != 1 || !d.lastSmartFailed["/dev/sda"] {
		t.Fatalf("once the sink is registered the fault fires once and the edge advances; events=%d", len(events))
	}
}

// A healthy fleet publishes nothing.
func TestDetectorNoFaultWhenHealthy(t *testing.T) {
	var n int
	SetNodeFaultEventSink(func(NodeFaultEvent) { n++ })
	defer SetNodeFaultEventSink(nil)
	d := New(Config{SmartAlert: true, MdadmAlert: true, Cooldown: time.Millisecond})
	d.evaluate(Snapshot{Time: time.Now(), Host: "h",
		Smart: map[string]SmartInfo{"/dev/sda": {Health: "PASS"}},
		Mdadm: MdstatSummary{Status: "HEALTHY"}})
	if n != 0 {
		t.Fatalf("healthy box must not publish, got %d", n)
	}
}

func TestMdadmFaultMessage(t *testing.T) {
	m := MdstatSummary{Status: "DEGRADED", Arrays: []MdArrayInfo{
		{Name: "md0", ExpectedMembers: 2, ActiveMembers: 2},                   // healthy — excluded
		{Name: "md1", ExpectedMembers: 3, ActiveMembers: 2, FailedMissing: 1}, // degraded
	}}
	got := mdadmFaultMessage(m)
	if !strings.Contains(got, "md1 (2/3 members)") || strings.Contains(got, "md0") {
		t.Errorf("mdadm message wrong: %q", got)
	}
}
