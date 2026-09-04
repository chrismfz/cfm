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

// ZFS pool degraded fires once on entry and re-fires after a recovery.
func TestDetectorZfsFaultPublish(t *testing.T) {
	var events []NodeFaultEvent
	SetNodeFaultEventSink(func(ev NodeFaultEvent) { events = append(events, ev) })
	defer SetNodeFaultEventSink(nil)

	d := New(Config{ZfsAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	bad := map[string]ZpoolStatus{"tank": {Pool: "tank", State: "DEGRADED", UnhealthyVdevs: 1}}

	d.evaluate(Snapshot{Time: base, Host: "h", Zfs: bad})                                                                                  // fire
	d.evaluate(Snapshot{Time: base.Add(time.Minute), Host: "h", Zfs: bad})                                                                 // no refire
	d.evaluate(Snapshot{Time: base.Add(2 * time.Minute), Host: "h", Zfs: map[string]ZpoolStatus{"tank": {Pool: "tank", State: "ONLINE"}}}) // recover
	d.evaluate(Snapshot{Time: base.Add(3 * time.Minute), Host: "h", Zfs: bad})                                                             // refire

	n := 0
	var first NodeFaultEvent
	for _, e := range events {
		if e.Type == "disk_zfs_degraded" {
			if n == 0 {
				first = e
			}
			n++
		}
	}
	if n != 2 {
		t.Fatalf("zfs should fire on entry and re-fire after recovery, got %d", n)
	}
	if first.Key != "tank" || first.Severity != "critical" || !strings.Contains(first.Message, "tank") {
		t.Errorf("zfs event wrong: %+v", first)
	}
}

// A previously-healthy disk that disappears fires disk_dead — after a short
// streak, once, re-armed on reappearance; a whole-scan failure never fires.
func TestDetectorDiskDeadPublish(t *testing.T) {
	var events []NodeFaultEvent
	SetNodeFaultEventSink(func(ev NodeFaultEvent) { events = append(events, ev) })
	defer SetNodeFaultEventSink(nil)
	deadCount := func() int {
		n := 0
		for _, e := range events {
			if e.Type == "disk_dead" {
				n++
			}
		}
		return n
	}

	d := New(Config{SmartAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	two := map[string]SmartInfo{"/dev/sda": {Health: "PASS"}, "/dev/sdb": {Health: "PASS"}}
	one := map[string]SmartInfo{"/dev/sda": {Health: "PASS"}}

	d.evaluate(Snapshot{Time: base, Host: "h", Smart: two}) // seed both healthy
	// sdb gone; must not fire until it has been absent for diskDeadMissingCycles.
	for i := 1; i < diskDeadMissingCycles; i++ {
		d.evaluate(Snapshot{Time: base.Add(time.Duration(i) * time.Minute), Host: "h", Smart: one})
		if deadCount() != 0 {
			t.Fatalf("must not fire before %d missing cycles (fired at %d)", diskDeadMissingCycles, i)
		}
	}
	d.evaluate(Snapshot{Time: base.Add(time.Duration(diskDeadMissingCycles) * time.Minute), Host: "h", Smart: one}) // streak == threshold → fire
	if deadCount() != 1 || events[len(events)-1].Key != "/dev/sdb" {
		t.Fatalf("expected 1 disk_dead for /dev/sdb, got %d: %+v", deadCount(), events)
	}

	// whole-scan failure (empty) must NOT fire disk_dead for the remaining disk
	d.evaluate(Snapshot{Time: base.Add(20 * time.Minute), Host: "h", Smart: map[string]SmartInfo{}})
	d.evaluate(Snapshot{Time: base.Add(21 * time.Minute), Host: "h", Smart: map[string]SmartInfo{}})
	if deadCount() != 1 {
		t.Fatalf("an empty scan must not mass-fire disk_dead, got %d", deadCount())
	}

	// sdb returns healthy (re-arm), then vanishes again → fires again
	d.evaluate(Snapshot{Time: base.Add(30 * time.Minute), Host: "h", Smart: two})
	for i := 1; i <= diskDeadMissingCycles; i++ {
		d.evaluate(Snapshot{Time: base.Add(time.Duration(30+i) * time.Minute), Host: "h", Smart: one})
	}
	if deadCount() != 2 {
		t.Fatalf("disk_dead should re-fire after reappear+revanish, got %d", deadCount())
	}
}

// A device that was never healthy (only ever FAIL / errored) does not fire
// disk_dead when it vanishes — it would have fired disk_smart_fail instead.
func TestDiskDeadIgnoresNeverHealthyDevice(t *testing.T) {
	var dead int
	SetNodeFaultEventSink(func(ev NodeFaultEvent) {
		if ev.Type == "disk_dead" {
			dead++
		}
	})
	defer SetNodeFaultEventSink(nil)

	d := New(Config{SmartAlert: true, Cooldown: time.Millisecond})
	base := time.Now()
	d.evaluate(Snapshot{Time: base, Host: "h", Smart: map[string]SmartInfo{"/dev/sda": {Health: "PASS"}, "/dev/sdc": {Health: "FAIL"}}})
	d.evaluate(Snapshot{Time: base.Add(1 * time.Minute), Host: "h", Smart: map[string]SmartInfo{"/dev/sda": {Health: "PASS"}}})
	d.evaluate(Snapshot{Time: base.Add(2 * time.Minute), Host: "h", Smart: map[string]SmartInfo{"/dev/sda": {Health: "PASS"}}})
	if dead != 0 {
		t.Fatalf("never-healthy device must not fire disk_dead, got %d", dead)
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
