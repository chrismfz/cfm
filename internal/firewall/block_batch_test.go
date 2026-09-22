package firewall

import (
	"net"
	"testing"
	"time"
)

func TestSplitBlockEntries(t *testing.T) {
	ip := net.ParseIP
	h := time.Hour
	v4, v6, skipped := SplitBlockEntries([]BlockEntry{
		{IP: ip("198.51.100.1"), TTL: h},
		{IP: nil},
		{IP: ip("0.0.0.0")},
		{IP: ip("198.51.100.2"), TTL: -time.Second}, // already expired
		{IP: ip("2001:db8::1"), TTL: 10 * time.Millisecond},
		{IP: ip("::ffff:198.51.100.3"), TTL: h},
		{IP: ip("198.51.100.1"), TTL: 2 * h}, // longer: wins
		{IP: ip("198.51.100.1"), TTL: h},     // shorter: ignored
		{IP: ip("198.51.100.3")},             // permanent beats a TTL
		{IP: ip("198.51.100.3"), TTL: 9 * h},
	})
	if skipped != 3 {
		t.Errorf("skipped = %d, want 3 (nil, unspecified, expired)", skipped)
	}
	if len(v4) != 2 || v4[0].IP.String() != "198.51.100.1" || v4[0].TTL != 2*h ||
		v4[1].IP.String() != "198.51.100.3" || v4[1].TTL != 0 || len(v4[1].IP) != net.IPv4len {
		t.Errorf("v4 = %+v, want .1 for 2h then .3 permanent (as a 4-byte v4 address), first-seen order", v4)
	}
	if len(v6) != 1 || v6[0].TTL != time.Second {
		t.Errorf("v6 = %+v, want one entry raised to the 1s timeout grain", v6)
	}
}

func TestPlanBlockBatch(t *testing.T) {
	ip := net.ParseIP
	h := time.Hour
	current := []SetElementTimed{
		{Elem: "198.51.100.10"},                            // permanent
		{Elem: "198.51.100.11", Expires: 30 * time.Minute}, // 30m left
		{Elem: "198.51.100.12", Expires: h - 30*time.Second},
		{Elem: "10.0.0.0/8"}, // an interval element: not a host block
	}
	plan := PlanBlockBatch([]BlockEntry{
		{IP: ip("198.51.100.1"), TTL: h},  // absent: add
		{IP: ip("198.51.100.10"), TTL: h}, // permanent: keep
		{IP: ip("198.51.100.11"), TTL: h}, // 30m < 1h: extend
		{IP: ip("198.51.100.12"), TTL: h}, // within the slack of 1h: keep
	}, current)
	want := []PlannedBlock{
		{BlockEntry: BlockEntry{IP: ip("198.51.100.1"), TTL: h}},
		{BlockEntry: BlockEntry{IP: ip("198.51.100.11"), TTL: h}, Replace: true},
	}
	if plan.Kept != 2 || len(plan.Writes) != len(want) {
		t.Fatalf("plan = %+v, want 2 kept and writes %+v", plan, want)
	}
	for i := range want {
		if !plan.Writes[i].IP.Equal(want[i].IP) || plan.Writes[i].TTL != want[i].TTL || plan.Writes[i].Replace != want[i].Replace {
			t.Errorf("write %d = %+v, want %+v", i, plan.Writes[i], want[i])
		}
	}
	if r := plan.Result(); r != (BlockBatchResult{Added: 1, Extended: 1, Kept: 2}) {
		t.Errorf("Result() = %+v", r)
	}

	// Asking for permanent replaces a timed block, never a permanent one.
	perm := PlanBlockBatch([]BlockEntry{{IP: ip("198.51.100.11")}, {IP: ip("198.51.100.10")}}, current)
	if perm.Kept != 1 || len(perm.Writes) != 1 || !perm.Writes[0].Replace || perm.Writes[0].TTL != 0 {
		t.Errorf("permanent over timed/permanent: %+v", perm)
	}

	// The slack is 5% of the TTL, at most a minute: a short block with
	// seconds left is still extended.
	short := PlanBlockBatch([]BlockEntry{{IP: ip("198.51.100.13"), TTL: 50 * time.Second}},
		[]SetElementTimed{{Elem: "198.51.100.13", Expires: time.Second}})
	if len(short.Writes) != 1 || !short.Writes[0].Replace {
		t.Errorf("a 50s block with 1s left must be extended: %+v", short)
	}
}
