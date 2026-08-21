package nft

import (
	"errors"
	"net"
	"sort"
	"testing"
	"time"

	"cfm/internal/firewall"
)

func TestPlanManualBlockReconcile(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	want := map[string]net.IP{}
	for _, s := range []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"} {
		want[ip(s).String()] = ip(s)
	}
	present := []firewall.SetElementTimed{
		{Elem: "1.2.3.4"}, // permanent present → skip
		{Elem: "5.6.7.8", Expires: 5 * time.Minute}, // timed present → overlap (re-add permanent)
		// 9.9.9.9 absent → missing
		{Elem: "203.0.113.9", Expires: time.Hour}, // unrelated present → ignored
	}

	missing, overlap := planManualBlockReconcile(want, present)

	sort.Strings(missing)
	if len(missing) != 1 || missing[0] != "9.9.9.9" {
		t.Fatalf("missing = %v, want [9.9.9.9]", missing)
	}
	if len(overlap) != 1 || overlap[0].String() != "5.6.7.8" {
		t.Fatalf("overlap = %v, want [5.6.7.8]", overlap)
	}
}

func TestPlanManualBlockReconcile_IPv6Canonical(t *testing.T) {
	// want keyed by Go's canonical form; present uses a fully-expanded but equal
	// address — it must still be recognized as present (not re-added).
	w := net.ParseIP("2001:db8::1")
	want := map[string]net.IP{w.String(): w}
	present := []firewall.SetElementTimed{{Elem: " 2001:0db8:0000:0000:0000:0000:0000:0001 "}}

	missing, overlap := planManualBlockReconcile(want, present)
	if len(missing) != 0 || len(overlap) != 0 {
		t.Fatalf("expected present IPv6 to be skipped; missing=%v overlap=%v", missing, overlap)
	}
}

func TestPlanManualBlockReconcile_EmptyPresent(t *testing.T) {
	a, b := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	want := map[string]net.IP{a.String(): a, b.String(): b}

	missing, overlap := planManualBlockReconcile(want, nil)
	if len(overlap) != 0 {
		t.Fatalf("overlap = %v, want none", overlap)
	}
	sort.Strings(missing)
	if len(missing) != 2 || missing[0] != "10.0.0.1" || missing[1] != "10.0.0.2" {
		t.Fatalf("missing = %v, want both addresses", missing)
	}
}

// A malformed present element (not parseable as an IP) must be ignored, not
// crash or mask a desired address.
func TestPlanManualBlockReconcile_IgnoresUnparseablePresent(t *testing.T) {
	a := net.ParseIP("172.16.5.5")
	want := map[string]net.IP{a.String(): a}
	present := []firewall.SetElementTimed{{Elem: "not-an-ip"}, {Elem: ""}}

	missing, overlap := planManualBlockReconcile(want, present)
	if len(overlap) != 0 {
		t.Fatalf("overlap = %v, want none", overlap)
	}
	if len(missing) != 1 || missing[0] != "172.16.5.5" {
		t.Fatalf("missing = %v, want [172.16.5.5]", missing)
	}
}

func TestBucketHostsByFamily(t *testing.T) {
	ips := []net.IP{
		net.ParseIP("1.2.3.4"),        // v4
		net.ParseIP("1.2.3.4"),        // v4 dup → deduped
		net.ParseIP("::ffff:9.9.9.9"), // IPv4-mapped → v4 bucket, keyed "9.9.9.9"
		net.ParseIP("2001:db8::1"),    // v6
		nil,                           // dropped
	}
	v4, v6 := bucketHostsByFamily(ips)

	if len(v4) != 2 {
		t.Fatalf("v4 = %v, want 2 entries (1.2.3.4, 9.9.9.9)", v4)
	}
	if _, ok := v4["1.2.3.4"]; !ok {
		t.Fatalf("v4 missing 1.2.3.4: %v", v4)
	}
	if _, ok := v4["9.9.9.9"]; !ok {
		t.Fatalf("IPv4-mapped address should bucket as v4 keyed 9.9.9.9: %v", v4)
	}
	if len(v6) != 1 {
		t.Fatalf("v6 = %v, want 1 entry (2001:db8::1)", v6)
	}
	if _, ok := v6["2001:db8::1"]; !ok {
		t.Fatalf("v6 missing 2001:db8::1: %v", v6)
	}
}

// --- reconcileFamilyBlocks fallback / racy branches (injected fakes) ---

func wantIPs(ss ...string) map[string]net.IP {
	m := map[string]net.IP{}
	for _, s := range ss {
		ip := net.ParseIP(s)
		m[ip.String()] = ip
	}
	return m
}

func TestReconcileFamilyBlocks_Success(t *testing.T) {
	// Empty set → everything is "missing" and goes through bulkAdd once; no
	// per-IP addOne, no failures.
	var bulkCalls, addOneCalls int
	list := func(string) ([]firewall.SetElementTimed, error) { return nil, nil }
	bulk := func(_ string, elems []string) error { bulkCalls++; return nil }
	add := func(net.IP) error { addOneCalls++; return nil }

	failed := reconcileFamilyBlocks("block_v4", wantIPs("1.1.1.1", "2.2.2.2"), list, bulk, add)
	if len(failed) != 0 || bulkCalls != 1 || addOneCalls != 0 {
		t.Fatalf("success path: failed=%v bulkCalls=%d addOneCalls=%d", failed, bulkCalls, addOneCalls)
	}
}

func TestReconcileFamilyBlocks_ListErrorFallsBackPerIP(t *testing.T) {
	// Set can't be read → every want IP goes per-IP; the one that fails is
	// reported.
	list := func(string) ([]firewall.SetElementTimed, error) { return nil, errors.New("nft down") }
	bulk := func(string, []string) error { t.Fatalf("bulkAdd must not be called on list error"); return nil }
	add := func(ip net.IP) error {
		if ip.String() == "2.2.2.2" {
			return errors.New("add failed")
		}
		return nil
	}

	failed := reconcileFamilyBlocks("block_v4", wantIPs("1.1.1.1", "2.2.2.2"), list, bulk, add)
	if len(failed) != 1 || failed[0].String() != "2.2.2.2" {
		t.Fatalf("list-error fallback: failed=%v, want [2.2.2.2]", failed)
	}
}

func TestReconcileFamilyBlocks_BatchErrorFallsBackPerIP(t *testing.T) {
	// bulkAdd fails → the missing IPs are retried per-IP; a per-IP failure is
	// reported, a success is not.
	var addOneCalls int
	list := func(string) ([]firewall.SetElementTimed, error) { return nil, nil }
	bulk := func(string, []string) error { return errors.New("File exists") }
	add := func(ip net.IP) error {
		addOneCalls++
		if ip.String() == "2.2.2.2" {
			return errors.New("still failing")
		}
		return nil
	}

	failed := reconcileFamilyBlocks("block_v4", wantIPs("1.1.1.1", "2.2.2.2"), list, bulk, add)
	if addOneCalls != 2 {
		t.Fatalf("batch-error fallback should retry both per-IP, got %d", addOneCalls)
	}
	if len(failed) != 1 || failed[0].String() != "2.2.2.2" {
		t.Fatalf("batch-error fallback: failed=%v, want [2.2.2.2]", failed)
	}
}

func TestReconcileFamilyBlocks_BulkRetryAfterRace(t *testing.T) {
	// bulkAdd fails once (a raced element already exists); the re-list shows two
	// of the three now present, so the retry bulk-adds only the still-missing one
	// and no per-IP fallback is needed.
	want := wantIPs("1.1.1.1", "2.2.2.2", "3.3.3.3")
	listCalls := 0
	list := func(string) ([]firewall.SetElementTimed, error) {
		listCalls++
		if listCalls == 1 {
			return nil, nil // empty → all three missing
		}
		return []firewall.SetElementTimed{{Elem: "1.1.1.1"}, {Elem: "2.2.2.2"}}, nil
	}
	bulkCalls := 0
	var lastBulk []string
	bulk := func(_ string, elems []string) error {
		bulkCalls++
		lastBulk = append([]string(nil), elems...)
		if bulkCalls == 1 {
			return errors.New("File exists")
		}
		return nil
	}
	addOneCalls := 0
	add := func(net.IP) error { addOneCalls++; return nil }

	failed := reconcileFamilyBlocks("block_v4", want, list, bulk, add)
	if len(failed) != 0 {
		t.Fatalf("unexpected failures: %v", failed)
	}
	if bulkCalls != 2 {
		t.Fatalf("bulkCalls=%d, want 2 (initial + retry)", bulkCalls)
	}
	if addOneCalls != 0 {
		t.Fatalf("retry succeeded, so no per-IP fallback expected; addOneCalls=%d", addOneCalls)
	}
	if len(lastBulk) != 1 || lastBulk[0] != "3.3.3.3" {
		t.Fatalf("retry bulk should carry only the still-missing IP, got %v", lastBulk)
	}
}

func TestReconcileFamilyBlocks_RetryReassertsRacedTimed(t *testing.T) {
	// bulkAdd fails; the re-list shows one wanted IP raced into a TIMED block. It
	// must be re-asserted permanent per-IP (not left to expire), and the
	// still-missing IP is bulk-retried.
	want := wantIPs("1.1.1.1", "2.2.2.2")
	listCalls := 0
	list := func(string) ([]firewall.SetElementTimed, error) {
		listCalls++
		if listCalls == 1 {
			return nil, nil // empty → both missing
		}
		return []firewall.SetElementTimed{{Elem: "1.1.1.1", Expires: 10 * time.Minute}}, nil
	}
	bulkCalls := 0
	var lastBulk []string
	bulk := func(_ string, elems []string) error {
		bulkCalls++
		lastBulk = append([]string(nil), elems...)
		if bulkCalls == 1 {
			return errors.New("File exists")
		}
		return nil
	}
	var reasserted []string
	add := func(ip net.IP) error { reasserted = append(reasserted, ip.String()); return nil }

	failed := reconcileFamilyBlocks("block_v4", want, list, bulk, add)
	if len(failed) != 0 {
		t.Fatalf("unexpected failures: %v", failed)
	}
	if len(reasserted) != 1 || reasserted[0] != "1.1.1.1" {
		t.Fatalf("raced-timed IP should be re-asserted permanent per-IP, got %v", reasserted)
	}
	if len(lastBulk) != 1 || lastBulk[0] != "2.2.2.2" {
		t.Fatalf("retry bulk should carry only the still-missing IP, got %v", lastBulk)
	}
}

func TestReconcileFamilyBlocks_PerIPWhenRetryAlsoFails(t *testing.T) {
	// Both the initial bulk and the retry fail → fall back per-IP over the
	// still-missing set; a per-IP failure is reported.
	want := wantIPs("1.1.1.1", "2.2.2.2")
	list := func(string) ([]firewall.SetElementTimed, error) { return nil, nil } // always empty
	bulk := func(string, []string) error { return errors.New("nope") }           // always fails
	addOneCalls := 0
	add := func(ip net.IP) error {
		addOneCalls++
		if ip.String() == "2.2.2.2" {
			return errors.New("still failing")
		}
		return nil
	}

	failed := reconcileFamilyBlocks("block_v4", want, list, bulk, add)
	if addOneCalls != 2 {
		t.Fatalf("per-IP fallback should try both, got %d", addOneCalls)
	}
	if len(failed) != 1 || failed[0].String() != "2.2.2.2" {
		t.Fatalf("failed=%v, want [2.2.2.2]", failed)
	}
}

func TestReconcileFamilyBlocks_TimedOverlapReasserted(t *testing.T) {
	// One desired IP is present as a timed element → it is re-asserted per-IP
	// (overlap), the other is missing → bulk. Nothing fails.
	var overlapReasserted []string
	list := func(string) ([]firewall.SetElementTimed, error) {
		return []firewall.SetElementTimed{{Elem: "1.1.1.1", Expires: 10 * time.Minute}}, nil
	}
	bulk := func(_ string, elems []string) error {
		if len(elems) != 1 || elems[0] != "2.2.2.2" {
			t.Fatalf("bulk should get only the missing IP, got %v", elems)
		}
		return nil
	}
	add := func(ip net.IP) error { overlapReasserted = append(overlapReasserted, ip.String()); return nil }

	failed := reconcileFamilyBlocks("block_v4", wantIPs("1.1.1.1", "2.2.2.2"), list, bulk, add)
	if len(failed) != 0 {
		t.Fatalf("unexpected failures: %v", failed)
	}
	if len(overlapReasserted) != 1 || overlapReasserted[0] != "1.1.1.1" {
		t.Fatalf("timed overlap should be re-asserted per-IP, got %v", overlapReasserted)
	}
}
