package feedutil

import (
	"net"
	"reflect"
	"testing"
)

func TestNormalizeCIDRsV4_DropsContainedAndDedups(t *testing.T) {
	// 10.0.0.0/8 covers 10.1.0.0/16 and 10.1.2.0/24 → only the /8 survives.
	// 192.168.1.0/24 is disjoint → kept. Exact dup of the /8 dropped.
	in := []string{
		"10.1.0.0/16",
		"10.0.0.0/8",
		"10.1.2.0/24",
		"192.168.1.0/24",
		"10.0.0.0/8",
	}
	got := NormalizeCIDRsV4(in)
	want := []string{"10.0.0.0/8", "192.168.1.0/24"} // sorted by start asc
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeCIDRsV4_Canonicalizes(t *testing.T) {
	// A non-canonical network address is normalized to its masked form.
	got := NormalizeCIDRsV4([]string{"10.1.2.3/24"})
	want := []string{"10.1.2.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeCIDRsV4_SkipsInvalidAndNonCIDR(t *testing.T) {
	// bare IPs (no "/"), blanks and garbage are skipped; only valid CIDRs remain.
	got := NormalizeCIDRsV4([]string{"", "  ", "1.2.3.4", "not-a-cidr", "203.0.113.0/24"})
	want := []string{"203.0.113.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if NormalizeCIDRsV4(nil) != nil {
		t.Fatalf("nil input must return nil")
	}
}

// The regression the whole fix is about: an input with overlaps must come out
// with NO overlaps (so the kernel's interval set won't ENOTEMPTY). Verified by
// checking pairwise containment on the numeric ranges of the result.
func TestNormalizeCIDRsV4_ResultHasNoOverlaps(t *testing.T) {
	in := []string{
		"10.0.0.0/8", "10.10.0.0/16", "10.10.10.0/24", // nested
		"172.16.0.0/12", "172.16.5.0/24", // nested
		"192.0.2.0/24", // disjoint
		"10.0.0.0/8",   // dup
	}
	got := NormalizeCIDRsV4(in)
	type rng struct{ s, e uint32 }
	ranges := make([]rng, 0, len(got))
	for _, c := range got {
		// reuse the internal parser via cidrRangeV4 by re-parsing
		st, en := mustRangeV4(t, c)
		ranges = append(ranges, rng{st, en})
	}
	for i := 0; i < len(ranges); i++ {
		for j := i + 1; j < len(ranges); j++ {
			a, b := ranges[i], ranges[j]
			if a.s <= b.e && b.s <= a.e {
				t.Fatalf("overlap survived normalization: %v and %v (%v)", got[i], got[j], got)
			}
		}
	}
	// The three 10.* entries collapse to the /8; 172.16.5.0/24 folds into /12.
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.0.2.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestNormalizeCIDRsV6_DropsContainedAndDedups(t *testing.T) {
	in := []string{
		"2001:db8::/48",
		"2001:db8:0:1::/64", // contained in the /48
		"2001:db8::/32",     // covers the /48
		"2001:db8::/32",     // dup
		"2a00:1450::/32",    // disjoint
	}
	got := NormalizeCIDRsV6(in)
	want := []string{"2001:db8::/32", "2a00:1450::/32"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if NormalizeCIDRsV6(nil) != nil {
		t.Fatalf("nil input must return nil")
	}
}

// mustRangeV4 re-derives the numeric range of a canonical CIDR for the overlap
// assertion (kept local to the test so it doesn't widen the package surface).
func mustRangeV4(t *testing.T, cidr string) (uint32, uint32) {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("re-parse %q: %v", cidr, err)
	}
	return cidrRangeV4(ipnet)
}
