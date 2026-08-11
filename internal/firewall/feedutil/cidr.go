package feedutil

// CIDR normalization for interval (nets) sets: canonicalize, dedup, and DROP
// overlaps/contained subnets. Both firewall backends must do this before writing
// a *_nets set — the exec-nft path relied on `nft` doing it, but the netlink
// (nftlib) path sends elements straight to the kernel, which REJECTS overlapping
// interval elements with ENOTEMPTY ("directory not empty"). Sharing one
// implementation here keeps the two backends from drifting.
//
// The logic was moved verbatim from the nft backend (its long-standing
// normalizeCIDRsV4/V6); behaviour is unchanged.

import (
	"math/big"
	"net"
	"strconv"
	"strings"
)

// ---------- IPv4 ----------

type v4range struct {
	start uint32
	end   uint32
	cidr  string
}

func ip4ToU32(ip net.IP) uint32 {
	ip4 := ip.To4()
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}

func cidrRangeV4(c *net.IPNet) (uint32, uint32) {
	network := c.IP.Mask(c.Mask).To4()
	start := ip4ToU32(network)
	ones, bits := c.Mask.Size()
	// host count = 2^(bits-ones)
	host := uint32(1)<<(uint(bits-ones)) - 1
	end := start + host
	return start, end
}

func maskOnes(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}

// NormalizeCIDRsV4 canonicalizes, dedups and drops contained/overlapping IPv4
// CIDRs, returning a set safe to load into an nftables interval set. Entries that
// are not IPv4 CIDRs (blank, non-CIDR, or an IPv6 CIDR) are skipped rather than
// indexed blindly — feeding a v6 CIDR to the v4 range math would panic
// (index-out-of-range on a nil To4()), which in a feed goroutine with no
// recover() would crash-loop the daemon.
func NormalizeCIDRsV4(in []string) []string {
	// parse + canonicalize + dedup
	seen := make(map[string]struct{})
	var arr []v4range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() == nil { // not an IPv4 CIDR — wrong family, skip
			continue
		}
		// canonical cidr string
		canon := ipnet.IP.Mask(ipnet.Mask).String() + "/" + strconv.Itoa(maskOnes(ipnet.Mask))
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV4(ipnet)
		arr = append(arr, v4range{start: st, end: en, cidr: canon})
	}

	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc (so the super-range comes first)
	sortFunc := func(i, j int) bool {
		if arr[i].start == arr[j].start {
			return arr[i].end > arr[j].end
		}
		return arr[i].start < arr[j].start
	}
	// local insertion sort to avoid an extra import
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && sortFunc(j, j-1); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	var coverEnd uint32 = 0
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// current starts within an already-covered range and ends before/at coverEnd => contained → drop
		if r.start <= coverEnd && r.end <= coverEnd {
			continue
		}
		// outside coverage → keep
		if r.start > coverEnd {
			out = append(out, r.cidr)
			coverEnd = r.end
			continue
		}
		// partial overlap shouldn't happen with CIDRs, but keep the new one to be safe
		if r.end > coverEnd {
			out = append(out, r.cidr)
			coverEnd = r.end
		}
	}
	return out
}

// ---------- IPv6 ----------

type v6range struct {
	start *big.Int
	end   *big.Int
	cidr  string
}

func ip6ToBig(ip net.IP) *big.Int {
	ip = ip.To16()
	return new(big.Int).SetBytes(ip)
}

func cidrRangeV6(n *net.IPNet) (*big.Int, *big.Int) {
	base := ip6ToBig(n.IP.Mask(n.Mask))
	ones, bits := n.Mask.Size()
	rem := uint(bits - ones)
	hostCount := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), rem), big.NewInt(1))
	end := new(big.Int).Add(base, hostCount)
	return base, end
}

// NormalizeCIDRsV6 is the IPv6 counterpart of NormalizeCIDRsV4. Entries that are
// not IPv6 CIDRs (blank, non-CIDR, or an IPv4 CIDR) are skipped — see the
// wrong-family note on NormalizeCIDRsV4.
func NormalizeCIDRsV6(in []string) []string {
	seen := make(map[string]struct{})
	var arr []v6range
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || strings.IndexByte(s, '/') == -1 {
			continue
		}
		_, ipnet, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		if ipnet.IP.To4() != nil { // an IPv4 CIDR — wrong family, skip
			continue
		}
		ipnet.IP = ipnet.IP.Mask(ipnet.Mask)
		canon := ipnet.String()
		if _, ok := seen[canon]; ok {
			continue
		}
		seen[canon] = struct{}{}
		st, en := cidrRangeV6(ipnet)
		arr = append(arr, v6range{start: st, end: en, cidr: canon})
	}
	if len(arr) == 0 {
		return nil
	}

	// sort: start asc, end desc
	less := func(a, b v6range) bool {
		c := a.start.Cmp(b.start)
		if c == 0 {
			return a.end.Cmp(b.end) > 0
		}
		return c < 0
	}
	for i := 1; i < len(arr); i++ {
		for j := i; j > 0 && less(arr[j], arr[j-1]); j-- {
			arr[j], arr[j-1] = arr[j-1], arr[j]
		}
	}

	out := make([]string, 0, len(arr))
	coverEnd := new(big.Int).SetUint64(0)
	for _, r := range arr {
		if len(out) == 0 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		if r.start.Cmp(coverEnd) <= 0 && r.end.Cmp(coverEnd) <= 0 {
			// contained
			continue
		}
		if r.start.Cmp(coverEnd) == 1 {
			// disjoint → keep
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
			continue
		}
		// unexpected partial: keep and extend cover
		if r.end.Cmp(coverEnd) == 1 {
			out = append(out, r.cidr)
			coverEnd = new(big.Int).Set(r.end)
		}
	}
	return out
}

// ---------- set-name keying (shared by both backends) ----------

// NormalizeNetsForSet de-overlaps the CIDRs of an interval ("nets") set,
// selecting the address family from the set name. A non-nets set name (a
// "_hosts" set or anything without a family token) returns elems unchanged.
//
// The family token (`_v4_nets` / `_v6_nets`) always appears immediately after
// the set's base prefix, and any feed-name suffix is appended AFTER it (e.g.
// `block_ext_v6_nets_<feedKey>`). A sanitized feed name can itself contain the
// OTHER family's token (a feed literally named "block v4 nets" → set
// `block_ext_v6_nets_block_v4_nets`), so a plain "contains _v4_nets first"
// test would pick the wrong family and run the v4 normalizer over v6 CIDRs.
// We therefore key on whichever token appears FIRST — that is always the real
// family marker, never the feed-name echo. (The normalizers are also
// family-tolerant, so a mis-key degrades to dropped entries, never a panic.)
//
// Both backends call this instead of keeping their own substring matcher, so
// the two can't drift.
func NormalizeNetsForSet(setName string, elems []string) []string {
	i4 := strings.Index(setName, "_v4_nets")
	i6 := strings.Index(setName, "_v6_nets")
	switch {
	case i4 >= 0 && (i6 < 0 || i4 < i6):
		return NormalizeCIDRsV4(elems)
	case i6 >= 0:
		return NormalizeCIDRsV6(elems)
	default:
		return elems
	}
}
