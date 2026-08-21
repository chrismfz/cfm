package nft

import (
	"fmt"
	"net"
	"strings"

	"cfm/internal/firewall"
)

// AddManualBlocksBulk adds host IPs to the manual block sets (block_v4/block_v6)
// as PERMANENT entries, in a couple of batched `nft -f -` transactions instead
// of one fork per IP. It is the fast path for applying a large cfm.deny at
// startup, where the per-IP AddBlock path forks nft twice per address
// (RemoveBlock + add) and dominates boot time.
//
//   - IPs already present as permanent are skipped (nothing to do).
//   - IPs present with a timeout (e.g. a temporary autoblock landed on the same
//     address) are re-added permanent per-IP, so cfm.deny's permanent intent
//     wins — matching the per-IP AddBlock path (RemoveBlock + add).
//   - IPs not present at all are added in bulk via AddElementsBulk.
//
// On a warm restart the sets already hold these, so this reads each set once
// (one `nft -j list set` per family) and adds nothing; on a cold boot the whole
// list lands in a handful of nft calls. Either way it replaces the old ~2 forks
// per IP. The block sets are created by EnsureBase, which always runs earlier in
// startup, so ListSetElementsTimed finds them present.
//
// Degraded/racy cases fall back to the proven per-IP path and stay correct,
// just without the speedup:
//   - if a set cannot be read, that whole family goes per-IP;
//   - if a batch add fails (e.g. a concurrent autoblock added one of the
//     "missing" IPs between the read and the add, so nft reports "File exists"
//     for the batch), that family's missing IPs go per-IP — where AddBlock's
//     RemoveBlock+add clears the raced duplicate.
//
// It returns the IPs that still could not be applied (nil on full success) plus
// a matching error, so the caller can mark only the succeeded subset as done
// and re-apply the remainder itself, rather than redo the whole slice.
func (b *Backend) AddManualBlocksBulk(ips []net.IP) (failed []net.IP, err error) {
	v4, v6 := bucketHostsByFamily(ips)
	listTimed := b.ListSetElementsTimed
	bulkAdd := func(set string, elems []string) error { return b.AddElementsBulk(set, elems, nil) }
	addOne := func(ip net.IP) error { return b.AddBlock(ip, "", nil) }

	failed = append(failed, reconcileFamilyBlocks(setV4, v4, listTimed, bulkAdd, addOne)...)
	failed = append(failed, reconcileFamilyBlocks(setV6, v6, listTimed, bulkAdd, addOne)...)

	if len(failed) > 0 {
		return failed, fmt.Errorf("AddManualBlocksBulk: %d of %d entries failed to apply", len(failed), len(ips))
	}
	return nil, nil
}

// reconcileFamilyBlocks reconciles one address family's desired permanent host
// IPs against the live set, using injected primitives so its fallback/racy
// branches are unit-testable without a live nft backend. It returns the IPs it
// could not land (empty on success).
func reconcileFamilyBlocks(
	set string,
	want map[string]net.IP,
	listTimed func(string) ([]firewall.SetElementTimed, error),
	bulkAdd func(string, []string) error,
	addOne func(net.IP) error,
) []net.IP {
	if len(want) == 0 {
		return nil
	}
	// Track failures in a set so re-asserting the same IP in the first pass and
	// the retry can't double-count it.
	failed := map[string]net.IP{}
	fail := func(ip net.IP) { failed[ip.String()] = ip }

	timed, err := listTimed(set)
	if err != nil {
		// Can't read the set → fall back to the proven per-IP path.
		for _, ip := range want {
			if e := addOne(ip); e != nil {
				fail(ip)
			}
		}
		return failedSlice(failed)
	}
	missing, overlapTimed := planManualBlockReconcile(want, timed)
	// Present-but-timed: make permanent per-IP (rare).
	for _, ip := range overlapTimed {
		if e := addOne(ip); e != nil {
			fail(ip)
		}
	}
	if len(missing) == 0 {
		return failedSlice(failed)
	}
	if e := bulkAdd(set, missing); e == nil {
		return failedSlice(failed)
	}

	// The batch failed: a raced concurrent add (e.g. an autoblock landing on one
	// of the missing IPs between the read and the add), or a partially-committed
	// multi-chunk add, made some element already exist and failed the whole
	// atomic add. Re-read the set and retry the bulk over only what is genuinely
	// still missing — re-asserting any want IP that raced into a timed block back
	// to permanent — so one bad element can't force the whole family per-IP. If
	// the re-read itself fails we don't re-issue the same failing bulk; either
	// way we fall back per-IP for whatever is left.
	retry := missing
	if t2, e2 := listTimed(set); e2 == nil {
		var overlap2 []net.IP
		retry, overlap2 = planManualBlockReconcile(want, t2)
		for _, ip := range overlap2 {
			if e := addOne(ip); e != nil {
				fail(ip)
			}
		}
		if len(retry) > 0 && bulkAdd(set, retry) == nil {
			retry = nil // retry bulk landed
		}
	}
	for _, key := range retry {
		if e := addOne(want[key]); e != nil {
			fail(want[key])
		}
	}
	return failedSlice(failed)
}

// failedSlice flattens a failure set (deduped by IP string) into a slice.
func failedSlice(m map[string]net.IP) []net.IP {
	if len(m) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(m))
	for _, ip := range m {
		out = append(out, ip)
	}
	return out
}

// bucketHostsByFamily dedupes host IPs and splits them into v4/v6 maps keyed by
// canonical string. IPv4 and IPv4-mapped-IPv6 addresses both bucket as v4 (To4
// non-nil), matching AddBlock's own set selection; nil entries are dropped.
func bucketHostsByFamily(ips []net.IP) (v4, v6 map[string]net.IP) {
	v4 = make(map[string]net.IP)
	v6 = make(map[string]net.IP)
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			v4[ip.String()] = ip
		} else {
			v6[ip.String()] = ip
		}
	}
	return v4, v6
}

// planManualBlockReconcile decides, for one address family, which desired host
// IPs must be bulk-added (missing) and which are present but carry a timeout and
// so must be re-added permanent per-IP (overlapTimed). IPs already present as
// permanent are skipped. Comparison is by parsed IP value, so a canonical-form
// mismatch (notably IPv6) never causes a spurious re-add or a missed entry.
//
// Permanent-vs-timed uses SetElementTimed.Expires (zero == no timeout, per its
// documented contract). For CFM's blocks this is effectively exact: timed blocks
// carry second-granularity TTLs and nft reports the remaining time as an integer
// number of seconds, so a live timed element reads ≥ 1s. The one theoretical
// gap is an element caught in its final sub-second (expires rounding to 0): it
// would be misread as permanent and skipped rather than re-asserted, leaving a
// same-address permanent deny as an about-to-expire block. That is a vanishing
// window on an already-rare perm∩timed overlap, and it self-heals on the next
// cfm.deny reload or daemon restart, which re-adds the IP permanent.
func planManualBlockReconcile(want map[string]net.IP, present []firewall.SetElementTimed) (missing []string, overlapTimed []net.IP) {
	permPresent := make(map[string]bool, len(present))
	timedPresent := make(map[string]bool)
	for _, el := range present {
		ip := net.ParseIP(strings.TrimSpace(el.Elem))
		if ip == nil {
			continue // not a host IP (e.g. a CIDR in a nets set) — ignore
		}
		if el.Expires > 0 {
			timedPresent[ip.String()] = true
		} else {
			permPresent[ip.String()] = true
		}
	}
	for key, ip := range want {
		switch {
		case permPresent[key]:
			// already permanent — nothing to do
		case timedPresent[key]:
			overlapTimed = append(overlapTimed, ip)
		default:
			missing = append(missing, key)
		}
	}
	return missing, overlapTimed
}
