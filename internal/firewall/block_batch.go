package firewall

import (
	"net"
	"time"
)

// Batched host blocks: many addresses in one kernel transaction.
//
// AddBlock costs two `nft` processes per address on the exec backend
// (RemoveBlock, add; four when the add hits an existing element and retries)
// and one netlink transaction per address on nftlib. That is fine for one autoblock, but a batch — a fleet blocklist
// delta, a bulk API call — would fork per address. AddBlockBatch instead reads
// each block set once and writes the whole batch in one transaction (exec: one
// `nft -f -` run; nftlib: one per 1000 addresses): a few kernel round trips for
// any batch size, more only when the set changed between the read and the
// write and the write is retried.
//
// It only ever adds or extends a block, never shortens or removes one. That is
// the safe way to merge blocks from another source: a 6h block arriving for an
// address this node already blocks permanently (e.g. from cfm.deny) must not
// quietly turn the permanent block into a 6h one. AddBlock, by contrast,
// replaces whatever is there.
//
// RemoveBlockBatch is the unblock side: it reads each block set once and
// deletes, in one transaction, just the addresses the set holds. Deleting one
// it doesn't hold would abort the whole transaction, and most addresses of a
// fleet-wide unblock aren't blocked on any one node.

// BlockEntry is one address for AddBlockBatch: blocked permanently, or for
// TTL. Permanence is explicit, never "TTL 0": a caller counting a TTL down to
// an expiry must not turn a block whose time ran out into a permanent one.
type BlockEntry struct {
	IP        net.IP
	TTL       time.Duration // ignored when Permanent
	Permanent bool
}

// BlockBatchResult counts what AddBlockBatch did.
type BlockBatchResult struct {
	Added    int // weren't blocked
	Extended int // were blocked for less time than asked; now for the new TTL
	Kept     int // already blocked at least as long, or permanently: unchanged
	Skipped  int // not usable: no IP, an unspecified address, or no time left
}

// Add sums two results.
func (r BlockBatchResult) Add(o BlockBatchResult) BlockBatchResult {
	return BlockBatchResult{
		Added:    r.Added + o.Added,
		Extended: r.Extended + o.Extended,
		Kept:     r.Kept + o.Kept,
		Skipped:  r.Skipped + o.Skipped,
	}
}

// PlannedBlock is one element a backend writes. Replace means the address is
// already in the set with a shorter timeout: the backend deletes it and adds
// it back with the new one, in the same transaction.
type PlannedBlock struct {
	BlockEntry
	Replace bool
}

// BlockBatchPlan is what one address family's block set needs.
type BlockBatchPlan struct {
	Writes []PlannedBlock
	Kept   int
}

// Result counts the plan as a BlockBatchResult.
func (p BlockBatchPlan) Result() BlockBatchResult {
	r := BlockBatchResult{Kept: p.Kept}
	for _, w := range p.Writes {
		if w.Replace {
			r.Extended++
		} else {
			r.Added++
		}
	}
	return r
}

// SplitBlockEntries drops unusable entries (no IP, an unspecified address, a
// non-permanent entry with no time left), merges repeats of an address (the
// longest block wins; permanent beats any TTL) and splits by family,
// preserving first-seen order. IPv4-mapped IPv6 addresses count as IPv4. A
// TTL under one second is raised to one second, the kernel's timeout grain.
func SplitBlockEntries(entries []BlockEntry) (v4, v6 []BlockEntry, skipped int) {
	type slot struct {
		v6  bool
		idx int
	}
	seen := map[string]slot{}
	for _, e := range entries {
		if e.IP == nil || e.IP.IsUnspecified() || (!e.Permanent && e.TTL <= 0) {
			skipped++
			continue
		}
		ip := e.IP
		isV6 := ip.To4() == nil
		if !isV6 {
			ip = ip.To4()
		}
		ttl := e.TTL
		if e.Permanent {
			ttl = 0
		} else if ttl < time.Second {
			ttl = time.Second
		}
		e = BlockEntry{IP: ip, TTL: ttl, Permanent: e.Permanent}
		key := ip.String()
		if s, ok := seen[key]; ok {
			list := v4
			if s.v6 {
				list = v6
			}
			if longerBlock(e, list[s.idx]) {
				list[s.idx] = e
			}
			continue
		}
		if isV6 {
			seen[key] = slot{v6: true, idx: len(v6)}
			v6 = append(v6, e)
		} else {
			seen[key] = slot{idx: len(v4)}
			v4 = append(v4, e)
		}
	}
	return v4, v6, skipped
}

// longerBlock reports whether block a outlasts block b.
func longerBlock(a, b BlockEntry) bool {
	if b.Permanent {
		return false
	}
	return a.Permanent || a.TTL > b.TTL
}

// PlanBlockBatch decides, for one family's block set, which entries to add,
// which to extend and which to keep, given the set's current elements. want
// must come from SplitBlockEntries (one family, no repeats).
//
// An address already blocked permanently is kept. One blocked with a timeout
// is kept if it has at least the requested time left, less a small slack (5%
// of it, at most a minute), so a block delivered twice — with a slightly
// smaller TTL the second time, since it counts down to the same expiry — isn't
// rewritten each time.
func PlanBlockBatch(want []BlockEntry, current []SetElementTimed) BlockBatchPlan {
	cur := make(map[string]time.Duration, len(current))
	for _, c := range current {
		ip := net.ParseIP(c.Elem)
		if ip == nil {
			continue // a CIDR or unparsable element: not a host block
		}
		cur[ip.String()] = c.Expires
	}
	var p BlockBatchPlan
	for _, w := range want {
		left, present := cur[w.IP.String()]
		switch {
		case !present:
			p.Writes = append(p.Writes, PlannedBlock{BlockEntry: w})
		case left == 0: // permanent (backends report a timed element's last instant as > 0)
			p.Kept++
		case !w.Permanent && left+extendSlack(w.TTL) >= w.TTL:
			p.Kept++
		default:
			p.Writes = append(p.Writes, PlannedBlock{BlockEntry: w, Replace: true})
		}
	}
	return p
}

func extendSlack(ttl time.Duration) time.Duration {
	s := ttl / 20
	if s > time.Minute {
		s = time.Minute
	}
	return s
}

// SplitHostAddrs splits addresses by family for RemoveBlockBatch, dropping
// nil and unspecified addresses and repeats, in first-seen order.
// IPv4-mapped IPv6 addresses count as IPv4.
func SplitHostAddrs(ips []net.IP) (v4, v6 []net.IP) {
	seen := map[string]bool{}
	for _, ip := range ips {
		if ip == nil || ip.IsUnspecified() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		if ip4 := ip.To4(); ip4 != nil {
			v4 = append(v4, ip4)
		} else {
			v6 = append(v6, ip)
		}
	}
	return v4, v6
}

// HostsPresent returns the addresses of want that current holds as host
// elements, in the order of want: what a batch unblock deletes.
func HostsPresent(want []net.IP, current []SetElementTimed) []net.IP {
	cur := make(map[string]bool, len(current))
	for _, c := range current {
		if ip := net.ParseIP(c.Elem); ip != nil {
			cur[ip.String()] = true
		}
	}
	var out []net.IP
	for _, ip := range want {
		if cur[ip.String()] {
			out = append(out, ip)
		}
	}
	return out
}
