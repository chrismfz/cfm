package firewall

import (
	"net"
	"time"
)

// Batched host blocks: many addresses in one kernel transaction.
//
// AddBlock costs up to three `nft` processes per address on the exec backend
// (RemoveBlock, add, a retry) and one netlink transaction per address on
// nftlib. That is fine for one autoblock, but a batch — a fleet blocklist
// delta, a bulk API call — would fork per address, and each `nft` process
// loads the whole ruleset. AddBlockBatch instead reads each block set once and
// writes the whole batch in one transaction per address family (per 1000
// addresses): a few kernel round trips for any batch size.
//
// It only ever adds or extends a block, never shortens or removes one. That is
// the safe way to merge blocks from another source: a 6h block arriving for an
// address this node already blocks permanently (e.g. from cfm.deny) must not
// quietly turn the permanent block into a 6h one. AddBlock, by contrast,
// replaces whatever is there.

// BlockEntry is one address for AddBlockBatch. TTL 0 blocks permanently.
type BlockEntry struct {
	IP  net.IP
	TTL time.Duration
}

// BlockBatchResult counts what AddBlockBatch did.
type BlockBatchResult struct {
	Added    int // weren't blocked
	Extended int // were blocked for less time than asked; now for the new TTL
	Kept     int // already blocked at least as long, or permanently: unchanged
	Skipped  int // not usable: no IP, an unspecified address, or a TTL already expired
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

// SplitBlockEntries drops unusable entries, merges repeats of an address
// (the longest block wins; permanent beats any TTL) and splits by family,
// preserving first-seen order. IPv4-mapped IPv6 addresses count as IPv4. A
// TTL under one second is raised to one second, the kernel's timeout grain.
func SplitBlockEntries(entries []BlockEntry) (v4, v6 []BlockEntry, skipped int) {
	type slot struct {
		v6  bool
		idx int
	}
	seen := map[string]slot{}
	for _, e := range entries {
		if e.IP == nil || e.IP.IsUnspecified() || e.TTL < 0 {
			skipped++
			continue
		}
		ip := e.IP
		isV6 := ip.To4() == nil
		if !isV6 {
			ip = ip.To4()
		}
		ttl := e.TTL
		if ttl > 0 && ttl < time.Second {
			ttl = time.Second
		}
		e = BlockEntry{IP: ip, TTL: ttl}
		key := ip.String()
		if s, ok := seen[key]; ok {
			list := v4
			if s.v6 {
				list = v6
			}
			if longerBlock(e.TTL, list[s.idx].TTL) {
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

// longerBlock reports whether a block of ttl a outlasts one of ttl b
// (0 = permanent).
func longerBlock(a, b time.Duration) bool {
	if b == 0 {
		return false
	}
	return a == 0 || a > b
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
		case left == 0: // permanent
			p.Kept++
		case w.TTL != 0 && left+extendSlack(w.TTL) >= w.TTL:
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
