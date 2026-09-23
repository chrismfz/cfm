//go:build linux

package nftlib

import (
	"fmt"

	"cfm/internal/firewall"

	"github.com/google/nftables"
)

// blockBatchAttempts bounds the read-plan-write rounds of one AddBlockBatch.
const blockBatchAttempts = 3

// AddBlockBatch blocks many host addresses over netlink: one read of each
// block set, then one transaction per setWriteChunk addresses (the netlink
// message-size bound) — both families in the same transaction — where
// AddBlock costs one transaction per address. It only adds or extends, never
// shortens (firewall.PlanBlockBatch).
//
// Between the read and the write the set can change:
//   - An element due for replacement can expire: its delete fails with ENOENT
//     and the kernel aborts that transaction. The write is retried from a
//     fresh read (up to blockBatchAttempts rounds); chunks that already
//     committed are counted once and left out of the retry.
//   - Another writer can add one of the new addresses. On current kernels a
//     plain add then rewrites that element's timeout, so a permanent block
//     could take the batch's TTL. google/nftables has no exclusive add, so
//     this backend can't refuse it the way the nft backend's `create
//     element` does. Within this process every writer holds b.mu, which this
//     holds from the read to the last write; only another process (e.g. a
//     CLI `cfm block` in the same instant) can race it.
func (b *Backend) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return b.hostBatch("AddBlockBatch", setBlockV4, setBlockV6, entries)
}

// AddAllowBatch is AddBlockBatch for the allow sets: it only adds or extends
// an allow, never shortens one — a permanent allow stays permanent.
func (b *Backend) AddAllowBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	return b.hostBatch("AddAllowBatch", setAllowV4, setAllowV6, entries)
}

// hostBatch writes entries to the host sets set4/set6 (see AddBlockBatch).
func (b *Backend) hostBatch(op, set4, set6 string, entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	v4, v6, skipped := firewall.SplitBlockEntries(entries)
	res := firewall.BlockBatchResult{Skipped: skipped}
	if len(v4)+len(v6) == 0 {
		return res, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	fams := []struct {
		name string
		set  *nftables.Set
		want []firewall.BlockEntry
	}{{name: set4, want: v4}, {name: set6, want: v6}}
	for i := range fams {
		if len(fams[i].want) == 0 {
			continue
		}
		set, err := b.lookupSet(fams[i].name)
		if err != nil {
			return res, fmt.Errorf("nftlib %s %s: %w", op, fams[i].name, err)
		}
		fams[i].set = set
	}
	var lastErr error
	for attempt := 0; attempt < blockBatchAttempts; attempt++ {
		var writes []blockWrite
		var planned firewall.BlockBatchResult
		for _, f := range fams {
			if len(f.want) == 0 {
				continue
			}
			elems, err := b.conn.GetSetElements(f.set)
			if err != nil {
				return res, fmt.Errorf("nftlib %s read %s: %w", op, f.name, err)
			}
			plan := firewall.PlanBlockBatch(f.want, elemsToTimed(elems, f.set.Interval))
			planned = planned.Add(plan.Result())
			for _, w := range plan.Writes {
				writes = append(writes, blockWrite{set: f.set, PlannedBlock: w})
			}
		}
		n, err := b.writeBlockBatch(writes)
		if err == nil {
			return res.Add(planned), nil
		}
		// Count what committed and leave it out of the next round: its fresh
		// read would show those addresses as already blocked, i.e. kept.
		done := map[string]bool{}
		var committed []firewall.PlannedBlock
		for _, w := range writes[:n] {
			done[w.IP.String()] = true
			committed = append(committed, w.PlannedBlock)
		}
		res = res.Add(firewall.BlockBatchPlan{Writes: committed}.Result())
		for i := range fams {
			var rest []firewall.BlockEntry
			for _, e := range fams[i].want {
				if !done[e.IP.String()] {
					rest = append(rest, e)
				}
			}
			fams[i].want = rest
		}
		lastErr = err
	}
	return res, fmt.Errorf("nftlib %s: %w", op, lastErr)
}

// blockWrite is one planned element and the set it goes to.
type blockWrite struct {
	set *nftables.Set
	firewall.PlannedBlock
}

// writeBlockBatch writes the plan in chunks of setWriteChunk, each one
// transaction: the replaced addresses' deletes, then every add with its own
// timeout. It returns how many writes (a prefix) committed.
func (b *Backend) writeBlockBatch(writes []blockWrite) (int, error) {
	for i := 0; i < len(writes); i += setWriteChunk {
		chunk := writes[i:min(i+setWriteChunk, len(writes))]
		dels := map[*nftables.Set][]nftables.SetElement{}
		adds := map[*nftables.Set][]nftables.SetElement{}
		var order []*nftables.Set
		for _, w := range chunk {
			if _, seen := adds[w.set]; !seen {
				order = append(order, w.set)
			}
			key := normalizeIP(w.IP)
			if w.Replace {
				dels[w.set] = append(dels[w.set], nftables.SetElement{Key: key})
			}
			e := nftables.SetElement{Key: key}
			if !w.Permanent {
				e.Timeout = w.TTL
			}
			adds[w.set] = append(adds[w.set], e)
		}
		for _, s := range order {
			if len(dels[s]) > 0 {
				if err := b.conn.SetDeleteElements(s, dels[s]); err != nil {
					return i, err
				}
			}
		}
		for _, s := range order {
			if err := b.conn.SetAddElements(s, adds[s]); err != nil {
				return i, err
			}
		}
		if err := b.conn.Flush(); err != nil {
			return i, err
		}
	}
	return len(writes), nil
}
