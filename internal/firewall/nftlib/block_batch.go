//go:build linux

package nftlib

import (
	"fmt"

	"cfm/internal/firewall"

	"github.com/google/nftables"
)

// AddBlockBatch blocks many host addresses over netlink: one read of each
// block set, then one transaction per family and per setWriteChunk addresses
// (the netlink message-size bound), where AddBlock costs one transaction per
// address. It only adds or extends, never shortens (firewall.PlanBlockBatch).
//
// Between the read and the write another writer can change the set: an
// element due for replacement can expire (its delete then fails with ENOENT
// and the kernel aborts that transaction), or an autoblock can add one of the
// new addresses (harmless: an add without NLM_F_EXCL doesn't fail on an
// existing element). A failed write is retried once from a fresh read; the
// chunks already written are then kept, not rewritten.
func (b *Backend) AddBlockBatch(entries []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	v4, v6, skipped := firewall.SplitBlockEntries(entries)
	res := firewall.BlockBatchResult{Skipped: skipped}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, fam := range []struct {
		set  string
		want []firewall.BlockEntry
	}{{setBlockV4, v4}, {setBlockV6, v6}} {
		if len(fam.want) == 0 {
			continue
		}
		r, err := b.blockBatchFamily(fam.set, fam.want)
		res = res.Add(r)
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// blockBatchFamily writes one family's batch. Must be called with b.mu held.
func (b *Backend) blockBatchFamily(setName string, want []firewall.BlockEntry) (firewall.BlockBatchResult, error) {
	set, err := b.lookupSet(setName)
	if err != nil {
		return firewall.BlockBatchResult{}, fmt.Errorf("nftlib AddBlockBatch %s: %w", setName, err)
	}
	var done firewall.BlockBatchResult // chunks written by an earlier attempt
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		elems, err := b.conn.GetSetElements(set)
		if err != nil {
			return done, fmt.Errorf("nftlib AddBlockBatch read %s: %w", setName, err)
		}
		plan := firewall.PlanBlockBatch(want, elemsToTimed(elems))
		written, err := b.writeBlockBatch(set, plan.Writes)
		if err == nil {
			// On a retry the earlier attempt's writes now read as kept; count
			// them as the adds/extensions they were.
			r := plan.Result()
			r.Kept -= done.Added + done.Extended
			return done.Add(r), nil
		}
		done = done.Add(written)
		lastErr = err
	}
	return done, fmt.Errorf("nftlib AddBlockBatch %s: %w", setName, lastErr)
}

// writeBlockBatch writes the plan in chunks, each one transaction: the
// replaced addresses' deletes, then every add with its own timeout. It
// returns what the chunks that committed wrote.
func (b *Backend) writeBlockBatch(set *nftables.Set, writes []firewall.PlannedBlock) (firewall.BlockBatchResult, error) {
	var written firewall.BlockBatchResult
	for i := 0; i < len(writes); i += setWriteChunk {
		chunk := writes[i:min(i+setWriteChunk, len(writes))]
		var dels, adds []nftables.SetElement
		for _, w := range chunk {
			key := normalizeIP(w.IP)
			if w.Replace {
				dels = append(dels, nftables.SetElement{Key: key})
			}
			adds = append(adds, nftables.SetElement{Key: key, Timeout: w.TTL})
		}
		if len(dels) > 0 {
			if err := b.conn.SetDeleteElements(set, dels); err != nil {
				return written, err
			}
		}
		if err := b.conn.SetAddElements(set, adds); err != nil {
			return written, err
		}
		if err := b.conn.Flush(); err != nil {
			return written, err
		}
		written = written.Add(firewall.BlockBatchPlan{Writes: chunk}.Result())
	}
	return written, nil
}
