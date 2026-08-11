//go:build linux

package nftlib

import (
	"fmt"
	"hash/fnv"
	"sort"
	"time"

	"cfm/internal/logging"

	"github.com/google/nftables"
)

// setWriteChunk bounds how many set elements go into one netlink Flush. A single
// giant SetAddElements+Flush overflows the netlink socket buffer and fails with
// "sendmsg: message too long" (observed on a 113k-entry blocklist feed), so
// writes are split into batches. Kept conservative so each batch stays well
// under the default socket send buffer.
const setWriteChunk = 1000

// chunkedAdd writes nftElems to set. Caller must hold b.mu.
//
// Two shapes, chosen from the ELEMENTS (an IntervalEnd marker ⇒ interval set —
// reliable regardless of whether GetSetByName populated set.Interval):
//
//   - Interval sets (CIDR/nets): the flush must be its OWN netlink transaction —
//     flushing and re-adding an interval set in one batch fails with ENOTEMPTY
//     ("directory not empty"); CFM's CLI path (replacePortSetCLI) splits them for
//     the same reason. And the elements are start/IntervalEnd PAIRS that must not
//     be split across messages, so they go in a single add batch. Interval feeds
//     are small in practice (a very large one could still hit the message limit —
//     none exist today).
//   - Plain sets (host IPs): flush queued with the first batch, then batches of
//     setWriteChunk each with its own Flush, so a huge set (e.g. a 113k blocklist)
//     can't overflow the netlink socket buffer. A large set is briefly partial
//     during a refresh — acceptable versus failing to apply it at all.
func (b *Backend) chunkedAdd(set *nftables.Set, nftElems []nftables.SetElement, flushFirst bool) error {
	interval := false
	for i := range nftElems {
		if nftElems[i].IntervalEnd {
			interval = true
			break
		}
	}

	if interval {
		if flushFirst {
			b.conn.FlushSet(set)
			if err := b.conn.Flush(); err != nil { // separate transaction
				return err
			}
		}
		if len(nftElems) == 0 {
			return nil
		}
		if err := b.conn.SetAddElements(set, nftElems); err != nil {
			return err
		}
		return b.conn.Flush()
	}

	if flushFirst {
		b.conn.FlushSet(set)
	}
	if len(nftElems) == 0 {
		if flushFirst {
			return b.conn.Flush() // flush-only: empty the set
		}
		return nil
	}
	for i := 0; i < len(nftElems); i += setWriteChunk {
		end := i + setWriteChunk
		if end > len(nftElems) {
			end = len(nftElems)
		}
		if err := b.conn.SetAddElements(set, nftElems[i:end]); err != nil {
			return err
		}
		if err := b.conn.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// hashElems is an order-independent content hash of a set's elements, used to
// skip rewriting an unchanged set. Sorted so a reordered-but-identical feed
// hashes the same.
func hashElems(elems []string) uint64 {
	cp := make([]string, len(elems))
	copy(cp, elems)
	sort.Strings(cp)
	h := fnv.New64a()
	for _, e := range cp {
		_, _ = h.Write([]byte(e))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

// AddElementsBulk adds all elements to a named set via netlink (zero forks),
// chunked so a large batch can't overflow the netlink message limit.
func (b *Backend) AddElementsBulk(setName string, elems []string, ttl *time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib AddElementsBulk %s: %w", setName, err)
	}

	nftElems := parseElems(set, elems, ttl)
	if len(nftElems) == 0 {
		return nil
	}

	if err := b.chunkedAdd(set, nftElems, false); err != nil {
		return fmt.Errorf("nftlib AddElementsBulk %s (%d elems): %w", setName, len(nftElems), err)
	}
	return nil
}

// ReplaceSetFlushAdd flushes a set and repopulates it, chunked so a large set
// can't overflow the netlink message limit. For PERMANENT (no-TTL) sets it skips
// the write entirely when the content is unchanged since the last successful
// apply (a blocklist that didn't change this hour is a no-op instead of
// re-writing tens of thousands of the same elements). TTL sets are always
// rewritten — their kernel contents expire, so an unchanged input does not mean
// the kernel still holds them.
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) (err error) {
	start := time.Now()
	n := len(elems)
	// Record size/duration/outcome for the self-test, and log a failure so a feed
	// that never applies is visible. Registered before defer b.mu.Unlock so (LIFO)
	// it runs AFTER the unlock — recordFeedWrite takes statMu only, no nesting.
	defer func() {
		b.recordFeedWrite(setName, n, time.Since(start), err)
		if err != nil {
			logging.Logf("[nftlib] set write %s elems=%d dur=%s error=%v",
				setName, n, time.Since(start).Round(time.Millisecond), err)
		}
	}()

	b.mu.Lock()
	defer b.mu.Unlock()

	set, e := b.lookupSet(setName)
	if e != nil {
		err = fmt.Errorf("nftlib ReplaceSetFlushAdd %s: %w", setName, e)
		return err
	}

	// Skip-if-unchanged, permanent (no-TTL) sets only.
	permanent := ttl == nil
	var h uint64
	if permanent {
		h = hashElems(elems)
		if prev, ok := b.appliedHash[setName]; ok && prev == h {
			return nil // no-op: identical content already applied
		}
	}

	nftElems := parseElems(set, elems, ttl)
	n = len(nftElems)
	if e := b.chunkedAdd(set, nftElems, true); e != nil {
		// A multi-transaction write (chunked, or interval flush-then-add) may have
		// PARTIALLY committed — the flush landed but a later add failed, leaving the
		// kernel set empty or half-written. Drop any cached content hash so the next
		// apply always rewrites; otherwise skip-if-unchanged could leave the set
		// silently empty (a fail-open blocklist) after the content reverts to a
		// previously-applied hash. Safe on a nil/absent map (no-op).
		delete(b.appliedHash, setName)
		err = fmt.Errorf("nftlib ReplaceSetFlushAdd %s (%d elems): %w", setName, n, e)
		return err
	}

	if permanent {
		if b.appliedHash == nil {
			b.appliedHash = make(map[string]uint64)
		}
		b.appliedHash[setName] = h
	}
	return nil
}
