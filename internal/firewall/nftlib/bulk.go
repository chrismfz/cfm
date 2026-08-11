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

// chunkedAdd adds nftElems to set in batches of setWriteChunk, one Flush per
// batch, so no single netlink message exceeds the kernel/socket limit. When
// flushFirst is true a set flush is queued before the first batch (the flush +
// first batch execute as one transaction; later batches are separate
// transactions — a large set is therefore briefly partial DURING a refresh,
// which is acceptable versus failing to apply the set at all). Caller must hold
// b.mu.
func (b *Backend) chunkedAdd(set *nftables.Set, nftElems []nftables.SetElement, flushFirst bool) error {
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
