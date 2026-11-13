//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/firewall/feedutil"
	"cfm/internal/firewall/setprobe"
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
// A replace (flushFirst) is ONE netlink batch: the flush and every add commit
// together, so a packet sees the old content or the new one, never an empty
// or half-filled set. It used to be a flush and then one batch per
// setWriteChunk elements, each its own transaction, and the feed unions the
// base rules drop on (block_ext_v4_hosts, …) were partial for the whole
// refill. The batch still carries the elements in messages of setWriteChunk
// (the attribute-length limit below applies per message); the write socket's
// buffer is raised for it (growSendBuffer). If the kernel refuses the batch
// (too large for the buffer, an element it rejects) nothing changed, and the
// chunked write below runs instead, logged.
//
// The chunked write, two shapes chosen from the ELEMENTS (an IntervalEnd
// marker ⇒ interval set — reliable regardless of whether GetSetByName
// populated set.Interval):
//
//   - Interval sets (CIDR/nets): the flush is its OWN netlink transaction —
//     flushing and re-adding an interval set in one batch failed with
//     ENOTEMPTY ("directory not empty") on this netlink path once. (The one-
//     batch replace above does exactly that; the live test
//     LiveNFTFeedReplaceIsAtomic runs it on interval sets, overlap changes
//     included.) The elements
//     are start/IntervalEnd PAIRS, added in batches of setWriteChunk each with
//     its own Flush, cut only between pairs: a start without its end is an
//     interval open to the top of the address space. The batches are not
//     optional. google/nftables puts a message's elements in one netlink
//     attribute, whose 16-bit length silently wraps
//     past 64 KiB (~1,600 IPv4 or ~1,000 IPv6 CIDRs), and the kernel then read
//     a truncated list: ~360 of 2,000 /24s, or a start left without its end,
//     an allow set accepting everything above it.
//   - Plain sets (host IPs): flush queued with the first batch, then batches of
//     setWriteChunk each with its own Flush, so a huge set (e.g. a 113k blocklist)
//     can't overflow the netlink socket buffer. A large set is partial
//     during the refresh — the fallback only, versus failing to apply it at all.
func (b *Backend) chunkedAdd(set *nftables.Set, nftElems []nftables.SetElement, flushFirst bool) error {
	interval := false
	for i := range nftElems {
		if nftElems[i].IntervalEnd {
			interval = true
			break
		}
	}

	if flushFirst {
		err := b.replaceOneBatch(set, nftElems)
		if err == nil {
			return nil
		}
		logging.Logf("[nftlib] replace set %s elems=%d: one batch failed (%v); writing it in batches, with the set briefly partial",
			set.Name, len(nftElems), err)
	}

	if interval {
		if flushFirst {
			b.conn.FlushSet(set)
			if err := b.conn.Flush(); err != nil { // separate transaction
				return err
			}
		}
		for i := 0; i < len(nftElems); {
			end := min(i+setWriteChunk, len(nftElems))
			if end < len(nftElems) && nftElems[end].IntervalEnd {
				end++ // keep the pair together
			}
			if err := b.conn.SetAddElements(set, nftElems[i:end]); err != nil {
				return err
			}
			if err := b.conn.Flush(); err != nil {
				return err
			}
			i = end
		}
		return nil
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

// replaceOneBatch queues the flush and all of nftElems in messages of
// setWriteChunk (interval pairs kept together) and sends them as one batch.
// Caller must hold b.mu.
func (b *Backend) replaceOneBatch(set *nftables.Set, nftElems []nftables.SetElement) error {
	b.conn.FlushSet(set)
	for i := 0; i < len(nftElems); {
		end := min(i+setWriteChunk, len(nftElems))
		if end < len(nftElems) && nftElems[end].IntervalEnd {
			end++ // keep the pair together
		}
		if err := b.conn.SetAddElements(set, nftElems[i:end]); err != nil {
			return err
		}
		i = end
	}
	return b.conn.Flush()
}

// kernelHolds is setprobe.Holds with an error read as "no" (rewrite); a var
// for tests.
var kernelHolds = func(set, elem string) bool {
	ok, err := setprobe.Holds(set, elem)
	return err == nil && ok
}

// hashElems is feedutil.HashElems, the content hash both engines key their
// skip-if-unchanged on.
func hashElems(elems []string) uint64 { return feedutil.HashElems(elems) }

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

	// Interval (nets) sets: de-overlap the CIDRs first, exactly as the exec-nft
	// backend does. The kernel rejects overlapping interval elements with ENOTEMPTY
	// ("directory not empty"); nft merges them in userspace, netlink does not, so we
	// must feed a clean, non-overlapping set. Shared keying+impl (no drift with nft).
	elems = feedutil.NormalizeNetsForSet(setName, elems)
	n = len(elems)

	// Skip-if-unchanged, permanent (no-TTL) sets only.
	permanent := ttl == nil
	var h uint64
	if permanent {
		h = hashElems(elems)
		// No-op when identical content was already applied AND the kernel still
		// holds one of its elements: a set another process emptied or recreated
		// (`cfm reset` / `cfm disable` from the CLI; invalidateCache only sees
		// this process) is written again.
		if prev, ok := b.appliedHash[setName]; ok && prev == h && (len(elems) == 0 || kernelHolds(setName, elems[0])) {
			return nil
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
