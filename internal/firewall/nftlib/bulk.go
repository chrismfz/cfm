//go:build linux

package nftlib

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"cfm/internal/firewall/feedutil"
	"cfm/internal/firewall/setprobe"
	"cfm/internal/logging"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// setWriteChunk bounds how many set elements go into one netlink Flush. A single
// giant SetAddElements+Flush overflows the netlink socket buffer and fails with
// "sendmsg: message too long" (observed on a 113k-entry blocklist feed), so
// writes are split into batches. Kept conservative so each batch stays well
// under the default socket send buffer.
const setWriteChunk = 1000

// chunkedAdd writes nftElems to set. Caller must hold b.mu.
//
// A replace normally does not come here: replaceSet sends it as ONE batch and
// uses this chunked write only as its fallback. Two shapes, chosen from the
// ELEMENTS (an IntervalEnd marker ⇒ interval set — reliable regardless of
// whether GetSetByName populated set.Interval):
//
//   - Interval sets (CIDR/nets): the flush is its OWN netlink transaction —
//     flushing and re-adding an interval set in one batch failed with
//     ENOTEMPTY ("directory not empty") on this netlink path once. (replaceSet's
//     one batch does exactly that, and falls back here on that ENOTEMPTY; the
//     live test LiveNFTFeedReplaceIsAtomic runs it on interval sets, overlap
//     changes included.) The elements
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

// replaceSet replaces set's content with nftElems. Caller must hold b.mu.
// verified=false means the content is in place but not confirmed (the caller
// then records no content hash, and the next apply writes again).
//
// It is ONE netlink batch (replaceOneBatch): the flush and every add commit
// together, so a packet sees the old content or the new one, never an empty
// or half-filled set. It used to be a flush and then one transaction per
// setWriteChunk elements, and the feed unions the base rules drop on
// (block_ext_v4_hosts, …) were partial for the whole refill. The batch still
// carries the elements in messages of setWriteChunk (the attribute-length
// limit, chunkedAdd); the write socket's buffers are raised for it
// (growBuffers).
//
// A refused batch changed nothing. What happens next depends on why:
//   - too large for the send buffer (EMSGSIZE), or, on an interval set whose
//     intervals do not overlap (intervalsOverlap), the ENOTEMPTY a one-batch
//     flush-and-refill once got on this netlink path: the chunked write
//     (chunkedAdd), logged; the set is partial meanwhile. ENOTEMPTY is also
//     the kernel's answer to an overlapping interval, which the chunked write
//     would hit after its flush, so overlapping content is an error instead;
//   - anything else (an element the kernel rejects): an error, and the set
//     KEEPS its old content. The chunked write would flush it and stop at the
//     bad message, leaving every address after it unblocked;
//   - ENOBUFS: the ACKs overflowed the receive buffer, which says nothing
//     about the batch (the kernel commits or aborts before it acks). The set
//     is asked for elements spread across the new content (probeElems): all
//     there, the batch is taken as applied, unverified; one missing, the
//     chunked write. A feed that changed by a few addresses can pass this on
//     its old content, which the next apply's rewrite then corrects. Seen
//     only where SO_RCVBUFFORCE is refused and rmem_max caps the buffer.
func (b *Backend) replaceSet(set *nftables.Set, nftElems []nftables.SetElement) (verified bool, err error) {
	err = b.replaceOneBatch(set, nftElems)
	if err == nil {
		return true, nil
	}
	interval := len(nftElems) > 0 && nftElems[len(nftElems)-1].IntervalEnd
	switch {
	case isNLErr(err, unix.ENOBUFS, "no buffer space"):
		if probes := probeElems(nftElems, replaceProbes); len(probes) > 0 && kernelHoldsAll(set.Name, probes) {
			logging.Logf("[nftlib] replace set %s elems=%d: the ACKs overflowed (%v), and the set holds the new content; taken as applied",
				set.Name, len(nftElems), err)
			return false, nil
		}
	case isNLErr(err, unix.EMSGSIZE, "message too long"):
	case interval && isNLErr(err, unix.ENOTEMPTY, "directory not empty"):
		if intervalsOverlap(nftElems) {
			return false, fmt.Errorf("one batch refused (overlapping intervals), the set keeps its old content: %w", err)
		}
	default:
		return false, fmt.Errorf("one batch refused, the set keeps its old content: %w", err)
	}
	logging.Logf("[nftlib] replace set %s elems=%d: one batch failed (%v); writing it in batches, with the set briefly partial",
		set.Name, len(nftElems), err)
	if err := b.chunkedAdd(set, nftElems, true); err != nil {
		return false, err
	}
	return true, nil // the chunked write reports each transaction
}

// replaceProbes is how many elements replaceSet asks the kernel for after an
// ENOBUFS.
const replaceProbes = 32

// probeElems picks up to n addresses evenly across what the batch wrote, as
// strings setprobe reads: each host, or each interval's start. Taken from the
// parsed elements, so nothing parseElems dropped is asked for.
func probeElems(nftElems []nftables.SetElement, n int) []string {
	var keys [][]byte
	for i := range nftElems {
		if !nftElems[i].IntervalEnd {
			keys = append(keys, nftElems[i].Key)
		}
	}
	if len(keys) > n {
		picked := make([][]byte, 0, n)
		for i := 0; i < n; i++ {
			picked = append(picked, keys[i*(len(keys)-1)/(n-1)])
		}
		keys = picked
	}
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		if ip := keyToIP(k); ip != nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// intervalsOverlap reports whether start/IntervalEnd pairs overlap. An end
// key of all zeroes is the top of the address space (the end of a range that
// reaches 255.255.255.255 wraps).
func intervalsOverlap(nftElems []nftables.SetElement) bool {
	type iv struct{ start, end []byte }
	var ivs []iv
	for i := 0; i+1 < len(nftElems); i += 2 {
		if nftElems[i].IntervalEnd || !nftElems[i+1].IntervalEnd {
			return true // not pairs: cannot tell, treat as bad content
		}
		ivs = append(ivs, iv{nftElems[i].Key, nftElems[i+1].Key})
	}
	sort.Slice(ivs, func(a, b int) bool { return bytes.Compare(ivs[a].start, ivs[b].start) < 0 })
	top := func(k []byte) bool { return bytes.Count(k, []byte{0}) == len(k) }
	for i := 1; i < len(ivs); i++ {
		prev := ivs[i-1].end
		if top(prev) || bytes.Compare(ivs[i].start, prev) < 0 {
			return true
		}
	}
	return false
}

func kernelHoldsAll(set string, elems []string) bool {
	for _, e := range elems {
		if !kernelHolds(set, e) {
			return false
		}
	}
	return true
}

// isNLErr matches a netlink error by errno, or by its text: google/nftables
// wraps some receive errors with %v, which drops the chain.
func isNLErr(err error, errno unix.Errno, text string) bool {
	return errors.Is(err, errno) || strings.Contains(strings.ToLower(err.Error()), text)
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

// ReplaceSetFlushAdd replaces a set's content in ONE netlink batch (replaceSet:
// the flush and every add commit together; a refused batch changes nothing,
// and only a too-large one falls back to the chunked write). For PERMANENT (no-TTL) sets it skips
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
	verified, e := b.replaceSet(set, nftElems)
	if e != nil {
		// A refused one batch changed nothing, but the chunked fallback may have
		// PARTIALLY committed — the flush landed but a later add failed, leaving the
		// kernel set empty or half-written. Drop any cached content hash so the next
		// apply always rewrites; otherwise skip-if-unchanged could leave the set
		// silently empty (a fail-open blocklist) after the content reverts to a
		// previously-applied hash. Safe on a nil/absent map (no-op).
		delete(b.appliedHash, setName)
		err = fmt.Errorf("nftlib ReplaceSetFlushAdd %s (%d elems): %w", setName, n, e)
		return err
	}

	if !verified {
		delete(b.appliedHash, setName) // applied, unverified: write again next time
		return nil
	}
	if permanent {
		if b.appliedHash == nil {
			b.appliedHash = make(map[string]uint64)
		}
		b.appliedHash[setName] = h
	}
	return nil
}
