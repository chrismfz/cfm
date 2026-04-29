//go:build linux

package nftlib

import (
	"fmt"
	"time"
)

// AddElementsBulk adds all elements to a named set in ONE netlink Flush().
// Zero forks. Zero execs. Any batch size = one kernel roundtrip.
// This is the fork-storm fix: the nft exec backend spawns one subprocess per
// batch; this method replaces every one of those with a single syscall.
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

	if err := b.conn.SetAddElements(set, nftElems); err != nil {
		return fmt.Errorf("nftlib AddElementsBulk %s (%d elems): %w", setName, len(nftElems), err)
	}
	return b.conn.Flush()
}

// ReplaceSetFlushAdd atomically flushes a set and repopulates it in ONE
// netlink Flush(). The flush and add are queued together before any syscall,
// so the kernel processes them as a single transaction.
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	set, err := b.lookupSet(setName)
	if err != nil {
		return fmt.Errorf("nftlib ReplaceSetFlushAdd %s: %w", setName, err)
	}

	// Queue flush + add; both execute in one conn.Flush() call.
	b.conn.FlushSet(set)

	nftElems := parseElems(set, elems, ttl)
	if len(nftElems) > 0 {
		if err := b.conn.SetAddElements(set, nftElems); err != nil {
			return fmt.Errorf("nftlib ReplaceSetFlushAdd %s (%d elems): %w", setName, len(nftElems), err)
		}
	}

	return b.conn.Flush()
}
