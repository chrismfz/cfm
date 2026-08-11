//go:build linux

package nftlib

import (
	"fmt"
	"time"

	"cfm/internal/logging"
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
func (b *Backend) ReplaceSetFlushAdd(setName string, elems []string, ttl *time.Duration) (err error) {
	start := time.Now()
	n := 0
	// Record size/duration/outcome for the self-test, and log the failure so a
	// feed that never applies (e.g. a large set hitting "message too long") is
	// visible. Registered before the b.mu.Unlock defer so (LIFO) it runs AFTER
	// the unlock — recordFeedWrite takes statMu only, so no lock nesting.
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

	// Queue flush + add; both execute in one conn.Flush() call.
	b.conn.FlushSet(set)

	nftElems := parseElems(set, elems, ttl)
	n = len(nftElems)
	if n > 0 {
		if e := b.conn.SetAddElements(set, nftElems); e != nil {
			err = fmt.Errorf("nftlib ReplaceSetFlushAdd %s (%d elems): %w", setName, n, e)
			return err
		}
	}

	err = b.conn.Flush()
	return err
}
