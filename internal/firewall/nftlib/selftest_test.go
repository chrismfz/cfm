//go:build linux

package nftlib

import (
	"errors"
	"testing"
	"time"
)

func TestNftlibSelfTest_RingBoundedAndWorst(t *testing.T) {
	b := &Backend{feedWrites: make(map[string]fwSample)}

	// Record more than the ring capacity; only the last ensureBaseRingCap are kept,
	// but Samples counts every call.
	total := ensureBaseRingCap + 12
	for i := 0; i < total; i++ {
		// Make one call in the retained window clearly the worst.
		nl := time.Duration(i) * time.Millisecond
		if i == total-3 {
			nl = 9 * time.Second
		}
		b.recordEnsureBase(time.Duration(i)*time.Millisecond, nl, 0, nil)
	}

	st := b.NftlibSelfTest()
	if st.Engine != "nftlib" {
		t.Fatalf("engine = %q", st.Engine)
	}
	if st.Samples != total {
		t.Fatalf("samples = %d, want %d", st.Samples, total)
	}
	if len(st.EnsureBaseRecent) != ensureBaseRingCap {
		t.Fatalf("retained = %d, want %d (ring must be bounded)", len(st.EnsureBaseRecent), ensureBaseRingCap)
	}
	// Chronological order: last entry is the most recent call (i == total-1).
	last := st.EnsureBaseRecent[len(st.EnsureBaseRecent)-1]
	if last.LockWaitMs != int64(total-1) {
		t.Fatalf("last lock_wait_ms = %d, want %d", last.LockWaitMs, total-1)
	}
	if st.EnsureBaseWorst == nil || st.EnsureBaseWorst.NLWorkMs != 9000 {
		t.Fatalf("worst should be the 9s nl_work call, got %+v", st.EnsureBaseWorst)
	}
}

func TestNftlibSelfTest_FeedWritesOrderedErrorsFirst(t *testing.T) {
	b := &Backend{feedWrites: make(map[string]fwSample)}
	b.recordFeedWrite("block_ext_v4_hosts", 50000, 12*time.Second, errors.New("sendmsg: message too long"))
	b.recordFeedWrite("allow_ext_v4_hosts", 3, 2*time.Millisecond, nil)
	b.recordFeedWrite("block_ext_v6_hosts", 0, 1*time.Millisecond, nil)
	// latest-wins for the same set
	b.recordFeedWrite("allow_ext_v4_hosts", 4, 3*time.Millisecond, nil)

	st := b.NftlibSelfTest()
	if len(st.FeedWrites) != 3 {
		t.Fatalf("expected 3 distinct sets, got %d: %+v", len(st.FeedWrites), st.FeedWrites)
	}
	// Errored set sorts first.
	if st.FeedWrites[0].Set != "block_ext_v4_hosts" || st.FeedWrites[0].Err == "" {
		t.Fatalf("errored set must sort first, got %+v", st.FeedWrites)
	}
	if st.FeedWrites[0].Elems != 50000 || st.FeedWrites[0].DurMs != 12000 {
		t.Fatalf("errored set fields wrong: %+v", st.FeedWrites[0])
	}
	// latest-wins captured the second allow write.
	for _, f := range st.FeedWrites {
		if f.Set == "allow_ext_v4_hosts" && f.Elems != 4 {
			t.Fatalf("latest-wins failed for allow set: %+v", f)
		}
	}
}

func TestNftlibSelfTest_Empty(t *testing.T) {
	b := &Backend{feedWrites: make(map[string]fwSample)}
	st := b.NftlibSelfTest()
	if st.Samples != 0 || len(st.EnsureBaseRecent) != 0 || st.EnsureBaseWorst != nil || len(st.FeedWrites) != 0 {
		t.Fatalf("empty backend should yield an empty snapshot, got %+v", st)
	}
}
