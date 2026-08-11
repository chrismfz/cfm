//go:build linux

package nftlib

import "testing"

func TestHashElems_OrderIndependentAndSensitive(t *testing.T) {
	a := []string{"1.2.3.4", "5.6.7.8", "9.9.9.9"}
	b := []string{"9.9.9.9", "1.2.3.4", "5.6.7.8"} // same content, different order
	if hashElems(a) != hashElems(b) {
		t.Fatalf("hash must be order-independent: %d != %d", hashElems(a), hashElems(b))
	}

	// A changed element must change the hash (so a real feed update is never skipped).
	c := []string{"1.2.3.4", "5.6.7.8", "9.9.9.10"}
	if hashElems(a) == hashElems(c) {
		t.Fatalf("hash must change when an element changes")
	}

	// Adding/removing an element must change the hash.
	d := []string{"1.2.3.4", "5.6.7.8"}
	if hashElems(a) == hashElems(d) {
		t.Fatalf("hash must change when the element count changes")
	}

	// Empty vs non-empty differ; empty is stable.
	if hashElems(nil) != hashElems([]string{}) {
		t.Fatalf("nil and empty must hash the same")
	}
	if hashElems(nil) == hashElems(a) {
		t.Fatalf("empty must differ from non-empty")
	}
}

// invalidateCache must drop the applied-content cache so a recreated/flushed set
// is rewritten on the next apply (never silently skipped).
func TestInvalidateCache_DropsAppliedHash(t *testing.T) {
	b := &Backend{appliedHash: map[string]uint64{"block_ext_v4_hosts": 12345}}
	b.invalidateCache()
	if len(b.appliedHash) != 0 {
		t.Fatalf("invalidateCache must clear appliedHash, got %v", b.appliedHash)
	}
}
