//go:build linux

package nftlib

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

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

// An unchanged permanent set is skipped only while the kernel still holds one
// of its elements: emptied or recreated by another process (`cfm reset` from
// the CLI), it is written again. A TTL set is always written.
func TestReplaceSetFlushAdd_SkipNeedsTheKernelToHoldTheSet(t *testing.T) {
	var batches int
	b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
		if isBatch(req) {
			batches++
		}
		return nil, io.EOF
	})
	const name = "block_ext_v4_hosts"
	b.namedSets[name] = &nftables.Set{Name: name, KeyType: nftables.TypeIPAddr, HasTimeout: true,
		Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
	holds := true
	var asked []string
	orig := kernelHolds
	kernelHolds = func(set, elem string) bool { asked = append(asked, set+" "+elem); return holds }
	t.Cleanup(func() { kernelHolds = orig })

	elems := []string{"198.51.100.1", "198.51.100.2"}
	write := func(ttl *time.Duration) int {
		t.Helper()
		before := batches
		if err := b.ReplaceSetFlushAdd(name, elems, ttl); err != nil {
			t.Fatal(err)
		}
		return batches - before
	}
	if n := write(nil); n != 1 {
		t.Fatalf("first write: %d transactions, want 1", n)
	}
	if n := write(nil); n != 0 {
		t.Fatalf("unchanged, kernel holds it: %d transactions, want 0 (skipped)", n)
	}
	if len(asked) != 1 || asked[0] != name+" 198.51.100.1" {
		t.Fatalf("the skip asked the kernel %v, want one lookup of the first element", asked)
	}
	holds = false
	if n := write(nil); n != 1 {
		t.Fatalf("unchanged, kernel lost it: %d transactions, want 1 (rewritten)", n)
	}
	holds = true
	d := time.Hour
	if n := write(&d); n != 1 {
		t.Fatalf("TTL set: %d transactions, want 1 (always rewritten)", n)
	}
}

// What a refused one-batch replace does next depends on why (replaceSet):
// too large → the chunked write; an element the kernel rejects → an error,
// the set keeping its old content (the chunked write would flush it and stop
// at the bad message); ENOBUFS → taken as applied only when the kernel holds
// the new content, and never recorded as verified.
func TestReplaceSet_RefusedBatchByCause(t *testing.T) {
	const name = "block_ext_v4_hosts"
	elems := make([]string, 3000)
	for i := range elems {
		elems[i] = fmt.Sprintf("198.51.%d.%d", i/256, i%256)
	}
	for _, tc := range []struct {
		name      string
		firstErr  error
		holds     bool
		wantErr   bool
		wantBatch int  // transactions sent
		wantHash  bool // content hash recorded (skip next time)
	}{
		{"ok", nil, true, false, 1, true},
		{"too large", unix.EMSGSIZE, true, false, 1 + 3, false},
		{"rejected element", unix.EINVAL, true, true, 1, false},
		{"acks overflowed, applied", unix.ENOBUFS, true, false, 1, false},
		{"acks overflowed, not applied", unix.ENOBUFS, false, false, 1 + 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var batches int
			b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
				if !isBatch(req) {
					return nil, io.EOF
				}
				batches++
				if batches == 1 && tc.firstErr != nil {
					return nil, tc.firstErr
				}
				return nil, io.EOF
			})
			b.namedSets[name] = &nftables.Set{Name: name, KeyType: nftables.TypeIPAddr, HasTimeout: true,
				Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
			orig := kernelHolds
			kernelHolds = func(string, string) bool { return tc.holds }
			t.Cleanup(func() { kernelHolds = orig })

			err := b.ReplaceSetFlushAdd(name, elems, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if batches != tc.wantBatch {
				t.Fatalf("%d transactions, want %d", batches, tc.wantBatch)
			}
			if _, ok := b.appliedHash[name]; ok != tc.wantHash {
				t.Fatalf("content hash recorded = %v, want %v", ok, tc.wantHash)
			}
		})
	}
}
