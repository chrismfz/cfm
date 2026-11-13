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
// the new content, and then not recorded as verified. A chunked write that
// succeeds is recorded, so an unchanged feed is skipped next time as before.
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
		{"too large", unix.EMSGSIZE, true, false, 1 + 3, true},
		{"rejected element", unix.EINVAL, true, true, 1, false},
		{"acks overflowed, applied", unix.ENOBUFS, true, false, 1, false},
		{"acks overflowed, not applied", unix.ENOBUFS, false, false, 1 + 3, true},
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

// ENOTEMPTY on an interval set is the one-batch quirk only when the intervals
// do not overlap; overlapping content is the kernel refusing the content, and
// the chunked write would flush the set and stop at it.
func TestReplaceSet_IntervalENOTEMPTY(t *testing.T) {
	const name = "block_ext_v4_nets"
	for _, tc := range []struct {
		name      string
		overlap   bool
		wantErr   bool
		wantBatch int
	}{
		{"quirk", false, false, 1 + 1 + 1}, // refused batch, flush alone, one add
		{"overlap", true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var batches int
			b := nlBackend(t, func(req []netlink.Message) ([]netlink.Message, error) {
				if !isBatch(req) {
					return nil, io.EOF
				}
				batches++
				if batches == 1 {
					return nil, unix.ENOTEMPTY
				}
				return nil, io.EOF
			})
			set := &nftables.Set{Name: name, KeyType: nftables.TypeIPAddr, Interval: true, HasTimeout: true,
				Table: &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}}
			b.namedSets[name] = set
			elems := parseElems(set, []string{"10.1.0.0/16", "10.3.0.0/16"}, nil)
			if tc.overlap {
				elems = append(elems, parseElems(set, []string{"10.1.2.0/24"}, nil)...)
			}
			b.mu.Lock()
			_, err := b.replaceSet(set, elems)
			b.mu.Unlock()
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if batches != tc.wantBatch {
				t.Fatalf("%d transactions, want %d", batches, tc.wantBatch)
			}
		})
	}
}

func TestIntervalsOverlap(t *testing.T) {
	set := &nftables.Set{Interval: true}
	for _, tc := range []struct {
		cidrs []string
		want  bool
	}{
		{[]string{"10.0.0.0/24", "10.0.1.0/24"}, false}, // adjacent
		{[]string{"10.0.1.0/24", "10.0.0.0/24"}, false}, // any order
		{[]string{"10.0.0.0/16", "10.0.5.0/24"}, true},
		{[]string{"255.255.255.0/24", "10.0.0.0/8"}, false}, // end wraps to 0
		{[]string{"255.255.0.0/16", "255.255.255.0/24"}, true},
		{nil, false},
	} {
		if got := intervalsOverlap(parseElems(set, tc.cidrs, nil)); got != tc.want {
			t.Errorf("intervalsOverlap(%v) = %v, want %v", tc.cidrs, got, tc.want)
		}
	}
}

// The ENOBUFS check asks for what the batch wrote: hosts, or interval starts,
// spread across the content, first and last included.
func TestProbeElems(t *testing.T) {
	iv := &nftables.Set{Interval: true}
	got := probeElems(parseElems(iv, []string{"10.1.0.0/16", "2001:db8::/32"}, nil), 32)
	if len(got) != 2 || got[0] != "10.1.0.0" || got[1] != "2001:db8::" {
		t.Fatalf("interval starts: %v", got)
	}
	var hosts []string
	for i := 0; i < 1000; i++ {
		hosts = append(hosts, fmt.Sprintf("198.51.%d.%d", i/256, i%256))
	}
	hosts = append(hosts, "not-an-address")
	got = probeElems(parseElems(&nftables.Set{}, hosts, nil), 32)
	if len(got) != 32 || got[0] != "198.51.0.0" || got[31] != "198.51.3.231" {
		t.Fatalf("hosts: %d probes, first %q last %q", len(got), got[0], got[len(got)-1])
	}
}
