package firewall

import (
	"net"
	"testing"
	"time"
)

// extendFake models a block set: AddBlockBatch plans like the real backends
// (PlanBlockBatch), AddBlock replaces the element like they do.
type extendFake struct {
	Backend
	left map[string]time.Duration // 0 = permanent
}

func (f *extendFake) AddBlockBatch(entries []BlockEntry) (BlockBatchResult, error) {
	var cur []SetElementTimed
	for ip, d := range f.left {
		cur = append(cur, SetElementTimed{Elem: ip, Expires: d})
	}
	v4, _, skipped := SplitBlockEntries(entries)
	plan := PlanBlockBatch(v4, cur)
	r := BlockBatchResult{Skipped: skipped, Kept: plan.Kept}
	for _, w := range plan.Writes {
		if w.Replace {
			r.Extended++
		} else {
			r.Added++
		}
		f.left[w.IP.String()] = w.TTL
	}
	return r, nil
}

func (f *extendFake) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	f.left[ip.String()] = 0
	if ttl != nil {
		f.left[ip.String()] = *ttl
	}
	return nil
}

// A 1h block of an address banned for 7d must leave the 7d ban: AddBlock
// replaced it (mars, 2026-10-09: the ban expired after an hour).
func TestExtendBlockNeverShortens(t *testing.T) {
	ip := net.ParseIP("34.153.214.160")
	f := &extendFake{left: map[string]time.Duration{}}

	if kept, err := ExtendBlock(f, ip, 7*24*time.Hour); err != nil || kept {
		t.Fatalf("first block: kept=%v err=%v, want an add", kept, err)
	}
	if kept, err := ExtendBlock(f, ip, time.Hour); err != nil || !kept {
		t.Fatalf("1h over 7d: kept=%v err=%v, want kept", kept, err)
	}
	if got := f.left[ip.String()]; got != 7*24*time.Hour {
		t.Fatalf("after a 1h block over a 7d one: %v left, want 7d", got)
	}
	// A longer one extends.
	if kept, err := ExtendBlock(f, ip, 30*24*time.Hour); err != nil || kept {
		t.Fatalf("30d over 7d: kept=%v err=%v, want an extend", kept, err)
	}
	if got := f.left[ip.String()]; got != 30*24*time.Hour {
		t.Fatalf("after a 30d block: %v left, want 30d", got)
	}
	// A permanent block stays permanent.
	perm := net.ParseIP("203.0.113.7")
	_ = f.AddBlock(perm, "", nil)
	if kept, err := ExtendBlock(f, perm, time.Hour); err != nil || !kept || f.left[perm.String()] != 0 {
		t.Fatalf("1h over permanent: kept=%v err=%v left=%v, want permanent kept", kept, err, f.left[perm.String()])
	}
	// The old replace path is what shortened it.
	_ = f.AddBlock(ip, "", ptrDur(time.Hour))
	if f.left[ip.String()] != time.Hour {
		t.Fatal("fake AddBlock no longer models the replace this guards against")
	}
	// Not blockable.
	if _, err := ExtendBlock(f, net.IPv4zero, time.Hour); err == nil {
		t.Fatal("an unspecified address must report an error")
	}
}

func ptrDur(d time.Duration) *time.Duration { return &d }
