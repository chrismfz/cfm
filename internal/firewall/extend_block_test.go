package firewall

import (
	"errors"
	"fmt"
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

// errBatchFake fails AddBlockBatch with err and records AddBlock calls.
type errBatchFake struct {
	Backend
	err      error
	addBlock []string
}

func (f *errBatchFake) AddBlockBatch([]BlockEntry) (BlockBatchResult, error) {
	return BlockBatchResult{}, f.err
}

func (f *errBatchFake) AddBlock(ip net.IP, _ string, ttl *time.Duration) error {
	f.addBlock = append(f.addBlock, ip.String()+" "+ttl.String())
	return nil
}

// A set that cannot be read (an `nft -j list set` timeout under load) must
// not mean no ban at all: without an exclusive create (nftlib) ExtendBlock
// falls back to AddBlock. A write the
// kernel refused does not fall back (AddBlock would replace a longer ban the
// batch saw and meant to keep).
func TestExtendBlockFallsBackOnReadError(t *testing.T) {
	ip := net.ParseIP("203.0.113.40")
	f := &errBatchFake{err: fmt.Errorf("%w: inet cfm block_v4: %w", ErrBlockRead, errors.New("signal: killed"))}
	if kept, err := ExtendBlock(f, ip, time.Hour); err != nil || kept {
		t.Fatalf("read error: kept=%v err=%v, want blocked through AddBlock", kept, err)
	}
	if len(f.addBlock) != 1 || f.addBlock[0] != "203.0.113.40 1h0m0s" {
		t.Fatalf("AddBlock calls = %v", f.addBlock)
	}
	if res, err := ExtendBlockResult(f, ip, time.Hour); err != nil || res.Added != 1 {
		t.Fatalf("ExtendBlockResult on a read error = %+v, %v, want Added=1", res, err)
	}

	f = &errBatchFake{err: errors.New("nft block batch (1 v4, 0 v6), 3 attempts: Error: File exists")}
	if _, err := ExtendBlock(f, ip, time.Hour); err == nil {
		t.Fatal("a refused write reported success")
	}
	if len(f.addBlock) != 0 {
		t.Fatalf("a refused write fell back to AddBlock: %v", f.addBlock)
	}
}

// creatorFake is errBatchFake with an exclusive create (the exec backend).
type creatorFake struct {
	errBatchFake
	exists  bool
	created []string
}

func (f *creatorFake) CreateBlock(ip net.IP, ttl time.Duration) (bool, error) {
	f.created = append(f.created, ip.String()+" "+ttl.String())
	return f.exists, nil
}

// Where the backend can create exclusively, a failed read never replaces a
// ban: an existing one (a permanent cfm.deny ban) stays, and AddBlock is not
// called. ExtendBlock then reports blocked, not kept.
func TestExtendBlockReadErrorPrefersExclusiveCreate(t *testing.T) {
	ip := net.ParseIP("203.0.113.41")
	readErr := fmt.Errorf("%w: inet cfm block_v4: %w", ErrBlockRead, errors.New("signal: killed"))
	for _, exists := range []bool{false, true} {
		f := &creatorFake{errBatchFake: errBatchFake{err: readErr}, exists: exists}
		res, err := ExtendBlockResult(f, ip, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		// An existing ban of unknown length is Present, never Kept (which
		// promises one at least as long).
		if exists && (res.Present != 1 || res.Kept != 0) || !exists && res.Added != 1 {
			t.Errorf("exists=%v: result %+v", exists, res)
		}
		if len(f.created) != 1 || len(f.addBlock) != 0 {
			t.Errorf("exists=%v: created=%v addBlock=%v, want one create and no AddBlock", exists, f.created, f.addBlock)
		}
	}
}

func TestExtendBlockPresentIsNotKept(t *testing.T) {
	readErr := fmt.Errorf("%w: x", ErrBlockRead)
	f := &creatorFake{errBatchFake: errBatchFake{err: readErr}, exists: true}
	kept, err := ExtendBlock(f, net.ParseIP("203.0.113.42"), time.Hour)
	if err != nil || kept {
		t.Fatalf("kept=%v err=%v, want blocked and not kept", kept, err)
	}
}
