//go:build linux

package nftlib

import (
	"os"
	"syscall"
	"testing"

	cfgpkg "cfm/internal/config"
	"cfm/internal/firewall/autoblock"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/nltest"
	"golang.org/x/sys/unix"
)

const getTableType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETTABLE)

const getObjType = netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETOBJ)

// enoent answers r with the kernel's ENOENT. nltest.Error keeps the
// request's flags, and a dump request's (Root|Match) read as Capped|
// AcknowledgeTLVs on an error message, so the reply carries none.
func enoent(r []netlink.Message) ([]netlink.Message, error) {
	req := r[0]
	req.Header.Flags = 0
	return nltest.Error(int(unix.ENOENT), []netlink.Message{req})
}

// tableLookupBackend returns a Backend whose every inet cfm table lookup gets
// reply (and every counter dump gets ENOENT), with EnsureBase replaced by a
// counter, and the count of kernel requests. The counter read makes exactly
// one request (GETTABLE, or GETOBJ with a cached handle); every further
// request is the throttle pass reading its sets.
func tableLookupBackend(t *testing.T, reply func([]netlink.Message) ([]netlink.Message, error)) (b *Backend, repairs, reqs *int) {
	t.Helper()
	repairs, reqs = new(int), new(int)
	var st nlStats
	conn := nlTestConn(t, &st, func(req []netlink.Message) ([]netlink.Message, error) {
		if len(req) == 0 {
			return nil, nil
		}
		*reqs++
		switch req[0].Header.Type {
		case getTableType:
			return reply(req)
		case getObjType:
			return enoent(req)
		}
		return nil, nil
	})
	cfg := &cfgpkg.Config{}
	cfg.Throttle.Enabled = true
	// Explicit, so the pass does not read THROTTLE_SOURCES from the env.
	cfg.Throttle.Sources = []string{"syn", "new"}
	b = &Backend{
		conn:       conn,
		namedSets:  map[string]*nftables.Set{},
		last:       map[string]uint64{},
		ab:         autoblock.New(),
		cfg:        cfg,
		repairBase: func() error { *repairs++; return nil },
	}
	return b, repairs, reqs
}

// CLAUDE.md §2: a failed or unknown read never starts a repair; only a
// definite "table absent" (the kernel's ENOENT answer to GETTABLE) does. And
// a failed counter read (log-only) never skips the throttle autoblock pass.
func TestDumpFloodCounters_RepairsOnlyADefiniteAbsence(t *testing.T) {
	cases := []struct {
		name       string
		reply      func([]netlink.Message) ([]netlink.Message, error)
		wantRepair int
	}{
		{"deadline", func([]netlink.Message) ([]netlink.Message, error) { return nil, os.ErrDeadlineExceeded }, 0},
		{"enobufs", func([]netlink.Message) ([]netlink.Message, error) { return nil, syscall.ENOBUFS }, 0},
		{"kernel EBUSY", func(r []netlink.Message) ([]netlink.Message, error) { return nltest.Error(int(unix.EBUSY), r) }, 0},
		{"absent (ENOENT)", enoent, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, repairs, reqs := tableLookupBackend(t, tc.reply)
			b.dumpFloodCountersOnce()
			if *repairs != tc.wantRepair {
				t.Fatalf("repairs = %d, want %d", *repairs, tc.wantRepair)
			}
			if *reqs < 2 {
				t.Fatalf("kernel requests = %d: the throttle pass did not run after the failed counter read", *reqs)
			}
		})
	}
}

// A cached handle hides an out-of-band wipe from lookupTable: the counter
// dump's ENOENT must drop the cache (so the next tick asks the kernel) without
// repairing on its own, and the throttle pass still runs.
func TestDumpFloodCounters_StaleCachedTableDropsTheCache(t *testing.T) {
	b, repairs, reqs := tableLookupBackend(t, enoent)
	stale := &nftables.Table{Name: cfmTableName, Family: nftables.TableFamilyINet}
	b.table = stale
	b.dumpFloodCountersOnce()
	if *repairs != 0 {
		t.Fatalf("a failed counter dump must not repair by itself: repairs = %d", *repairs)
	}
	if b.table == stale {
		t.Fatal("the stale cached table handle was kept after the kernel's ENOENT")
	}
	if *reqs < 2 {
		t.Fatalf("kernel requests = %d: the throttle pass did not run after the failed counter dump", *reqs)
	}
	// Next tick: the lookup now reaches the kernel, whose ENOENT repairs.
	b.dumpFloodCountersOnce()
	if *repairs == 0 {
		t.Fatal("the next tick did not repair the definitely absent table")
	}
}

func TestLookupTable_ClassifiesAbsence(t *testing.T) {
	b, _, _ := tableLookupBackend(t, enoent)
	b.mu.Lock()
	_, err := b.lookupTable()
	b.mu.Unlock()
	if !tableAbsent(err) || !isNotFound(err) {
		t.Fatalf("ENOENT must read as absent (and stay isNotFound for DropEverything): %v", err)
	}
	b, _, _ = tableLookupBackend(t, func([]netlink.Message) ([]netlink.Message, error) { return nil, os.ErrDeadlineExceeded })
	b.mu.Lock()
	_, err = b.lookupTable()
	b.mu.Unlock()
	if err == nil || tableAbsent(err) {
		t.Fatalf("a deadline must not read as absent: %v", err)
	}
}
